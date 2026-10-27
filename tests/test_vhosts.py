import http.server
import itertools
import json
import threading
from pathlib import Path

import pytest

from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon import vhosts
from soul_toolkit.recon.modules import Context, Options, web

FIXTURES = Path(__file__).parent / "fixtures"


def make_ctx(tmp_path, target="127.0.0.1", **opts):
    return Context(target=target, outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult(target), options=Options(**opts))


# ----------------------------------------------------------------- pure helpers


@pytest.mark.parametrize("target,redirect,is_ip,expected", [
    ("10.10.10.10", None, True, None),               # nothing to fuzz under
    ("10.10.10.10", "hotel.thm", True, "hotel.thm"),  # redirect revealed a name
    ("hotel.thm", None, False, "hotel.thm"),
    ("hotel.thm", "www.hotel.thm", False, "hotel.thm"),  # www. dropped
    ("localhost", None, False, None),                # single label
    ("Box.THM.", None, False, "box.thm"),
])
def test_fuzz_domain(target, redirect, is_ip, expected):
    assert vhosts.fuzz_domain(target, redirect, is_ip) == expected


def test_wildcard_size():
    assert vhosts.wildcard_size([20, 20]) == 20
    assert vhosts.wildcard_size([20, 21]) is None
    assert vhosts.wildcard_size([20, None]) is None
    assert vhosts.wildcard_size([]) is None


def test_build_ffuf():
    cmd = vhosts.build_ffuf("http://10.10.10.10", "box.thm", "w.txt", Path("o.json"),
                            threads=30, timeout=8, maxtime=600, filter_size=154)
    assert cmd[:3] == ["ffuf", "-u", "http://10.10.10.10/"]
    assert cmd[cmd.index("-H") + 1] == "Host: FUZZ.box.thm"
    assert cmd[cmd.index("-fs") + 1] == "154" and "-ac" not in cmd
    assert cmd[cmd.index("-maxtime") + 1] == "600"
    dynamic = vhosts.build_ffuf("http://x", "box.thm", "w.txt", Path("o.json"),
                                threads=1, timeout=1, maxtime=1, filter_size=None)
    assert "-ac" in dynamic and "-fs" not in dynamic


def test_build_gobuster_vhost():
    cmd = vhosts.build_gobuster_vhost("https://10.10.10.10", "box.thm", "w.txt", Path("o.txt"),
                                      threads=30, timeout=8, filter_size=154, tls=True)
    assert cmd[:2] == ["gobuster", "vhost"] and "--append-domain" in cmd
    assert cmd[cmd.index("--domain") + 1] == "box.thm"
    assert cmd[cmd.index("--exclude-length") + 1] == "154" and cmd[-1] == "-k"


def test_parse_real_ffuf_output():
    found = vhosts.parse_ffuf((FIXTURES / "ffuf-vhosts.json").read_text())
    assert found == [{"host": "admin.hotel.thm", "status": 403, "size": 9},
                     {"host": "dev.hotel.thm", "status": 200, "size": 47}]
    assert vhosts.parse_ffuf("") == [] and vhosts.parse_ffuf("{not json") == []


def test_parse_real_gobuster_vhost_output():
    found = vhosts.parse_gobuster_vhost((FIXTURES / "gobuster-vhosts.txt").read_text())
    assert [v["host"] for v in found] == ["admin.hotel.thm", "dev.hotel.thm"]
    old_style = vhosts.parse_gobuster_vhost("Found: dev.box.thm (Status: 200) [Size: 47]\nnoise\n")
    assert old_style == [{"host": "dev.box.thm", "status": 200, "size": 47}]


def test_hosts_line():
    found = [{"host": "dev.box.thm"}, {"host": "admin.box.thm"}]
    assert vhosts.hosts_line("10.10.10.10", "box.thm", found) == "10.10.10.10 box.thm dev.box.thm admin.box.thm"


def test_bundled_wordlist():
    path, _ = vhosts.resolve_wordlist(None)
    assert Path(path).is_file() and "dev" in Path(path).read_text().split()
    with pytest.raises(FileNotFoundError):
        vhosts.resolve_wordlist("/nope/missing.txt")


# ----------------------------------------------------------------- module (local server)

VHOSTS = {"dev.hotel.thm": (200, b"<html>dev site with lots of content here</html>"),
          "admin.hotel.thm": (403, b"forbidden")}
_counter = itertools.count()


class _VhostHandler(http.server.BaseHTTPRequestHandler):
    dynamic = False

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        if host in VHOSTS:
            status, body = VHOSTS[host]
        elif self.dynamic:
            status, body = 200, b"x" * (10 + next(_counter))  # size changes every request
        else:
            status, body = 200, b"<html>default</html>"  # 20 bytes for any unknown name
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _DynamicHandler(_VhostHandler):
    dynamic = True


@pytest.fixture
def vhost_server():
    servers = []

    def start(handler=_VhostHandler):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for s in servers:
        s.shutdown()


def fake_ffuf(calls, fixture="ffuf-vhosts.json"):
    def _run(cmd, timeout=None):
        calls.append(cmd)
        if cmd[0] == "ffuf":
            Path(cmd[cmd.index("-o") + 1]).write_text((FIXTURES / fixture).read_text())
        return runner.CommandResult(cmd, 0, "", "", 0.1)
    return _run


def test_module_calibrates_and_reports_vhosts(tmp_path, monkeypatch, vhost_server):
    port = vhost_server()
    calls = []
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/ffuf" if tool == "ffuf" else None)
    monkeypatch.setattr(runner, "run", fake_ffuf(calls))
    ctx = make_ctx(tmp_path, target="10.10.10.10")
    mod = web.WebModule()
    findings = mod._vhost_fuzz(ctx, Service(port, name="http"), f"http://127.0.0.1:{port}", "hotel.thm")
    [cmd] = calls
    assert cmd[cmd.index("-fs") + 1] == "20"  # the measured wildcard size
    [f] = findings
    assert f.severity == "medium" and [v["host"] for v in f.data["vhosts"]] == ["admin.hotel.thm", "dev.hotel.thm"]
    assert f.data["hosts_line"] == "10.10.10.10 hotel.thm admin.hotel.thm dev.hotel.thm"
    [lead] = ctx.result.leads
    assert lead.kind == "web-vhosts"
    assert lead.command == "echo '10.10.10.10 hotel.thm admin.hotel.thm dev.hotel.thm' | sudo tee -a /etc/hosts"


def test_module_dynamic_wildcard_uses_autocalibration(tmp_path, monkeypatch, vhost_server):
    port = vhost_server(_DynamicHandler)
    calls = []
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/ffuf" if tool == "ffuf" else None)
    monkeypatch.setattr(runner, "run", fake_ffuf(calls))
    web.WebModule()._vhost_fuzz(make_ctx(tmp_path), Service(port, name="http"), f"http://127.0.0.1:{port}", "x.thm")
    assert "-ac" in calls[0] and "-fs" not in calls[0]


def test_module_falls_back_to_gobuster(tmp_path, monkeypatch, vhost_server):
    port = vhost_server()
    calls = []

    def run(cmd, timeout=None):
        calls.append(cmd)
        return runner.CommandResult(cmd, 0, (FIXTURES / "gobuster-vhosts.txt").read_text(), "", 0.1)

    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/gobuster" if tool == "gobuster" else None)
    monkeypatch.setattr(runner, "run", run)
    findings = web.WebModule()._vhost_fuzz(make_ctx(tmp_path), Service(port, name="http"),
                                           f"http://127.0.0.1:{port}", "hotel.thm")
    assert calls[0][:2] == ["gobuster", "vhost"] and calls[0][calls[0].index("--exclude-length") + 1] == "20"
    assert len(findings[0].data["vhosts"]) == 2


def test_module_without_tools_warns(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "which", lambda tool: None)
    ctx = make_ctx(tmp_path)
    assert web.WebModule()._vhost_fuzz(ctx, Service(80, name="http"), "http://127.0.0.1:9", "x.thm") == []
    assert any("ffuf" in h for h in ctx.result.hints)


def test_vhost_fuzz_only_runs_with_a_name(tmp_path, monkeypatch, vhost_server):
    port = vhost_server()
    seen = []
    monkeypatch.setattr(web.WebModule, "_content_discovery", lambda self, ctx, svc, base, page: [])
    monkeypatch.setattr(web.WebModule, "_vhost_fuzz", lambda self, ctx, svc, base, domain: seen.append(domain) or [])
    web.WebModule().run(make_ctx(tmp_path, target="127.0.0.1"), Service(port, name="http"))
    assert seen == []  # plain IP, no redirect: nothing to fuzz
    web.WebModule().run(make_ctx(tmp_path, target="localhost"), Service(port, name="http"))
    assert seen == []  # single-label name
    web.WebModule().run(make_ctx(tmp_path, target="127.0.0.1", vhosts=False), Service(port, name="http"))
    assert seen == []


def test_report_renders_vhosts(tmp_path, monkeypatch, vhost_server):
    from soul_toolkit.recon.report import render_markdown

    port = vhost_server()
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/ffuf" if tool == "ffuf" else None)
    monkeypatch.setattr(runner, "run", fake_ffuf([]))
    ctx = make_ctx(tmp_path)
    ctx.result.findings = web.WebModule()._vhost_fuzz(ctx, Service(port, name="http"),
                                                      f"http://127.0.0.1:{port}", "hotel.thm")
    md = render_markdown(ctx.result)
    assert "| `dev.hotel.thm` | 200 | 47 |" in md
    assert "127.0.0.1 hotel.thm admin.hotel.thm dev.hotel.thm" in md


# ----------------------------------------------------------------- real tools (skipped when missing)


@pytest.mark.parametrize("tool", ["ffuf", "gobuster"])
def test_real_tool_against_local_vhost_server(tool, tmp_path, monkeypatch, vhost_server):
    if not runner.which(tool):
        pytest.skip(f"{tool} not installed")
    port = vhost_server()
    real_which = runner.which
    monkeypatch.setattr(runner, "which", lambda t: real_which(t) if t == tool else None)
    wl = tmp_path / "words.txt"
    wl.write_text("www\ndev\nadmin\nmail\ntest\n")
    ctx = make_ctx(tmp_path, target="hotel.thm", vhost_wordlist=str(wl), brute_timeout=60)
    ctx.result.address = "127.0.0.1"
    [f] = web.WebModule()._vhost_fuzz(ctx, Service(port, name="http"), f"http://127.0.0.1:{port}", "hotel.thm")
    assert {v["host"] for v in f.data["vhosts"]} == {"dev.hotel.thm", "admin.hotel.thm"}
    assert f.data["hosts_line"] == "127.0.0.1 hotel.thm admin.hotel.thm dev.hotel.thm"
    if tool == "ffuf":
        assert json.loads((tmp_path / f"vhosts-{port}.json").read_text())["results"]


def test_vhosts_lead_replaces_redirect_lead(tmp_path, monkeypatch, vhost_server):
    port = vhost_server()
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/ffuf" if tool == "ffuf" else None)
    monkeypatch.setattr(runner, "run", fake_ffuf([]))
    ctx = make_ctx(tmp_path)
    ctx.lead("web-vhost", port, "Add hotel.thm", "redirect", "echo '127.0.0.1 hotel.thm' | sudo tee -a /etc/hosts")
    ctx.lead("web-vhost", 8080, "Other port", "redirect", "echo other")
    web.WebModule()._vhost_fuzz(ctx, Service(port, name="http"), f"http://127.0.0.1:{port}", "hotel.thm")
    assert [(x.kind, x.port) for x in ctx.result.leads] == [("web-vhost", 8080), ("web-vhosts", port)]


def test_parse_gobuster_vhost_38_format():
    # gobuster 3.8 dropped the "Found:" prefix; both formats must parse.
    out = "admin.hotel.thm Status: 200 [Size: 13]\ndev.hotel.thm Status: 200 [Size: 13]\nnoise line\n"
    assert [v["host"] for v in vhosts.parse_gobuster_vhost(out)] == ["admin.hotel.thm", "dev.hotel.thm"]
