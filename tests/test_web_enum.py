import http.server
import threading
from email.message import Message
from typing import ClassVar

import pytest

from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon.modules import Context, Options, web


def make_ctx(tmp_path, **opts):
    return Context(target="127.0.0.1", outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult("127.0.0.1"), options=Options(**opts))


def page(headers=None, body=""):
    return web.HttpResponse(200, {k.lower(): v for k, v in (headers or {}).items()}, body)


# ----------------------------------------------------------------- extension picking


def test_link_extensions():
    body = ('<a href="login.php">x</a><a href="/a/b.php?x=1">y</a><form action="post.php">'
            '<script src="https://cdn.example.com/lib.js"></script><a href="mailto:a@b.c">m</a>'
            '<img src=logo.png><a href="/dir/">d</a>')
    assert web.link_extensions(body) == ["php", "js", "png"]


@pytest.mark.parametrize("svc,resp,exts,stack", [
    (Service(80), page({"X-Powered-By": "PHP/7.4.3"}), "php,txt,bak", "PHP"),
    (Service(80), page({"Set-Cookie": "PHPSESSID=abc; path=/"}), "php,txt,bak", "PHP"),
    (Service(80), page(body='<meta name="generator" content="WordPress 6.1">'), "php,txt,bak", "PHP"),
    (Service(80), page(body='<a href="index.php">home</a>'), "php,txt,bak", "PHP"),
    (Service(80), page({"Server": "Microsoft-IIS/10.0"}), "aspx,asp,txt", "ASP.NET"),
    (Service(80, product="Microsoft IIS httpd", version="10.0"), page(), "aspx,asp,txt", "ASP.NET"),
    (Service(80), page({"X-AspNet-Version": "4.0.30319"}), "aspx,asp,txt", "ASP.NET"),
    (Service(8080, product="Apache Tomcat"), page(), "jsp,do,txt", "Java"),
    (Service(8080), page({"Set-Cookie": "JSESSIONID=1"}), "jsp,do,txt", "Java"),
    (Service(8000, product="SimpleHTTPServer"), page(), "html,txt", "static HTML"),
    (Service(80), page(body='<a href="about.html">a</a>'), "html,txt", "static HTML"),
])
def test_pick_extensions(svc, resp, exts, stack):
    got, why = web.pick_extensions(svc, resp)
    assert got == exts and why.startswith(stack)


def test_pick_extensions_none_and_combined():
    assert web.pick_extensions(Service(80, product="nginx"), page({"Server": "nginx"}))[0] == ""
    assert web.pick_extensions(Service(80), None)[0] == ""
    # two stacks: union, in priority order, no duplicate "txt"
    got, why = web.pick_extensions(Service(80), page({"X-Powered-By": "PHP/8.1"}, '<a href="x.html">'))
    assert got == "php,txt,bak,html" and "PHP" in why and "static HTML" in why
    # cookies set in several headers are all seen
    msg = Message()
    msg["Set-Cookie"] = "a=1"
    msg["Set-Cookie"] = "JSESSIONID=2"
    resp = web.HttpResponse(200, web._headers(msg), "")
    assert web.pick_extensions(Service(80), resp)[0] == "jsp,do,txt"


# ----------------------------------------------------------------- recursion candidates

HITS = [
    {"path": "/admin", "status": 301, "size": 0, "redirect": "http://127.0.0.1/admin/"},
    {"path": "/css", "status": 301, "size": 0, "redirect": "/css/"},
    {"path": "/.git", "status": 301, "size": 0, "redirect": "/.git/"},
    {"path": "/uploads", "status": 301, "size": 0, "redirect": "/uploads/"},
    {"path": "/blog", "status": 301, "size": 0, "redirect": "/blog/"},
    {"path": "/login", "status": 302, "size": 0, "redirect": "/index.php"},  # redirect elsewhere: not a dir
    {"path": "/index.php", "status": 200, "size": 10, "redirect": ""},
]


def test_directories_and_candidates():
    assert web.directories(HITS) == ["/admin", "/css", "/.git", "/uploads", "/blog"]
    # interesting names first, static dirs dropped, capped
    assert web.recurse_candidates(HITS) == ["/admin", "/uploads", "/blog"]
    assert web.recurse_candidates(HITS, limit=1) == ["/admin"]


# ----------------------------------------------------------------- content discovery (fake gobuster)

ROOT_OUT = (
    "/admin                (Status: 301) [Size: 0] [--> /admin/]\n"
    "/css                  (Status: 301) [Size: 0] [--> /css/]\n"
    "/index.php            (Status: 200) [Size: 120]\n"
)
ADMIN_OUT = "/config.php.bak       (Status: 200) [Size: 42]\n/index.php            (Status: 200) [Size: 5]\n"


def fake_gobuster(calls, outputs):
    def run(cmd, timeout=None):
        calls.append((cmd, timeout))
        url = cmd[cmd.index("-u") + 1]
        return runner.CommandResult(cmd, 0, outputs.get(url, ""), "", 0.1)
    return run


@pytest.fixture
def gobuster_present(monkeypatch):
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/" + tool)


def test_content_discovery_picks_extensions_and_recurses(tmp_path, monkeypatch, gobuster_present):
    calls = []
    monkeypatch.setattr(runner, "run", fake_gobuster(calls, {"http://x": ROOT_OUT, "http://x/admin": ADMIN_OUT}))
    ctx = make_ctx(tmp_path)
    findings = web.WebModule()._content_discovery(ctx, Service(80, name="http"), "http://x",
                                                  page({"X-Powered-By": "PHP/8.1"}))
    urls = [c[c.index("-u") + 1] for c, _ in calls]
    assert urls == ["http://x", "http://x/admin"]  # /css skipped as static
    assert all(c[c.index("-x") + 1] == "php,txt,bak" for c, _ in calls)
    assert calls[1][0][calls[1][0].index("-o") + 1].endswith("gobuster-80-admin.txt")
    summary = findings[0]
    assert [h["path"] for h in summary.data["paths"]] == ["/admin", "/css", "/index.php",
                                                         "/admin/config.php.bak", "/admin/index.php"]
    assert summary.data["recursed"] == ["/admin"]
    assert "extensions: php,txt,bak (PHP (x-powered-by: PHP/8.1))" in summary.detail
    assert "recursed into /admin/" in summary.detail
    juicy = next(f for f in findings if f.title == "Interesting paths worth checking")
    assert "/admin/config.php.bak" in [h["path"] for h in juicy.data["paths"]]


def test_user_extensions_win_and_no_recurse(tmp_path, monkeypatch, gobuster_present):
    calls = []
    monkeypatch.setattr(runner, "run", fake_gobuster(calls, {"http://x": ROOT_OUT}))
    ctx = make_ctx(tmp_path, extensions="txt", recurse=False)
    web.WebModule()._content_discovery(ctx, Service(80, name="http"), "http://x", page({"X-Powered-By": "PHP"}))
    assert len(calls) == 1 and calls[0][0][calls[0][0].index("-x") + 1] == "txt"


def test_no_extensions_flag_when_nothing_detected(tmp_path, monkeypatch, gobuster_present):
    calls = []
    monkeypatch.setattr(runner, "run", fake_gobuster(calls, {}))
    [f] = web.WebModule()._content_discovery(make_ctx(tmp_path), Service(80, name="http"), "http://x", page())
    assert "-x" not in calls[0][0] and f.title == "Content discovery: nothing found"


def test_time_budget_is_shared_and_stops_recursion(tmp_path, monkeypatch, gobuster_present):
    clock = [1000.0]
    monkeypatch.setattr(web.time, "monotonic", lambda: clock[0])
    calls = []
    inner = fake_gobuster(calls, {"http://x": ROOT_OUT + "/uploads (Status: 301) [Size: 0] [--> /uploads/]\n",
                                  "http://x/admin": ADMIN_OUT})

    def run(cmd, timeout=None):
        res = inner(cmd, timeout)
        clock[0] += 50  # every gobuster run takes 50s
        return res

    monkeypatch.setattr(runner, "run", run)
    ctx = make_ctx(tmp_path, brute_timeout=110)
    findings = web.WebModule()._content_discovery(ctx, Service(80, name="http"), "http://x", page())
    assert [t for _, t in calls] == [110, 60]  # second run only gets what's left
    assert len(calls) == 2  # /uploads skipped: 10s left < MIN_RUN_SECONDS
    assert "partial - time budget reached" in findings[0].detail


def test_wildcard_retry_inside_recursion(tmp_path, monkeypatch, gobuster_present):
    calls = []
    wildcard = ("Error: the server returns a status code that matches the provided options for non existing "
                "urls. http://x/admin/1b4 => 200 (Length: 1234). To continue please exclude the status code "
                "or the length")

    def run(cmd, timeout=None):
        calls.append(cmd)
        url = cmd[cmd.index("-u") + 1]
        if url == "http://x/admin" and "--exclude-length" not in cmd:
            return runner.CommandResult(cmd, 1, "", wildcard, 0.1)
        return runner.CommandResult(cmd, 0, ROOT_OUT if url == "http://x" else ADMIN_OUT, "", 0.1)

    monkeypatch.setattr(runner, "run", run)
    findings = web.WebModule()._content_discovery(make_ctx(tmp_path), Service(80, name="http"), "http://x", page())
    assert calls[-1][calls[-1].index("--exclude-length") + 1] == "1234"
    assert "/admin/config.php.bak" in [h["path"] for h in findings[0].data["paths"]]


# ----------------------------------------------------------------- real gobuster (skipped when missing)


class _PhpishHandler(http.server.BaseHTTPRequestHandler):
    files: ClassVar[dict] = {"/index.php": b"home", "/admin/": b"admin", "/admin/notes.txt": b"secret notes",
             "/admin/index.php": b"panel", "/css/": b"", "/css/site.txt": b"x"}

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/admin", "/css"):
            self.send_response(301)
            self.send_header("Location", path + "/")
            body = b""
        elif path in self.files:
            self.send_response(200)
            body = self.files[path]
        else:
            self.send_response(404)
            body = b"not found"
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_real_gobuster_recursion(tmp_path):
    if not runner.which("gobuster"):
        pytest.skip("gobuster not installed")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PhpishHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        wl = tmp_path / "words.txt"
        wl.write_text("admin\ncss\nindex\nnotes\nmissing\n")
        ctx = make_ctx(tmp_path, wordlist=str(wl), brute_timeout=60, threads=5)
        findings = web.WebModule().run(ctx, Service(port, name="http"))
        summary = next(f for f in findings if f.title.startswith("Content discovery:"))
        paths = {h["path"] for h in summary.data["paths"]}
        assert {"/admin", "/css", "/index.php", "/admin/notes.txt", "/admin/index.php"} <= paths
        assert not any(p.startswith("/css/") for p in paths)  # static dir not recursed
        assert summary.data["extensions"] == "php,txt,bak"
    finally:
        srv.shutdown()
