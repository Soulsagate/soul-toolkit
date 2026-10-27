"""Text files worth reading.

fowsniff-gobuster-80.txt is real gobuster output from a TryHackMe box (with /security.txt)."""

from pathlib import Path

from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon import leads
from soul_toolkit.recon.modules import Context, Options, web

FOWSNIFF = (Path(__file__).parent / "fixtures" / "fowsniff-gobuster-80.txt").read_text()


def make_ctx(tmp_path, **opts):
    return Context(target="127.0.0.1", outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult("127.0.0.1"), options=Options(**opts))


def gobuster_says(monkeypatch, output):
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/" + tool)
    monkeypatch.setattr(runner, "run", lambda cmd, timeout=None: runner.CommandResult(cmd, 0, output, "", 0.1))


def hit(path, status=200, size=10):
    return {"path": path, "status": status, "size": size, "redirect": ""}


def test_readable_files_from_a_real_run():
    files = web.readable_files(web.parse_gobuster(FOWSNIFF))
    assert [h["path"] for h in files] == ["/security.txt"]  # not robots.txt, index.html or the 403s


def test_readable_files_order_and_exclusions():
    hits = [hit("/notes.txt"), hit("/backup.bak"), hit("/db.sql"), hit("/robots.txt"), hit("/index.html"),
            hit("/.git/config.json"), hit("/secret.txt", status=403), hit("/empty.log", size=0),
            hit("/humans.txt"), hit("/dev/app.conf"), hit("/old", status=301)]
    files = [h["path"] for h in web.readable_files(hits)]
    # backups, dumps and configs before plain text; robots.txt, .git, 403s, empty files and dirs left out
    assert files == ["/backup.bak", "/db.sql", "/dev/app.conf", "/humans.txt", "/notes.txt"]


def test_fowsniff_content_discovery_gives_a_files_lead(tmp_path, monkeypatch):
    gobuster_says(monkeypatch, FOWSNIFF)
    ctx = make_ctx(tmp_path, recurse=False)
    findings = web.WebModule()._content_discovery(ctx, Service(80, name="http"), "http://10.64.152.7", None)
    files = next(f for f in findings if f.title == "Files worth reading")
    assert files.severity == "low" and files.detail == "/security.txt"
    [lead] = ctx.result.leads
    assert lead.kind == "web-files" and lead.title == "Read /security.txt"
    assert lead.command == "curl -s http://10.64.152.7/security.txt"
    assert leads.score_for("web-files") == leads.score_for("web-paths")


def test_files_lead_lists_the_rest_and_paths_lead_skips_them(tmp_path, monkeypatch):
    out = "".join(f"{p:<22}(Status: 200) [Size: 42]\n" for p in
                  ("/backup.bak", "/notes.txt", "/todo.md", "/admin"))
    gobuster_says(monkeypatch, out)
    ctx = make_ctx(tmp_path, recurse=False)
    web.WebModule()._content_discovery(ctx, Service(80, name="http"), "http://x", None)
    by_kind = {x.kind: x for x in ctx.result.leads}
    assert by_kind["web-files"].title == "Read /backup.bak and 2 more"
    assert "Also: /notes.txt, /todo.md." in by_kind["web-files"].why
    # /backup.bak is "interesting" too, but the paths lead is spent on /admin rather than repeating it
    assert by_kind["web-paths"].command == "curl -si http://x/admin"
