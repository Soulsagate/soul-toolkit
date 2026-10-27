from pathlib import Path

import pytest

from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Lead, Service
from soul_toolkit.recon import engine, leads
from soul_toolkit.recon.modules import Context, Options, select_modules, smb
from soul_toolkit.recon.modules import ftp as ftp_mod
from soul_toolkit.recon.report import render_markdown


def make_ctx(tmp_path, services=()):
    r = HostResult("10.10.10.10", services=list(services))
    return Context(target="10.10.10.10", outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=r, options=Options())


def L(kind, port=80, title="t", command=""):
    return Lead(kind, port, title, "why", command, leads.score_for(kind))


def test_every_kind_has_a_score_and_unknown_kinds_fail_loudly():
    assert all(isinstance(v, int) for v in leads.SCORES.values())
    with pytest.raises(ValueError):
        leads.score_for("made-up")


def test_rank_orders_by_score_then_port_and_dedupes():
    ranked = leads.rank([
        L("web-browse", 80, "browse", "curl -s http://x/"),
        L("ftp-anon", 21, "ftp", "wget -m ftp://x/"),
        L("web-git", 8080, "git b", "git-dumper b"),
        L("web-git", 80, "git a", "git-dumper a"),
        L("smb-enum", 445, "enum", "enum4linux-ng -A x"),
        L("smb-enum", 139, "enum", "enum4linux-ng -A x"),  # same command on another port
    ])
    assert [x.title for x in ranked] == ["git a", "git b", "ftp", "enum", "browse"]
    assert ranked[3].port == 139


def test_rank_is_deterministic():
    items = [L("web-paths", p, f"p{p}", f"curl {p}") for p in (8080, 80, 443)]
    assert leads.rank(items) == leads.rank(list(reversed(items)))


def test_host_leads_suggest_full_sweep_only_for_limited_scans():
    r = HostResult("10.10.10.10")
    assert leads.host_leads(r) == []
    [quick] = leads.host_leads(r, quick=True)
    assert quick.command == "toolkit recon 10.10.10.10" and "top 1000" in quick.why
    [given] = leads.host_leads(r, ports_given=True)
    assert "ports you gave" in given.why


def test_other_hints_drop_hints_covered_by_a_lead():
    r = HostResult("x")
    r.leads = [L("smb-share", 445, "share", "smbclient //x/files -N")]
    r.hints = ["Try the 'files' share: smbclient //x/files -N", "Install gobuster"]
    assert leads.other_hints(r) == ["Install gobuster"]


def test_report_where_to_start_section():
    r = HostResult("10.10.10.10")
    r.leads = leads.rank([L("web-browse", 80, "Browse it", "curl -s http://x/")] +
                         [L("web-paths", p, f"Paths on {p}", f"curl -si http://x:{p}/admin") for p in range(1, 7)])
    md = render_markdown(r)
    start = md.index("## Where to start")
    assert start < md.index("## Open ports")
    assert "1. **Paths on 1** (1/tcp)" in md
    assert "   ```bash\n   curl -si http://x:1/admin\n   ```" in md
    # only 5 in the top list; the rest move to "Other leads"
    other = md.index("## Other leads and ideas")
    assert md.index("Paths on 6") > other and md.index("Browse it") > other


def test_report_where_to_start_empty():
    # nothing answered at all: point at the usual causes (wrong IP, VPN down), not at flags
    md = render_markdown(HostResult("10.10.10.10"))
    assert "_Nothing answered._" in md and "ip -br addr show tun0" in md and "--min-rate 300" in md
    assert "--quick" not in md
    # ports but no leads: no advice about flags that weren't used
    md = render_markdown(HostResult("10.10.10.10", services=[Service(8000, name="unknown")]))
    assert "_Nothing stood out._" in md and "--quick" not in md


def test_ftp_webroot_lead(tmp_path, monkeypatch):
    listing = ["-rw-r--r--    1 0        0             418 Jun 07  2020 index.php"]
    monkeypatch.setattr(ftp_mod, "anon_login", lambda *a, **k: ftp_mod.AnonResult(True, listing))
    ctx = make_ctx(tmp_path, [Service(21, name="ftp"), Service(80, name="http")])
    ftp_mod.FtpModule().run(ctx, Service(21, name="ftp"))
    lead = next(x for x in ctx.result.leads if x.kind == "ftp-webroot")
    assert lead.command == "curl -si http://10.10.10.10/index.php"
    # no web server -> no web-root lead
    ctx2 = make_ctx(tmp_path, [Service(21, name="ftp")])
    ftp_mod.FtpModule().run(ctx2, Service(21, name="ftp"))
    assert not any(x.kind == "ftp-webroot" for x in ctx2.result.leads)


def test_smb_share_lead(tmp_path, monkeypatch):
    out = "Disk|print$|Printer Drivers\nDisk|files|Team files\nDisk|backup|\nIPC|IPC$|IPC Service\n"
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/" + tool)

    def fake(cmd, timeout=None):
        if "-L" in cmd:
            return runner.CommandResult(cmd, 0, out, "", 0.1)
        # the read check couldn't tell either way -> the share stays an unconfirmed lead
        return runner.CommandResult(cmd, 1, "NT_STATUS_CONNECTION_REFUSED listing \\*\n", "", 0.1)

    monkeypatch.setattr(runner, "run", fake)
    ctx = make_ctx(tmp_path, [Service(445, name="microsoft-ds")])
    smb.SmbModule().run(ctx, Service(445, name="microsoft-ds"))
    kinds = {x.kind: x for x in ctx.result.leads}
    assert kinds["smb-share"].command == "smbclient //10.10.10.10/files -N"
    assert "enum4linux-ng" in kinds["smb-enum"].command
    assert any("backup" in h and "unconfirmed" in h for h in ctx.result.hints)


FIXTURE_XML = (Path(__file__).parent / "fixtures" / "services.xml").read_text()


def test_engine_ranks_leads_and_prints_where_to_start(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(runner, "require", lambda *a, **k: "/usr/bin/nmap")
    monkeypatch.setattr(runner, "run", lambda cmd, timeout=None: runner.CommandResult(cmd, 0, FIXTURE_XML, "", 0.1))
    monkeypatch.setattr(engine, "is_root", lambda: False)
    note = ["-rw-r--r-- 1 0 0 418 Jun 07  2020 note.txt"]
    monkeypatch.setattr(ftp_mod, "anon_login", lambda *a, **k: ftp_mod.AnonResult(True, note))
    cfg = engine.ReconConfig(target="10.10.10.10", output=tmp_path, ports=[21, 22],
                             modules=select_modules(["ftp", "ssh"]))
    result = engine.run_recon(cfg, Logger(colour=False))
    assert [x.kind for x in result.leads] == ["ftp-anon", "rescan", "udp", "ssh-later"]
    err = capsys.readouterr().err
    assert "Where to start:" in err and "1. Download everything from anonymous FTP (21/tcp)" in err
    assert "$ wget -m ftp://anonymous:anonymous@10.10.10.10/" in err
    assert "## Where to start" in (tmp_path / "10.10.10.10" / "report.md").read_text()
