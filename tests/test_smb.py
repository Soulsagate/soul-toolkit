"""SMB read-access check. The smbclient output below was recorded from real Samba servers:
the lab's guest share (readable) and a share limited to one user (access denied)."""

import pytest

from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon import leads
from soul_toolkit.recon.modules import Context, Options, smb
from soul_toolkit.recon.report import render_markdown
from soul_toolkit.recon.report_html import render_html

# smbclient -L //HOST -N -g
LISTING = """Disk|public|Public files
Disk|private|Staff only
IPC|IPC$|IPC Service (Lab file server)
SMB1 disabled -- no workgroup available
"""
# smbclient //HOST/public -N -c ls   (exit 0)
LS_READ = """  .                                   D        0  Tue Oct 27 10:44:41 2026
  ..                                  D        0  Tue Oct 27 10:44:41 2026
  onboarding.txt                      N       77  Tue Oct 27 10:44:41 2026

\t\t264212084 blocks of size 1024. 28803476 blocks available
"""
LS_DENIED = "tree connect failed: NT_STATUS_ACCESS_DENIED\n"        # exit 1
LS_NO_SHARE = "tree connect failed: NT_STATUS_BAD_NETWORK_NAME\n"   # exit 1
LS_REFUSED = "NT_STATUS_CONNECTION_REFUSED listing \\*\n"           # exit 1


def result(stdout="", rc=0, timed_out=False):
    return runner.CommandResult(["smbclient"], -9 if timed_out else rc, stdout, "", 20.0 if timed_out else 0.1,
                                timed_out=timed_out)


def make_ctx(tmp_path):
    svc = Service(445, name="microsoft-ds")
    return Context(target="10.10.10.10", outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult("10.10.10.10", services=[svc]), options=Options()), svc


def fake_smb(monkeypatch, per_share, listing=LISTING):
    """per_share: share name -> CommandResult for its `ls`. Returns the list of commands run."""
    calls = []

    def run(cmd, timeout=None):
        calls.append((cmd, timeout))
        if "-L" in cmd:
            return runner.CommandResult(cmd, 0, listing, "", 0.1)
        share = cmd[1].rsplit("/", 1)[1]
        return per_share[share]

    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/" + tool)
    monkeypatch.setattr(runner, "run", run)
    return calls


@pytest.mark.parametrize("res, expected", [
    (result(LS_READ), "READ"),
    (result(LS_DENIED, rc=1), "NO ACCESS"),
    (result(LS_NO_SHARE, rc=1), "NO ACCESS"),
    (result(timed_out=True), "TIMED OUT"),
    (result(LS_REFUSED, rc=1), "UNKNOWN"),
    (result("", rc=1), "UNKNOWN"),
])
def test_read_access(res, expected):
    assert smb.read_access(res) == expected


def test_readable_share_is_checked_shown_and_ranked(tmp_path, monkeypatch):
    calls = fake_smb(monkeypatch, {"public": result(LS_READ), "private": result(LS_DENIED, rc=1)})
    ctx, svc = make_ctx(tmp_path)
    [f] = smb.SmbModule().run(ctx, svc)

    checks = [(cmd, t) for cmd, t in calls if "-L" not in cmd]
    assert checks == [
        (["smbclient", "//10.10.10.10/public", "-N", "-p", "445", "-c", "ls"], smb.SHARE_TIMEOUT),
        (["smbclient", "//10.10.10.10/private", "-N", "-p", "445", "-c", "ls"], smb.SHARE_TIMEOUT),
    ]  # IPC$ is never checked
    assert [s.get("access") for s in f.data["shares"]] == ["READ", "NO ACCESS", None]
    assert f.detail == "public, private, IPC$ - readable without a password: public"

    lead = next(x for x in ctx.result.leads if x.kind.startswith("smb-") and x.kind != "smb-enum")
    assert lead.kind == "smb-readable" and lead.command == "smbclient //10.10.10.10/public -N"
    assert "'public' is readable without a password" in lead.why
    assert leads.score_for("smb-readable") > leads.score_for("smb-share") > leads.score_for("smb-locked")
    assert leads.score_for("ftp-anon") > leads.score_for("smb-readable") > leads.score_for("web-vhosts")

    md = render_markdown(HostResult("10.10.10.10", findings=[f]))
    assert "| Share | Type | Access | Comment |" in md
    assert "| `public` | Disk | READ | Public files |" in md and "| `private` | Disk | NO ACCESS | Staff only |" in md
    assert "| `IPC$` | IPC | - | IPC Service (Lab file server) |" in md
    html = render_html(HostResult("10.10.10.10", findings=[f]))
    assert '<span class="st st-2">READ</span>' in html and '<span class="st st-4">NO ACCESS</span>' in html


def test_read_check_never_writes(tmp_path, monkeypatch):
    calls = fake_smb(monkeypatch, {"public": result(LS_READ), "private": result(LS_DENIED, rc=1)})
    ctx, svc = make_ctx(tmp_path)
    smb.SmbModule().run(ctx, svc)
    for cmd, _ in calls:
        assert cmd[0] == "smbclient"
        if "-c" in cmd:
            assert cmd[cmd.index("-c") + 1] == "ls"  # nothing that could create, change or delete


def test_no_readable_share_gives_a_low_credentials_lead(tmp_path, monkeypatch):
    fake_smb(monkeypatch, {"public": result(LS_DENIED, rc=1), "private": result(LS_DENIED, rc=1)})
    ctx, svc = make_ctx(tmp_path)
    smb.SmbModule().run(ctx, svc)
    kinds = {x.kind: x for x in ctx.result.leads}
    assert "smb-readable" not in kinds and "smb-share" not in kinds
    assert kinds["smb-locked"].command == "smbclient //10.10.10.10/public -U '<user>'"


def test_timeout_keeps_the_share_as_an_unconfirmed_lead(tmp_path, monkeypatch):
    fake_smb(monkeypatch, {"public": result(timed_out=True), "private": result(LS_DENIED, rc=1)})
    ctx, svc = make_ctx(tmp_path)
    [f] = smb.SmbModule().run(ctx, svc)
    assert f.data["shares"][0]["access"] == "TIMED OUT"
    lead = next(x for x in ctx.result.leads if x.kind == "smb-share")
    assert lead.command == "smbclient //10.10.10.10/public -N" and "timed out" in lead.why
    assert "| `public` | Disk | TIMED OUT | Public files |" in render_markdown(HostResult("x", findings=[f]))


def test_default_shares_dont_make_a_readable_lead(tmp_path, monkeypatch):
    listing = "Disk|print$|Printer Drivers\nDisk|SYSVOL|Logon server share\nIPC|IPC$|Remote IPC\n"
    fake_smb(monkeypatch, {"print$": result(LS_READ), "SYSVOL": result(LS_READ)}, listing)
    ctx, svc = make_ctx(tmp_path)
    [f] = smb.SmbModule().run(ctx, svc)
    assert [s.get("access") for s in f.data["shares"]] == ["READ", "READ", None]
    assert {x.kind for x in ctx.result.leads} == {"smb-enum"}


def test_share_checks_are_capped(tmp_path, monkeypatch):
    names = [f"share{i}" for i in range(smb.MAX_SHARE_CHECKS + 3)]
    listing = "".join(f"Disk|{n}|\n" for n in names)
    calls = fake_smb(monkeypatch, {n: result(LS_DENIED, rc=1) for n in names}, listing)
    ctx, svc = make_ctx(tmp_path)
    [f] = smb.SmbModule().run(ctx, svc)
    assert len([c for c, _ in calls if "-c" in c]) == smb.MAX_SHARE_CHECKS
    assert [s["access"] for s in f.data["shares"][-3:]] == ["UNKNOWN"] * 3
    assert any(f"first {smb.MAX_SHARE_CHECKS} of {len(names)} shares" in h for h in ctx.result.hints)


def test_old_findings_without_access_still_render():
    from soul_toolkit.core.models import Finding
    f = Finding("smb", 445, "Null session can list SMB shares", "medium", "anon",
                {"shares": [{"type": "Disk", "name": "anon", "comment": "x"}]})
    md = render_markdown(HostResult("x", findings=[f]))
    assert "| Share | Type | Comment |" in md and "Access" not in md
    assert "<th scope=\"col\">Access</th>" not in render_html(HostResult("x", findings=[f]))
