import pytest

from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon.modules import Context, Options, nfs
from soul_toolkit.recon.report import render_markdown

# showmount pads the path column to the longest export
SHOWMOUNT = """Export list for 10.10.10.10:
/srv/nfs/share     *
/home/backup       10.10.0.0/16,192.168.1.5
/opt/everyone      (everyone)
/var/nobody
"""


def make_ctx(tmp_path, services=()):
    return Context(target="10.10.10.10", outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult("10.10.10.10", services=list(services)), options=Options())


def fake(stdout, rc=0, stderr="", calls=None):
    def run(cmd, timeout=None):
        if calls is not None:
            calls.append(cmd)
        return runner.CommandResult(cmd, rc, stdout, stderr, 0.1)
    return run


def test_parse_showmount():
    exports = nfs.parse_showmount(SHOWMOUNT)
    assert exports == [
        {"path": "/srv/nfs/share", "clients": ["*"]},
        {"path": "/home/backup", "clients": ["10.10.0.0/16", "192.168.1.5"]},
        {"path": "/opt/everyone", "clients": ["(everyone)"]},
        {"path": "/var/nobody", "clients": []},
    ]
    assert [nfs.is_world(e) for e in exports] == [True, False, True, True]
    assert nfs.parse_showmount("clnt_create: RPC: Program not registered\n") == []


def test_mount_point():
    assert nfs.mount_point("/srv/nfs/share") == "/mnt/nfs-srv-nfs-share"
    assert nfs.mount_point("/") == "/mnt/nfs-root"


def test_matches():
    m = nfs.NfsModule()
    assert m.matches(Service(2049, name="nfs")) and m.matches(Service(20048, name="mountd"))
    assert not m.matches(Service(111, name="rpcbind"))


def test_world_export_finding_and_lead(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/sbin/" + tool)
    monkeypatch.setattr(runner, "run", fake(SHOWMOUNT, calls=calls))
    svc = Service(2049, name="nfs")
    ctx = make_ctx(tmp_path, [svc])
    [f] = nfs.NfsModule().run(ctx, svc)
    assert calls == [["showmount", "-e", "10.10.10.10"]]
    assert f.severity == "high" and f.detail == "/srv/nfs/share, /opt/everyone, /var/nobody"
    [lead] = ctx.result.leads
    assert lead.kind == "nfs-world"
    assert lead.command == ("sudo mkdir -p /mnt/nfs-srv-nfs-share && sudo mount -t nfs -o ro,nolock "
                            "10.10.10.10:/srv/nfs/share /mnt/nfs-srv-nfs-share")
    assert "/opt/everyone" in lead.why
    md = render_markdown(HostResult("x", findings=[f]))
    assert "| Export | Allowed clients |" in md and "| /home/backup | 10.10.0.0/16, 192.168.1.5 |" in md


def test_restricted_exports_are_medium(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/sbin/" + tool)
    monkeypatch.setattr(runner, "run", fake("Export list for x:\n/home 10.10.0.0/16\n"))
    ctx = make_ctx(tmp_path)
    [f] = nfs.NfsModule().run(ctx, Service(2049, name="nfs"))
    assert f.severity == "medium" and ctx.result.leads[0].kind == "nfs-restricted"


def test_runs_once_per_host(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/sbin/" + tool)
    monkeypatch.setattr(runner, "run", fake(SHOWMOUNT, calls=calls))
    a, b = Service(2049, name="nfs"), Service(20048, name="mountd")
    ctx = make_ctx(tmp_path, [a, b])
    mod = nfs.NfsModule()
    assert mod.run(ctx, b) == [] and mod.run(ctx, a)
    assert len(calls) == 1


def test_showmount_error(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/sbin/" + tool)
    # real error from showmount against a host without rpcbind
    monkeypatch.setattr(runner, "run", fake("", rc=1, stderr="clnt_create: RPC: Unable to receive\n"))
    [f] = nfs.NfsModule().run(make_ctx(tmp_path), Service(2049, name="nfs"))
    assert f.severity == "info" and f.detail == "clnt_create: RPC: Unable to receive"


def test_missing_showmount(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "which", lambda tool: None)
    ctx = make_ctx(tmp_path)
    assert nfs.NfsModule().run(ctx, Service(2049, name="nfs")) == []
    assert any("nfs-common" in h for h in ctx.result.hints)


def test_real_showmount_error_path(tmp_path):
    if not runner.which("showmount"):
        pytest.skip("showmount not installed")
    ctx = make_ctx(tmp_path)
    ctx.target = "127.0.0.1"
    [f] = nfs.NfsModule().run(ctx, Service(2049, name="nfs"))  # nothing serves NFS here
    assert f.title == "No NFS exports listed" and f.detail
