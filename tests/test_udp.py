from pathlib import Path

from soul_toolkit import cli
from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon import engine, nmap
from soul_toolkit.recon.modules import Module
from soul_toolkit.recon.report import render_markdown

FIXTURES = Path(__file__).parent / "fixtures"
TCP_XML = (FIXTURES / "services.xml").read_text()
UDP_XML = (FIXTURES / "udp-services.xml").read_text()


def test_build_udp_commands():
    sweep = nmap.build_udp_sweep("10.10.10.10")
    assert sweep[:2] == ["nmap", "-sU"] and "-Pn" in sweep and sweep[-1] == "10.10.10.10"
    assert sweep[sweep.index("--top-ports") + 1] == "100" and sweep[sweep.index("--min-rate") + 1] == "1000"
    svc = nmap.build_udp_service_scan("::1", [161, 69, 161], scripts=False)
    assert "-sV" in svc and "-sC" not in svc and "-6" in svc and svc[svc.index("-p") + 1] == "69,161"


def test_parse_real_udp_xml():
    [h] = nmap.parse_xml(UDP_XML)
    [s] = h.services
    assert (s.port, s.protocol, s.name, s.extrainfo) == (161, "udp", "snmp", "public")
    assert s.label == "161/udp" and "net-snmp" in s.scripts["snmp-info"]


def test_want_udp(monkeypatch):
    log = Logger(quiet=True)
    monkeypatch.setattr(engine, "is_root", lambda: True)
    assert engine.want_udp(engine.ReconConfig("t"), log)               # auto: root, no -p
    assert not engine.want_udp(engine.ReconConfig("t", ports=[80]), log)  # auto: -p given
    assert engine.want_udp(engine.ReconConfig("t", ports=[80], udp=True), log)
    assert not engine.want_udp(engine.ReconConfig("t", udp=False), log)
    monkeypatch.setattr(engine, "is_root", lambda: False)
    assert not engine.want_udp(engine.ReconConfig("t", udp=True), log)  # needs root, warns instead


class _Recorder(Module):
    name = "rec"
    protocols = ("udp",)

    def __init__(self):
        self.seen = []

    def matches(self, svc):
        return True

    def run(self, ctx, svc):
        self.seen.append(svc.label)
        ctx.lead("ssh-later", svc.port, "t", "why")
        return [Finding(self.name, svc.port, "seen", "low")]


def fake_nmap(calls):
    def run(cmd, timeout=None):
        calls.append(cmd)
        if "-sU" in cmd:
            # the sweep only needs an open 161; the service scan returns the full fixture
            return runner.CommandResult(cmd, 0, UDP_XML, "", 0.1)
        return runner.CommandResult(cmd, 0, TCP_XML, "", 0.1)
    return run


def test_engine_udp_stage_and_protocol_stamping(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "require", lambda *a, **k: "/usr/bin/nmap")
    monkeypatch.setattr(runner, "run", fake_nmap(calls))
    monkeypatch.setattr(engine, "is_root", lambda: True)
    rec = _Recorder()
    cfg = engine.ReconConfig(target="10.10.10.10", output=tmp_path, ports=[22], udp=True, modules=[rec])
    result = engine.run_recon(cfg, Logger(quiet=True))
    udp_cmds = [c for c in calls if "-sU" in c]
    assert len(udp_cmds) == 2 and "--top-ports" in udp_cmds[0] and udp_cmds[1][udp_cmds[1].index("-p") + 1] == "161"
    assert rec.seen == ["161/udp"]  # TCP services are never offered to a UDP-only module
    [f] = result.findings
    assert f.protocol == "udp"
    lead = next(x for x in result.leads if x.kind == "ssh-later")
    assert lead.protocol == "udp" and lead.where == "161/udp"
    assert result.udp_scanned and not any(x.kind == "udp" for x in result.leads)
    out = tmp_path / "10.10.10.10"
    assert (out / "nmap-udp.xml").exists() and (out / "nmap-udp-services.xml").exists()
    md = render_markdown(result)
    assert "| 161/udp | snmp |" in md and "(161/udp, `rec`)" in md


def test_tcp_modules_never_see_udp(tmp_path, monkeypatch):
    seen = []

    class Tcp(_Recorder):
        protocols = ("tcp",)

        def run(self, ctx, svc):
            seen.append(svc.label)
            return []

    monkeypatch.setattr(runner, "require", lambda *a, **k: "/usr/bin/nmap")
    monkeypatch.setattr(runner, "run", fake_nmap([]))
    monkeypatch.setattr(engine, "is_root", lambda: True)
    engine.run_recon(engine.ReconConfig("10.10.10.10", output=tmp_path, ports=[22], udp=True, modules=[Tcp()]),
                     Logger(quiet=True))
    assert seen and all(label.endswith("/tcp") for label in seen)


def test_udp_failure_does_not_kill_the_run(tmp_path, monkeypatch):
    def run(cmd, timeout=None):
        if "-sU" in cmd:
            return runner.CommandResult(cmd, 1, "", "You requested a scan type which requires root", 0.1)
        return runner.CommandResult(cmd, 0, TCP_XML, "", 0.1)

    monkeypatch.setattr(runner, "require", lambda *a, **k: "/usr/bin/nmap")
    monkeypatch.setattr(runner, "run", run)
    monkeypatch.setattr(engine, "is_root", lambda: True)
    result = engine.run_recon(engine.ReconConfig("10.10.10.10", output=tmp_path, ports=[22], udp=True, modules=[]),
                              Logger(quiet=True))
    assert len(result.services) == 6 and not result.udp_scanned


def test_udp_only_host_still_runs_modules(tmp_path, monkeypatch):
    def run(cmd, timeout=None):
        if "-sU" in cmd:
            return runner.CommandResult(cmd, 0, UDP_XML, "", 0.1)
        return runner.CommandResult(cmd, 0, '<?xml version="1.0"?><nmaprun></nmaprun>', "", 0.1)

    monkeypatch.setattr(runner, "require", lambda *a, **k: "/usr/bin/nmap")
    monkeypatch.setattr(runner, "run", run)
    monkeypatch.setattr(engine, "is_root", lambda: True)
    rec = _Recorder()
    result = engine.run_recon(engine.ReconConfig("10.10.10.10", output=tmp_path, modules=[rec]), Logger(quiet=True))
    assert rec.seen == ["161/udp"] and result.address == "127.0.0.1"


def test_cli_udp_flags(monkeypatch):
    seen = []
    monkeypatch.setattr(engine, "run_recon", lambda cfg, log: seen.append(cfg.udp))
    cli.main(["recon", "10.10.10.10", "-q"])
    cli.main(["recon", "10.10.10.10", "-q", "--udp"])
    cli.main(["recon", "10.10.10.10", "-q", "--no-udp"])
    assert seen == [None, True, False]


def test_service_label_udp():
    assert Service(161, protocol="udp").label == "161/udp"
