from pathlib import Path

import pytest

from soul_toolkit import cli
from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.recon import engine, nmap

FIXTURES = Path(__file__).parent / "fixtures"
SERVICES = (FIXTURES / "services.xml").read_text()  # -p 21,22,80,139,445,8443 10.10.10.10, finished
UDP = (FIXTURES / "udp-services.xml").read_text()
SWEEP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sT -T4 --open -oX - -Pn -p- --min-rate 1000 10.10.10.10" version="7.94SVN">
<host><status state="up"/><address addr="10.10.10.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
</ports></host>
<runstats><finished time="1" elapsed="9.0" exit="success"/></runstats></nmaprun>
"""


@pytest.fixture
def nmap_calls(monkeypatch):
    calls = []

    def run(cmd, timeout=None):
        calls.append(cmd)
        if "-sU" in cmd:
            return runner.CommandResult(cmd, 0, UDP, "", 0.1)
        return runner.CommandResult(cmd, 0, SWEEP if "-p-" in cmd else SERVICES, "", 0.1)

    monkeypatch.setattr(runner, "require", lambda *a, **k: "/usr/bin/nmap")
    monkeypatch.setattr(runner, "run", run)
    monkeypatch.setattr(engine, "is_root", lambda: False)
    return calls


def go(tmp_path, **kw):
    cfg = engine.ReconConfig(target=kw.pop("target", "10.10.10.10"), output=tmp_path, modules=[], **kw)
    return engine.run_recon(cfg, Logger(quiet=True))


def outdir(tmp_path):
    d = tmp_path / "10.10.10.10"
    d.mkdir(exist_ok=True)
    return d


def test_scan_info():
    info = nmap.scan_info(SERVICES)
    assert info.complete and info.target == "10.10.10.10" and info.ports == [21, 22, 80, 139, 445, 8443]
    sweep = nmap.scan_info(SWEEP)
    assert sweep.ports is None and sweep.complete
    assert not nmap.scan_info(SERVICES.replace('exit="success"', 'exit="error"')).complete


def test_without_resume_everything_is_scanned(tmp_path, nmap_calls):
    go(tmp_path)
    go(tmp_path)
    assert len(nmap_calls) == 4  # sweep + service scan, twice


def test_resume_reuses_service_scan_and_skips_sweep(tmp_path, nmap_calls):
    first = go(tmp_path)
    nmap_calls.clear()
    again = go(tmp_path, resume=True)
    assert nmap_calls == []
    assert [s.label for s in again.services] == [s.label for s in first.services]
    assert "# reused nmap-services.xml from an earlier run (--resume)" in again.commands


def test_resume_with_only_the_sweep(tmp_path, nmap_calls):
    (outdir(tmp_path) / "nmap-ports.xml").write_text(SWEEP)
    go(tmp_path, resume=True)
    assert len(nmap_calls) == 1 and "-sV" in nmap_calls[0] and nmap_calls[0][nmap_calls[0].index("-p") + 1] == "22,80"


@pytest.mark.parametrize("xml,reason", [
    (SERVICES.replace('exit="success"', 'exit="error"'), "didn't finish"),
    (SERVICES.replace("10.10.10.10</", "10.10.10.99</").replace(" 10.10.10.10\"", " 10.10.10.99\""), "is for"),
    ("<nmaprun", "unreadable"),
])
def test_resume_rescans_bad_files(tmp_path, nmap_calls, xml, reason, capsys):
    (outdir(tmp_path) / "nmap-services.xml").write_text(xml)
    cfg = engine.ReconConfig(target="10.10.10.10", output=tmp_path, modules=[], resume=True)
    engine.run_recon(cfg, Logger(colour=False))
    assert any("-sV" in c for c in nmap_calls)
    assert reason in capsys.readouterr().err


def test_resume_with_ports(tmp_path, nmap_calls):
    (outdir(tmp_path) / "nmap-services.xml").write_text(SERVICES)
    subset = go(tmp_path, resume=True, ports=[22, 80])
    assert nmap_calls == [] and [s.port for s in subset.services] == [22, 80]
    go(tmp_path, resume=True, ports=[22, 3306])  # 3306 wasn't in the earlier scan
    assert len(nmap_calls) == 1


def test_resume_udp_as_root(tmp_path, nmap_calls, monkeypatch):
    # the UDP fixture was recorded against 127.0.0.1, so scan that
    monkeypatch.setattr(engine, "is_root", lambda: True)
    go(tmp_path, target="127.0.0.1", ports=[22], udp=True)
    nmap_calls.clear()
    result = go(tmp_path, target="127.0.0.1", ports=[22], udp=True, resume=True)
    assert not [c for c in nmap_calls if "-sU" in c]
    assert result.udp_scanned and any(s.label == "161/udp" for s in result.services)


def test_cli_resume_flag(monkeypatch):
    seen = []
    monkeypatch.setattr(engine, "run_recon", lambda cfg, log: seen.append(cfg.resume))
    cli.main(["recon", "10.10.10.10", "-q", "--resume"])
    cli.main(["recon", "10.10.10.10", "-q"])
    assert seen == [True, False]
