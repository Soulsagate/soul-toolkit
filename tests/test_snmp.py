import os
import shutil
import socket
import subprocess
import sys
import time

import pytest

from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon.modules import Context, Options, snmp

# Real output from onesixtyone 0.3.3 and snmpwalk 5.9.4 against net-snmp on 127.0.0.1
ONESIXTYONE = ("Scanning 1 hosts, 2 communities\n"
               "127.0.0.1 [public] Linux vm 6.18.44-fc-v165 #1 SMP PREEMPT_DYNAMIC @0 x86_64\n")
SYSTEM_WALK = """.1.3.6.1.2.1.1.1.0 = STRING: "Linux vm 6.18.44-fc-v165 #1 SMP PREEMPT_DYNAMIC @0 x86_64"
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.8072.3.2.10
.1.3.6.1.2.1.1.3.0 = Timeticks: (36745) 0:06:07.45
.1.3.6.1.2.1.1.4.0 = STRING: "admin@lab.local"
.1.3.6.1.2.1.1.5.0 = STRING: "lab-box"
.1.3.6.1.2.1.1.6.0 = STRING: "Lab rack 3"
"""
# Process table in the same format; the entries themselves are test data.
NAMES_WALK = """.1.3.6.1.2.1.25.4.2.1.2.1 = STRING: "systemd"
.1.3.6.1.2.1.25.4.2.1.2.712 = STRING: "sshd"
.1.3.6.1.2.1.25.4.2.1.2.940 = STRING: "backup.sh"
.1.3.6.1.2.1.25.4.2.1.2.951 = STRING: "mysqld_safe"
"""
ARGS_WALK = """.1.3.6.1.2.1.25.4.2.1.5.1 = ""
.1.3.6.1.2.1.25.4.2.1.5.712 = STRING: "-D -p 22"
.1.3.6.1.2.1.25.4.2.1.5.940 = STRING: "--user svc --password Winter2024!"
.1.3.6.1.2.1.25.4.2.1.5.951 = STRING: "-uroot -pS3cr3t"
"""
NO_USERS = ".1.3.6.1.4.1.77.1.2.25 = No Such Object available on this agent at this OID\n"


def make_ctx(tmp_path, target="10.10.10.10"):
    return Context(target=target, outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult(target), options=Options())


def fake_tools(calls, walks, onesixtyone=ONESIXTYONE):
    def run(cmd, timeout=None):
        calls.append(cmd)
        if cmd[0] == "onesixtyone":
            return runner.CommandResult(cmd, 0, onesixtyone, "", 0.1)
        community, oid = cmd[cmd.index("-c") + 1], cmd[-1]
        out = walks.get((community, oid))
        if out is None:
            return runner.CommandResult(cmd, 1, "", "Timeout: No Response from 10.10.10.10:161\n", 2)
        return runner.CommandResult(cmd, 0, out, "", 0.1)
    return run


WALKS = {("public", snmp.OID_SYSTEM): SYSTEM_WALK, ("public", snmp.OID_SYSTEM + ".1"): SYSTEM_WALK.splitlines()[0],
         ("public", snmp.OID_PROC_NAME): NAMES_WALK, ("public", snmp.OID_PROC_ARGS): ARGS_WALK,
         ("public", snmp.OID_WIN_USERS): NO_USERS}


def test_parsers():
    descr = "Linux vm 6.18.44-fc-v165 #1 SMP PREEMPT_DYNAMIC @0 x86_64"
    assert snmp.parse_onesixtyone(ONESIXTYONE) == {"public": descr}
    system = snmp.parse_walk(SYSTEM_WALK, snmp.OID_SYSTEM)
    assert system["5.0"] == "lab-box" and system["4.0"] == "admin@lab.local" and system["3.0"].startswith("(36745)")
    assert snmp.parse_walk(NO_USERS, snmp.OID_WIN_USERS) == {}
    # numeric OIDs without the leading dot (snmpwalk without -On, no MIBs) parse too
    assert snmp.parse_walk("iso.3.6.1.2.1.1.5.0 = STRING: \"x\"", snmp.OID_SYSTEM) == {}
    assert snmp.parse_walk('1.3.6.1.2.1.1.5.0 = STRING: "x"', snmp.OID_SYSTEM) == {"5.0": "x"}


def test_secret_pattern():
    lines = ["-D -p 22", "-p8080", "--password Winter2024!", "-uroot -pS3cr3t", "token=abc", "bypass",
             "-sU -T4 --open -Pn -sV"]
    hits = [s for s in lines if snmp.SECRET.search(s)]
    assert hits == ["--password Winter2024!", "-uroot -pS3cr3t", "token=abc"]


def test_snmp_host():
    assert snmp.snmp_host("10.10.10.10", 161) == "10.10.10.10:161"
    assert snmp.snmp_host("::1", 1161) == "udp6:[::1]:1161"


def test_matches_udp_only():
    m = snmp.SnmpModule()
    assert m.protocols == ("udp",) and m.matches(Service(161, protocol="udp", name="snmp"))


def test_full_run_with_onesixtyone(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/" + tool)
    monkeypatch.setattr(runner, "run", fake_tools(calls, WALKS))
    ctx = make_ctx(tmp_path)
    findings = snmp.SnmpModule().run(ctx, Service(161, protocol="udp", name="snmp"))
    assert calls[0][:3] == ["onesixtyone", "-c", str(tmp_path / "snmp-communities.txt")]
    assert (tmp_path / "snmp-communities.txt").read_text() == "public\nprivate\n"
    main = findings[0]
    assert main.title == "SNMP readable with community 'public'" and main.severity == "high"
    rows = dict(main.data["table"]["rows"])
    assert rows["sysName"] == "lab-box" and rows["sysContact"] == "admin@lab.local"
    procs = next(f for f in findings if f.title.startswith("Process arguments"))
    assert procs.data["lines"] == ["backup.sh --user svc --password Winter2024!", "mysqld_safe -uroot -pS3cr3t"]
    assert (tmp_path / "snmp-public-process-args.txt").exists()
    [lead] = ctx.result.leads
    assert lead.kind == "snmp-community"
    assert lead.command == "snmpwalk -v2c -c public 10.10.10.10:161 | tee snmp-full.txt"


def test_snmpwalk_fallback_and_rejected(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/snmpwalk" if tool == "snmpwalk" else None)
    monkeypatch.setattr(runner, "run", fake_tools(calls, {}))
    [f] = snmp.SnmpModule().run(make_ctx(tmp_path), Service(161, protocol="udp", name="snmp"))
    assert [c[c.index("-c") + 1] for c in calls] == ["public", "private"]
    assert f.title == "SNMP default communities rejected" and "snmpwalk" in f.detail


def test_private_mentions_write_access(tmp_path, monkeypatch):
    walks = {("private", snmp.OID_SYSTEM): SYSTEM_WALK}
    out = "Scanning 1 hosts, 2 communities\n10.10.10.10 [private] Linux box\n"
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/" + tool)
    monkeypatch.setattr(runner, "run", fake_tools([], walks, onesixtyone=out))
    findings = snmp.SnmpModule().run(make_ctx(tmp_path), Service(161, protocol="udp", name="snmp"))
    assert "read-write" in findings[0].detail


def test_no_tools_uses_nmap_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "which", lambda tool: None)
    ctx = make_ctx(tmp_path)
    svc = Service(161, protocol="udp", name="snmp", product="net-snmp SNMPv3 server", extrainfo="public")
    [f] = snmp.SnmpModule().run(ctx, svc)
    assert f.severity == "high" and ctx.result.leads[0].kind == "snmp-community"
    assert any("snmpwalk" in h for h in ctx.result.hints)
    assert snmp.SnmpModule().run(make_ctx(tmp_path), Service(161, protocol="udp", name="snmp")) == []


# ----------------------------------------------------------------- real snmpd (skipped when missing)


def _free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(not (shutil.which("snmpd") or os.path.exists("/usr/sbin/snmpd")) or not shutil.which("snmpwalk"),
                    reason="needs snmpd and snmpwalk")
def test_real_snmpd(tmp_path):
    port = _free_udp_port()
    conf = tmp_path / "snmpd.conf"
    conf.write_text(f"agentAddress udp:127.0.0.1:{port}\nrocommunity public 127.0.0.1\nsysName lab-box\n")
    snmpd = shutil.which("snmpd") or "/usr/sbin/snmpd"
    # a process whose arguments carry a "password", visible through hrSWRunParameters
    victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "--password", "hunter2"])
    agent = subprocess.Popen([snmpd, "-f", "-C", "-c", str(conf), "-Lo", "-p", str(tmp_path / "pid")],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if runner.run(["snmpwalk", "-v2c", "-c", "public", "-t", "1", "-r", "0", f"127.0.0.1:{port}",
                           "1.3.6.1.2.1.1.5"], timeout=5).ok:
                break
            time.sleep(0.1)
        out = tmp_path / "out"
        out.mkdir()
        ctx = make_ctx(out, target="127.0.0.1")
        findings = snmp.SnmpModule().run(ctx, Service(port, protocol="udp", name="snmp"))
        titles = [f.title for f in findings]
        assert titles[0] == "SNMP readable with community 'public'"
        assert dict(findings[0].data["table"]["rows"])["sysName"] == "lab-box"
        procs = next(f for f in findings if f.title.startswith("Process arguments"))
        assert any("--password hunter2" in line for line in procs.data["lines"])
    finally:
        agent.terminate()
        victim.terminate()
        agent.wait(5)
        victim.wait(5)
