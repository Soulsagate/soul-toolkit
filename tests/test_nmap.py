from pathlib import Path

import pytest

from soul_toolkit.recon import nmap

FIXTURE = Path(__file__).parent / "fixtures" / "services.xml"


def test_parse_services_fixture():
    hosts = nmap.parse_xml(FIXTURE.read_text())
    assert len(hosts) == 1
    h = hosts[0]
    assert h.address == "10.10.10.10"
    assert h.status == "up"
    assert h.hostnames == ["box.thm"]
    assert h.os_guess == "Linux 4.15 (95%)"
    # filtered 3306 is dropped
    assert h.open_ports == [21, 22, 80, 139, 445, 8443]


def test_parse_service_details_and_scripts():
    h = nmap.parse_xml(FIXTURE.read_text())[0]
    by_port = {s.port: s for s in h.services}
    ssh = by_port[22]
    assert ssh.product == "OpenSSH"
    assert ssh.version.startswith("7.6p1")
    assert "Ubuntu Linux" in ssh.banner
    assert "Anonymous FTP login allowed" in by_port[21].scripts["ftp-anon"]
    assert by_port[8443].is_tls and by_port[8443].is_web
    assert by_port[80].is_web and not by_port[80].is_tls
    assert not by_port[22].is_web


@pytest.mark.parametrize("bad", ["", "   ", "<nmaprun", "not xml at all"])
def test_parse_bad_xml(bad):
    with pytest.raises(nmap.NmapError):
        nmap.parse_xml(bad)


def test_parse_no_hosts():
    assert nmap.parse_xml('<?xml version="1.0"?><nmaprun></nmaprun>') == []


def test_build_port_sweep_defaults():
    cmd = nmap.build_port_sweep("10.10.10.10", syn=True)
    assert cmd[:2] == ["nmap", "-sS"]
    assert "-p-" in cmd and "-Pn" in cmd
    assert cmd[cmd.index("--min-rate") + 1] == "1000"
    assert cmd[-1] == "10.10.10.10"
    assert cmd[cmd.index("-oX") + 1] == "-"


def test_build_port_sweep_quick_connect_ping():
    cmd = nmap.build_port_sweep("box.thm", syn=False, full=False, min_rate=None, skip_ping=False)
    assert "-sT" in cmd and "-Pn" not in cmd and "--min-rate" not in cmd
    assert cmd[cmd.index("--top-ports") + 1] == "1000"


def test_build_service_scan():
    cmd = nmap.build_service_scan("10.10.10.10", [80, 22, 80], syn=False)
    assert "-sV" in cmd and "-sC" in cmd
    assert cmd[cmd.index("-p") + 1] == "22,80"
    assert "-sC" not in nmap.build_service_scan("10.10.10.10", [22], syn=False, scripts=False)


def test_build_service_scan_ipv6():
    assert "-6" in nmap.build_service_scan("::1", [22], syn=False)


def test_build_service_scan_requires_ports():
    with pytest.raises(ValueError):
        nmap.build_service_scan("10.10.10.10", [], syn=False)


@pytest.mark.parametrize(
    "spec,expected",
    [("22", [22]), ("80,22,80", [22, 80]), ("8000-8002, 22", [22, 8000, 8001, 8002]), ("10-8", [8, 9, 10])],
)
def test_parse_ports(spec, expected):
    assert nmap.parse_ports(spec) == expected


@pytest.mark.parametrize("spec", ["0", "65536", "abc", "", ","])
def test_parse_ports_invalid(spec):
    with pytest.raises(ValueError):
        nmap.parse_ports(spec)
