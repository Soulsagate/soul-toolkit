import json
from pathlib import Path

from soul_toolkit import cli
from soul_toolkit.core.models import Finding, HostResult
from soul_toolkit.recon import nmap
from soul_toolkit.recon.report import render_markdown, write_reports

FIXTURE = Path(__file__).parent / "fixtures" / "services.xml"


def sample_result() -> HostResult:
    h = nmap.parse_xml(FIXTURE.read_text())[0]
    r = HostResult(target="10.10.10.10", address=h.address, hostnames=h.hostnames, status=h.status,
                   os_guess=h.os_guess, services=h.services, started="2026-10-27 00:00:00 UTC", duration=75)
    r.findings = [
        Finding("web", 80, "Content discovery: 1 path(s)", "info", "wordlist: test",
                {"paths": [{"path": "/admin", "status": 301, "size": 10, "redirect": "http://x/admin/"}]}),
        Finding("ftp", 21, "Anonymous FTP login allowed", "high", "1 entry", {"listing": ["note.txt"]}),
        Finding("smb", 445, "Null session can list SMB shares", "medium", "anon",
                {"shares": [{"type": "Disk", "name": "anon", "comment": "a|b"}]}),
    ]
    r.hints = ["Do the thing"]
    r.commands = ["nmap -sT 10.10.10.10"]
    return r


def test_markdown_report_contents():
    md = render_markdown(sample_result())
    assert md.startswith("# Recon report: `10.10.10.10`")
    assert "| 22/tcp | ssh | OpenSSH 7.6p1" in md
    assert "8443/tcp | http (ssl)" in md
    # high severity first
    assert md.index("Anonymous FTP login allowed") < md.index("Null session") < md.index("Content discovery")
    assert "| `/admin` | 301 |" in md
    assert "a\\|b" in md  # pipes escaped inside tables
    assert "## Suggested next steps" in md and "## Commands run" in md
    assert "1m 15s" in md


def test_write_reports(tmp_path):
    md, js = write_reports(sample_result(), tmp_path)
    assert md.exists()
    data = json.loads(js.read_text())
    assert data["target"] == "10.10.10.10" and len(data["services"]) == 6


def test_reports_scrub_home_dir(tmp_path):
    r = sample_result()
    r.commands = [f"gobuster dir -w {Path.home()}/lists/words.txt"]
    md, js = write_reports(r, tmp_path)
    assert str(Path.home()) + "/" not in md.read_text()
    assert "~/lists/words.txt" in md.read_text() and "~/lists/words.txt" in js.read_text()


def test_cli_no_command_prints_help(capsys):
    assert cli.main([]) == 1
    assert "recon" in capsys.readouterr().out


def test_cli_rejects_bad_target():
    assert cli.main(["recon", "10.0.0.0/24"]) == 2
    assert cli.main(["recon", "a;id"]) == 2


def test_cli_requires_target():
    assert cli.main(["recon"]) == 2


def test_cli_rejects_bad_ports_and_modules():
    assert cli.main(["recon", "127.0.0.1", "-p", "99999"]) == 2
    assert cli.main(["recon", "127.0.0.1", "-m", "nope"]) == 2


def test_cli_list_modules(capsys):
    assert cli.main(["recon", "--list-modules"]) == 0
    out = capsys.readouterr().out
    for name in ("web", "ftp", "ssh", "smb"):
        assert name in out
