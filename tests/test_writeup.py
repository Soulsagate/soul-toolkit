from datetime import date
from pathlib import Path

from soul_toolkit import cli
from soul_toolkit.core.models import Finding, HostResult, Lead
from soul_toolkit.recon import engine, nmap, writeup

FIXTURE = Path(__file__).parent / "fixtures" / "services.xml"


def sample(target="cheese.thm") -> HostResult:
    h = nmap.parse_xml(FIXTURE.read_text())[0]
    r = HostResult(target=target, address=h.address, services=h.services)
    r.findings = [
        Finding("ftp", 21, "Anonymous FTP login allowed", "high", "1 entry in the FTP root"),
        Finding("web", 80, "HTTP fingerprint", "info", "server: Apache"),
        Finding("smb", 445, "Null session can list SMB shares", "medium", "anon"),
    ]
    r.leads = [Lead("ftp-anon", 21, "Download everything from anonymous FTP", "why",
                    "wget -m ftp://anonymous:anonymous@cheese.thm/", 85)]
    r.commands = ["nmap -sT -p- cheese.thm"]
    return r


def frontmatter(md: str) -> list[str]:
    assert md.startswith("---\n")
    return md.split("---\n")[1].splitlines()


def test_room_and_platform():
    assert writeup.default_room("cheese.thm") == "cheese"
    assert writeup.default_room("Box.HTB") == "Box"
    assert writeup.default_room("10.10.10.10") == "10.10.10.10"
    assert writeup.platform_for("cheese.thm") == "TryHackMe"
    assert writeup.platform_for("box.htb") == "Hack The Box"
    assert writeup.platform_for("10.10.10.10") == ""


def test_tags_from_services():
    assert writeup.tags_for(sample()) == ["writeup", "tryhackme", "ftp", "ssh", "web", "smb"]
    assert writeup.tags_for(sample("10.10.10.10"))[:2] == ["writeup", "ftp"]


def test_render_writeup():
    md = writeup.render_writeup(sample(), today=date(2026, 10, 27))
    fm = frontmatter(md)
    assert 'title: "cheese"' in fm and 'platform: "TryHackMe"' in fm and "date: 2026-10-27" in fm
    assert "  - smb" in fm and "status: in-progress" in fm
    assert "# cheese" in md
    assert "| 22/tcp | ssh | OpenSSH 7.6p1" in md
    # only medium/high findings, highest first
    assert md.index("Anonymous FTP login allowed") < md.index("Null session")
    assert "HTTP fingerprint" not in md
    assert "- [ ] **Download everything from anonymous FTP** (21/tcp) - `wget -m" in md
    assert "> [!note]- Commands run during recon" in md and "> `nmap -sT -p- cheese.thm`" in md
    # empty sections for the human part, in order
    sections = [line for line in md.splitlines() if line.startswith("## ")]
    assert sections == ["## Recon", "## Foothold", "## Privilege Escalation", "## Flags", "## Lessons learned"]
    assert "| user.txt | |" in md and "| root.txt | |" in md


def test_render_custom_room_is_yaml_safe():
    md = writeup.render_writeup(sample("10.10.10.10"), room='Pickle "Rick"', today=date(2026, 1, 2))
    fm = frontmatter(md)
    assert 'title: "Pickle \\"Rick\\""' in fm and not any(line.startswith("platform") for line in fm)
    assert "# Pickle \"Rick\"" in md


def test_render_empty_scan():
    md = writeup.render_writeup(HostResult("10.10.10.10"), today=date(2026, 1, 2))
    assert "_No open ports found._" in md and "_Nothing medium or high" in md and "Leads to try" not in md


def test_write_writeup_never_overwrites(tmp_path):
    first = writeup.write_writeup(sample(), tmp_path)
    assert first.name == "writeup.md"
    first.write_text("my notes")
    second = writeup.write_writeup(sample(), tmp_path)
    assert second != first and second.name.startswith("writeup-") and first.read_text() == "my notes"


def test_cli_room_implies_writeup(monkeypatch):
    seen = {}
    monkeypatch.setattr(engine, "run_recon", lambda cfg, log: seen.setdefault("cfg", cfg))
    assert cli.main(["recon", "10.10.10.10", "-q", "--room", "Pickle Rick"]) == 0
    assert seen["cfg"].writeup and seen["cfg"].room == "Pickle Rick"
    seen.clear()
    assert cli.main(["recon", "10.10.10.10", "-q"]) == 0
    assert not seen["cfg"].writeup


def test_engine_writes_writeup(tmp_path, monkeypatch):
    from soul_toolkit.core import runner
    from soul_toolkit.core.log import Logger

    xml = FIXTURE.read_text()
    monkeypatch.setattr(runner, "require", lambda *a, **k: "/usr/bin/nmap")
    monkeypatch.setattr(runner, "run", lambda cmd, timeout=None: runner.CommandResult(cmd, 0, xml, "", 0.1))
    monkeypatch.setattr(engine, "is_root", lambda: False)
    cfg = engine.ReconConfig(target="box.thm", output=tmp_path, ports=[22], modules=[], writeup=True)
    engine.run_recon(cfg, Logger(quiet=True))
    text = (tmp_path / "box.thm" / "writeup.md").read_text()
    assert 'room: "box"' in text and "## Foothold" in text


def test_rpc_helpers_collapse_into_nfs_tag():
    from soul_toolkit.core.models import Service

    r = HostResult("10.10.10.10", services=[
        Service(111, name="rpcbind"), Service(875, name="rquotad"), Service(2049, name="nfs"),
        Service(20048, name="mountd"), Service(42857, name="nlockmgr"), Service(2049, protocol="udp", name="nfs"),
    ])
    assert writeup.tags_for(r) == ["writeup", "rpc", "nfs"]
