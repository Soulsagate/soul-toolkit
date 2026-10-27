import io

from soul_toolkit import cli, doctor

ALL = {t.binary for t in doctor.TOOLS}


def run(monkeypatch, present, plat="debian", show_all=False, wordlists=False):
    monkeypatch.setattr(doctor.shutil, "which", lambda b: f"/usr/bin/{b}" if b in present else None)
    monkeypatch.setattr(doctor, "detect_platform", lambda: plat)
    monkeypatch.setattr(doctor, "_find_wordlist", lambda c: c[0] if wordlists else None)
    out = io.StringIO()
    return doctor.run_doctor(show_all=show_all, out=out), out.getvalue()


def test_detect_platform():
    assert doctor.detect_platform('ID=kali\nID_LIKE=debian\n', "Linux") == "debian"
    assert doctor.detect_platform('ID="endeavouros"\nID_LIKE="arch"\n', "Linux") == "arch"
    assert doctor.detect_platform("ID=ubuntu\nID_LIKE=debian\n", "Linux") == "debian"
    assert doctor.detect_platform("ID=fedora\n", "Linux") is None
    assert doctor.detect_platform("", "Darwin") == "macos"


def test_install_commands_group_by_manager():
    cmds = doctor.install_commands([("pacman", "nmap"), ("aur", "exploitdb"), ("pacman", "ffuf"),
                                    ("pacman", "nmap"), ("none", "not needed")])
    assert cmds == ["sudo pacman -S --needed nmap ffuf", "yay -S exploitdb", "# not needed"]
    assert doctor.install_commands([("builtin", "")]) == []


def test_every_tool_has_three_platforms():
    for t in doctor.TOOLS:
        for pkg in (t.arch, t.debian, t.macos):
            assert pkg[0] in ("pacman", "aur", "apt", "brew", "builtin", "none")
    assert [t.binary for t in doctor.TOOLS if t.required] == ["nmap"]


def test_all_present(monkeypatch):
    rc, out = run(monkeypatch, ALL, wordlists=True)
    assert rc == 0 and "Everything is installed." in out and "[--  ]" not in out


def test_missing_optional_tools(monkeypatch):
    rc, out = run(monkeypatch, {"nmap", "gobuster"})
    assert rc == 0
    assert "[--  ] searchsploit" in out and "exploits: Exploit-DB lookups" in out
    debian = out[out.index("Kali / Debian / Ubuntu (this machine):"):]
    assert "sudo apt install ffuf exploitdb smbclient nfs-common snmp onesixtyone seclists" in debian
    assert "Kali packages" in debian
    assert "yay -S exploitdb onesixtyone seclists" in out
    assert "brew install ffuf exploitdb samba net-snmp" in out and "SecLists.git" in out and "toolkit config" in out
    # detected platform first
    assert out.index("Kali / Debian / Ubuntu") < out.index("Arch /") < out.index("macOS:")


def test_missing_nmap_fails(monkeypatch):
    rc, out = run(monkeypatch, ALL - {"nmap"}, plat="arch", wordlists=True)
    assert rc == 1 and "[MISS] nmap" in out and "sudo pacman -S --needed nmap" in out


def test_show_all(monkeypatch):
    rc, out = run(monkeypatch, ALL, plat=None, show_all=True, wordlists=True)
    assert rc == 0
    assert "Install everything:" in out and "sudo apt install nmap gobuster ffuf" in out


def test_cli_doctor(monkeypatch):
    seen = []

    def fake(show_all):
        seen.append(show_all)
        return 0

    monkeypatch.setattr(doctor, "run_doctor", fake)
    assert cli.main(["doctor", "--all"]) == 0 and cli.main(["doctor"]) == 0
    assert seen == [True, False]
