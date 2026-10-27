"""`toolkit doctor`: which external tools are installed, what each one enables, and how to install the rest."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

# How to install a package: (manager, package). Managers: pacman, aur (via yay), apt, brew,
# builtin (ships with the OS), none (no package - the note says what to do instead).
Pkg = tuple[str, str]


@dataclass(frozen=True)
class Tool:
    binary: str
    required: bool
    features: str
    arch: Pkg
    debian: Pkg
    macos: Pkg


TOOLS: tuple[Tool, ...] = (
    Tool("nmap", True, "port sweep, service/version scan, UDP scan",
         ("pacman", "nmap"), ("apt", "nmap"), ("brew", "nmap")),
    Tool("gobuster", False, "web: content discovery (and vhost fuzzing when ffuf is missing)",
         ("pacman", "gobuster"), ("apt", "gobuster"), ("brew", "gobuster")),
    Tool("ffuf", False, "web: vhost fuzzing",
         ("pacman", "ffuf"), ("apt", "ffuf"), ("brew", "ffuf")),
    Tool("searchsploit", False, "exploits: Exploit-DB lookups for every versioned service",
         ("aur", "exploitdb"), ("apt", "exploitdb"), ("brew", "exploitdb")),
    Tool("smbclient", False, "smb: null-session share listing",
         ("pacman", "smbclient"), ("apt", "smbclient"), ("brew", "samba")),
    Tool("showmount", False, "nfs: export listing",
         ("pacman", "nfs-utils"), ("apt", "nfs-common"), ("builtin", "")),
    Tool("snmpwalk", False, "snmp: community check, system info, process arguments, users",
         ("pacman", "net-snmp"), ("apt", "snmp"), ("brew", "net-snmp")),
    Tool("onesixtyone", False, "snmp: faster community check (snmpwalk is used without it)",
         ("aur", "onesixtyone"), ("apt", "onesixtyone"), ("none", "not needed - snmpwalk covers it")),
)

PLATFORMS = {
    "arch": "Arch / EndeavourOS / Manjaro",
    "kali": "Kali / Parrot",
    "debian": "Debian / Ubuntu / Mint / LMDE",
    "macos": "macOS",
}
KALI_ONLY = {"exploitdb", "seclists"}  # in Kali's repos, not Debian's or Ubuntu's
SECLISTS = {"arch": ("aur", "seclists"), "kali": ("apt", "seclists"), "debian": ("apt", "seclists"),
            "macos": ("none", "")}
SECLISTS_CLONE = "git clone --depth 1 https://github.com/danielmiessler/SecLists.git"
# Plain Debian/Ubuntu: one missing package makes `apt install` refuse everything, so the Kali-only
# packages are installed from their upstream repos instead, into the paths recon looks in.
FROM_SOURCE = {
    "exploitdb": [
        "sudo git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb",
        "sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit",
    ],
    "seclists": [f"sudo {SECLISTS_CLONE} /usr/share/seclists"],
}


def _pkg(tool: Tool, plat: str) -> Pkg:
    return tool.debian if plat == "kali" else getattr(tool, plat)


def detect_platform(os_release: str | None = None, system: str | None = None) -> str | None:
    """"arch", "debian", "macos" or None, from /etc/os-release (ID and ID_LIKE) or the OS name."""
    system = system or platform.system()
    if system == "Darwin":
        return "macos"
    if os_release is None:
        try:
            os_release = Path("/etc/os-release").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    ids: list[str] = []
    for line in os_release.splitlines():
        key, _, value = line.partition("=")
        if key in ("ID", "ID_LIKE"):
            ids += value.strip().strip('"').lower().split()
    if any(i in ("arch", "manjaro", "endeavouros", "garuda", "blackarch") for i in ids):
        return "arch"
    if any(i in ("kali", "parrot") for i in ids):
        return "kali"
    if any(i in ("debian", "ubuntu", "linuxmint", "pop", "elementary", "zorin") for i in ids):
        return "debian"
    return None


def install_commands(pkgs: list[Pkg]) -> list[str]:
    """Collapse (manager, package) pairs into the commands to run, in a stable order."""
    by_mgr: dict[str, list[str]] = {}
    for mgr, name in pkgs:
        if name and name not in by_mgr.setdefault(mgr, []):
            by_mgr[mgr].append(name)
    out = []
    templates = {"pacman": "sudo pacman -S --needed {}", "aur": "yay -S {}", "apt": "sudo apt install {}",
                 "brew": "brew install {}"}
    for mgr, template in templates.items():
        if by_mgr.get(mgr):
            out.append(template.format(" ".join(by_mgr[mgr])))
    out += [f"# {note}" for note in by_mgr.get("none", [])]
    return out


def _find_wordlist(candidates: tuple[str, ...]) -> str | None:
    return next((c for c in candidates if Path(c).is_file()), None)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def run_doctor(show_all: bool = False, out=None) -> int:
    from soul_toolkit import __version__
    from soul_toolkit.recon import vhosts
    from soul_toolkit.recon.modules import web

    out = out or sys.stdout

    def say(line: str = "") -> None:
        print(line, file=out)

    plat = detect_platform()

    say(f"soul-toolkit {__version__} doctor")
    say(f"  Python {platform.python_version()} · platform: {PLATFORMS.get(plat, 'unknown')}"
        f" · root: {'yes' if is_root() else 'no (SYN and UDP scans need sudo)'}")
    from soul_toolkit.recon.settings import ConfigError, default_config_path, load_config

    cfg_path = default_config_path()
    try:
        cfg_values, cfg_profile, _ = load_config(cfg_path)
        cfg_state = (f"{len(cfg_values)} setting(s)" + (f", profile {cfg_profile}" if cfg_profile else "")
                     if cfg_path.is_file() else "none - using defaults; toolkit config --init creates one")
    except ConfigError as exc:
        cfg_state = f"ERROR: {exc}"
    say(f"  config: {cfg_path} ({cfg_state})")
    say()
    say("Tools:")
    missing: list[Tool] = []
    for t in TOOLS:
        path = shutil.which(t.binary)
        if not path:
            missing.append(t)
        mark = "ok  " if path else ("MISS" if t.required else "--  ")
        need = "required" if t.required else "optional"
        say(f"  [{mark}] {t.binary:<13} {need:<9} {t.features}")
        if path:
            say(f"         {'':<13} {'':<9} {path}")

    say()
    say("Wordlists:")
    web_wl = _find_wordlist(web.SYSTEM_WORDLISTS)
    vh_wl = _find_wordlist(vhosts.SYSTEM_WORDLISTS)
    say(f"  content discovery: {web_wl or 'bundled web-common.txt (small) - install SecLists for better results'}")
    say(f"  vhost fuzzing:     {vh_wl or 'bundled vhosts.txt (small) - install SecLists for better results'}")

    todo = list(TOOLS) if show_all else missing
    need_seclists = show_all or not (web_wl and vh_wl)
    if todo or need_seclists:
        say()
        say("Install " + ("everything:" if show_all else "what's missing:"))
        order = [plat] if plat and not show_all else []
        order += [p for p in PLATFORMS if p not in order]
        for p in order:
            pkgs = [_pkg(t, p) for t in todo]
            if need_seclists:
                pkgs.append(SECLISTS[p])
            from_source: list[str] = []
            if p == "debian":
                from_source = [name for _, name in pkgs if name in KALI_ONLY]
                pkgs = [(m, n) for m, n in pkgs if n not in KALI_ONLY]
            cmds = install_commands(pkgs)
            if p == "macos" and need_seclists:
                cmds.append(f"{SECLISTS_CLONE}  # then set wordlist / vhost_wordlist in `toolkit config`")
            if from_source:
                cmds.append(f"# {' and '.join(from_source)}: not in Debian/Ubuntu repos, install from source")
                for name in from_source:
                    cmds += FROM_SOURCE[name]
            label = PLATFORMS[p] + (" (this machine)" if p == plat else "")
            say(f"  {label}:")
            for c in cmds or ["# nothing to install"]:
                say(f"    {c}")
    else:
        say()
        say("Everything is installed.")

    if any(t.required for t in missing):
        say()
        say("nmap is required: `toolkit recon` can't run without it.")
        return 1
    return 0
