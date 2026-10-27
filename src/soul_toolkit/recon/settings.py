"""Recon settings, resolved in layers: built-in defaults < profile < explicit command-line flags.

Every key here is something a profile can set. The CLI leaves a flag as None when it wasn't
given, so an explicit flag always wins and anything unset falls through to the layer below.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "quick": False,          # top 1000 TCP ports instead of all 65535
    "udp": None,             # None = auto (root and no -p)
    "scripts": True,         # nmap -sC
    "min_rate": 1000,
    "brute": True,           # content discovery + vhost fuzzing
    "vhosts": True,
    "recurse": True,
    "wordlist": None,
    "vhost_wordlist": None,
    "extensions": "",
    "threads": 30,
    "brute_timeout": 600,
    "output": "results",
}

# Bigger lists the thorough profile uses when SecLists has them (first one found wins).
THOROUGH_WORDLISTS = (
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
)
THOROUGH_VHOST_WORDLISTS = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
)

PROFILES: dict[str, dict[str, Any]] = {
    # A first look in a few minutes: top 1000 ports, no UDP, one gobuster pass, no vhost fuzzing.
    "quick": {"quick": True, "udp": False, "recurse": False, "vhosts": False, "brute_timeout": 180},
    "default": {},
    # Leave it running: UDP even with -p (as root), bigger wordlists, a 30-minute web budget per port.
    "thorough": {"quick": False, "udp": True, "recurse": True, "vhosts": True, "brute_timeout": 1800},
}
PROFILE_HELP = {
    "quick": "top 1000 TCP ports, no UDP, no vhost fuzzing, one gobuster pass, 3 min web budget",
    "default": "all TCP ports, UDP when root, vhost fuzzing, one level of recursion, 10 min web budget",
    "thorough": "default + UDP even with -p, bigger SecLists wordlists when present, 30 min web budget",
}


def _first_file(candidates: tuple[str, ...]) -> str | None:
    return next((c for c in candidates if Path(c).is_file()), None)


def profile_values(name: str) -> dict[str, Any]:
    if name not in PROFILES:
        raise ValueError(f"unknown profile {name!r} (choose from {', '.join(PROFILES)})")
    values = dict(PROFILES[name])
    if name == "thorough":
        for key, candidates in (("wordlist", THOROUGH_WORDLISTS), ("vhost_wordlist", THOROUGH_VHOST_WORDLISTS)):
            found = _first_file(candidates)
            if found:
                values[key] = found
    return values


def resolve(cli: dict[str, Any], profile: str = "default") -> dict[str, Any]:
    """Merge the layers. *cli* holds every DEFAULTS key, None meaning "not given"."""
    out = dict(DEFAULTS)
    out.update(profile_values(profile))
    out.update({k: v for k, v in cli.items() if k in DEFAULTS and v is not None})
    return out
