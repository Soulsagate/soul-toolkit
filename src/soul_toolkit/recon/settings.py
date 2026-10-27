"""Recon settings, resolved in layers:

    built-in defaults < profile < config file < explicit command-line flags

Every key in DEFAULTS can come from any layer. The CLI leaves a flag as None when it wasn't
given, so an explicit flag always wins and anything unset falls through to the layer below.
The config file (~/.config/soul-toolkit/config.ini, [recon] section) can also pick the profile.
"""

from __future__ import annotations

import configparser
import os
import pwd
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
    "jobs": 4,               # module runs in parallel
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


def resolve(cli: dict[str, Any], profile: str = "default", config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Merge the layers. *cli* holds every DEFAULTS key, None meaning "not given"."""
    out = dict(DEFAULTS)
    out.update(profile_values(profile))
    out.update({k: v for k, v in (config or {}).items() if k in DEFAULTS})
    out.update({k: v for k, v in cli.items() if k in DEFAULTS and v is not None})
    return out


# --------------------------------------------------------------------------- config file

PATH_KEYS = {"wordlist", "vhost_wordlist", "output"}


class ConfigError(ValueError):
    pass


def user_home() -> Path:
    """The real user's home - under `sudo` that's the invoking user's, not /root."""
    sudo_user = os.environ.get("SUDO_USER", "")
    if hasattr(os, "geteuid") and os.geteuid() == 0 and sudo_user and sudo_user != "root":
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def default_config_path() -> Path:
    home = user_home()
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    base = Path(xdg) if xdg and home == Path.home() else home / ".config"
    return base / "soul-toolkit" / "config.ini"


def _expand(value: str, home: Path) -> str:
    if value == "~" or value.startswith("~/"):
        return str(home) + value[1:]
    return value


def load_config(path: Path) -> tuple[dict[str, Any], str | None, list[str]]:
    """Read the [recon] section. Returns (settings, profile or None, warnings).
    A missing file is fine (empty settings); a malformed one raises ConfigError."""
    if not path.is_file():
        return {}, None, []
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read(path, encoding="utf-8")
    except configparser.Error as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    if not parser.has_section("recon"):
        return {}, None, [f"{path}: no [recon] section - nothing used"]
    home = user_home()
    values: dict[str, Any] = {}
    warnings = []
    profile = None
    section = parser["recon"]
    for key in section:
        raw = section[key].strip()
        if key == "profile":
            if raw not in PROFILES:
                raise ConfigError(f"{path}: profile = {raw!r} - choose from {', '.join(PROFILES)}")
            profile = raw
            continue
        if key not in DEFAULTS:
            warnings.append(f"{path}: unknown setting {key!r} ignored")
            continue
        try:
            if key == "udp":
                values[key] = None if raw.lower() == "auto" else section.getboolean(key)
            elif isinstance(DEFAULTS[key], bool):
                values[key] = section.getboolean(key)
            elif isinstance(DEFAULTS[key], int):
                values[key] = section.getint(key)
            else:
                values[key] = _expand(raw, home) if key in PATH_KEYS else raw
        except ValueError:
            raise ConfigError(f"{path}: {key} = {raw!r} is not a valid value") from None
    return values, profile, warnings


EXAMPLE_CONFIG = """\
# soul-toolkit settings. Command-line flags always win over this file;
# this file wins over the profile. Delete a line to fall back to the default.

[recon]
# quick | default | thorough
profile = default

# Wordlists (paths may start with ~)
# wordlist = /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
# vhost_wordlist = /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Where results go
# output = ~/ctf/results

# gobuster/ffuf threads, parallel module runs, web time budget per port (seconds)
# threads = 30
# jobs = 4
# brute_timeout = 600

# nmap
# min_rate = 1000
# udp = auto
"""
