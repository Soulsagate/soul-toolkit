"""Virtual-host fuzzing helpers: build ffuf / gobuster vhost commands and parse their output.

Name-based virtual hosting serves different sites on one IP depending on the
`Host` header, so `dev.box.thm` can exist without any DNS record. We send
`Host: <word>.<domain>` to the target's IP and keep the answers that differ from
what a random, non-existent name gets (the "wildcard" response).
"""

from __future__ import annotations

import json
import re
import secrets
from importlib import resources
from pathlib import Path

SYSTEM_WORDLISTS = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
)

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# gobuster >= 3.2: "Found: dev.box.thm Status: 200 [Size: 47]"; older: "Found: dev.box.thm (Status: 200) [Size: 47]"
_GB_VHOST = re.compile(r"^(?:Found:\s+)?(?P<host>\S+)\s+\(?Status:\s*(?P<status>\d+)\)?\s*\[Size:\s*(?P<size>\d+)\]")


def bundled_wordlist() -> str:
    return str(resources.files("soul_toolkit").joinpath("data", "vhosts.txt"))


def resolve_wordlist(explicit: str | None) -> tuple[str, str]:
    """Return (path, label): the user's list, else SecLists, else the small bundled list."""
    if explicit:
        if not Path(explicit).is_file():
            raise FileNotFoundError(f"vhost wordlist not found: {explicit}")
        return explicit, explicit
    for cand in SYSTEM_WORDLISTS:
        if Path(cand).is_file():
            return cand, cand
    return bundled_wordlist(), "bundled vhosts.txt"


def fuzz_domain(target: str, redirect_host: str | None, target_is_ip: bool) -> str | None:
    """The domain to put after `FUZZ.`, or None when there's no name to fuzz under.

    A redirect to a vhost wins (that's the name the box wants); otherwise the target itself if it
    is a hostname with at least one dot. A leading `www.` is dropped: `FUZZ.www.box.thm` finds nothing.
    """
    name = redirect_host or ("" if target_is_ip else target)
    name = name.strip(".").lower()
    if name.startswith("www."):
        name = name[4:]
    if "." not in name:
        return None
    return name


def random_label() -> str:
    return "soulcheck-" + secrets.token_hex(6)


def wildcard_size(sizes: list[int | None]) -> int | None:
    """The size to filter out if every random-name probe got the same size, else None (dynamic)."""
    if not sizes or any(s is None for s in sizes) or len(set(sizes)) != 1:
        return None
    return sizes[0]


def build_ffuf(base: str, domain: str, wordlist: str, outfile: Path, *, threads: int, timeout: int,
               maxtime: int, filter_size: int | None) -> list[str]:
    cmd = [
        "ffuf", "-u", f"{base}/", "-H", f"Host: FUZZ.{domain}", "-w", wordlist,
        "-t", str(threads), "-timeout", str(timeout), "-maxtime", str(maxtime),
        "-of", "json", "-o", str(outfile), "-s", "-noninteractive",
    ]
    # A stable wildcard size is filtered exactly; a dynamic one falls back to ffuf's auto-calibration.
    cmd += ["-fs", str(filter_size)] if filter_size is not None else ["-ac"]
    return cmd


def build_gobuster_vhost(base: str, domain: str, wordlist: str, outfile: Path, *, threads: int, timeout: int,
                         filter_size: int | None, tls: bool) -> list[str]:
    cmd = [
        "gobuster", "vhost", "-u", base, "-w", wordlist, "--append-domain", "--domain", domain,
        "-t", str(threads), "-q", "--no-progress", "--no-color", "--no-error",
        "--timeout", f"{timeout}s", "-o", str(outfile),
    ]
    if filter_size is not None:
        cmd += ["--exclude-length", str(filter_size)]
    if tls:
        cmd.append("-k")
    return cmd


def parse_ffuf(text: str) -> list[dict]:
    """Parse ffuf's `-of json` output file."""
    try:
        results = json.loads(text).get("results", [])
    except (ValueError, AttributeError):
        return []
    out = []
    for r in results:
        host = r.get("host") or ""
        if not host:
            continue
        out.append({"host": host.lower(), "status": int(r.get("status", 0)), "size": int(r.get("length", 0))})
    return _sorted_unique(out)


def parse_gobuster_vhost(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        m = _GB_VHOST.match(_ANSI.sub("", raw).replace("\r", "").strip())
        if m:
            out.append({"host": m.group("host").lower(), "status": int(m.group("status")),
                        "size": int(m.group("size"))})
    return _sorted_unique(out)


def _sorted_unique(items: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for i in items:
        seen.setdefault(i["host"], i)
    return sorted(seen.values(), key=lambda i: i["host"])


def hosts_line(ip: str, domain: str, found: list[dict]) -> str:
    """The /etc/hosts line covering the base domain and every vhost found."""
    names = [domain] + [v["host"] for v in found if v["host"] != domain]
    return f"{ip} {' '.join(names)}"
