"""Rank what modules found into a short "Where to start" list.

Modules don't score anything themselves: they report a lead with a *kind*
(`ctx.lead("ftp-anon", ...)`) and this file decides how promising each kind is.
Keeping every weight in one table makes the ranking deterministic, easy to
test, and easy to argue about in a pull request.
"""

from __future__ import annotations

from soul_toolkit.core.models import HostResult, Lead

WHERE_TO_START = 5

# Higher = try it sooner. Roughly: known-bad version > direct file/source access >
# unauthenticated listing > attack surface you still have to dig through > housekeeping.
SCORES: dict[str, int] = {
    "backdoor": 100,             # a version with a known backdoor
    "ftp-fsroot": 95,            # anonymous FTP rooted at /
    "web-git": 90,               # source code + history
    "ftp-webroot": 88,           # anonymous FTP that looks like the web root
    "nfs-world": 90,             # NFS export anyone can mount
    "ftp-anon": 85,              # anonymous FTP with files
    "snmp-community": 82,        # default SNMP community readable
    "exploit-rce": 80,           # Exploit-DB has a remote code/command execution match
    "smb-share": 75,             # a readable-looking share via null session
    "web-vhosts": 75,            # extra virtual hosts discovered
    "web-vhost": 70,             # redirect to a name-based vhost
    "exploit-remote": 65,        # other remote/webapps Exploit-DB matches
    "web-paths": 60,             # interesting paths from content discovery
    "web-wordpress": 60,
    "ftp-writable": 55,
    "nfs-restricted": 50,        # NFS export limited to some client IPs
    "smtp-vrfy": 50,             # SMTP VRFY/EXPN enumerate usernames
    "web-robots": 45,
    "smb-enum": 40,              # SMB answers but no share listing
    "exploit-local": 25,         # only local/DoS matches - useful after a foothold
    "web-browse": 20,
    "rescan": 15,                # the scan itself was limited
    "udp": 12,                   # UDP wasn't scanned
    "ssh-later": 10,
}


def score_for(kind: str) -> int:
    try:
        return SCORES[kind]
    except KeyError:
        raise ValueError(f"unknown lead kind {kind!r}; add it to SCORES in recon/leads.py") from None


def host_leads(r: HostResult, *, quick: bool = False, ports_given: bool = False,
               suggest_udp: bool = False) -> list[Lead]:
    """Leads that come from the scan as a whole rather than one service."""
    out: list[Lead] = []
    if suggest_udp and not r.udp_scanned:
        out.append(Lead("udp", 0, "Scan the top 100 UDP ports",
                        "UDP wasn't scanned (it needs root, and is skipped by default with -p). "
                        "SNMP, TFTP and NFS-related services live there.",
                        f'sudo "$(which toolkit)" recon {r.target} --udp', score_for("udp")))
    if quick or ports_given:
        what = "the top 1000 ports" if quick and not ports_given else "only the ports you gave"
        out.append(Lead("rescan", 0, "Sweep all 65535 TCP ports",
                        f"This run covered {what}; CTF boxes love services on odd high ports.",
                        f"toolkit recon {r.target}", score_for("rescan")))
    return out


def rank(leads: list[Lead]) -> list[Lead]:
    """Sort by score (then port, then title) and drop duplicates of the same command."""
    seen: set[str] = set()
    out = []
    for lead in sorted(leads, key=lambda x: (-x.score, x.port, x.title)):
        key = lead.command or f"{lead.kind}:{lead.port}:{lead.title}"
        if key in seen:
            continue
        seen.add(key)
        out.append(lead)
    return out


def other_hints(r: HostResult) -> list[str]:
    """Hints that aren't already covered by a lead's command."""
    commands = [lead.command for lead in r.leads if lead.command]
    return [h for h in r.hints if not any(c in h for c in commands)]
