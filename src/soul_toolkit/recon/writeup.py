"""`--writeup`: an Obsidian-friendly writeup skeleton with the Recon section already filled in.

The output is plain Markdown with YAML frontmatter, so it also renders fine on GitHub.
Foothold / Privilege Escalation / Flags are left empty for the person doing the box.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from pathlib import Path

from soul_toolkit import __version__
from soul_toolkit.core.models import HostResult
from soul_toolkit.recon import leads as leads_mod
from soul_toolkit.recon.report import scrub

PLATFORMS = {".thm": "TryHackMe", ".htb": "Hack The Box"}
SERVICE_TAGS = {
    "microsoft-ds": "smb", "netbios-ssn": "smb", "ms-wbt-server": "rdp", "domain": "dns",
    "ldap": "ldap", "kerberos-sec": "kerberos", "mysql": "mysql", "postgresql": "postgres",
    "pop3": "mail", "imap": "mail", "pop3s": "mail", "imaps": "mail",
    # NFS's RPC helpers would each become a useless tag; they all mean "NFS is here"
    "mountd": "nfs", "nlockmgr": "nfs", "rquotad": "nfs", "nfs_acl": "nfs", "status": "nfs", "rpcbind": "rpc",
}
_EMOJI = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}


def default_room(target: str) -> str:
    """`cheese.thm` -> `cheese`; IPs are kept as they are."""
    for suffix in PLATFORMS:
        if target.lower().endswith(suffix):
            return target[: -len(suffix)]
    return target


def platform_for(target: str) -> str:
    return next((name for suffix, name in PLATFORMS.items() if target.lower().endswith(suffix)), "")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def tags_for(r: HostResult) -> list[str]:
    tags = ["writeup"]
    platform = platform_for(r.target)
    if platform:
        tags.append(_slug(platform))
    for s in r.services:
        name = s.name.lower()
        tag = "web" if s.is_web else SERVICE_TAGS.get(name, _slug(name))
        if tag and tag not in ("unknown", "tcpwrapped") and tag not in tags:
            tags.append(tag)
    return tags


def _yaml_str(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _cell(text: str) -> str:
    return (text or "-").replace("|", "\\|").replace("\n", " ")


def render_writeup(r: HostResult, room: str | None = None, today: date | None = None) -> str:
    room = room or default_room(r.target)
    today = today or date.today()
    platform = platform_for(r.target)
    lines: list[str] = []
    add = lines.append

    add("---")
    add(f"title: {_yaml_str(room)}")
    add(f"room: {_yaml_str(room)}")
    if platform:
        add(f"platform: {_yaml_str(platform)}")
    add(f"target: {_yaml_str(r.target)}")
    add(f"date: {today.isoformat()}")
    add("tags:")
    lines += [f"  - {t}" for t in tags_for(r)]
    add("status: in-progress")
    add("---")
    add("")
    add(f"# {room}")
    add("")
    where = f"`{r.target}`" + (f" · {platform}" if platform else "")
    if r.interrupted:
        add("> [!warning] Partial recon")
        add(f"> The scan was interrupted. Not finished: {'; '.join(r.incomplete) or 'unknown'}.")
        add("")
    add("> [!info] Target")
    add(f"> {where} · recon by soul-toolkit v{__version__} on {today.isoformat()}")
    add("")

    add("## Recon")
    add("")
    add("### Open ports")
    add("")
    if r.services:
        add("| Port | Service | Version |")
        add("|---|---|---|")
        for s in r.services:
            add(f"| {s.label} | {_cell(s.name)} | {_cell(s.banner)} |")
    else:
        add("_No open ports found._")
    add("")

    notable = [f for f in r.sorted_findings() if f.severity in ("high", "medium")]
    add("### Key findings")
    add("")
    if notable:
        for f in notable:
            detail = f" - {f.detail.splitlines()[0]}" if f.detail else ""
            add(f"- {_EMOJI[f.severity]} **{f.title}** ({f.port}/{f.protocol}){detail}")
    else:
        add("_Nothing medium or high from automated recon._")
    add("")

    top = r.leads[:leads_mod.WHERE_TO_START]
    if top:
        add("### Leads to try")
        add("")
        for lead in top:
            cmd = f" - `{lead.command}`" if lead.command else ""
            add(f"- [ ] **{lead.title}** ({lead.where}){cmd}")
        add("")

    if r.commands:
        add("> [!note]- Commands run during recon")
        for c in r.commands:
            add(f"> `{c}`  ")
        add("")

    for section in ("Foothold", "Privilege Escalation"):
        add(f"## {section}")
        add("")
        add("")

    add("## Flags")
    add("")
    add("| Flag | Value |")
    add("|---|---|")
    add("| user.txt | |")
    add("| root.txt | |")
    add("")
    add("## Lessons learned")
    add("")
    return "\n".join(lines).rstrip() + "\n"


def write_writeup(r: HostResult, outdir: Path, room: str | None = None) -> Path:
    """Write writeup.md, never overwriting one that already exists (it may hold your notes)."""
    path = outdir / "writeup.md"
    if path.exists():
        path = outdir / f"writeup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
    path.write_text(scrub(render_writeup(r, room)), encoding="utf-8")
    return path

