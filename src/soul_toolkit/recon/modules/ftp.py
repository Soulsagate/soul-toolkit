"""FTP follow-ups: anonymous login check, root listing analysis (no downloads)."""

from __future__ import annotations

import ftplib
import socket
from dataclasses import dataclass

from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

MAX_LIST = 50

# Top-level names that only exist together at a real Linux filesystem root.
FS_ROOT_MARKERS = {"bin", "etc", "usr", "var", "home", "root", "proc", "sbin", "lib", "dev", "boot"}


@dataclass
class Entry:
    perms: str
    name: str
    raw: str

    @property
    def is_dir(self) -> bool:
        return self.perms.startswith("d")

    @property
    def world_writable(self) -> bool:
        return len(self.perms) >= 9 and self.perms[8] == "w"


def parse_listing(lines: list[str]) -> list[Entry]:
    """Parse Unix-style `LIST` lines. '.' and '..' are dropped; unparseable lines are ignored."""
    entries = []
    for line in lines:
        line = line.replace(" [NSE: writeable]", "").rstrip()
        parts = line.split(None, 8)
        if len(parts) < 9 or len(parts[0]) < 10 or parts[0][0] not in "-dlbcps":
            continue
        name = parts[8].split(" -> ", 1)[0]
        if name in (".", ".."):
            continue
        entries.append(Entry(parts[0], name, line))
    return entries


def looks_like_fs_root(entries: list[Entry]) -> bool:
    names = {e.name.strip("/") for e in entries}
    return len(names & FS_ROOT_MARKERS) >= 5


def anon_listing(host: str, port: int, timeout: float) -> list[str] | None:
    """Return the root listing if anonymous login works, otherwise None."""
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=timeout)
        ftp.login("anonymous", "anonymous@example.com")
        lines: list[str] = []
        try:
            ftp.retrlines("LIST -a", lines.append)
        except ftplib.error_perm:
            ftp.retrlines("LIST", lines.append)
        return lines[:MAX_LIST]
    except (ftplib.Error, OSError, socket.timeout, EOFError):
        return None
    finally:
        try:
            ftp.quit()
        except Exception:
            ftp.close()


class FtpModule(Module):
    name = "ftp"
    description = "FTP: anonymous login, filesystem-root exposure, world-writable dirs"

    def matches(self, svc: Service) -> bool:
        return svc.name.lower() in ("ftp", "ftps") or (svc.port == 21 and svc.name in ("", "unknown"))

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        findings: list[Finding] = []
        script = svc.scripts.get("ftp-anon", "")
        nmap_says_anon = "Anonymous FTP login allowed" in script

        ctx.log.info(f"{svc.label} ftp: checking anonymous login")
        listing = anon_listing(ctx.target, svc.port, ctx.options.http_timeout)
        if listing is None and nmap_says_anon:
            listing = script.splitlines()[1:]

        url_host = f"{ctx.host_for_url()}:{svc.port}" if svc.port != 21 else ctx.host_for_url()

        if listing is not None:
            entries = parse_listing(listing)
            shown = [e.raw for e in entries] or [ln.strip() for ln in listing if ln.strip()]
            n = len(entries)
            findings.append(Finding(self.name, svc.port, "Anonymous FTP login allowed", "high",
                                    f"{n} entr{'y' if n == 1 else 'ies'} in the FTP root",
                                    {"listing": shown}))
            ctx.log.ok(f"{svc.label} ftp: anonymous login works")

            if looks_like_fs_root(entries):
                findings.append(Finding(self.name, svc.port, "FTP root is the server's filesystem root (/)", "high",
                                        "Anonymous users can read every world-readable file on the system."))
                ctx.log.ok(f"{svc.label} ftp: FTP root is the whole filesystem")
                ctx.hint(f"Browse it interactively (user: anonymous): ftp {ctx.target} {svc.port} - "
                         "don't mirror it, /proc and /dev will hang wget.")
            else:
                ctx.hint(f"Grab everything from anonymous FTP: wget -m ftp://anonymous:anonymous@{url_host}/")

            writable = [e for e in entries if e.is_dir and e.world_writable]
            if writable:
                findings.append(Finding(self.name, svc.port, "World-writable directories in FTP root", "medium",
                                        ", ".join(e.name for e in writable) + " - writable on disk; anonymous "
                                        "upload may still be disabled in the server config.",
                                        {"listing": [e.raw for e in writable]}))
                ctx.hint("Check if anonymous upload works: cd into the writable dir in ftp "
                         "and try `put` with a test file.")
        else:
            findings.append(Finding(self.name, svc.port, "Anonymous FTP login refused", "info", svc.banner))

        if svc.product.lower() == "vsftpd" and svc.version.startswith("2.3.4"):
            findings.append(Finding(self.name, svc.port, "vsftpd 2.3.4 - known backdoored version", "high",
                                    "CVE-2011-2523 (smiley-face backdoor)."))
        return findings
