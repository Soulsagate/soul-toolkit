"""FTP follow-ups: anonymous login check and a top-level directory listing (no downloads)."""

from __future__ import annotations

import ftplib
import socket

from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

MAX_LIST = 50


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
    description = "FTP: anonymous login check + root directory listing"

    def matches(self, svc: Service) -> bool:
        return svc.name.lower() in ("ftp", "ftps") or (svc.port == 21 and svc.name in ("", "unknown"))

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        findings: list[Finding] = []
        script = svc.scripts.get("ftp-anon", "")
        nmap_says_anon = "Anonymous FTP login allowed" in script

        ctx.log.info(f"{svc.label} ftp: checking anonymous login")
        listing = anon_listing(ctx.target, svc.port, ctx.options.http_timeout)

        if listing is not None or nmap_says_anon:
            files = listing if listing is not None else [l.strip() for l in script.splitlines()[1:] if l.strip()]
            findings.append(Finding(self.name, svc.port, "Anonymous FTP login allowed", "high",
                                    f"{len(files)} entr{'y' if len(files) == 1 else 'ies'} in the root directory",
                                    {"listing": files}))
            ctx.log.ok(f"{svc.label} ftp: anonymous login works")
            ctx.hint(f"Grab everything from anonymous FTP: wget -m ftp://anonymous:anonymous@{ctx.host_for_url()}:{svc.port}/")
        else:
            findings.append(Finding(self.name, svc.port, "Anonymous FTP login refused", "info", svc.banner))

        if svc.product.lower() == "vsftpd" and svc.version.startswith("2.3.4"):
            findings.append(Finding(self.name, svc.port, "vsftpd 2.3.4 - known backdoored version", "high",
                                    "CVE-2011-2523 (smiley-face backdoor)."))
        return findings
