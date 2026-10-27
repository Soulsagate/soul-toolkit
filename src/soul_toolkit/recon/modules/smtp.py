"""SMTP follow-ups: banner, EHLO capabilities, and whether VRFY / EXPN answer (username enumeration).

Each command is sent twice: once for "root" and once for a random name that can't exist. If
the answers differ, the server is telling real users apart (Postfix answers 252 vs 550,
Sendmail 250 vs 550). Enumerating users is left to the user, with a ready smtp-user-enum command.
"""

from __future__ import annotations

import secrets
import smtplib
import socket
import ssl
from dataclasses import dataclass, field

from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

SMTP_PORTS = {25, 465, 587, 2525}
TLS_PORTS = {465}
PROBE_USER = "root"
EXISTS = {250, 251}            # "this user exists" - enumeration works whatever the random name gets
REFUSED = {500, 502, 503, 530}  # not implemented / disabled / needs auth
USER_LIST = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"


@dataclass
class SmtpProbe:
    banner: str = ""
    ehlo: list[str] = field(default_factory=list)
    vrfy: tuple[int, str] = (0, "")         # answer for PROBE_USER
    vrfy_fake: tuple[int, str] = (0, "")    # answer for a random, non-existent name
    expn: tuple[int, str] = (0, "")
    expn_fake: tuple[int, str] = (0, "")

    @property
    def vrfy_enabled(self) -> bool:
        return enumerates(self.vrfy[0], self.vrfy_fake[0])

    @property
    def expn_enabled(self) -> bool:
        return enumerates(self.expn[0], self.expn_fake[0])


def enumerates(real: int, fake: int) -> bool:
    """Does the command tell an existing user apart from a made-up one?"""
    if real in EXISTS:
        return True
    return bool(real and fake) and real != fake and real not in REFUSED and fake not in REFUSED


def _text(msg: bytes | str) -> str:
    return (msg.decode("utf-8", "replace") if isinstance(msg, bytes) else msg).strip()


def _reply(reply: tuple[int, bytes | str]) -> tuple[int, str]:
    return reply[0], _text(reply[1])


def probe(host: str, port: int, tls: bool, timeout: float) -> SmtpProbe | None:
    """Connect, EHLO, then try VRFY and EXPN once. None if the server can't be reached."""
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # lab certs are self-signed
            s: smtplib.SMTP = smtplib.SMTP_SSL(timeout=timeout, context=ctx)
        else:
            s = smtplib.SMTP(timeout=timeout)
        code, banner = s.connect(host, port)
    except (OSError, smtplib.SMTPException, socket.timeout):
        return None
    out = SmtpProbe(banner=f"{code} {_text(banner)}")
    try:
        code, msg = s.ehlo("soul-toolkit.local")
        if code == 250:
            out.ehlo = _text(msg).splitlines()[1:]  # first line is the server greeting itself
        else:
            s.helo("soul-toolkit.local")
        fake = "nouser" + secrets.token_hex(4)
        out.vrfy = _reply(s.verify(PROBE_USER))
        out.vrfy_fake = _reply(s.verify(fake))
        out.expn = _reply(s.docmd("EXPN", PROBE_USER))
        out.expn_fake = _reply(s.docmd("EXPN", fake))
    except (OSError, smtplib.SMTPException, socket.timeout):
        pass  # keep whatever we learned before the server hung up
    finally:
        try:
            s.quit()
        except (OSError, smtplib.SMTPException):
            s.close()
    return out


class SmtpModule(Module):
    name = "smtp"
    description = "SMTP: banner, EHLO capabilities, VRFY/EXPN user-enumeration check"

    def matches(self, svc: Service) -> bool:
        name = svc.name.lower()
        return name in ("smtp", "smtps", "submission") or (svc.port in SMTP_PORTS and name in ("", "unknown"))

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        tls = svc.port in TLS_PORTS or svc.tunnel == "ssl" or svc.name.lower() == "smtps"
        ctx.log.info(f"{svc.label} smtp: banner, EHLO, VRFY/EXPN")
        p = probe(ctx.target, svc.port, tls, ctx.options.http_timeout)
        if p is None:
            return [Finding(self.name, svc.port, "SMTP did not answer", "info", svc.banner)]

        rows = [["Banner", p.banner], ["Capabilities", ", ".join(p.ehlo) or "-"],
                ["VRFY root / made-up user", f"{p.vrfy[0]} / {p.vrfy_fake[0]}"],
                ["EXPN root / made-up user", f"{p.expn[0]} / {p.expn_fake[0]}"]]
        findings = [Finding(self.name, svc.port, "SMTP banner and capabilities", "info", p.banner,
                            {"table": {"headers": ["Field", "Value"], "rows": rows}})]

        enabled = [c for c, on in (("VRFY", p.vrfy_enabled), ("EXPN", p.expn_enabled)) if on]
        if enabled:
            cmds = " and ".join(enabled)
            ctx.log.ok(f"{svc.label} smtp: {cmds} answer - usernames can be enumerated")
            real, fake = (p.vrfy, p.vrfy_fake) if enabled[0] == "VRFY" else (p.expn, p.expn_fake)
            findings.append(Finding(self.name, svc.port, f"SMTP {cmds} enabled - usernames can be enumerated",
                                    "medium", f"{enabled[0]} {PROBE_USER} -> {real[0]} {real[1]}; "
                                    f"made-up user -> {fake[0]} {fake[1]}"))
            ctx.lead("smtp-vrfy", svc.port, f"Enumerate usernames with SMTP {enabled[0]}",
                     f"The server answers {cmds} for real names. Valid usernames make every login "
                     "(SSH, web, SMB) far easier to attack later.",
                     f"smtp-user-enum -M {enabled[0]} -U {USER_LIST} -t {ctx.target} -p {svc.port}")
        return findings
