"""POP3 / IMAP follow-ups: banner, capabilities, and whether passwords would cross in clear text.

Everything comes from what nmap already collected (`-sV` and the pop3-/imap-capabilities
scripts). Recon only: no login attempts, no brute force. The lead hands you the commands to
read a mailbox by hand once you have credentials from somewhere else.
"""

from __future__ import annotations

import re

from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

POP3_PORTS = {110, 995}
IMAP_PORTS = {143, 993}
TLS_PORTS = {993, 995}  # TLS from the first byte (pop3s / imaps)
MAIL_NAMES = {"pop3", "pop3s", "imap", "imaps"}
# imap-capabilities output mixes the capability list with words from the server's greeting
# ("more ... listed capabilities have ... post-login ... OK Pre-login")
_NOISE = {"more", "listed", "capabilities", "have", "post-login", "pre-login", "ok", "capability"}
_TAG = re.compile(r"A\d{4}$")  # nmap glues its IMAP command tag onto the last word: AUTH=PLAINA0001


def protocol(svc: Service) -> str:
    """"pop3" or "imap"."""
    name = svc.name.lower()
    if "imap" in name or (not name.startswith("pop3") and svc.port in IMAP_PORTS):
        return "imap"
    return "pop3"


def uses_tls(svc: Service) -> bool:
    return svc.tunnel == "ssl" or svc.name.lower() in ("pop3s", "imaps") or svc.port in TLS_PORTS


def capabilities(svc: Service) -> list[str]:
    """Capabilities from nmap's pop3-/imap-capabilities script, cleaned up, in nmap's order."""
    out = svc.scripts.get(f"{protocol(svc)}-capabilities", "")
    caps: list[str] = []
    for word in out.split():
        word = _TAG.sub("", word).strip(",")
        if word and word.lower() not in _NOISE and word.upper() not in (c.upper() for c in caps):
            caps.append(word)
    return caps


def plaintext_login(proto: str, tls: bool, caps: list[str]) -> bool:
    """Would a login send the password in clear text? Only answered when nmap saw the capabilities."""
    if tls or not caps:
        return False
    upper = {c.upper() for c in caps}
    if proto == "pop3":
        # USER/PASS, or SASL PLAIN/LOGIN, without STLS to upgrade the connection first
        sasl_plain = any(c.startswith("SASL") and ("PLAIN" in c or "LOGIN" in c) for c in upper)
        return "STLS" not in upper and ("USER" in upper or sasl_plain)
    return "STARTTLS" not in upper and "LOGINDISABLED" not in upper


def mail_services(services: list[Service]) -> list[Service]:
    return [s for s in services if s.protocol == "tcp" and MailModule().matches(s)]


def _url(svc: Service, host: str) -> str:
    proto = protocol(svc) + ("s" if uses_tls(svc) else "")
    default = {"pop3": 110, "pop3s": 995, "imap": 143, "imaps": 993}[proto]
    port = f":{svc.port}" if svc.port != default else ""
    return f"{proto}://{host}{port}/"


class MailModule(Module):
    name = "mail"
    description = "POP3/IMAP: banner, capabilities, clear-text login check (from nmap; no login attempts)"

    def matches(self, svc: Service) -> bool:
        name = svc.name.lower()
        if name in MAIL_NAMES:
            return True
        return (svc.port in POP3_PORTS or svc.port in IMAP_PORTS) and name in ("", "unknown")

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        proto, tls = protocol(svc), uses_tls(svc)
        caps = capabilities(svc)
        label = proto.upper() + ("S" if tls else "")
        detail = svc.banner or "version unknown"
        if caps:
            detail += f"; capabilities: {', '.join(caps)}"
        findings = [Finding(self.name, svc.port, f"{label} mail server", "info", detail)]

        if plaintext_login(proto, tls, caps):
            upgrade = "STLS" if proto == "pop3" else "STARTTLS"
            findings.append(Finding(
                self.name, svc.port, f"{label} accepts passwords in clear text", "low",
                f"The server offers login ({'USER/PASS' if proto == 'pop3' else 'LOGIN/AUTH=PLAIN'}) "
                f"without {upgrade}, so credentials cross the network unencrypted."))

        # One lead per host, from the service that is easiest to use by hand (plain POP3 first).
        mail = mail_services(ctx.result.services) or [svc]
        best = min(mail, key=lambda s: (protocol(s) != "pop3", uses_tls(s), s.port))
        if best.port == svc.port:
            self._lead(ctx, best, mail)
        return findings

    def _lead(self, ctx: Context, svc: Service, mail: list[Service]) -> None:
        host = ctx.host_for_url()
        insecure = " -k" if uses_tls(svc) else ""
        url = _url(svc, host)
        if protocol(svc) == "pop3":
            if uses_tls(svc):
                by_hand = f"`openssl s_client -connect {host}:{svc.port} -quiet`"
            else:
                by_hand = f"`nc {host} {svc.port}`"
            how = (f"By hand: {by_hand}, then `USER <user>`, `PASS <password>`, `LIST` and `RETR 1`. "
                   f"The command below lists the mailbox; add `1` to the URL to read message 1.")
        else:
            how = "The command below lists the folders; add `INBOX;UID=1` to the URL to read the first message."
        imap = next((s for s in mail if protocol(s) == "imap"), None)
        if imap is not None and imap.port != svc.port:
            how += (f" IMAP works too: `curl{' -k' if uses_tls(imap) else ''} -u '<user>:<password>' "
                    f"'{_url(imap, host)}INBOX;UID=1'`.")
        others = ", ".join(s.label for s in mail)
        ctx.lead("mail-later", svc.port, "Keep the mail server for when you have credentials",
                 f"Mail is open on {others}. Mailboxes often hold more credentials, password resets and "
                 f"internal notes. No login is attempted here. {how}",
                 f"curl{insecure} -u '<user>:<password>' {url}")
