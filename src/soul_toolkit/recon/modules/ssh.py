"""SSH follow-ups: version notes and auth-method hints from nmap scripts."""

from __future__ import annotations

import re

from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

_OPENSSH_VER = re.compile(r"^(\d+)\.(\d+)")


def openssh_version(svc: Service) -> tuple[int, int] | None:
    if "openssh" not in svc.product.lower():
        return None
    m = _OPENSSH_VER.match(svc.version)
    return (int(m.group(1)), int(m.group(2))) if m else None


class SshModule(Module):
    name = "ssh"
    description = "SSH: version notes (e.g. user-enum CVE-2018-15473 on OpenSSH <= 7.7)"

    def matches(self, svc: Service) -> bool:
        return svc.name.lower() == "ssh" or (svc.port == 22 and svc.name in ("", "unknown"))

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        findings = [Finding(self.name, svc.port, "SSH service", "info", svc.banner or "version unknown")]

        ver = openssh_version(svc)
        if ver is not None and ver <= (7, 7):
            findings.append(Finding(self.name, svc.port, f"OpenSSH {ver[0]}.{ver[1]} - username enumeration",
                                    "low", "OpenSSH through 7.7 is affected by CVE-2018-15473."))

        ctx.hint(f"SSH on {svc.port}: keep it for later - look for creds/keys elsewhere before brute-forcing.")
        return findings
