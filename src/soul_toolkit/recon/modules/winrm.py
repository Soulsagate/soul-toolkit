"""WinRM notes: Windows Remote Management means a PowerShell shell for any user in
'Remote Management Users' - remember it for when credentials turn up. No extra connections."""

from __future__ import annotations

from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

WINRM_PORTS = {5985: False, 5986: True}  # port -> HTTPS


class WinrmModule(Module):
    name = "winrm"
    description = "WinRM (5985/5986): notes and the evil-winrm command for later"

    def matches(self, svc: Service) -> bool:
        return svc.port in WINRM_PORTS or svc.name.lower() in ("wsman", "wsmans")

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        tls = WINRM_PORTS.get(svc.port, svc.name.lower() == "wsmans" or svc.tunnel == "ssl")
        flags = " -S" if tls else ""
        port = f" -P {svc.port}" if svc.port not in WINRM_PORTS else ""
        ctx.lead("winrm-later", svc.port, "Keep WinRM for when you have credentials",
                 "Valid credentials for a user in 'Remote Management Users' (or an NTLM hash) give a "
                 "PowerShell shell over WinRM - often the intended way in on Windows boxes.",
                 f"evil-winrm -i {ctx.target}{port}{flags} -u <user> -p '<password>'")
        return [Finding(self.name, svc.port, "WinRM (Windows Remote Management) is open", "info",
                        f"{'HTTPS' if tls else 'HTTP'} transport. {svc.banner}".strip())]
