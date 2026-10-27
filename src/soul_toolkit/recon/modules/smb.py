"""SMB follow-ups: null-session share listing and signing status."""

from __future__ import annotations

from soul_toolkit.core import runner
from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

SMB_PORTS = {139, 445}


def parse_smbclient_shares(output: str) -> list[dict]:
    """Parse `smbclient -L //host -N -g` (grepable) output."""
    shares = []
    for line in output.splitlines():
        parts = line.strip().split("|")
        if len(parts) >= 2 and parts[0] in ("Disk", "IPC", "Printer"):
            shares.append({"type": parts[0], "name": parts[1], "comment": parts[2] if len(parts) > 2 else ""})
    return shares


class SmbModule(Module):
    name = "smb"
    description = "SMB: null-session share listing (smbclient) + message signing check"

    def matches(self, svc: Service) -> bool:
        return svc.port in SMB_PORTS or svc.name.lower() in ("microsoft-ds", "netbios-ssn", "smb")

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        findings: list[Finding] = []

        for script_id in ("smb2-security-mode", "smb-security-mode"):
            out = svc.scripts.get(script_id, "")
            if "not required" in out or "disabled" in out.lower():
                findings.append(Finding(self.name, svc.port, "SMB message signing not required", "low",
                                        out.strip().splitlines()[-1].strip() if out.strip() else ""))
                break

        # Only list shares once per host, not for both 139 and 445.
        if svc.port == 139 and any(s.port == 445 for s in ctx.result.services):
            return findings

        if not runner.which("smbclient"):
            ctx.log.warn("smbclient not installed - skipping share listing")
            ctx.hint("Install smbclient (samba package) to enable SMB share listing.")
            return findings

        ctx.log.info(f"{svc.label} smb: trying null-session share listing")
        res = ctx.run(["smbclient", "-L", f"//{ctx.target}", "-N", "-g", "-p", str(svc.port)], timeout=60)
        shares = parse_smbclient_shares(res.stdout)
        if shares:
            disks = [s for s in shares if s["type"] == "Disk"]
            findings.append(Finding(self.name, svc.port, "Null session can list SMB shares", "medium",
                                    ", ".join(s["name"] for s in shares), {"shares": shares}))
            ctx.log.ok(f"{svc.label} smb: {len(shares)} share(s) listed")
            custom = [s for s in disks if not s["name"].endswith("$")]
            if custom:
                ctx.lead("smb-share", svc.port, f"Connect to the '{custom[0]['name']}' share with a null session",
                         f"Anonymous listing shows {len(shares)} share(s): {', '.join(s['name'] for s in shares)}. "
                         "Non-default shares are where CTF files live.",
                         f"smbclient //{ctx.target}/{custom[0]['name']} -N")
            for s in custom[1:]:
                ctx.hint(f"Try the '{s['name']}' share: smbclient //{ctx.target}/{s['name']} -N")
        else:
            out = (res.stdout + res.stderr).strip()
            findings.append(Finding(self.name, svc.port, "Null-session share listing refused", "info",
                                    out.splitlines()[-1] if out else ""))
        ctx.lead("smb-enum", svc.port, "Enumerate users, groups and policies over SMB",
                 "enum4linux-ng tries null and guest sessions for users, shares and the password policy.",
                 f"enum4linux-ng -A {ctx.target}")
        return findings
