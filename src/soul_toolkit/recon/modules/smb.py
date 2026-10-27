"""SMB follow-ups: null-session share listing, read access per share, and signing status.

Read access is checked with one `smbclient //host/share -N -c ls` per share: it lists the top
directory and nothing else. Recon only - write access is never tested and nothing is ever
created or deleted on the target. That is also why smbmap's permission check isn't used: it
finds out whether a share is writable by creating (and then removing) a directory on it.
"""

from __future__ import annotations

from soul_toolkit.core import runner
from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

SMB_PORTS = {139, 445}
SHARE_TIMEOUT = 20      # seconds per share for the read check
MAX_SHARE_CHECKS = 12   # a file server with dozens of shares shouldn't stall the run

READ, NO_ACCESS, TIMED_OUT, UNKNOWN = "READ", "NO ACCESS", "TIMED OUT", "UNKNOWN"
# NT_STATUS codes that mean "the server answered and said no" rather than "something broke"
_DENIED = ("ACCESS_DENIED", "LOGON_FAILURE", "BAD_NETWORK_NAME", "WRONG_PASSWORD", "ACCOUNT_DISABLED",
           "ACCOUNT_RESTRICTION", "NETWORK_ACCESS_DENIED", "NO_SUCH_USER")
# Shares every Windows / Samba / AD server has; finding one readable isn't a CTF lead by itself
_DEFAULT_SHARES = {"netlogon", "sysvol", "print$"}


def parse_smbclient_shares(output: str) -> list[dict]:
    """Parse `smbclient -L //host -N -g` (grepable) output."""
    shares = []
    for line in output.splitlines():
        parts = line.strip().split("|")
        if len(parts) >= 2 and parts[0] in ("Disk", "IPC", "Printer"):
            shares.append({"type": parts[0], "name": parts[1], "comment": parts[2] if len(parts) > 2 else ""})
    return shares


def read_access(res: runner.CommandResult) -> str:
    """Classify the result of `smbclient //host/share -N -c ls`."""
    if res.timed_out:
        return TIMED_OUT
    out = res.stdout + res.stderr
    if any(f"NT_STATUS_{code}" in out for code in _DENIED):
        return NO_ACCESS
    if res.returncode == 0 and "NT_STATUS_" not in out:
        return READ
    return UNKNOWN


def is_custom(share: dict) -> bool:
    """A share someone set up on purpose: not IPC/printers, not an admin ($) or AD default share."""
    name = share["name"]
    return share["type"] == "Disk" and not name.endswith("$") and name.lower() not in _DEFAULT_SHARES


class SmbModule(Module):
    name = "smb"
    description = "SMB: null-session share listing + read access per share (smbclient), signing check"

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
            self._check_read(ctx, svc, shares)
            findings.append(self._share_finding(ctx, svc, shares))
        else:
            out = (res.stdout + res.stderr).strip()
            findings.append(Finding(self.name, svc.port, "Null-session share listing refused", "info",
                                    out.splitlines()[-1] if out else ""))
        ctx.lead("smb-enum", svc.port, "Enumerate users, groups and policies over SMB",
                 "enum4linux-ng tries null and guest sessions for users, shares and the password policy.",
                 f"enum4linux-ng -A {ctx.target}")
        return findings

    def _check_read(self, ctx: Context, svc: Service, shares: list[dict]) -> None:
        """Set share["access"] for every non-IPC share (read check only, see the module docstring)."""
        todo = [s for s in shares if s["type"] != "IPC"]
        for share in todo[:MAX_SHARE_CHECKS]:
            res = ctx.run(["smbclient", f"//{ctx.target}/{share['name']}", "-N", "-p", str(svc.port), "-c", "ls"],
                          timeout=SHARE_TIMEOUT)
            share["access"] = read_access(res)
        for share in todo[MAX_SHARE_CHECKS:]:
            share["access"] = UNKNOWN
        if len(todo) > MAX_SHARE_CHECKS:
            ctx.hint(f"Only the first {MAX_SHARE_CHECKS} of {len(todo)} shares were checked for read access.")

    def _share_finding(self, ctx: Context, svc: Service, shares: list[dict]) -> Finding:
        readable = [s["name"] for s in shares if s.get("access") == READ]
        detail = ", ".join(s["name"] for s in shares)
        if readable:
            detail += f" - readable without a password: {', '.join(readable)}"
        ctx.log.ok(f"{svc.label} smb: {len(shares)} share(s) listed, {len(readable)} readable")

        custom = [s for s in shares if is_custom(s)]
        open_ = [s for s in custom if s.get("access") == READ]
        unsure = [s for s in custom if s.get("access") in (TIMED_OUT, UNKNOWN)]
        listing = f"Anonymous listing shows {len(shares)} share(s): {', '.join(s['name'] for s in shares)}."
        if open_:
            first = open_[0]["name"]
            ctx.lead("smb-readable", svc.port, f"Read the '{first}' share with a null session",
                     f"{listing} '{first}' is readable without a password (a test `ls` worked) - "
                     "non-default shares are where CTF files live.",
                     f"smbclient //{ctx.target}/{first} -N")
        elif unsure:
            first = unsure[0]["name"]
            ctx.lead("smb-share", svc.port, f"Connect to the '{first}' share with a null session",
                     f"{listing} Read access couldn't be confirmed ({unsure[0]['access'].lower()}), so try it by hand.",
                     f"smbclient //{ctx.target}/{first} -N")
        elif custom:
            first = custom[0]["name"]
            ctx.lead("smb-locked", svc.port, f"Come back to the '{first}' share with credentials",
                     f"{listing} None of the non-default shares can be read without a password.",
                     f"smbclient //{ctx.target}/{first} -U '<user>'")
        lead_share = (open_ or unsure or custom or [None])[0]
        for s in open_ + unsure:
            if s is not lead_share:
                state = "readable" if s.get("access") == READ else "read access unconfirmed"
                ctx.hint(f"Try the '{s['name']}' share ({state}): smbclient //{ctx.target}/{s['name']} -N")
        return Finding(self.name, svc.port, "Null session can list SMB shares", "medium", detail, {"shares": shares})

