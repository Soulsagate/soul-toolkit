"""NFS follow-ups: list exports with `showmount -e` and flag the ones anyone can mount."""

from __future__ import annotations

import re

from soul_toolkit.core import runner
from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

NFS_NAMES = {"nfs", "nfs_acl", "mountd"}
WORLD = {"*", "(everyone)", "everyone", "0.0.0.0/0", "::/0", "(anyone)"}


def parse_showmount(output: str) -> list[dict]:
    """Parse `showmount -e` output into [{"path": ..., "clients": [...]}]."""
    exports = []
    for line in output.splitlines():
        line = line.rstrip()
        if not line.startswith("/"):
            continue  # "Export list for host:" header, errors, blank lines
        parts = line.rsplit(None, 1)
        if len(parts) == 2 and not parts[1].startswith("/"):
            path, clients = parts[0].rstrip(), [c for c in parts[1].split(",") if c]
        else:
            path, clients = line.strip(), []
        exports.append({"path": path, "clients": clients})
    return exports


def is_world(export: dict) -> bool:
    """Exported to everyone (no client list counts as everyone too)."""
    return not export["clients"] or any(c.lower() in WORLD for c in export["clients"])


def mount_point(path: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", path).strip("-") or "root"
    return f"/mnt/nfs-{slug}"


class NfsModule(Module):
    name = "nfs"
    description = "NFS: list exports (showmount -e), flag world-mountable ones"

    def matches(self, svc: Service) -> bool:
        return svc.name.lower() in NFS_NAMES or svc.port == 2049

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        # showmount asks the host, not a port: only run it for the first NFS-looking service.
        first = next((s for s in ctx.result.services if s.protocol == "tcp" and self.matches(s)), svc)
        if first is not svc:
            return []
        if not runner.which("showmount"):
            ctx.log.warn("showmount not installed - skipping NFS export listing")
            ctx.hint("Install nfs-common (Debian/Kali) or nfs-utils (Arch) for showmount, "
                     f"then run: showmount -e {ctx.target}")
            return []

        ctx.log.info(f"{svc.label} nfs: listing exports")
        res = ctx.run(["showmount", "-e", ctx.target], timeout=30)
        exports = parse_showmount(res.stdout)
        if not exports:
            err = (res.stderr or res.stdout).strip().splitlines()
            detail = err[-1] if err else "no exports listed"
            return [Finding(self.name, svc.port, "No NFS exports listed", "info", detail)]

        world = [e for e in exports if is_world(e)]
        rows = [[e["path"], ", ".join(e["clients"]) or "(everyone)"] for e in exports]
        table = {"table": {"headers": ["Export", "Allowed clients"], "rows": rows}, "exports": exports}
        ctx.log.ok(f"{svc.label} nfs: {len(exports)} export(s), {len(world)} open to everyone")

        findings = []
        if world:
            findings.append(Finding(self.name, svc.port, "NFS exports anyone can mount", "high",
                                    ", ".join(e["path"] for e in world), table))
            pick = world[0]
            others = [e["path"] for e in world[1:]]
            ctx.lead("nfs-world", svc.port, f"Mount the NFS export {pick['path']} (read-only)",
                     "It's exported to everyone. Exports often hold home directories, backups and SSH keys"
                     + (f"; also open: {', '.join(others)}" if others else "") + ". Note file owners - "
                     "root-owned files you can create there mean no_root_squash (a privesc lead later).",
                     f"sudo mkdir -p {mount_point(pick['path'])} && sudo mount -t nfs -o ro,nolock "
                     f"{ctx.target}:{pick['path']} {mount_point(pick['path'])}")
        else:
            findings.append(Finding(self.name, svc.port, "NFS exports (restricted to some clients)", "medium",
                                    ", ".join(e["path"] for e in exports), table))
            e = exports[0]
            ctx.lead("nfs-restricted", svc.port, f"Check whether your IP may mount {e['path']}",
                     f"Exported only to {', '.join(e['clients'])}. Compare with your VPN address (ip a show tun0).",
                     f"sudo mkdir -p {mount_point(e['path'])} && sudo mount -t nfs -o ro,nolock "
                     f"{ctx.target}:{e['path']} {mount_point(e['path'])}")
        return findings
