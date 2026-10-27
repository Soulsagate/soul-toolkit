"""SNMP follow-ups: try the default communities (public / private), then read the parts of the
MIB that matter in a CTF - system info, running processes with their arguments, and Windows users.

Community testing uses onesixtyone when installed, else snmpwalk. Only the two default names
are tried; this is a default-config check, not a community brute-force.
"""

from __future__ import annotations

import re

from soul_toolkit.core import runner
from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

COMMUNITIES = ("public", "private")
WALK_TIMEOUT = 60

OID_SYSTEM = "1.3.6.1.2.1.1"
OID_PROC_NAME = "1.3.6.1.2.1.25.4.2.1.2"
OID_PROC_ARGS = "1.3.6.1.2.1.25.4.2.1.5"
OID_WIN_USERS = "1.3.6.1.4.1.77.1.2.25"
SYSTEM_FIELDS = {"1.0": "sysDescr", "4.0": "sysContact", "5.0": "sysName", "6.0": "sysLocation"}

_ONESIXTYONE = re.compile(r"^(?P<host>\S+) \[(?P<community>[^\]]+)\] (?P<descr>.*)$")
_WALK = re.compile(r"^\.?(?P<oid>[\d.]+) = (?:(?P<type>[\w-]+): )?(?P<value>.*)$")
# Arguments that usually carry secrets: --password / pass= / token / api key, or mysql-style -pS3cret
# (a lowercase "-p" glued to a non-digit, so "-p 22", "-p8080" and nmap's "-Pn" don't count).
SECRET = re.compile(r"\bpass|\bpwd\b|secret|token|api[_-]?key|credential|(?-i:(^|\s)-p[^\s\d-])", re.I)


def parse_onesixtyone(output: str) -> dict[str, str]:
    """{community: sysDescr} for every community onesixtyone found."""
    found = {}
    for line in output.splitlines():
        m = _ONESIXTYONE.match(line.strip())
        if m:
            found.setdefault(m.group("community"), m.group("descr"))
    return found


def parse_walk(output: str, base: str) -> dict[str, str]:
    """Parse `snmpwalk -On` output into {oid suffix under *base*: value} (quotes stripped)."""
    out: dict[str, str] = {}
    prefix = base.strip(".") + "."
    for line in output.splitlines():
        m = _WALK.match(line.strip())
        if not m or "No Such" in m.group("value"):
            continue
        oid = m.group("oid").strip(".")
        if not oid.startswith(prefix):
            continue
        value = m.group("value").strip()
        if m.group("type") == "STRING" and len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        out[oid[len(prefix):]] = value
    return out


def snmp_host(target: str, port: int) -> str:
    return f"udp6:[{target}]:{port}" if ":" in target else f"{target}:{port}"


class SnmpModule(Module):
    name = "snmp"
    description = "SNMP: default communities (public/private), system info, process arguments, users"
    protocols = ("udp",)

    def matches(self, svc: Service) -> bool:
        return svc.name.lower() == "snmp" or svc.port == 161

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        host = snmp_host(ctx.target, svc.port)
        has_walk = bool(runner.which("snmpwalk"))
        ctx.log.info(f"{svc.label} snmp: trying communities {', '.join(COMMUNITIES)}")
        found, how = self._communities(ctx, svc, host, has_walk)
        if not found:
            if how == "none":
                return []
            return [Finding(self.name, svc.port, "SNMP default communities rejected", "info",
                            f"{', '.join(COMMUNITIES)} tested with {how}")]

        community = found[0]
        ctx.log.ok(f"{svc.label} snmp: readable with community {', '.join(repr(c) for c in found)}")
        findings: list[Finding] = []
        system: dict[str, str] = {}
        if has_walk:
            system = self._walk(ctx, host, community, OID_SYSTEM, "system")
        info = {name: system[k] for k, name in SYSTEM_FIELDS.items() if system.get(k)}
        rows = [["Communities", ", ".join(found)], *[[k, v] for k, v in info.items()]]
        writable = " 'private' is often the read-write community." if "private" in found else ""
        findings.append(Finding(self.name, svc.port, f"SNMP readable with community '{community}'", "high",
                                (info.get("sysDescr") or svc.banner) + writable,
                                {"table": {"headers": ["Field", "Value"], "rows": rows}}))
        ctx.lead("snmp-community", svc.port, f"Walk the whole SNMP tree with community '{community}'",
                 "Read-only SNMP leaks running processes with their command lines (often including passwords), "
                 "installed software, users and network config. Start with process arguments.",
                 f"snmpwalk -v2c -c {community} {host} | tee snmp-full.txt")

        if has_walk:
            findings += self._processes(ctx, svc, host, community)
            findings += self._windows_users(ctx, svc, host, community)
        else:
            ctx.hint("Install snmp (snmpwalk) to read process arguments and users over SNMP.")
        return findings

    # -- helpers ---------------------------------------------------------------

    def _communities(self, ctx: Context, svc: Service, host: str, has_walk: bool) -> tuple[list[str], str]:
        if runner.which("onesixtyone") and ":" not in ctx.target:  # onesixtyone is IPv4-only
            wordlist = ctx.outdir / "snmp-communities.txt"
            wordlist.write_text("\n".join(COMMUNITIES) + "\n", encoding="utf-8")
            res = ctx.run(["onesixtyone", "-c", str(wordlist), "-p", str(svc.port), ctx.target], timeout=30)
            return list(parse_onesixtyone(res.stdout)), "onesixtyone"
        if has_walk:
            found = []
            for c in COMMUNITIES:
                res = ctx.run(["snmpwalk", "-v2c", "-c", c, "-On", "-t", "2", "-r", "1", host, OID_SYSTEM + ".1"],
                              timeout=15)
                if res.ok and " = " in res.stdout:
                    found.append(c)
            return found, "snmpwalk"
        ctx.log.warn("neither onesixtyone nor snmpwalk installed - SNMP checks limited to nmap's results")
        ctx.hint("Install snmp (snmpwalk) and onesixtyone to test SNMP communities.")
        # nmap's own SNMP probe uses "public" and reports it in the version info when it answers.
        if "public" in svc.extrainfo.split():
            return ["public"], "nmap"
        return [], "none"

    def _walk(self, ctx: Context, host: str, community: str, oid: str, label: str) -> dict[str, str]:
        res = ctx.run(["snmpwalk", "-v2c", "-c", community, "-On", "-t", "2", "-r", "1", host, oid],
                      timeout=WALK_TIMEOUT)
        if res.stdout.strip():
            (ctx.outdir / f"snmp-{community}-{label}.txt").write_text(res.stdout, encoding="utf-8")
        return parse_walk(res.stdout, oid)

    def _processes(self, ctx: Context, svc: Service, host: str, community: str) -> list[Finding]:
        names = self._walk(ctx, host, community, OID_PROC_NAME, "process-names")
        args = self._walk(ctx, host, community, OID_PROC_ARGS, "process-args")
        lines = [f"{names.get(pid, '?')} {a}".strip() for pid, a in args.items() if a]
        suspicious = [line for line in lines if SECRET.search(line)]
        if not suspicious:
            return []
        ctx.log.ok(f"{svc.label} snmp: {len(suspicious)} process command line(s) look like they hold secrets")
        return [Finding(self.name, svc.port, "Process arguments over SNMP may contain credentials", "high",
                        f"{len(suspicious)} of {len(lines)} process command lines match password/token/key "
                        f"patterns. Full list: snmp-{community}-process-args.txt", {"lines": suspicious[:30]})]

    def _windows_users(self, ctx: Context, svc: Service, host: str, community: str) -> list[Finding]:
        users = sorted(set(self._walk(ctx, host, community, OID_WIN_USERS, "windows-users").values()))
        if not users:
            return []
        return [Finding(self.name, svc.port, f"Windows user accounts listed over SNMP ({len(users)})", "medium",
                        ", ".join(users[:20]), {"lines": users})]
