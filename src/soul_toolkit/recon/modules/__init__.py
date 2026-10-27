"""Service modules for recon.

Each module looks at one open service and decides whether it applies
(`matches`). If it does, `run` performs follow-up enumeration and returns
`Finding` objects. Adding a new service is one file + one line in `ALL`.
"""

from __future__ import annotations

import ipaddress
import shlex
import socket
from dataclasses import dataclass, field
from pathlib import Path

from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import Finding, HostResult, Lead, Service
from soul_toolkit.recon.leads import score_for


@dataclass
class Options:
    """Module-facing settings (a subset of the CLI flags)."""

    brute: bool = True
    wordlist: str | None = None
    threads: int = 30
    brute_timeout: int = 600
    http_timeout: int = 8
    extensions: str = ""  # empty = pick from the fingerprint
    recurse: bool = True
    vhosts: bool = True
    vhost_wordlist: str | None = None


@dataclass
class Context:
    target: str
    outdir: Path
    log: Logger
    result: HostResult
    options: Options = field(default_factory=Options)

    def run(self, cmd: list[str], timeout: float | None = None) -> runner.CommandResult:
        """Run an external command and record it in the report's command log."""
        self.log.debug(f"$ {shlex.join(cmd)}")
        res = runner.run(cmd, timeout=timeout)
        self.result.commands.append(res.pretty)
        return res

    def hint(self, text: str) -> None:
        if text not in self.result.hints:
            self.result.hints.append(text)

    def lead(self, kind: str, port: int, title: str, why: str, command: str = "") -> None:
        """Report something worth trying next. Its rank comes from `kind` (see recon/leads.py)."""
        self.result.leads.append(Lead(kind, port, title, why, command, score_for(kind)))

    def target_ip(self) -> str:
        """The IP to put in /etc/hosts lines: the target, nmap's resolved address, or a DNS lookup."""
        try:
            ipaddress.ip_address(self.target)
            return self.target
        except ValueError:
            pass
        if self.result.address:
            return self.result.address
        try:
            return socket.gethostbyname(self.target)
        except OSError:
            return "<target-ip>"

    def host_for_url(self) -> str:
        return f"[{self.target}]" if ":" in self.target else self.target


def hosts_command(ip: str, names: list[str]) -> str:
    """`echo '<ip> <names>' | sudo tee -a /etc/hosts`, names deduped and ordered most-specific first, so
    two modules that learn the same names produce the same command (and the same lead)."""
    clean = {n.strip().strip(".").lower() for n in names if n and n.strip().strip(".")}
    ordered = sorted(clean, key=lambda n: (-n.count("."), n))
    return f"echo '{ip} {' '.join(ordered)}' | sudo tee -a /etc/hosts"


class Module:
    name = "base"
    description = ""
    protocols: tuple[str, ...] = ("tcp",)  # the engine only offers services on these protocols

    def matches(self, svc: Service) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    def run(self, ctx: Context, svc: Service) -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError


def all_modules() -> list[Module]:
    from soul_toolkit.recon.modules.exploits import ExploitsModule
    from soul_toolkit.recon.modules.ftp import FtpModule
    from soul_toolkit.recon.modules.ldap import LdapModule
    from soul_toolkit.recon.modules.mail import MailModule
    from soul_toolkit.recon.modules.mysql import MysqlModule
    from soul_toolkit.recon.modules.nfs import NfsModule
    from soul_toolkit.recon.modules.postgres import PostgresModule
    from soul_toolkit.recon.modules.rdp import RdpModule
    from soul_toolkit.recon.modules.redis import RedisModule
    from soul_toolkit.recon.modules.smb import SmbModule
    from soul_toolkit.recon.modules.smtp import SmtpModule
    from soul_toolkit.recon.modules.snmp import SnmpModule
    from soul_toolkit.recon.modules.ssh import SshModule
    from soul_toolkit.recon.modules.web import WebModule
    from soul_toolkit.recon.modules.winrm import WinrmModule

    return [
        WebModule(), FtpModule(), SshModule(), SmbModule(), NfsModule(), SmtpModule(), MailModule(), SnmpModule(),
        MysqlModule(), PostgresModule(), RedisModule(), RdpModule(), WinrmModule(), LdapModule(),
        ExploitsModule(),  # last: it reads every service, so its leads land after the specific ones
    ]


def select_modules(names: list[str] | None) -> list[Module]:
    mods = all_modules()
    if not names:
        return mods
    wanted = {n.strip().lower() for n in names if n.strip()}
    known = {m.name for m in mods}
    unknown = wanted - known
    if unknown:
        raise ValueError(f"unknown module(s): {', '.join(sorted(unknown))} (available: {', '.join(sorted(known))})")
    return [m for m in mods if m.name in wanted]
