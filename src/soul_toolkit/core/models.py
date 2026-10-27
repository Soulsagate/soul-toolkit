"""Data structures shared across the toolkit."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high")

WEB_PORTS = {80, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090}
TLS_PORTS = {443, 8443}


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    scripts: dict[str, str] = field(default_factory=dict)
    hostname: str = ""  # name the service itself reported (nmap -sV), e.g. a domain controller's

    @property
    def label(self) -> str:
        return f"{self.port}/{self.protocol}"

    @property
    def banner(self) -> str:
        parts = [self.product, self.version]
        if self.extrainfo:
            parts.append(f"({self.extrainfo})")
        return " ".join(p for p in parts if p)

    @property
    def is_web(self) -> bool:
        name = self.name.lower()
        if "http" in name:
            return True
        return self.port in WEB_PORTS and name in ("", "unknown", "tcpwrapped")

    @property
    def is_tls(self) -> bool:
        name = self.name.lower()
        return self.tunnel == "ssl" or name in ("https", "ssl/http", "https-alt") or self.port in TLS_PORTS


@dataclass
class Finding:
    module: str
    port: int
    title: str
    severity: str = "info"
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    protocol: str = "tcp"  # set by the engine from the service the module ran on

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")

    @property
    def rank(self) -> int:
        return SEVERITIES.index(self.severity)


@dataclass
class Lead:
    """Something worth trying next, with the reason and a copy-paste command."""

    kind: str
    port: int
    title: str
    why: str
    command: str = ""
    score: int = 0
    protocol: str = "tcp"

    @property
    def where(self) -> str:
        return f"{self.port}/{self.protocol}" if self.port else "host"


@dataclass
class HostResult:
    target: str
    address: str = ""
    hostnames: list[str] = field(default_factory=list)
    status: str = "unknown"
    os_guess: str = ""
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    leads: list[Lead] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    udp_scanned: bool = False
    interrupted: bool = False  # Ctrl-C: the report only holds what finished
    incomplete: list[str] = field(default_factory=list)  # stages / module runs that didn't finish
    started: str = ""
    finished: str = ""
    duration: float = 0.0

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.rank, f.port, f.module))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
