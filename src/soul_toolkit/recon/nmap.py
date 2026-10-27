"""Build nmap commands and parse nmap's XML output into structured data.

Recon runs nmap in two stages:

1. **Port sweep**  - fast scan to find which TCP ports are open.
2. **Service scan** - version detection (-sV) and default scripts (-sC),
   only against the ports found in stage 1.

Parsing XML (rather than scraping the normal text output) keeps the results
reliable across nmap versions.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, field

from soul_toolkit.core.models import Service
from soul_toolkit.core.target import is_ipv6


class NmapError(RuntimeError):
    pass


@dataclass
class NmapHost:
    address: str = ""
    status: str = "unknown"
    hostnames: list[str] = field(default_factory=list)
    os_guess: str = ""
    services: list[Service] = field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        return sorted(s.port for s in self.services)


def _base(target: str, syn: bool, skip_ping: bool) -> list[str]:
    cmd = ["nmap", "-sS" if syn else "-sT", "-T4", "--open", "-oX", "-"]
    if skip_ping:
        cmd.append("-Pn")
    if is_ipv6(target):
        cmd.append("-6")
    return cmd


def build_port_sweep(
    target: str,
    *,
    syn: bool,
    full: bool = True,
    min_rate: int | None = 1000,
    skip_ping: bool = True,
) -> list[str]:
    cmd = _base(target, syn, skip_ping)
    cmd += ["-p-"] if full else ["--top-ports", "1000"]
    if min_rate:
        cmd += ["--min-rate", str(min_rate)]
    cmd.append(target)
    return cmd


def build_service_scan(
    target: str,
    ports: Iterable[int],
    *,
    syn: bool,
    scripts: bool = True,
    skip_ping: bool = True,
) -> list[str]:
    port_list = sorted(set(ports))
    if not port_list:
        raise ValueError("service scan needs at least one port")
    cmd = _base(target, syn, skip_ping)
    cmd.append("-sV")
    if scripts:
        cmd.append("-sC")
    cmd += ["-p", ",".join(str(p) for p in port_list), target]
    return cmd


def _udp_base(target: str, skip_ping: bool) -> list[str]:
    cmd = ["nmap", "-sU", "-T4", "--open", "-oX", "-"]
    if skip_ping:
        cmd.append("-Pn")
    if is_ipv6(target):
        cmd.append("-6")
    return cmd


def build_udp_sweep(target: str, *, top: int = 100, min_rate: int | None = 1000, skip_ping: bool = True) -> list[str]:
    """Top-N UDP ports. Needs root. Only ports that actually answer come back as 'open';
    the many 'open|filtered' ones are ignored when parsing."""
    cmd = [*_udp_base(target, skip_ping), "--top-ports", str(top)]
    if min_rate:
        cmd += ["--min-rate", str(min_rate)]
    cmd.append(target)
    return cmd


def build_udp_service_scan(target: str, ports: Iterable[int], *, scripts: bool = True,
                           skip_ping: bool = True) -> list[str]:
    port_list = sorted(set(ports))
    if not port_list:
        raise ValueError("service scan needs at least one port")
    cmd = [*_udp_base(target, skip_ping), "-sV"]
    if scripts:
        cmd.append("-sC")
    cmd += ["-p", ",".join(str(p) for p in port_list), target]
    return cmd


def parse_ports(spec: str) -> list[int]:
    """Parse a user port spec like '22,80,8000-8010' into a sorted list."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo_s, hi_s = chunk.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(chunk))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"port(s) out of range: {bad[:5]}")
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def script_fields(output: str) -> dict[str, str]:
    """`Key: value` lines of an NSE script's output (rdp-ntlm-info, smb-os-discovery, ...) as a dict."""
    fields = {}
    for line in output.splitlines():
        key, sep, value = line.strip().partition(":")
        if sep and key and " " not in key.strip() and value.strip():
            fields[key.strip()] = value.strip()
    return fields


def parse_xml(xml_text: str) -> list[NmapHost]:
    """Parse nmap -oX output. Only ports in state 'open' are kept."""
    if not xml_text or not xml_text.strip():
        raise NmapError("nmap produced no XML output")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapError(f"could not parse nmap XML: {exc}") from exc

    hosts: list[NmapHost] = []
    for h in root.findall("host"):
        host = NmapHost()

        status = h.find("status")
        if status is not None:
            host.status = status.get("state", "unknown")

        addrs = h.findall("address")
        ip_addr = next((a for a in addrs if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if ip_addr is not None:
            host.address = ip_addr.get("addr", "")
        elif addrs:
            host.address = addrs[0].get("addr", "")

        host.hostnames = [hn.get("name", "") for hn in h.findall("hostnames/hostname") if hn.get("name")]

        osmatch = h.find("os/osmatch")
        if osmatch is not None:
            host.os_guess = f"{osmatch.get('name', '')} ({osmatch.get('accuracy', '?')}%)"

        for p in h.findall("ports/port"):
            state_el = p.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue
            svc_el = p.find("service")
            svc = Service(
                port=int(p.get("portid", "0")),
                protocol=p.get("protocol", "tcp"),
                state=state,
            )
            if svc_el is not None:
                svc.name = svc_el.get("name", "")
                svc.product = svc_el.get("product", "")
                svc.version = svc_el.get("version", "")
                svc.extrainfo = svc_el.get("extrainfo", "")
                svc.tunnel = svc_el.get("tunnel", "")
                svc.hostname = svc_el.get("hostname", "")
            svc.scripts = {
                s.get("id", "?"): (s.get("output") or "").strip() for s in p.findall("script")
            }
            host.services.append(svc)

        host.services.sort(key=lambda s: (s.protocol, s.port))
        hosts.append(host)
    return hosts
