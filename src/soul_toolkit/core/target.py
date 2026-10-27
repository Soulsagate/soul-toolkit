"""Target validation helpers."""

from __future__ import annotations

import ipaddress
import re

_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


class InvalidTarget(ValueError):
    pass


def validate_target(target: str) -> str:
    """Accept a single IPv4/IPv6 address or hostname. Ranges/CIDRs are rejected on purpose."""
    target = target.strip()
    if not target:
        raise InvalidTarget("empty target")
    if "/" in target:
        raise InvalidTarget("CIDR ranges aren't supported by recon yet; pass one host at a time")
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    if _HOSTNAME.match(target):
        return target.rstrip(".")
    raise InvalidTarget(f"'{target}' is not a valid IP address or hostname")


def is_ipv6(target: str) -> bool:
    try:
        return ipaddress.ip_address(target).version == 6
    except ValueError:
        return False


def safe_dirname(target: str) -> str:
    """Filesystem-friendly name for a target (IPv6 colons become underscores)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", target)
