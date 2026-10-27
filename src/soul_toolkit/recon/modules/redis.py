"""Redis follow-ups: does it answer INFO without authentication?

One inline `INFO` command is sent; the reply says it all - the INFO text (no auth), `-NOAUTH`
(password set) or `-DENIED` (protected mode). No keys are read and nothing is changed.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

MAX_REPLY = 256_000
SHOWN = ("redis_version", "redis_mode", "os", "role", "executable", "config_file", "connected_clients",
         "used_memory_human")


@dataclass
class RedisReply:
    info: dict[str, str] = field(default_factory=dict)
    keyspace: dict[str, str] = field(default_factory=dict)  # db0 -> "keys=3,expires=0,avg_ttl=0"
    error: str = ""

    @property
    def open(self) -> bool:
        return bool(self.info) and not self.error

    @property
    def keys(self) -> int:
        total = 0
        for stats in self.keyspace.values():
            for part in stats.split(","):
                k, _, v = part.partition("=")
                if k == "keys" and v.isdigit():
                    total += int(v)
        return total


def parse_info(text: str) -> tuple[dict[str, str], dict[str, str]]:
    info, keyspace = {}, {}
    section = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#"):
            section = line[1:].strip().lower()
        elif ":" in line:
            k, _, v = line.partition(":")
            (keyspace if section == "keyspace" else info)[k] = v
    return info, keyspace


def query_info(host: str, port: int, timeout: float) -> RedisReply | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"INFO\r\n")
            buf = b""
            while b"\r\n" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
            head, _, rest = buf.partition(b"\r\n")
            if head.startswith((b"-", b"+")):
                return RedisReply(error=head[1:].decode("utf-8", "replace").strip())
            if not head.startswith(b"$") or not head[1:].lstrip(b"-").isdigit():
                return None  # not Redis
            need = min(int(head[1:]), MAX_REPLY)
            while len(rest) < need:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                rest += chunk
            info, keyspace = parse_info(rest[:need].decode("utf-8", "replace"))
            return RedisReply(info=info, keyspace=keyspace)
    except OSError:
        return None


class RedisModule(Module):
    name = "redis"
    description = "Redis: unauthenticated INFO check (version, role, config path, keyspace)"

    def matches(self, svc: Service) -> bool:
        return svc.name.lower() == "redis" or (svc.port == 6379 and svc.name in ("", "unknown"))

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        ctx.log.info(f"{svc.label} redis: sending INFO")
        r = query_info(ctx.target, svc.port, ctx.options.http_timeout)
        if r is None:
            return [Finding(self.name, svc.port, "Redis did not answer INFO", "info", svc.banner)]
        if r.error:
            upper = r.error.upper()
            if upper.startswith("NOAUTH") or "AUTHENTICATION REQUIRED" in upper:
                title = "Redis requires a password"
            elif upper.startswith("DENIED"):
                title = "Redis is in protected mode (refuses remote clients)"
            else:
                title = "Redis refused INFO"
            first_sentence = r.error.split(". ", 1)[0].rstrip(".") + "."
            return [Finding(self.name, svc.port, title, "info", first_sentence)]

        version = r.info.get("redis_version", "?")
        ctx.log.ok(f"{svc.label} redis: INFO answered without a password (Redis {version}, {r.keys} key(s))")
        rows = [[k, r.info[k]] for k in SHOWN if r.info.get(k)]
        rows += [[db, stats] for db, stats in r.keyspace.items()]
        ctx.lead("redis-unauth", svc.port, "Look inside the unauthenticated Redis",
                 f"Redis {version} answers without a password and holds {r.keys} key(s). Sessions, tokens and "
                 "app secrets often live there: INFO keyspace, then SCAN 0 and GET what looks interesting.",
                 f"redis-cli -h {ctx.target} -p {svc.port}")
        return [Finding(self.name, svc.port, "Redis accepts commands without a password", "high",
                        f"Redis {version}, role {r.info.get('role', '?')}, {r.keys} key(s)",
                        {"table": {"headers": ["Field", "Value"], "rows": rows}})]
