"""PostgreSQL follow-ups: does the server let `postgres` in without a password?

PostgreSQL never accepts an *empty* password for password auth, so the meaningful
"empty password" check is whether pg_hba.conf says `trust` for us. One startup message
as user `postgres` tells us which authentication method the server wants; when it is
trust we also get the exact server_version. Nothing is queried.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

USER = "postgres"
PROTOCOL_3 = 196608
AUTH_METHODS = {0: "trust (no password)", 2: "kerberos", 3: "cleartext password", 5: "md5 password", 7: "GSSAPI",
                9: "SSPI", 10: "SCRAM-SHA-256 password"}


@dataclass
class PgProbe:
    auth_code: int | None = None
    error: str = ""          # server's FATAL message, if it refused us
    error_code: str = ""     # SQLSTATE
    params: dict[str, str] = field(default_factory=dict)  # ParameterStatus after a successful login

    @property
    def trusted(self) -> bool:
        return self.auth_code == 0

    @property
    def method(self) -> str:
        if self.auth_code is None:
            return "unknown"
        return AUTH_METHODS.get(self.auth_code, f"auth code {self.auth_code}")


def startup_message(user: str, database: str = "postgres") -> bytes:
    body = struct.pack("!I", PROTOCOL_3)
    for k, v in (("user", user), ("database", database), ("application_name", "soul-toolkit")):
        body += k.encode() + b"\x00" + v.encode() + b"\x00"
    body += b"\x00"
    return struct.pack("!I", len(body) + 4) + body


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def read_message(sock: socket.socket) -> tuple[bytes, bytes]:
    kind = _recv_exact(sock, 1)
    (length,) = struct.unpack("!I", _recv_exact(sock, 4))
    return kind, _recv_exact(sock, length - 4)


def parse_error(payload: bytes) -> dict[str, str]:
    """ErrorResponse fields: one type byte + NUL-terminated string each (M=message, C=SQLSTATE)."""
    fields = {}
    for part in payload.split(b"\x00"):
        if part:
            fields[chr(part[0])] = part[1:].decode("utf-8", "replace")
    return fields


def probe(host: str, port: int, timeout: float) -> PgProbe | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(startup_message(USER))
            result = PgProbe()
            for _ in range(64):
                kind, payload = read_message(sock)
                if kind == b"R":
                    (result.auth_code,) = struct.unpack("!I", payload[:4])
                    if not result.trusted:
                        return result  # it wants a password: stop here
                elif kind == b"S":  # ParameterStatus: name\0value\0
                    name, _, rest = payload.partition(b"\x00")
                    result.params[name.decode()] = rest.split(b"\x00", 1)[0].decode("utf-8", "replace")
                elif kind == b"E":
                    err = parse_error(payload)
                    result.error, result.error_code = err.get("M", ""), err.get("C", "")
                    return result
                elif kind == b"Z":  # ReadyForQuery: fully logged in
                    sock.sendall(b"X" + struct.pack("!I", 4))  # Terminate
                    return result
            return result
    except (OSError, ConnectionError, struct.error):
        return None


class PostgresModule(Module):
    name = "postgres"
    description = "PostgreSQL: auth method for user postgres (trust = no password), server version"

    def matches(self, svc: Service) -> bool:
        return svc.name.lower() in ("postgresql", "postgres") or (svc.port == 5432 and svc.name in ("", "unknown"))

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        ctx.log.info(f"{svc.label} postgres: checking how user '{USER}' must authenticate")
        p = probe(ctx.target, svc.port, ctx.options.http_timeout)
        if p is None:
            return [Finding(self.name, svc.port, "PostgreSQL did not answer the startup message", "info",
                            svc.banner)]
        cmd = f"psql -h {ctx.target} -p {svc.port} -U {USER}"
        if p.trusted:
            version = p.params.get("server_version", svc.version)
            ctx.log.ok(f"{svc.label} postgres: '{USER}' logs in WITHOUT a password")
            ctx.lead("postgres-trust", svc.port, f"Log in to PostgreSQL as {USER} - no password",
                     "pg_hba.conf trusts you, and postgres is the superuser: every database, the user table "
                     "(SELECT usename, passwd FROM pg_shadow) and server files via pg_read_file().", cmd)
            return [Finding(self.name, svc.port, f"PostgreSQL lets '{USER}' in without a password", "high",
                            f"Authentication method: trust. Server version {version}.")]
        if p.error:
            # 28000 = no pg_hba.conf entry for our address (or SSL off); other codes are rare here
            title = ("PostgreSQL refuses connections from your address" if p.error_code == "28000"
                     else "PostgreSQL refused the startup message")
            return [Finding(self.name, svc.port, title, "info", p.error)]
        ctx.lead("db-later", svc.port, "Keep PostgreSQL for when you have credentials",
                 f"It wants a password ({p.method}). Database passwords in web configs and .env files "
                 "very often work here.", f"psql -h {ctx.target} -p {svc.port} -U <user>")
        return [Finding(self.name, svc.port, f"PostgreSQL requires a password ({p.method})", "info",
                        svc.banner)]
