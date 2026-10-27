"""MySQL / MariaDB follow-ups: version from the server greeting, and an empty-password check
for `root` and the anonymous account (the same two accounts nmap's mysql-empty-password tries).

This speaks just enough of the MySQL wire protocol for one login with an empty password per
account - no queries are run. nmap's script isn't used because it crashes (nselib mysql.lua
"unfinished string for format 'z'") against current MariaDB whenever the anonymous account
doesn't exist, which is the common case, and then reports nothing for root either.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

ACCOUNTS = ("root", "")  # "" = anonymous

# Client capability flags for the login packet.
CLIENT_LONG_PASSWORD = 0x1
CLIENT_PROTOCOL_41 = 0x200
CLIENT_SECURE_CONNECTION = 0x8000
CLIENT_PLUGIN_AUTH = 0x80000
CAPS = CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH


class ProtocolError(Exception):
    pass


@dataclass
class Greeting:
    version: str = ""
    plugin: str = "mysql_native_password"
    error: str = ""  # set when the server refuses us before login ("Host ... is not allowed to connect")


@dataclass
class MysqlResult:
    greeting: Greeting
    empty: list[str] = field(default_factory=list)  # accounts that logged in with an empty password
    errors: dict[str, str] = field(default_factory=dict)  # account -> server's refusal message


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError("connection closed")
        buf += chunk
    return buf


def read_packet(sock: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(sock, 4)
    length = int.from_bytes(header[:3], "little")
    return header[3], _recv_exact(sock, length)


def write_packet(sock: socket.socket, seq: int, payload: bytes) -> None:
    sock.sendall(len(payload).to_bytes(3, "little") + bytes([seq & 0xFF]) + payload)


def _error_message(payload: bytes) -> str:
    """ERR packet: 0xff, code (2), optional '#'+sqlstate (5), message."""
    msg = payload[3:]
    if msg[:1] == b"#":
        msg = msg[6:]
    return msg.decode("utf-8", "replace").strip()


def parse_greeting(payload: bytes) -> Greeting:
    if payload[:1] == b"\xff":
        return Greeting(error=_error_message(payload))
    if payload[:1] != b"\x0a":
        raise ProtocolError(f"unexpected greeting (protocol byte {payload[:1].hex() or 'none'})")
    end = payload.index(b"\x00", 1)
    version = payload[1:end].decode("utf-8", "replace")
    if version.startswith("5.5.5-"):  # MariaDB's compatibility prefix
        version = version[6:]
    g = Greeting(version=version)
    # skip thread id (4) + salt part 1 (8) + filler (1) + caps (2) + charset (1) + status (2) + caps (2)
    pos = end + 1 + 4 + 8 + 1 + 2 + 1 + 2 + 2
    if len(payload) > pos:
        salt_len = payload[pos]
        pos += 1 + 10 + max(13, salt_len - 8)
        name_end = payload.find(b"\x00", pos)
        name = payload[pos:name_end if name_end != -1 else None].decode("ascii", "replace")
        if name:
            g.plugin = name
    return g


def login_packet(user: str, plugin: str) -> bytes:
    return (struct.pack("<IIB", CAPS, 1 << 24, 0x21) + b"\x00" * 23 + user.encode() + b"\x00"
            + b"\x00"  # auth response length 0: empty password
            + plugin.encode() + b"\x00")


def try_empty_password(host: str, port: int, user: str, timeout: float) -> tuple[Greeting, bool, str]:
    """Log in as *user* with an empty password. Returns (greeting, success, server message)."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        seq, payload = read_packet(sock)
        greeting = parse_greeting(payload)
        if greeting.error:
            return greeting, False, greeting.error
        write_packet(sock, seq + 1, login_packet(user, greeting.plugin))
        for _ in range(4):  # OK / ERR, possibly after an auth switch or caching_sha2 status byte
            seq, payload = read_packet(sock)
            kind = payload[:1]
            if kind == b"\x00":
                return greeting, True, ""
            if kind == b"\xff":
                return greeting, False, _error_message(payload)
            if kind == b"\xfe":
                # Auth switch: for mysql_native_password / caching_sha2_password an empty password is
                # still an empty response. Plugins that sign even an empty password (MariaDB ed25519)
                # will refuse it - such rare accounts show up as "refused", never as a false "empty".
                write_packet(sock, seq + 1, b"")
            elif kind == b"\x01" and payload[1:2] == b"\x03":  # caching_sha2 "fast auth ok", OK follows
                continue
            else:  # 0x01 0x04 = full auth needed: there is a password
                return greeting, False, "password required"
        return greeting, False, "no final answer from server"


def check(host: str, port: int, timeout: float) -> MysqlResult | None:
    result = None
    for user in ACCOUNTS:
        try:
            greeting, ok, msg = try_empty_password(host, port, user, timeout)
        except (OSError, ProtocolError, ValueError, IndexError):
            continue
        result = result or MysqlResult(greeting)
        if greeting.error:
            break  # refused before login: same answer for every account
        if ok:
            result.empty.append(user or "anonymous")
        else:
            result.errors[user or "anonymous"] = msg
    return result


class MysqlModule(Module):
    name = "mysql"
    description = "MySQL/MariaDB: version from the greeting, empty-password check for root/anonymous"

    def matches(self, svc: Service) -> bool:
        return svc.name.lower() == "mysql" or (svc.port == 3306 and svc.name.lower() in ("", "unknown"))

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        ctx.log.info(f"{svc.label} mysql: greeting + empty-password check (root, anonymous)")
        res = check(ctx.target, svc.port, ctx.options.http_timeout)
        if res is None:
            return [Finding(self.name, svc.port, "MySQL did not complete a handshake", "info", svc.banner)]
        g = res.greeting
        if g.error:
            return [Finding(self.name, svc.port, "MySQL refuses connections from your address", "info", g.error)]

        version = g.version or svc.banner
        findings = [Finding(self.name, svc.port, f"MySQL server {version}", "info",
                            f"auth plugin: {g.plugin}")]
        cmd = f"mysql -h {ctx.target} -P {svc.port}"
        if "root" in res.empty:
            ctx.log.ok(f"{svc.label} mysql: root has an EMPTY password")
            findings.append(Finding(self.name, svc.port, "MySQL root account has an empty password", "high",
                                    f"Logged in as root with an empty password ({version})."))
            ctx.lead("mysql-empty", svc.port, "Log in to MySQL as root - no password",
                     "Full database access: look for application users and password hashes, and check "
                     "FILE privilege / secure_file_priv (reading files from the server).",
                     f"{cmd} -u root")
        elif "anonymous" in res.empty:
            findings.append(Finding(self.name, svc.port, "MySQL anonymous account has an empty password", "medium",
                                    "Any username with an empty password is accepted."))
            ctx.lead("mysql-anon", svc.port, "Log in to MySQL anonymously",
                     "The anonymous account is usually low-privileged, but list the databases it can see.",
                     f"{cmd} -u anonymous")
        else:
            ctx.lead("db-later", svc.port, "Keep MySQL for when you have credentials",
                     "Empty passwords are refused. Passwords found in web configs (config.php, .env, "
                     "wp-config.php) very often work here.", f"{cmd} -u <user> -p")
        return findings
