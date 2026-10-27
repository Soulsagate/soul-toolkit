import os
import pwd
import shutil
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon.modules import Context, Options
from soul_toolkit.recon.modules import postgres as pg


def make_ctx(tmp_path):
    return Context(target="127.0.0.1", outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult("127.0.0.1"), options=Options(http_timeout=3))


def msg(kind: bytes, payload: bytes) -> bytes:
    return kind + struct.pack("!I", len(payload) + 4) + payload


def auth(code: int, extra: bytes = b"") -> bytes:
    return msg(b"R", struct.pack("!I", code) + extra)


def param(name, value):
    return msg(b"S", name.encode() + b"\x00" + value.encode() + b"\x00")


# Real field layout of PostgreSQL 16's ErrorResponse for a missing pg_hba.conf entry
NO_HBA = msg(b"E", b"SFATAL\x00VFATAL\x00C28000\x00Mno pg_hba.conf entry for host \"10.8.0.2\", user \"postgres\", "
                   b"database \"postgres\", no encryption\x00Fauth.c\x00L542\x00RClientAuthentication\x00\x00")


def pg_server(replies: bytes):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            (length,) = struct.unpack("!I", self.request.recv(4))
            self.request.recv(length - 4)
            self.request.sendall(replies)
            try:
                self.request.recv(16)
            except OSError:
                pass

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def server():
    servers = []

    def start(replies):
        srv = pg_server(replies)
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


def test_startup_message():
    m = pg.startup_message("postgres")
    assert struct.unpack("!II", m[:8]) == (len(m), 196608)
    assert b"user\x00postgres\x00database\x00postgres\x00" in m and m.endswith(b"\x00\x00")


def test_trust(tmp_path, server):
    port = server(auth(0) + param("server_version", "16.15 (Ubuntu 16.15-0ubuntu0.24.04.1)")
                  + msg(b"K", b"\x00" * 8) + msg(b"Z", b"I"))
    ctx = make_ctx(tmp_path)
    [f] = pg.PostgresModule().run(ctx, Service(port, name="postgresql"))
    assert f.severity == "high" and "16.15 (Ubuntu" in f.detail
    [lead] = ctx.result.leads
    assert lead.kind == "postgres-trust" and lead.command == f"psql -h 127.0.0.1 -p {port} -U postgres"


@pytest.mark.parametrize("reply,method", [
    (auth(10, b"SCRAM-SHA-256\x00\x00"), "SCRAM-SHA-256 password"),
    (auth(5, b"salt"), "md5 password"),
])
def test_password_required(tmp_path, server, reply, method):
    port = server(reply)
    ctx = make_ctx(tmp_path)
    [f] = pg.PostgresModule().run(ctx, Service(port, name="postgresql"))
    assert f.title == f"PostgreSQL requires a password ({method})" and ctx.result.leads[0].kind == "db-later"


def test_no_hba_entry(tmp_path, server):
    port = server(NO_HBA)
    [f] = pg.PostgresModule().run(make_ctx(tmp_path), Service(port, name="postgresql"))
    assert f.title == "PostgreSQL refuses connections from your address"
    assert f.detail.startswith("no pg_hba.conf entry for host")


def test_unreachable(tmp_path):
    [f] = pg.PostgresModule().run(make_ctx(tmp_path), Service(9, name="postgresql"))
    assert f.title == "PostgreSQL did not answer the startup message"


# ----------------------------------------------------------------- real PostgreSQL (skipped when missing)

PG_BIN = next(iter(sorted(Path("/usr/lib/postgresql").glob("*/bin"), reverse=True)), None) \
    if Path("/usr/lib/postgresql").is_dir() else None
_initdb = shutil.which("initdb") or (str(PG_BIN / "initdb") if PG_BIN else None)


def _as_postgres(cmd):
    # PostgreSQL refuses to run as root; drop to the postgres user when we are root.
    if os.geteuid() == 0:
        return ["runuser", "-u", "postgres", "--", *cmd]
    return cmd


def _have_real_postgres():
    if not _initdb or not Path(_initdb).exists():
        return False
    if os.geteuid() == 0:
        try:
            pwd.getpwnam("postgres")
        except KeyError:
            return False
        return bool(shutil.which("runuser"))
    return True


@pytest.mark.skipif(not _have_real_postgres(), reason="needs a local PostgreSQL install")
def test_real_postgres_trust_then_scram():
    bindir = Path(_initdb).parent
    base = Path(tempfile.mkdtemp(prefix="soul-pg-"))
    if os.geteuid() == 0:
        shutil.chown(base, "postgres")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    data = base / "data"
    ctl = [str(bindir / "pg_ctl"), "-D", str(data)]
    try:
        subprocess.run(_as_postgres([_initdb, "-D", str(data), "-A", "trust", "-U", "postgres"]),
                       check=True, capture_output=True)
        subprocess.run(_as_postgres([*ctl, "-o", f"-p {port} -k {base} -c listen_addresses=127.0.0.1",
                                     "-l", str(base / "log"), "-w", "start"]), check=True, capture_output=True)
        p = pg.probe("127.0.0.1", port, 5)
        assert p.trusted and p.params["server_version"]
        hba = data / "pg_hba.conf"
        hba.write_text(hba.read_text().replace("trust", "scram-sha-256"))
        subprocess.run(_as_postgres([*ctl, "reload"]), check=True, capture_output=True)
        time.sleep(1)
        p = pg.probe("127.0.0.1", port, 5)
        assert p.method == "SCRAM-SHA-256 password"
    finally:
        subprocess.run(_as_postgres([*ctl, "-m", "immediate", "stop"]), capture_output=True)
        shutil.rmtree(base, ignore_errors=True)
