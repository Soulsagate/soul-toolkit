import os
import shutil
import socket
import socketserver
import subprocess
import threading
import time

import pytest

from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon.modules import Context, Options, mysql


def make_ctx(tmp_path):
    return Context(target="127.0.0.1", outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult("127.0.0.1"), options=Options(http_timeout=3))


def greeting(version="5.5.5-10.11.14-MariaDB-0ubuntu0.24.04.1", plugin="mysql_native_password"):
    """A protocol-10 server greeting laid out like MariaDB 10.11's."""
    salt = b"12345678"
    return (b"\x0a" + version.encode() + b"\x00" + (7).to_bytes(4, "little") + salt + b"\x00"
            + (0xF7FE).to_bytes(2, "little") + b"\x2d" + (2).to_bytes(2, "little") + (0x81FF).to_bytes(2, "little")
            + bytes([21]) + b"\x00" * 10 + b"123456789012\x00" + plugin.encode() + b"\x00")


OK = b"\x00\x00\x00\x02\x00\x00\x00"


def err(msg, code=1045):
    return b"\xff" + code.to_bytes(2, "little") + b"#28000" + msg.encode()


def mysql_server(answers, first=None):
    """*answers* maps a username to a list of reply payloads (after the login packet)."""

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            s = self.request
            mysql.write_packet(s, 0, first or greeting())
            if first and first[:1] == b"\xff":
                return
            seq, payload = mysql.read_packet(s)
            user = payload[32:payload.index(b"\x00", 32)].decode()
            for reply in answers.get(user, [err(f"Access denied for user '{user}'@'localhost' (using password: NO)")]):
                seq += 1
                mysql.write_packet(s, seq, reply)
                if reply[:1] == b"\xfe":
                    seq, _ = mysql.read_packet(s)

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def server():
    servers = []

    def start(answers, first=None):
        srv = mysql_server(answers, first)
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


def test_parse_greeting():
    g = mysql.parse_greeting(greeting())
    assert g.version == "10.11.14-MariaDB-0ubuntu0.24.04.1" and g.plugin == "mysql_native_password"
    g8 = mysql.parse_greeting(greeting("8.0.36", "caching_sha2_password"))
    assert g8.version == "8.0.36" and g8.plugin == "caching_sha2_password"
    refused = mysql.parse_greeting(b"\xff\x6a\x04Host '10.8.0.2' is not allowed to connect to this MariaDB server")
    assert refused.error == "Host '10.8.0.2' is not allowed to connect to this MariaDB server"


def test_login_packet_has_empty_auth():
    p = mysql.login_packet("root", "mysql_native_password")
    assert p[32:37] == b"root\x00" and p[37] == 0 and p.endswith(b"mysql_native_password\x00")


def test_root_empty_password(tmp_path, server):
    port = server({"root": [OK]})
    ctx = make_ctx(tmp_path)
    findings = mysql.MysqlModule().run(ctx, Service(port, name="mysql"))
    assert [f.title for f in findings] == ["MySQL server 10.11.14-MariaDB-0ubuntu0.24.04.1",
                                           "MySQL root account has an empty password"]
    [lead] = ctx.result.leads
    assert lead.kind == "mysql-empty" and lead.command == f"mysql -h 127.0.0.1 -P {port} -u root"


def test_anonymous_only(tmp_path, server):
    port = server({"": [OK]})
    ctx = make_ctx(tmp_path)
    findings = mysql.MysqlModule().run(ctx, Service(port, name="mysql"))
    assert findings[-1].severity == "medium" and ctx.result.leads[0].kind == "mysql-anon"


def test_password_required(tmp_path, server):
    port = server({})
    ctx = make_ctx(tmp_path)
    [f] = mysql.MysqlModule().run(ctx, Service(port, name="mysql"))
    assert f.severity == "info" and ctx.result.leads[0].kind == "db-later"


def test_auth_switch_and_caching_sha2(tmp_path, server):
    switch = b"\xfemysql_native_password\x00" + b"x" * 20 + b"\x00"
    port = server({"root": [switch, OK]})
    assert mysql.check("127.0.0.1", port, 3).empty == ["root"]
    port = server({"root": [b"\x01\x03", OK]}, first=greeting("8.0.36", "caching_sha2_password"))
    assert mysql.check("127.0.0.1", port, 3).empty == ["root"]
    port = server({"root": [b"\x01\x04"]}, first=greeting("8.0.36", "caching_sha2_password"))
    res = mysql.check("127.0.0.1", port, 3)
    assert res.empty == [] and res.errors["root"] == "password required"


def test_host_not_allowed(tmp_path, server):
    port = server({}, first=b"\xff\x6a\x04Host '10.8.0.2' is not allowed to connect to this MySQL server")
    [f] = mysql.MysqlModule().run(make_ctx(tmp_path), Service(port, name="mysql"))
    assert f.title == "MySQL refuses connections from your address" and "not allowed" in f.detail


def test_unreachable(tmp_path):
    [f] = mysql.MysqlModule().run(make_ctx(tmp_path), Service(9, name="mysql"))
    assert f.title == "MySQL did not complete a handshake"


# ----------------------------------------------------------------- real MariaDB (skipped when missing)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(not (shutil.which("mariadb-install-db") and (shutil.which("mariadbd") or
                                                                  os.path.exists("/usr/sbin/mariadbd"))),
                    reason="needs a local MariaDB server install")
def test_real_mariadb_empty_root(tmp_path):
    data, port = tmp_path / "data", _free_port()
    user = ["--user=root"] if os.geteuid() == 0 else []
    subprocess.run(["mariadb-install-db", *user, f"--datadir={data}", "--auth-root-authentication-method=normal"],
                   check=True, capture_output=True)
    daemon = shutil.which("mariadbd") or "/usr/sbin/mariadbd"
    proc = subprocess.Popen([daemon, "--no-defaults", *user, f"--datadir={data}", f"--port={port}",
                             "--bind-address=127.0.0.1", f"--socket={tmp_path / 'sock'}",
                             f"--pid-file={tmp_path / 'pid'}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        res = mysql.check("127.0.0.1", port, 5)
        assert "MariaDB" in res.greeting.version and "root" in res.empty
    finally:
        proc.terminate()
        proc.wait(20)
