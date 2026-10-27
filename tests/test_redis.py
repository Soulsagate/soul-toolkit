import shutil
import socket
import socketserver
import subprocess
import threading
import time

import pytest

from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon.modules import Context, Options, redis

# INFO text in Redis 7.0's layout (trimmed)
INFO = ("# Server\r\nredis_version:7.0.15\r\nredis_mode:standalone\r\nos:Linux 6.8.0 x86_64\r\n"
        "executable:/usr/bin/redis-server\r\nconfig_file:/etc/redis/redis.conf\r\n\r\n# Clients\r\n"
        "connected_clients:1\r\n\r\n# Memory\r\nused_memory_human:919.92K\r\n\r\n# Replication\r\nrole:master\r\n"
        "\r\n# Keyspace\r\ndb0:keys=3,expires=0,avg_ttl=0\r\ndb2:keys=4,expires=1,avg_ttl=0\r\n")
NOAUTH = "-NOAUTH Authentication required.\r\n"
# Real protected-mode reply from Redis 7.0 (first two sentences)
DENIED = ("-DENIED Redis is running in protected mode because protected mode is enabled and no password is set "
          "for the default user. In this mode connections are only accepted from the loopback interface.\r\n")


def make_ctx(tmp_path):
    return Context(target="127.0.0.1", outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult("127.0.0.1"), options=Options(http_timeout=3))


@pytest.fixture
def server():
    servers = []

    def start(reply: str):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(64)
                self.request.sendall(reply.encode())

        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


def bulk(text: str) -> str:
    return f"${len(text.encode())}\r\n{text}\r\n"


def test_parse_info():
    info, keyspace = redis.parse_info(INFO)
    assert info["redis_version"] == "7.0.15" and info["role"] == "master"
    assert keyspace == {"db0": "keys=3,expires=0,avg_ttl=0", "db2": "keys=4,expires=1,avg_ttl=0"}
    assert redis.RedisReply(info=info, keyspace=keyspace).keys == 7


def test_unauthenticated(tmp_path, server):
    port = server(bulk(INFO))
    ctx = make_ctx(tmp_path)
    [f] = redis.RedisModule().run(ctx, Service(port, name="redis"))
    assert f.severity == "high" and f.detail == "Redis 7.0.15, role master, 7 key(s)"
    rows = dict(f.data["table"]["rows"])
    assert rows["config_file"] == "/etc/redis/redis.conf" and rows["db2"].startswith("keys=4")
    [lead] = ctx.result.leads
    assert lead.kind == "redis-unauth" and lead.command == f"redis-cli -h 127.0.0.1 -p {port}"


@pytest.mark.parametrize("reply,title,detail", [
    (NOAUTH, "Redis requires a password", "NOAUTH Authentication required."),
    (DENIED, "Redis is in protected mode (refuses remote clients)",
     "DENIED Redis is running in protected mode because protected mode is enabled and no password is set "
     "for the default user."),
])
def test_refusals(tmp_path, server, reply, title, detail):
    ctx = make_ctx(tmp_path)
    [f] = redis.RedisModule().run(ctx, Service(server(reply), name="redis"))
    assert (f.title, f.severity, f.detail) == (title, "info", detail) and not ctx.result.leads


def test_not_redis(tmp_path, server):
    [f] = redis.RedisModule().run(make_ctx(tmp_path), Service(server("HTTP/1.1 400 Bad Request\r\n\r\n"),
                                                                  name="redis"))
    assert f.title == "Redis did not answer INFO"


@pytest.mark.skipif(not shutil.which("redis-server"), reason="redis-server not installed")
def test_real_redis(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen(["redis-server", "--port", str(port), "--bind", "127.0.0.1", "--protected-mode", "no",
                             "--save", "", "--dir", str(tmp_path)], stdout=subprocess.DEVNULL)
    try:
        for _ in range(50):
            r = redis.query_info("127.0.0.1", port, 2)
            if r and r.open:
                break
            time.sleep(0.1)
        assert r.open and r.info["redis_version"] and r.info["role"] == "master"
    finally:
        proc.terminate()
        proc.wait(10)
