"""Integration test: run recon against the deliberately vulnerable lab in tests/lab/.

Needs Docker (with a running daemon) and nmap. Skipped otherwise, or when SOUL_SKIP_LAB=1;
SOUL_REQUIRE_LAB=1 turns those skips into failures (CI's lab job uses it). Set SOUL_LAB_KEEP=1
to leave the lab running afterwards. Checks that need an optional tool (gobuster, ffuf,
smbclient, showmount) only run when that tool is installed.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from soul_toolkit.core.log import Logger
from soul_toolkit.recon import engine
from soul_toolkit.recon.modules import Options, select_modules

LAB = Path(__file__).parent / "lab"
COMPOSE = ["docker", "compose", "-f", str(LAB / "docker-compose.yml")]
TARGET = "172.29.99.10"
PORTS = (21, 80, 8080, 445, 2049)


def _skip_or_fail(reason: str) -> None:
    if os.environ.get("SOUL_REQUIRE_LAB") == "1":
        pytest.fail(f"lab required but unavailable: {reason}")
    pytest.skip(reason)


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0


def _wait_for_ports(deadline: float) -> list[int]:
    missing = list(PORTS)
    while missing and time.monotonic() < deadline:
        for port in list(missing):
            try:
                socket.create_connection((TARGET, port), timeout=1).close()
                missing.remove(port)
            except OSError:
                pass
        if missing:
            time.sleep(1)
    return missing


@pytest.fixture(scope="module")
def lab():
    if os.environ.get("SOUL_SKIP_LAB") == "1":
        pytest.skip("SOUL_SKIP_LAB=1")
    if not shutil.which("nmap"):
        _skip_or_fail("nmap not installed")
    if not _docker_ok():
        _skip_or_fail("Docker not available (no docker CLI or daemon)")
    up = subprocess.run([*COMPOSE, "up", "-d", "--build"], capture_output=True, text=True, timeout=1200)
    if up.returncode != 0:
        pytest.fail(f"docker compose up failed:\n{up.stderr[-2000:]}")
    try:
        missing = _wait_for_ports(time.monotonic() + 120)
        if missing:
            logs = subprocess.run([*COMPOSE, "logs", "--tail", "30"], capture_output=True, text=True).stdout
            pytest.fail(f"lab ports never opened: {missing}\n{logs[-3000:]}")
        yield TARGET
    finally:
        if os.environ.get("SOUL_LAB_KEEP") != "1":
            subprocess.run([*COMPOSE, "down", "-v"], capture_output=True, timeout=300)


@pytest.fixture(scope="module")
def result(lab, tmp_path_factory):
    out = tmp_path_factory.mktemp("lab-results")
    cfg = engine.ReconConfig(
        target=lab, output=out, full=False, udp=False, modules=select_modules(None), writeup=True,
        room="Soul Lab", jobs=4, options=Options(brute_timeout=300),
    )
    r = engine.run_recon(cfg, Logger(quiet=True))
    return r, out / lab


def titles(r) -> set[str]:
    return {f.title for f in r.findings}


def test_services_found(result):
    r, _ = result
    open_tcp = {s.port for s in r.services if s.protocol == "tcp"}
    assert set(PORTS) <= open_tcp
    names = {s.port: s.name for s in r.services}
    assert names[21] == "ftp" and names[80] == "http" and names[2049] == "nfs"


def test_anonymous_ftp(result):
    r, _ = result
    ftp = next(f for f in r.findings if f.title == "Anonymous FTP login allowed")
    assert ftp.severity == "high" and any("note.txt" in line for line in ftp.data["listing"])
    assert any(x.kind == "ftp-anon" for x in r.leads)


def test_web_redirect_git_and_robots(result):
    r, _ = result
    assert "Redirects to virtual host 'lab.thm'" in titles(r)
    git = next(f for f in r.findings if f.title == "Exposed .git repository")
    assert git.port == 8080 and git.severity == "high"
    robots = next(f for f in r.findings if f.title == "robots.txt lists paths")
    assert "Disallow: /admin/" in robots.data["entries"]


@pytest.mark.skipif(not shutil.which("gobuster"), reason="gobuster not installed")
def test_content_discovery(result):
    r, _ = result
    paths = {h["path"] for f in r.findings if f.port == 8080 and "paths" in f.data for h in f.data["paths"]}
    assert {"/admin", "/backup"} <= paths
    assert "/admin/index.html" in paths  # one level of recursion


@pytest.mark.skipif(not (shutil.which("ffuf") or shutil.which("gobuster")), reason="ffuf/gobuster not installed")
def test_vhost_fuzzing_finds_dev(result):
    r, _ = result
    vh = next(f for f in r.findings if f.title.startswith("Virtual hosts found"))
    assert [v["host"] for v in vh.data["vhosts"]] == ["dev.lab.thm"]
    assert vh.data["hosts_line"] == f"{TARGET} lab.thm dev.lab.thm"


@pytest.mark.skipif(not shutil.which("smbclient"), reason="smbclient not installed")
def test_null_session_smb(result):
    r, _ = result
    smb = next(f for f in r.findings if f.title == "Null session can list SMB shares")
    access = {s["name"]: s.get("access") for s in smb.data["shares"]}
    assert access["public"] == "READ"  # the guest share, checked with a read-only `ls`
    assert access["IPC$"] is None      # IPC$ is never checked
    lead = next(x for x in r.leads if x.command == f"smbclient //{TARGET}/public -N")
    assert lead.kind == "smb-readable"


@pytest.mark.skipif(not shutil.which("showmount"), reason="showmount not installed")
def test_world_readable_nfs(result):
    r, _ = result
    nfs = next(f for f in r.findings if f.title == "NFS exports anyone can mount")
    assert nfs.data["exports"] == [{"path": "/srv/nfs", "clients": ["*"]}]


def test_where_to_start_and_reports(result):
    r, out = result
    top = [x.kind for x in r.leads[:5]]
    assert "web-git" in top and "ftp-anon" in top
    md = (out / "report.md").read_text()
    assert md.index("## Where to start") < md.index("## Open ports")
    if shutil.which("smbclient"):
        assert "| `public` | Disk | READ | Public files |" in md
    assert (out / "report.html").read_text().startswith("<!doctype html>")
    assert json.loads((out / "findings.json").read_text())["target"] == TARGET
    assert 'room: "Soul Lab"' in (out / "writeup.md").read_text()
