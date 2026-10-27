import io
import sys
import threading
import time
from pathlib import Path

import pytest

from soul_toolkit import cli
from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import Finding
from soul_toolkit.core.progress import LiveStatus, fmt_elapsed
from soul_toolkit.recon import engine
from soul_toolkit.recon.modules import Module

TCP_XML = (Path(__file__).parent / "fixtures" / "services.xml").read_text()  # 6 TCP services


@pytest.fixture(autouse=True)
def fake_nmap(monkeypatch):
    real_run = runner.run

    def run(cmd, timeout=None):
        if cmd[0] == "nmap":
            return runner.CommandResult(cmd, 0, TCP_XML, "", 0.1)
        return real_run(cmd, timeout)

    monkeypatch.setattr(runner, "require", lambda *a, **k: "/usr/bin/nmap")
    monkeypatch.setattr(runner, "run", run)
    monkeypatch.setattr(engine, "is_root", lambda: False)
    yield
    runner.reset()


class Sleepy(Module):
    """Takes longer on lower ports, so completion order is the reverse of task order."""
    name = "sleepy"

    def __init__(self):
        self.active = 0
        self.peak = 0
        self.lock = threading.Lock()

    def matches(self, svc):
        return True

    def run(self, ctx, svc):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
        time.sleep(0.6 - svc.port / 20000)
        with self.lock:
            self.active -= 1
        ctx.lead("ssh-later", svc.port, f"lead {svc.port}", "why")
        ctx.hint("shared hint")
        return [Finding(self.name, svc.port, f"finding {svc.port}", "info")]


def config(tmp_path, mod, jobs=4):
    return engine.ReconConfig(target="10.10.10.10", output=tmp_path, ports=[21], modules=[mod], jobs=jobs, udp=False)


def test_fmt_elapsed():
    assert fmt_elapsed(5) == "0:05" and fmt_elapsed(125) == "2:05" and fmt_elapsed(3725) == "1:02:05"


def test_runner_stop_all_kills_children_and_blocks_new_ones():
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", runner.run([sys.executable, "-c",
                                                                       "import time; time.sleep(30)"])))
    t.start()
    time.sleep(0.5)
    started = time.monotonic()
    runner.stop_all()
    t.join(10)
    assert time.monotonic() - started < 5 and out["r"].returncode != 0
    blocked = runner.run(["true"])
    assert blocked.returncode == -1 and "interrupted" in blocked.stderr
    runner.reset()
    assert runner.run(["true"]).ok


def test_logger_status_line_is_redrawn_around_log_lines(monkeypatch):
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    log = Logger(colour=False, live=True)
    log.status("[1/3] running")
    log.info("hello")
    log.status(None)
    text = err.getvalue()
    assert text.startswith("[1/3] running\r\x1b[K[*] hello\n[1/3] running\r\x1b[K")


def test_live_status_does_nothing_off_tty(monkeypatch):
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    with LiveStatus(Logger(colour=False, live=False), lambda: "status"):
        time.sleep(0.05)
    assert err.getvalue() == ""


def test_parallel_results_are_in_task_order(tmp_path):
    mod = Sleepy()
    started = time.monotonic()
    result = engine.run_recon(config(tmp_path, mod, jobs=6), Logger(quiet=True))
    assert time.monotonic() - started < 2.5  # 6 x ~0.6s, in parallel
    assert mod.peak > 1
    ports = [21, 22, 80, 139, 445, 8443]
    assert [f.title for f in result.findings] == [f"finding {p}" for p in ports]
    assert [x.title for x in result.leads if x.kind == "ssh-later"] == [f"lead {p}" for p in ports]
    assert result.hints == ["shared hint"] and not result.interrupted


def test_jobs_limits_concurrency(tmp_path):
    mod = Sleepy()
    engine.run_recon(config(tmp_path, mod, jobs=2), Logger(quiet=True))
    assert mod.peak == 2


def test_ctrl_c_during_modules_writes_partial_report(tmp_path, monkeypatch):
    real_wait = engine.wait
    calls = {"n": 0}

    def wait_then_interrupt(pending, timeout=None, return_when=None):
        calls["n"] += 1
        if calls["n"] > 1 and len(pending) < 6:  # after the first module finished
            raise KeyboardInterrupt
        return real_wait(pending, timeout=timeout, return_when=return_when)

    monkeypatch.setattr(engine, "wait", wait_then_interrupt)
    mod = Sleepy()
    with pytest.raises(KeyboardInterrupt):
        engine.run_recon(config(tmp_path, mod, jobs=1), Logger(quiet=True))
    md = (tmp_path / "10.10.10.10" / "report.md").read_text()
    assert "Partial report" in md and "module runs:" in md
    assert "finding 21" in md and "| 8443/tcp |" in md  # finished work + the scan itself are kept
    assert "finding 8443" not in md


def test_ctrl_c_during_nmap_writes_partial_report(tmp_path, monkeypatch):
    def run(cmd, timeout=None):
        raise KeyboardInterrupt

    monkeypatch.setattr(runner, "run", run)
    cfg = engine.ReconConfig(target="10.10.10.10", output=tmp_path, modules=[], udp=False)
    with pytest.raises(KeyboardInterrupt):
        engine.run_recon(cfg, Logger(quiet=True))
    md = (tmp_path / "10.10.10.10" / "report.md").read_text()
    assert "Not finished: TCP port sweep; TCP service scan; service modules" in md
    html = (tmp_path / "10.10.10.10" / "report.html").read_text()
    assert 'class="partial"' in html


def test_cli_ctrl_c_returns_130(monkeypatch):
    def boom(cfg, log):
        raise KeyboardInterrupt

    monkeypatch.setattr(engine, "run_recon", boom)
    assert cli.main(["recon", "10.10.10.10", "-q"]) == 130


def test_cli_jobs(monkeypatch):
    seen = []
    monkeypatch.setattr(engine, "run_recon", lambda cfg, log: seen.append(cfg.jobs))
    cli.main(["recon", "10.10.10.10", "-q", "-j", "8"])
    cli.main(["recon", "10.10.10.10", "-q", "--jobs", "0"])
    cli.main(["recon", "10.10.10.10", "-q"])
    assert seen == [8, 1, 4]


def test_logger_can_silence_worker_threads(monkeypatch):
    err = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err)
    log = Logger(colour=False, live=False)
    log.main_thread_only = True
    t = threading.Thread(target=lambda: log.warn("from a worker"))
    t.start()
    t.join()
    log.warn("from main")
    assert err.getvalue() == "[!] from main\n"
