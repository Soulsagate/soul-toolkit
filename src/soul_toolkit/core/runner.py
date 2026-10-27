"""Run external tools (nmap, gobuster, ...) safely and consistently.

Commands are always passed as argument lists, never through a shell, so target
strings can't be used for command injection.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass

# Child processes currently running, so an interrupt can stop them all (module threads included).
_active: set[subprocess.Popen] = set()
_lock = threading.Lock()
_stopping = threading.Event()


class ToolMissing(RuntimeError):
    """Raised when a required external binary is not on PATH."""


def which(tool: str) -> str | None:
    return shutil.which(tool)


def require(tool: str, hint: str = "") -> str:
    path = shutil.which(tool)
    if not path:
        msg = f"'{tool}' not found on PATH."
        if hint:
            msg += f" {hint}"
        raise ToolMissing(msg)
    return path


@dataclass
class CommandResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def pretty(self) -> str:
        return shlex.join(self.cmd)


def _to_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def run(cmd: list[str], timeout: float | None = None) -> CommandResult:
    """Run *cmd* and capture its output. Never raises on non-zero exit.

    After stop_all() it starts nothing and returns a failed result straight away."""
    start = time.monotonic()
    if _stopping.is_set():
        return CommandResult(cmd, -1, "", "not started: run interrupted", 0.0)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    with _lock:
        _active.add(proc)
    try:
        out, err = proc.communicate(timeout=timeout)
        return CommandResult(cmd, proc.returncode, out, err, time.monotonic() - start)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return CommandResult(cmd, -1, _to_text(out), _to_text(err), time.monotonic() - start, timed_out=True)
    except BaseException:  # Ctrl-C in the calling thread: don't leave the child behind
        proc.kill()
        proc.wait()
        raise
    finally:
        with _lock:
            _active.discard(proc)


def stop_all() -> None:
    """Terminate every running child process and refuse to start new ones (used on Ctrl-C)."""
    _stopping.set()
    with _lock:
        procs = list(_active)
    for p in procs:
        try:
            p.terminate()
        except OSError:
            pass


def reset() -> None:
    """Allow commands again after stop_all() (tests, or a second run in one process)."""
    _stopping.clear()
