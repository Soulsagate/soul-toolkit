"""Run external tools (nmap, gobuster, ...) safely and consistently.

Commands are always passed as argument lists, never through a shell, so target
strings can't be used for command injection.
"""

from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass


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
    """Run *cmd* and capture its output. Never raises on non-zero exit."""
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return CommandResult(cmd, proc.returncode, proc.stdout, proc.stderr, time.monotonic() - start)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            cmd, -1, _to_text(exc.stdout), _to_text(exc.stderr), time.monotonic() - start, timed_out=True
        )
