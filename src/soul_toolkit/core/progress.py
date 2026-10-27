"""Live progress: redraw a status line (with elapsed time) once a second while work runs."""

from __future__ import annotations

import threading
import time
from typing import Callable

from soul_toolkit.core.log import Logger


def fmt_elapsed(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


class LiveStatus:
    """`with LiveStatus(log, render):` keeps `render()` on the status line, refreshed every
    *interval* seconds, and removes it on exit. Does nothing when the logger isn't live (not a TTY)."""

    def __init__(self, log: Logger, render: Callable[[], str], interval: float = 1.0):
        self.log, self.render, self.interval = log, render, interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.log.status(self.render())
            self._stop.wait(self.interval)

    def __enter__(self) -> LiveStatus:
        if self.log.live:
            self._thread = threading.Thread(target=self._loop, name="live-status", daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(2)
        self.log.status(None)


class Stopwatch:
    def __init__(self) -> None:
        self.start = time.monotonic()

    @property
    def elapsed(self) -> str:
        return fmt_elapsed(time.monotonic() - self.start)
