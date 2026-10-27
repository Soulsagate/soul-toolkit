"""Tiny console logger with optional colour. No third-party dependencies."""

from __future__ import annotations

import os
import shutil
import sys
import threading

_RESET = "\033[0m"
_COLOURS = {
    "info": "\033[36m",   # cyan
    "ok": "\033[32m",     # green
    "warn": "\033[33m",   # yellow
    "err": "\033[31m",    # red
    "step": "\033[35m",   # magenta
    "dim": "\033[2m",
}
_TAGS = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]", "step": "[>]", "dim": "   "}


def _use_colour() -> bool:
    return sys.stderr.isatty() and "NO_COLOR" not in os.environ


class Logger:
    """Thread-safe. On a terminal it can also show one live status line at the bottom
    (progress, elapsed time) that normal log lines are printed above."""

    def __init__(self, verbose: bool = False, quiet: bool = False, colour: bool | None = None,
                 live: bool | None = None):
        self.verbose = verbose
        self.quiet = quiet
        self.colour = _use_colour() if colour is None else colour
        self.live = (sys.stderr.isatty() and not quiet) if live is None else live
        self._lock = threading.RLock()
        self._status = ""
        self.main_thread_only = False  # set after Ctrl-C: module threads winding down stay quiet

    def _clear_status(self) -> None:
        if self._status:
            sys.stderr.write("\r\033[K")

    def _draw_status(self) -> None:
        if self._status:
            width = shutil.get_terminal_size((100, 20)).columns - 1
            text = self._status if len(self._status) <= width else self._status[: width - 3] + "..."
            sys.stderr.write(f"\033[2m{text}\033[0m" if self.colour else text)
            sys.stderr.flush()

    def status(self, text: str | None) -> None:
        """Show (or with None, remove) the live status line. No-op unless live."""
        if not self.live:
            return
        with self._lock:
            self._clear_status()
            self._status = text or ""
            self._draw_status()
            if not self._status:
                sys.stderr.flush()

    def _print(self, line: str) -> None:
        if self.main_thread_only and threading.current_thread() is not threading.main_thread():
            return
        with self._lock:
            self._clear_status()
            print(line, file=sys.stderr, flush=True)
            self._draw_status()

    def _emit(self, kind: str, msg: str) -> None:
        tag = _TAGS[kind]
        if self.colour:
            tag = f"{_COLOURS[kind]}{tag}{_RESET}"
        self._print(f"{tag} {msg}")

    def info(self, msg: str) -> None:
        if not self.quiet:
            self._emit("info", msg)

    def ok(self, msg: str) -> None:
        if not self.quiet:
            self._emit("ok", msg)

    def step(self, msg: str) -> None:
        if not self.quiet:
            self._emit("step", msg)

    def line(self, msg: str = "") -> None:
        """Untagged output (indented continuation lines, summaries)."""
        if not self.quiet:
            self._print(msg)

    def debug(self, msg: str) -> None:
        if self.verbose and not self.quiet:
            self._emit("dim", msg)

    def warn(self, msg: str) -> None:
        self._emit("warn", msg)

    def error(self, msg: str) -> None:
        self._emit("err", msg)
