"""Tiny console logger with optional colour. No third-party dependencies."""

from __future__ import annotations

import os
import sys

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
    def __init__(self, verbose: bool = False, quiet: bool = False, colour: bool | None = None):
        self.verbose = verbose
        self.quiet = quiet
        self.colour = _use_colour() if colour is None else colour

    def _emit(self, kind: str, msg: str) -> None:
        tag = _TAGS[kind]
        if self.colour:
            tag = f"{_COLOURS[kind]}{tag}{_RESET}"
        print(f"{tag} {msg}", file=sys.stderr, flush=True)

    def info(self, msg: str) -> None:
        if not self.quiet:
            self._emit("info", msg)

    def ok(self, msg: str) -> None:
        if not self.quiet:
            self._emit("ok", msg)

    def step(self, msg: str) -> None:
        if not self.quiet:
            self._emit("step", msg)

    def debug(self, msg: str) -> None:
        if self.verbose and not self.quiet:
            self._emit("dim", msg)

    def warn(self, msg: str) -> None:
        self._emit("warn", msg)

    def error(self, msg: str) -> None:
        self._emit("err", msg)
