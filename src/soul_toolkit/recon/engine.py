"""Recon orchestration: port sweep -> service scan -> service modules -> report."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import Finding, HostResult
from soul_toolkit.core.target import safe_dirname
from soul_toolkit.recon import nmap
from soul_toolkit.recon.modules import Context, Module, Options
from soul_toolkit.recon.report import write_reports


@dataclass
class ReconConfig:
    target: str
    output: Path = Path("results")
    ports: list[int] | None = None
    full: bool = True
    min_rate: int | None = 1000
    skip_ping: bool = True
    scripts: bool = True
    modules: list[Module] | None = None
    options: Options = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.options is None:
            self.options = Options()


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def sudo_owner() -> tuple[int, int] | None:
    """(uid, gid) of the user who invoked sudo, or None if we're not running under sudo."""
    uid, gid = os.environ.get("SUDO_UID", ""), os.environ.get("SUDO_GID", "")
    if is_root() and uid.isdigit() and gid.isdigit() and int(uid) != 0:
        return int(uid), int(gid)
    return None


def hand_back(owner: tuple[int, int] | None, tree: Path, base: Path | None = None) -> None:
    """chown everything under *tree* (and *base* itself, non-recursively) to the sudo user,
    so a `sudo toolkit recon` run doesn't leave root-owned files in the user's folder."""
    if owner is None:
        return
    uid, gid = owner
    targets = [base] if base is not None else []
    if tree.exists():
        targets.append(tree)
        for root, dirs, files in os.walk(tree):
            targets += [Path(root, n) for n in dirs + files]
    for p in targets:
        try:
            os.lchown(p, uid, gid)
        except OSError:
            pass


def run_recon(cfg: ReconConfig, log: Logger) -> HostResult:
    runner.require("nmap", "Install it with your package manager (e.g. `sudo pacman -S nmap`).")

    outdir = cfg.output / safe_dirname(cfg.target)
    base_created = not cfg.output.exists()
    outdir.mkdir(parents=True, exist_ok=True)
    try:
        return _run_stages(cfg, log, outdir)
    finally:
        hand_back(sudo_owner(), outdir, cfg.output if base_created else None)


def _run_stages(cfg: ReconConfig, log: Logger, outdir: Path) -> HostResult:
    result = HostResult(target=cfg.target, started=_now())
    t0 = time.monotonic()

    syn = is_root()
    if not syn:
        log.warn("Not running as root: using TCP connect scans (-sT). Run with sudo for faster SYN scans.")

    # ---- Stage 1: port sweep ------------------------------------------------
    if cfg.ports:
        ports = cfg.ports
        log.step(f"Stage 1/3: skipped, using {len(ports)} given port(s)")
    else:
        scope = "all 65535 TCP ports" if cfg.full else "top 1000 TCP ports"
        log.step(f"Stage 1/3: port sweep ({scope})")
        cmd = nmap.build_port_sweep(cfg.target, syn=syn, full=cfg.full, min_rate=cfg.min_rate, skip_ping=cfg.skip_ping)
        sweep = _run_nmap(cmd, outdir / "nmap-ports.xml", result, log)
        host = sweep[0] if sweep else None
        ports = host.open_ports if host else []
        if host:
            result.status = host.status
        if not ports:
            log.warn("No open TCP ports found.")
            return _finish(result, outdir, t0, log)
        log.ok(f"Open ports: {', '.join(map(str, ports))}")

    # ---- Stage 2: service scan ----------------------------------------------
    log.step(f"Stage 2/3: service/version scan on {len(ports)} port(s)")
    cmd = nmap.build_service_scan(cfg.target, ports, syn=syn, scripts=cfg.scripts, skip_ping=cfg.skip_ping)
    hosts = _run_nmap(cmd, outdir / "nmap-services.xml", result, log)
    if hosts:
        h = hosts[0]
        result.address, result.hostnames, result.os_guess = h.address, h.hostnames, h.os_guess
        result.status = h.status
        result.services = h.services
    for s in result.services:
        log.info(f"  {s.label:<10} {s.name:<14} {s.banner}")

    # ---- Stage 3: service modules -------------------------------------------
    modules = cfg.modules if cfg.modules is not None else []
    log.step(f"Stage 3/3: service modules ({', '.join(m.name for m in modules) or 'none'})")
    ctx = Context(target=cfg.target, outdir=outdir, log=log, result=result, options=cfg.options)
    for svc in result.services:
        for mod in modules:
            if not mod.matches(svc):
                continue
            try:
                result.findings.extend(mod.run(ctx, svc))
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # one broken module must not kill the whole run
                log.error(f"{svc.label} {mod.name}: module crashed: {exc}")
                result.findings.append(Finding(mod.name, svc.port, "Module error", "info", repr(exc)))

    return _finish(result, outdir, t0, log)


def _run_nmap(cmd: list[str], xml_path: Path, result: HostResult, log: Logger) -> list[nmap.NmapHost]:
    log.debug("$ " + " ".join(cmd))
    res = runner.run(cmd)
    result.commands.append(res.pretty)
    if res.stdout:
        xml_path.write_text(res.stdout, encoding="utf-8")
    if res.returncode != 0:
        msg = (res.stderr.strip().splitlines() or ["unknown error"])[-1]
        raise nmap.NmapError(f"nmap exited with code {res.returncode}: {msg}")
    return nmap.parse_xml(res.stdout)


def _finish(result: HostResult, outdir: Path, t0: float, log: Logger) -> HostResult:
    result.duration = time.monotonic() - t0
    result.finished = _now()
    md, js = write_reports(result, outdir)
    high = sum(1 for f in result.findings if f.severity in ("high", "medium"))
    log.ok(f"Done in {result.duration:.0f}s - {len(result.services)} open port(s), "
           f"{len(result.findings)} finding(s) ({high} medium/high)")
    log.ok(f"Report: {md}")
    log.debug(f"JSON:   {js}")
    return result
