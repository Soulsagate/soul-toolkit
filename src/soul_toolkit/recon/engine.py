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
from soul_toolkit.recon import leads, nmap
from soul_toolkit.recon.modules import Context, Module, Options
from soul_toolkit.recon.report import write_reports
from soul_toolkit.recon.writeup import write_writeup


@dataclass
class ReconConfig:
    target: str
    output: Path = Path("results")
    ports: list[int] | None = None
    full: bool = True
    min_rate: int | None = 1000
    skip_ping: bool = True
    scripts: bool = True
    udp: bool | None = None  # None = auto: on when root and no explicit -p
    modules: list[Module] | None = None
    options: Options = None  # type: ignore[assignment]
    writeup: bool = False
    room: str | None = None

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


def want_udp(cfg: ReconConfig, log: Logger) -> bool:
    if cfg.udp is False:
        return False
    if not is_root():
        if cfg.udp:
            log.warn("UDP scans need root - skipping UDP. Run with sudo to include it.")
        return False
    return bool(cfg.udp) or not cfg.ports


def _run_stages(cfg: ReconConfig, log: Logger, outdir: Path) -> HostResult:
    result = HostResult(target=cfg.target, started=_now())
    t0 = time.monotonic()

    syn = is_root()
    if not syn:
        log.warn("Not running as root: using TCP connect scans (-sT). Run with sudo for faster SYN scans.")
    udp = want_udp(cfg, log)
    total = 4 if udp else 3
    stage = iter(range(1, total + 1))

    # ---- TCP port sweep -----------------------------------------------------
    if cfg.ports:
        ports = cfg.ports
        log.step(f"Stage {next(stage)}/{total}: skipped, using {len(ports)} given port(s)")
    else:
        scope = "all 65535 TCP ports" if cfg.full else "top 1000 TCP ports"
        log.step(f"Stage {next(stage)}/{total}: port sweep ({scope})")
        cmd = nmap.build_port_sweep(cfg.target, syn=syn, full=cfg.full, min_rate=cfg.min_rate, skip_ping=cfg.skip_ping)
        sweep = _run_nmap(cmd, outdir / "nmap-ports.xml", result, log)
        host = sweep[0] if sweep else None
        ports = host.open_ports if host else []
        if host:
            result.status = host.status
        if ports:
            log.ok(f"Open ports: {', '.join(map(str, ports))}")
        else:
            log.warn("No open TCP ports found.")

    # ---- TCP service scan ---------------------------------------------------
    if ports:
        log.step(f"Stage {next(stage)}/{total}: service/version scan on {len(ports)} port(s)")
        cmd = nmap.build_service_scan(cfg.target, ports, syn=syn, scripts=cfg.scripts, skip_ping=cfg.skip_ping)
        hosts = _run_nmap(cmd, outdir / "nmap-services.xml", result, log)
        if hosts:
            h = hosts[0]
            result.address, result.hostnames, result.os_guess = h.address, h.hostnames, h.os_guess
            result.status = h.status
            result.services = h.services
        for s in result.services:
            log.info(f"  {s.label:<10} {s.name:<14} {s.banner}")
    else:
        log.step(f"Stage {next(stage)}/{total}: service scan skipped (no open TCP ports)")

    # ---- UDP (root only) ----------------------------------------------------
    if udp:
        log.step(f"Stage {next(stage)}/{total}: UDP scan (top 100 ports)")
        _udp_stage(cfg, result, outdir, log)

    if not result.services:
        return _finish(cfg, result, outdir, t0, log)

    # ---- Service modules ----------------------------------------------------
    modules = cfg.modules if cfg.modules is not None else []
    log.step(f"Stage {next(stage)}/{total}: service modules ({', '.join(m.name for m in modules) or 'none'})")
    ctx = Context(target=cfg.target, outdir=outdir, log=log, result=result, options=cfg.options)
    for svc in result.services:
        for mod in modules:
            if svc.protocol not in mod.protocols or not mod.matches(svc):
                continue
            before = {id(x) for x in result.leads}
            try:
                found = mod.run(ctx, svc)
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # one broken module must not kill the whole run
                log.error(f"{svc.label} {mod.name}: module crashed: {exc}")
                found = [Finding(mod.name, svc.port, "Module error", "info", repr(exc))]
            # Modules only know port numbers; stamp the protocol onto what they produced.
            for f in found:
                f.protocol = svc.protocol
            for lead in result.leads:
                if id(lead) not in before:
                    lead.protocol = svc.protocol
            result.findings.extend(found)

    return _finish(cfg, result, outdir, t0, log)


def _udp_stage(cfg: ReconConfig, result: HostResult, outdir: Path, log: Logger) -> None:
    """Top-100 UDP sweep, then -sV/-sC on whatever answered. A UDP failure never ends the run."""
    try:
        cmd = nmap.build_udp_sweep(cfg.target, min_rate=cfg.min_rate, skip_ping=cfg.skip_ping)
        sweep = _run_nmap(cmd, outdir / "nmap-udp.xml", result, log)
        result.udp_scanned = True
        ports = sweep[0].open_ports if sweep else []
        if not ports:
            log.info("  no UDP ports answered (open|filtered ports aren't reported)")
            return
        log.ok(f"Open UDP ports: {', '.join(map(str, ports))}")
        cmd = nmap.build_udp_service_scan(cfg.target, ports, scripts=cfg.scripts, skip_ping=cfg.skip_ping)
        hosts = _run_nmap(cmd, outdir / "nmap-udp-services.xml", result, log)
    except nmap.NmapError as exc:
        log.warn(f"UDP scan failed, continuing with TCP results: {exc}")
        return
    if not hosts:
        return
    h = hosts[0]
    if not result.address:
        result.address, result.hostnames, result.status = h.address, h.hostnames, h.status
    udp = [s for s in h.services if s.protocol == "udp"]
    for s in udp:
        log.info(f"  {s.label:<10} {s.name:<14} {s.banner}")
    result.services += udp


def print_where_to_start(result: HostResult, log: Logger) -> None:
    top = result.leads[:leads.WHERE_TO_START]
    if not top:
        return
    log.ok("Where to start:")
    for i, lead in enumerate(top, 1):
        log.line(f"    {i}. {lead.title} ({lead.where})")
        if lead.command:
            log.line(f"       $ {lead.command}")


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


def _finish(cfg: ReconConfig, result: HostResult, outdir: Path, t0: float, log: Logger) -> HostResult:
    result.duration = time.monotonic() - t0
    result.finished = _now()
    host = leads.host_leads(result, quick=not cfg.full, ports_given=bool(cfg.ports), suggest_udp=cfg.udp is not False)
    result.leads = leads.rank(result.leads + host)
    md, js = write_reports(result, outdir)
    high = sum(1 for f in result.findings if f.severity in ("high", "medium"))
    log.ok(f"Done in {result.duration:.0f}s - {len(result.services)} open port(s), "
           f"{len(result.findings)} finding(s) ({high} medium/high)")
    print_where_to_start(result, log)
    log.ok(f"Report: {md}  (HTML: {md.with_suffix('.html').name})")
    if cfg.writeup:
        log.ok(f"Writeup: {write_writeup(result, outdir, cfg.room)}")
    log.debug(f"JSON:   {js}")
    return result
