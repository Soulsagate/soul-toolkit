"""Recon orchestration: port sweep -> service scan -> service modules -> report."""

from __future__ import annotations

import os
import shlex
import signal
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import Finding, HostResult, Lead, Service
from soul_toolkit.core.progress import LiveStatus, Stopwatch, fmt_elapsed
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
    jobs: int = 4  # module runs in parallel
    resume: bool = False  # reuse finished nmap XML in the output dir instead of rescanning

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
    """Run every stage and write the reports. On Ctrl-C, stop running tools, write a partial
    report from whatever finished, then re-raise KeyboardInterrupt."""
    runner.require("nmap", "Install it with your package manager (e.g. `sudo pacman -S nmap`).")
    runner.reset()

    outdir = cfg.output / safe_dirname(cfg.target)
    base_created = not cfg.output.exists()
    outdir.mkdir(parents=True, exist_ok=True)
    result = HostResult(target=cfg.target, started=_now())
    t0 = time.monotonic()
    try:
        _run_stages(cfg, log, outdir, result)
    except KeyboardInterrupt:
        log.main_thread_only = True
        runner.stop_all()
        result.interrupted = True
        log.status(None)
        log.warn("Interrupted - stopping running tools and writing a partial report.")
        _finish_uninterruptible(cfg, result, outdir, t0, log)
        raise
    else:
        _finish(cfg, result, outdir, t0, log)
    finally:
        hand_back(sudo_owner(), outdir, cfg.output if base_created else None)
    return result


def want_udp(cfg: ReconConfig, log: Logger) -> bool:
    if cfg.udp is False:
        return False
    if not is_root():
        if cfg.udp:
            log.warn("UDP scans need root - skipping UDP. Run with sudo to include it.")
        return False
    return bool(cfg.udp) or not cfg.ports


def reuse_xml(cfg: ReconConfig, path: Path, result: HostResult, log: Logger,
              ports: list[int] | None = None) -> list[nmap.NmapHost] | None:
    """With --resume, the hosts from an earlier run's XML - if it finished, is for this target and
    (for service scans) covered *ports*. None means "scan again" (the reason is logged)."""
    if not cfg.resume or not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        info = nmap.scan_info(text)
        hosts = nmap.parse_xml(text)
    except nmap.NmapError:
        log.warn(f"--resume: {path.name} is unreadable - scanning again")
        return None
    problem = ""
    if not info.complete:
        problem = "that scan didn't finish"
    elif info.target != cfg.target:
        problem = f"it is for {info.target or 'another target'}"
    elif ports is not None and info.ports is not None and not set(ports) <= set(info.ports):
        problem = "it covered different ports"
    if problem:
        log.warn(f"--resume: not reusing {path.name} ({problem}) - scanning again")
        return None
    log.info(f"--resume: reusing {path.name}")
    result.commands.append(f"# reused {path.name} from an earlier run (--resume)")
    return hosts


def _run_stages(cfg: ReconConfig, log: Logger, outdir: Path, result: HostResult) -> None:
    syn = is_root()
    if not syn:
        log.warn("Not running as root: using TCP connect scans (-sT). Run with sudo for faster SYN scans.")
    udp = want_udp(cfg, log)
    total = 4 if udp else 3
    stage = iter(range(1, total + 1))
    # Whatever is still listed here when Ctrl-C lands goes into the partial report.
    result.incomplete = ["TCP port sweep", "TCP service scan", *(["UDP scan"] if udp else []), "service modules"]

    # A finished service scan from an earlier run makes the sweep unnecessary too.
    services_xml = outdir / "nmap-services.xml"
    reused = reuse_xml(cfg, services_xml, result, log, cfg.ports)

    # ---- TCP port sweep -----------------------------------------------------
    if cfg.ports:
        ports = cfg.ports
        log.step(f"Stage {next(stage)}/{total}: skipped, using {len(ports)} given port(s)")
    elif reused is not None:
        ports = reused[0].open_ports if reused else []
        log.step(f"Stage {next(stage)}/{total}: port sweep skipped (--resume)")
    else:
        scope = "all 65535 TCP ports" if cfg.full else "top 1000 TCP ports"
        log.step(f"Stage {next(stage)}/{total}: port sweep ({scope})")
        sweep = reuse_xml(cfg, outdir / "nmap-ports.xml", result, log)
        if sweep is None:
            cmd = nmap.build_port_sweep(cfg.target, syn=syn, full=cfg.full, min_rate=cfg.min_rate,
                                        skip_ping=cfg.skip_ping)
            sweep = _run_nmap(cmd, outdir / "nmap-ports.xml", result, log, "port sweep")
        host = sweep[0] if sweep else None
        ports = host.open_ports if host else []
        if host:
            result.status = host.status
        if ports:
            log.ok(f"Open ports: {', '.join(map(str, ports))}")
        else:
            log.warn("No open TCP ports found.")
    result.incomplete.remove("TCP port sweep")

    # ---- TCP service scan ---------------------------------------------------
    if ports:
        what = "reused from an earlier run (--resume)" if reused is not None else f"on {len(ports)} port(s)"
        log.step(f"Stage {next(stage)}/{total}: service/version scan {what}")
        hosts = reused
        if hosts is None:
            cmd = nmap.build_service_scan(cfg.target, ports, syn=syn, scripts=cfg.scripts, skip_ping=cfg.skip_ping)
            hosts = _run_nmap(cmd, services_xml, result, log, "service scan")
        if hosts:
            h = hosts[0]
            result.address, result.hostnames, result.os_guess = h.address, h.hostnames, h.os_guess
            result.status = h.status
            result.services = h.services
            if reused is not None and cfg.ports:  # an earlier scan may have covered more ports than asked
                result.services = [s for s in h.services if s.port in cfg.ports]
        for s in result.services:
            log.info(f"  {s.label:<10} {s.name:<14} {s.banner}")
    else:
        log.step(f"Stage {next(stage)}/{total}: service scan skipped (no open TCP ports)")
    result.incomplete.remove("TCP service scan")

    # ---- UDP (root only) ----------------------------------------------------
    if udp:
        log.step(f"Stage {next(stage)}/{total}: UDP scan (top 100 ports)")
        _udp_stage(cfg, result, outdir, log)
        result.incomplete.remove("UDP scan")

    # ---- Service modules ----------------------------------------------------
    modules = cfg.modules if cfg.modules is not None else []
    if result.services:
        log.step(f"Stage {next(stage)}/{total}: service modules ({', '.join(m.name for m in modules) or 'none'})")
        _run_modules(cfg, log, outdir, result, modules)
    result.incomplete.remove("service modules")


@dataclass
class _TaskOutput:
    findings: list[Finding]
    leads: list[Lead]
    hints: list[str]
    commands: list[str]
    seconds: float


@dataclass
class _Board:
    """Shared between the worker threads and the status line: who is running since when."""
    running: dict[int, float] = field(default_factory=dict)
    done: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


def _run_task(cfg: ReconConfig, log: Logger, outdir: Path, result: HostResult, svc: Service, mod: Module,
              index: int, board: _Board) -> _TaskOutput:
    """One module on one service, with its own result collector so parallel runs never share lists."""
    with board.lock:
        board.running[index] = time.monotonic()
    local = HostResult(target=result.target, address=result.address, hostnames=result.hostnames,
                       services=result.services)
    ctx = Context(target=cfg.target, outdir=outdir, log=log, result=local, options=cfg.options)
    try:
        found = mod.run(ctx, svc)
    except Exception as exc:  # one broken module must not kill the whole run
        log.error(f"{svc.label} {mod.name}: module crashed: {exc}")
        found = [Finding(mod.name, svc.port, "Module error", "info", repr(exc))]
    finally:
        with board.lock:
            started = board.running.pop(index)
    # Modules only know port numbers; stamp the protocol onto what they produced.
    for item in [*found, *local.leads]:
        item.protocol = svc.protocol
    return _TaskOutput(found, local.leads, local.hints, local.commands, time.monotonic() - started)


def _run_modules(cfg: ReconConfig, log: Logger, outdir: Path, result: HostResult, modules: list[Module]) -> None:
    tasks = [(svc, mod) for svc in result.services for mod in modules
             if svc.protocol in mod.protocols and mod.matches(svc)]
    if not tasks:
        return
    outputs: list[_TaskOutput | None] = [None] * len(tasks)
    board = _Board()
    clock = Stopwatch()

    def render() -> str:
        now = time.monotonic()
        with board.lock:
            running = sorted(board.running.items(), key=lambda kv: kv[1])
            done = board.done
        names = ", ".join(f"{tasks[i][0].label} {tasks[i][1].name} {fmt_elapsed(now - t)}" for i, t in running)
        return f"    [{done}/{len(tasks)} done, {clock.elapsed}] running: {names or '-'}"

    pool = ThreadPoolExecutor(max_workers=max(1, cfg.jobs), thread_name_prefix="module")
    futures = {pool.submit(_run_task, cfg, log, outdir, result, svc, mod, i, board): i
               for i, (svc, mod) in enumerate(tasks)}
    try:
        with LiveStatus(log, render):
            pending = set(futures)
            while pending:
                # Short waits keep the main thread responsive to Ctrl-C.
                finished, pending = wait(pending, timeout=0.5, return_when=FIRST_COMPLETED)
                for fut in finished:
                    i = futures[fut]
                    outputs[i] = fut.result()
                    with board.lock:
                        board.done += 1
                        done = board.done
                    svc, mod = tasks[i]
                    log.info(f"[{done}/{len(tasks)}] {svc.label} {mod.name} finished in "
                             f"{fmt_elapsed(outputs[i].seconds)}")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        # Merge in task order, not completion order, so reports are the same run to run.
        for out in outputs:
            if out is None:
                continue
            result.findings.extend(out.findings)
            result.leads.extend(out.leads)
            result.commands.extend(out.commands)
            result.hints.extend(h for h in out.hints if h not in result.hints)
        unfinished = [f"{svc.label} {mod.name}" for (svc, mod), out in zip(tasks, outputs) if out is None]
        if unfinished:
            result.incomplete = [f"module runs: {', '.join(unfinished)}"]


def _udp_stage(cfg: ReconConfig, result: HostResult, outdir: Path, log: Logger) -> None:
    """Top-100 UDP sweep, then -sV/-sC on whatever answered. A UDP failure never ends the run."""
    try:
        hosts = reuse_xml(cfg, outdir / "nmap-udp-services.xml", result, log)
        if hosts is None:
            sweep = reuse_xml(cfg, outdir / "nmap-udp.xml", result, log)
            if sweep is None:
                cmd = nmap.build_udp_sweep(cfg.target, min_rate=cfg.min_rate, skip_ping=cfg.skip_ping)
                sweep = _run_nmap(cmd, outdir / "nmap-udp.xml", result, log, "UDP sweep")
            result.udp_scanned = True
            ports = sweep[0].open_ports if sweep else []
            if not ports:
                log.info("  no UDP ports answered (open|filtered ports aren't reported)")
                return
            log.ok(f"Open UDP ports: {', '.join(map(str, ports))}")
            cmd = nmap.build_udp_service_scan(cfg.target, ports, scripts=cfg.scripts, skip_ping=cfg.skip_ping)
            hosts = _run_nmap(cmd, outdir / "nmap-udp-services.xml", result, log, "UDP service scan")
        result.udp_scanned = True
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


def _run_nmap(cmd: list[str], xml_path: Path, result: HostResult, log: Logger,
              label: str = "nmap") -> list[nmap.NmapHost]:
    log.debug("$ " + " ".join(cmd))
    clock = Stopwatch()
    with LiveStatus(log, lambda: f"    {label}: nmap running, {clock.elapsed} elapsed (Ctrl-C saves a partial report)"):
        res = runner.run(cmd)
    result.commands.append(res.pretty)
    if res.stdout:
        xml_path.write_text(res.stdout, encoding="utf-8")
    if res.returncode != 0:
        msg = (res.stderr.strip().splitlines() or ["unknown error"])[-1]
        raise nmap.NmapError(f"nmap exited with code {res.returncode}: {msg}")
    return nmap.parse_xml(res.stdout)


def _finish_uninterruptible(cfg: ReconConfig, result: HostResult, outdir: Path, t0: float, log: Logger) -> None:
    """Write the partial report; a second Ctrl-C while writing it is ignored."""
    main = threading.current_thread() is threading.main_thread()
    old = signal.signal(signal.SIGINT, signal.SIG_IGN) if main else None
    try:
        _finish(cfg, result, outdir, t0, log)
    finally:
        if old is not None:
            signal.signal(signal.SIGINT, old)


def _finish(cfg: ReconConfig, result: HostResult, outdir: Path, t0: float, log: Logger) -> HostResult:
    result.duration = time.monotonic() - t0
    result.finished = _now()
    host = leads.host_leads(result, quick=not cfg.full, ports_given=bool(cfg.ports), suggest_udp=cfg.udp is not False)
    result.leads = leads.rank(result.leads + host)
    md, js = write_reports(result, outdir)
    high = sum(1 for f in result.findings if f.severity in ("high", "medium"))
    if result.interrupted:
        log.warn(f"Partial results - not finished: {'; '.join(result.incomplete) or 'unknown'}")
    log.ok(f"{'Stopped after' if result.interrupted else 'Done in'} {result.duration:.0f}s - "
           f"{len(result.services)} open port(s), "
           f"{len(result.findings)} finding(s) ({high} medium/high)")
    print_where_to_start(result, log)
    log.ok(f"Report: {md}  (HTML: {md.with_suffix('.html').name})")
    if cfg.writeup:
        log.ok(f"Writeup: {write_writeup(result, outdir, cfg.room)}")
    log.debug(f"JSON:   {js}")
    log.ok(f"Saved in: {display_path(outdir)}/")
    log.line(f"    open the report: {open_command(md.with_suffix('.html'))}")
    return result


_SHELL_SAFE = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./~+@%:,")


def _home() -> Path:
    from soul_toolkit.recon.settings import user_home  # the sudo user's home, not /root

    return user_home()


def display_path(path: Path) -> str:
    """Absolute path with the user's home shown as '~', so people can find their results."""
    p = path.resolve()
    home = _home().resolve()
    try:
        rel = p.relative_to(home)
    except ValueError:
        return str(p)
    return "~" if str(rel) == "." else f"~/{rel}"


def open_command(path: Path) -> str:
    """A copy-pasteable command that opens *path* with the desktop's default app."""
    opener = "open" if sys.platform == "darwin" else "xdg-open"
    shown = display_path(path)
    if all(c in _SHELL_SAFE for c in shown):
        return f"{opener} {shown}"  # '~' unquoted so the shell expands it
    return f"{opener} {shlex.quote(str(path.resolve()))}"
