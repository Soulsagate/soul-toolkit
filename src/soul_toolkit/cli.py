"""Command-line entry point: `toolkit <command> ...`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from soul_toolkit import __version__
from soul_toolkit.core.log import Logger
from soul_toolkit.core.runner import ToolMissing
from soul_toolkit.core.target import InvalidTarget, validate_target

BANNER = f"soul-toolkit v{__version__} :: authorized targets only (see DISCLAIMER.md)"


# --------------------------------------------------------------------------- recon


def add_recon_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "recon",
        help="staged nmap scan + service-aware follow-ups + report",
        description="Port sweep -> service scan -> per-service modules -> Markdown/JSON report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sudo toolkit recon 10.10.12.34\n"
            "  toolkit recon 10.10.12.34 --quick --no-brute\n"
            "  toolkit recon cheese.thm --writeup    # + writeup.md for your notes vault\n"
            "  toolkit recon box.thm -p 80          # also fuzzes *.box.thm vhosts\n"
            "  toolkit recon target.thm -p 80,8080 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt\n"
        ),
    )
    p.add_argument("target", nargs="?", help="IP address or hostname of a host you are authorized to test")

    scan = p.add_argument_group("scanning")
    scan.add_argument("-p", "--ports", help="skip the port sweep and use these ports (e.g. 22,80,8000-8010)")
    scan.add_argument("--quick", action="store_true", help="sweep the top 1000 ports instead of all 65535")
    scan.add_argument("--min-rate", type=int, default=1000, metavar="N",
                      help="nmap --min-rate for the sweep (default 1000; 0 = nmap default)")
    scan.add_argument("--ping", action="store_true",
                      help="do host discovery (default is -Pn, since lab boxes often drop ping)")
    scan.add_argument("--no-scripts", action="store_true", help="skip nmap default scripts (-sC)")
    udp = scan.add_mutually_exclusive_group()
    udp.add_argument("--udp", dest="udp", action="store_true", default=None,
                     help="scan the top 100 UDP ports (needs root; on by default as root unless -p is given)")
    udp.add_argument("--no-udp", dest="udp", action="store_false", help="never scan UDP")

    mods = p.add_argument_group("modules")
    mods.add_argument("-m", "--modules", help="comma-separated modules to run (default: all)")
    mods.add_argument("--no-modules", action="store_true", help="nmap only, no follow-up modules")
    mods.add_argument("--list-modules", action="store_true", help="list available modules and exit")
    mods.add_argument("--no-brute", action="store_true", help="skip content discovery and vhost fuzzing")
    mods.add_argument("--no-vhost", action="store_true", help="skip vhost fuzzing only")
    mods.add_argument("--vhost-wordlist", metavar="FILE",
                      help="wordlist for vhost fuzzing (default: SecLists subdomains-top1million-5000.txt if found)")
    mods.add_argument("-w", "--wordlist", help="wordlist for gobuster (default: SecLists common.txt if found)")
    mods.add_argument("-x", "--extensions", default="",
                      help="extensions for gobuster, e.g. php,txt,html (default: picked from the fingerprint)")
    mods.add_argument("--no-recurse", action="store_true",
                      help="don't run gobuster again inside the directories it finds")
    mods.add_argument("-t", "--threads", type=int, default=30, help="gobuster threads (default 30)")
    mods.add_argument("--brute-timeout", type=int, default=600, metavar="SEC",
                      help="max seconds of content discovery per web port, recursion included (default 600)")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", default="results", help="output directory (default: ./results)")
    out.add_argument("--writeup", action="store_true",
                     help="also write writeup.md: an Obsidian-friendly skeleton with the Recon section filled in")
    out.add_argument("--room", metavar="NAME", help="room/box name for the writeup (implies --writeup; "
                     "default: the target, minus .thm/.htb)")
    out.add_argument("-v", "--verbose", action="store_true", help="show the commands being run")
    out.add_argument("-q", "--quiet", action="store_true", help="only print warnings and errors")

    p.set_defaults(func=cmd_recon)


def cmd_recon(args: argparse.Namespace) -> int:
    # Imported lazily so `toolkit --help` stays fast and other commands don't pay for it.
    from soul_toolkit.recon import nmap
    from soul_toolkit.recon.engine import ReconConfig, run_recon
    from soul_toolkit.recon.modules import Options, all_modules, select_modules

    log = Logger(verbose=args.verbose, quiet=args.quiet)

    if args.list_modules:
        for m in all_modules():
            print(f"{m.name:<9} {m.description}")
        return 0

    if not args.target:
        log.error("a target is required (e.g. toolkit recon 10.10.12.34)")
        return 2

    try:
        target = validate_target(args.target)
        ports = nmap.parse_ports(args.ports) if args.ports else None
        if args.no_modules:
            modules = []
        else:
            modules = select_modules(args.modules.split(",") if args.modules else None)
    except (InvalidTarget, ValueError) as exc:
        log.error(str(exc))
        return 2

    cfg = ReconConfig(
        target=target,
        output=Path(args.output),
        ports=ports,
        full=not args.quick,
        min_rate=args.min_rate or None,
        skip_ping=not args.ping,
        scripts=not args.no_scripts,
        udp=args.udp,
        modules=modules,
        writeup=args.writeup or bool(args.room),
        room=args.room,
        options=Options(
            brute=not args.no_brute,
            wordlist=args.wordlist,
            threads=max(1, args.threads),
            brute_timeout=max(10, args.brute_timeout),
            extensions=args.extensions,
            recurse=not args.no_recurse,
            vhosts=not args.no_vhost,
            vhost_wordlist=args.vhost_wordlist,
        ),
    )

    if not args.quiet:
        log.info(BANNER)
        log.info(f"Target: {target}")
    try:
        run_recon(cfg, log)
    except ToolMissing as exc:
        log.error(str(exc))
        return 127
    except nmap.NmapError as exc:
        log.error(str(exc))
        return 1
    except OSError as exc:
        log.error(f"{exc.strerror or exc}: {exc.filename or ''}".rstrip(": "))
        return 1
    except KeyboardInterrupt:
        log.warn("Interrupted.")
        return 130
    return 0


# --------------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="toolkit",
        description="soul-toolkit - a modular pentest toolkit for authorized labs and CTFs.",
    )
    parser.add_argument("--version", action="version", version=f"soul-toolkit {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    add_recon_parser(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
