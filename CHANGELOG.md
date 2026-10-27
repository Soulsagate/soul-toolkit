# Changelog

All notable changes to this project. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

## 0.2.0 - 2026-10-27

The "what do I try next" release: recon now ends with a ranked list of leads, writes reports you
can use straight away, and covers a lot more services.

### Added

- **Where to start**: a ranked list of the 3-5 most promising leads across all services, each with
  why it matters and a copy-paste command - at the top of the report and printed when the run ends.
  Ranking is rules-based and deterministic (`recon/leads.py`).
- **HTML report**: `report.html` next to `report.md` - one self-contained file, light/dark,
  collapsible sections, severity colours, copy buttons.
- **`--writeup` / `--room NAME`**: `writeup.md`, an Obsidian-friendly skeleton (frontmatter, Recon
  section pre-filled, empty Foothold / PrivEsc / Flags). Never overwrites an existing writeup.
- **Exploit-DB lookups** (`exploits` module): `searchsploit` for every service with a product and
  version, deduped, remote exploits first.
- **Web**: vhost fuzzing (ffuf, else gobuster vhost) with wildcard filtering and the `/etc/hosts`
  line to add; gobuster extensions picked from the fingerprint (PHP, ASP.NET, Java, static);
  one level of recursion; one time budget per port.
- **UDP**: top 100 UDP ports when running as root (`--udp` / `--no-udp`).
- **New modules**: `nfs` (showmount), `smtp` (banner, VRFY/EXPN enumeration check), `snmp`
  (default communities, process arguments, users), `mysql` (empty root/anonymous password),
  `postgres` (trust auth), `redis` (unauthenticated INFO), `rdp`, `winrm` and `ldap` (notes +
  hints from nmap's results).
- **`toolkit doctor`**: checks every external tool and prints install commands for Arch,
  Debian/Kali and macOS.
- **`toolkit config`** and `~/.config/soul-toolkit/config.ini` for default wordlists, threads,
  output dir and profile.
- **`--profile quick|default|thorough`**.
- **Parallel modules** (`--jobs`), a live progress line with elapsed time, and **Ctrl-C writes a
  partial report** instead of losing the run.
- **`--resume`**: reuse finished nmap results from an earlier run.
- Install with **pipx**: `pipx install git+https://github.com/Soulsagate/soul-toolkit`.
- GitHub Actions CI (ruff + pytest on Python 3.9-3.13), `docs/writing-a-module.md`,
  `CONTRIBUTING.md`, this changelog.

### Changed

- "Suggested next steps" is replaced by **Where to start** plus "Other leads and ideas".
- `--brute-timeout` is the content-discovery budget for a whole web port (recursion included),
  not per gobuster run.
- `--no-brute` also skips vhost fuzzing.

### Fixed

- gobuster 3.8 compatibility (`--no-progress` instead of `-z`; vhost results without the
  `Found:` prefix).
- A path is listed once even when gobuster prints it twice.

## 0.1.0 - 2026-10-27

First release.

### Added

- `toolkit recon`: staged nmap scan (port sweep, then `-sV -sC` on open ports), then per-service
  modules, then a Markdown + JSON report.
- Modules: `web` (fingerprint, vhost-redirect detection, robots.txt, exposed `.git`, gobuster with
  wildcard handling), `ftp` (anonymous login, filesystem-root and world-writable detection,
  vsftpd 2.3.4 backdoor), `ssh` (version notes), `smb` (null-session share listing, signing).
- Results are handed back to the invoking user when run under sudo; reports scrub the home
  directory.
