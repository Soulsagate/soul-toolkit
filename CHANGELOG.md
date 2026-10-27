# Changelog

All notable changes to this project. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## Unreleased

## 0.3.2 - 2026-10-27

### Added

- **On PyPI.** Releases are now published to PyPI as well, so from this version
  `pipx install soul-toolkit` works. The `git+https://...` install keeps working. Publishing uses
  PyPI's trusted publishing from the release workflow, so no upload token is stored anywhere.
- **Demo GIF** at the top of the README: a real run against the bundled lab, with the long waits
  sped up.

### Changed

- README links and images are absolute, so they also work on the PyPI project page.
- The source distribution now includes the test fixtures, the Docker lab and `scripts/`, so its
  test suite runs on its own.

## 0.3.1 - 2026-10-27

Fixes from the first run by someone other than the author: a fresh Linux Mint Debian Edition 6
install against a TryHackMe box with SSH, HTTP, POP3 and IMAP.

### Added

- **`mail` module** for POP3, IMAP, POP3S and IMAPS (ports 110, 143, 993, 995, or nmap's
  `pop3` / `imap` / `pop3s` / `imaps`). It reports the server and its capabilities from nmap's
  `pop3-capabilities` / `imap-capabilities` (cleaned of the greeting words nmap mixes in), and
  flags a server that takes passwords in clear text with no STLS / STARTTLS (low). One lead per
  host, "Keep the mail server for when you have credentials", ranks just above the SSH one,
  since mailboxes often hold more credentials. It comes with ready commands to read a mailbox by
  hand (`curl -u '<user>:<password>' pop3://...`, or `nc` then `USER` / `PASS` / `RETR`). Recon
  only: it works from nmap's results and never logs in or guesses passwords. Writeups get a
  `mail` tag.
- **Files worth reading.** Text-like files that content discovery finds with a 2xx (`.txt`,
  `.bak`, `.old`, `.log`, `.md`, `.conf`, `.xml`, `.json`, `security.txt`, `humans.txt`...),
  except robots.txt, are listed as a "Files worth reading" finding. A lead, ranked like the
  interesting-paths one, gives a `curl` command for the most promising file and lists the rest.
  Backups, dumps, configs and logs come first. The tester's box had a `/security.txt` that recon
  listed but never pointed at.

### Fixed

- **No more `<IP>`-style placeholders to trip over.** The tester typed `<IP>` literally and bash
  read `<` as a redirect. The README, the getting-started guide, `--help`, and the leads and
  hints recon prints now use real example values (`10.10.42.17`, the vhost that was found, the
  EDB-ID from the table) wherever they can. The guide says to replace example values and never
  type the `< >` around placeholders. Placeholders only remain where a value can't be known, like
  `ssh <user>@...`.
- **robots.txt that only says `Disallow: /`** (or has no entries) no longer becomes a lead. On
  the tester's box it was the #1 lead in "Where to start", pointing at nothing. It's now an info
  finding, "robots.txt only blocks the whole site". The lead appears only when robots.txt names
  specific paths, and it counts only those.

## 0.3.0 - 2026-10-27

The "easy to pick up" release: a redesigned HTML report, a step-by-step guide for new users,
install commands that work on every major distro, and runs that tell you where your results are.
"Where to start" is sharper too: SMB shares are checked for read access, and Exploit-DB and
stock-Apache noise no longer crowds out real discoveries.

### Added

- **[Getting started guide](docs/getting-started.md)**: from a fresh machine to the first report,
  with per-distro install commands (Arch, Kali, Debian/Ubuntu/Mint/LMDE, WSL2), the VPN and the
  first scan, reading the results, everyday commands, updating, and troubleshooting for the
  errors new users actually hit. Linked from the top of the README.

- **SMB share access.** After listing shares with a null session, the `smb` module checks
  whether each share (except IPC$) can actually be read, using one
  `smbclient //HOST/SHARE -N -c ls` per share, with a 20-second timeout each. The share table in
  `report.md` and `report.html` gets an Access column (READ / NO ACCESS, or TIMED OUT / UNKNOWN
  when it can't tell). A non-default share confirmed readable now ranks just below anonymous
  FTP in "Where to start". If no non-default share is readable, the lead drops to a low "come
  back with credentials" one. It is a read check only: write access is never tested and nothing
  is created on the target, which is why smbmap's permission check (it writes a temporary
  directory) isn't used.

- Every run now ends by printing the full folder its results were saved in (home shown as `~`,
  the sudo user's home under `sudo`) and a copy-paste `xdg-open` / `open` command for the HTML
  report. The README's Output section explains where results go, how to open them, and how to
  keep them in one place with `-o` or the config file.

### Changed

- Redesigned the HTML report. It now has a summary card with severity chips, a sticky section
  nav (sidebar on wide screens, top bar on phones), and "Where to start" as numbered cards with a
  Copy button. Findings are cards you can filter by severity and expand or collapse all at once.
  The tables are easier to read, with HTTP status codes in colour and UDP ports marked. An
  interrupted run gets a clear "Partial report" banner. Light and dark themes meet WCAG AA
  contrast, and the page works at phone width. It prints in the light theme with every section
  expanded. It is still one offline file: no network requests, and readable with JavaScript off.

### Fixed

- `toolkit doctor` on plain Debian, Ubuntu, Linux Mint and LMDE printed one `apt install` line that
  included the Kali-only `exploitdb` and `seclists` packages, so apt refused to install anything.
  Kali/Parrot and Debian/Ubuntu/Mint are now detected separately; on the latter those two are
  installed from their upstream repos (`/opt/exploitdb` + a `searchsploit` symlink,
  `/usr/share/seclists`), which is where recon already looks.
- Checked against gobuster 3.5 (Debian 12 / LMDE 6's version) as well as 3.6 and 3.8.
- **Smarter Exploit-DB leads**, from the first real run against a TryHackMe box. searchsploit
  matches titles and version ranges loosely, and three kinds of noise were outranking real
  discoveries in "Where to start":
  - DoS-only matches (Exploit-DB files some as "remote") no longer become leads.
  - For Apache httpd, titles about other Apache projects (Tomcat, Struts, ...) are dropped.
  - Each title's version range is checked against the detected version for *that* product
    (`OpenSSH 2.3 < 7.7` covers 7.2p2; `Apache + PHP < 5.3.12` is PHP's range, not httpd's).
    Unconfirmed matches become a low-ranked "check whether these really apply" lead, confirmed
    username-enumeration a weak one, and only confirmed code execution stays near the top.
- Apache's stock 403s (`.ht*`, `server-status`) are hidden from the content-discovery table and
  never used as an "interesting path" lead (on a real box they were half of a 70-row table); the
  report says how many were hidden, and the raw gobuster files still have them. Paths you can open
  (2xx, then directories) come first.

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
- **`tests/lab/`**: a deliberately vulnerable Docker lab (anonymous FTP, a web app with an exposed
  `.git` and a hidden vhost, null-session SMB, a world-readable NFS export) and an integration test
  that runs recon against it.
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
- Anonymous FTP is still reported (with a "list it by hand" lead) when login works but the
  directory listing fails, e.g. passive mode blocked.
- Writeup tags fold NFS's RPC helper services (mountd, nlockmgr, rquotad...) into one `nfs` tag.

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
