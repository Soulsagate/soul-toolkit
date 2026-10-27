# soul-toolkit

A modular pentest toolkit for **authorized** labs, CTFs and TryHackMe / Hack The Box boxes.
One command, sub-commands per job. The first (and flagship) command is **`recon`**.

> ⚠️ **Authorized use only.** Only point this at machines you own or have explicit
> permission to test. Read [DISCLAIMER.md](DISCLAIMER.md).

## `toolkit recon`

Give it an IP, get back a clean report instead of a terminal full of scrollback.

```
toolkit recon 10.10.42.17
```

It runs recon in stages, and each stage decides what the next one does:

| Stage | What happens |
|---|---|
| 1. Port sweep | `nmap` across all 65535 TCP ports (or top 1000 with `--quick`) |
| 2. Service scan | `nmap -sV -sC` on only the open ports |
| 3. UDP scan | top 100 UDP ports, then `-sV -sC` on the ones that answer (root only: on by default under sudo unless `-p` is given; `--udp` / `--no-udp`) |
| 4. Service modules | follow-ups chosen per service (see below) |
| 5. Report | `report.md` + `report.html` + `findings.json`: a ranked **Where to start** list (best leads across all services, each with why and a copy-paste command), then findings by severity |

### Service modules

| Module | Triggers on | Does |
|---|---|---|
| `web` | HTTP/HTTPS | fingerprint (server, title, generator), vhost-redirect detection, vhost fuzzing (`ffuf`, else `gobuster vhost`) when the target is a hostname or redirects to one - with the wildcard size filtered out and the `/etc/hosts` line to add, `robots.txt`, exposed `.git`, `gobuster` content discovery with extensions picked from the fingerprint (PHP → `php,txt,bak`, ASP.NET → `aspx,asp,txt`, Java → `jsp,do,txt`), one level of recursion into found directories, automatic wildcard handling and a time cap per port, flags interesting paths |
| `ftp` | FTP | anonymous login check + root listing (nothing is downloaded), known-backdoor version check |
| `ssh` | SSH | version notes (e.g. CVE-2018-15473 user enumeration on OpenSSH ≤ 7.7) |
| `smb` | 139 / 445 | null-session share listing via `smbclient`, message-signing check |
| `nfs` | NFS (2049 / mountd) | `showmount -e` export listing; exports open to everyone are flagged with a ready read-only `mount` command |
| `smtp` | SMTP (25 / 465 / 587) | banner + EHLO capabilities; checks whether VRFY / EXPN tell real users from made-up ones (one probe each) and hands you the `smtp-user-enum` command |
| `snmp` | SNMP (161/udp) | tries the default `public` / `private` communities (`onesixtyone`, else `snmpwalk`), then reads system info, process command lines that look like they carry passwords, and Windows users |
| `mysql` | MySQL / MariaDB (3306) | version from the server greeting; tries `root` and the anonymous account with an empty password (one login each, nothing else) |
| `postgres` | PostgreSQL (5432) | asks how user `postgres` must log in: `trust` (no password at all) is flagged, otherwise the method (SCRAM / md5) is noted |
| `redis` | Redis (6379) | one unauthenticated `INFO`: version, role, config path and how many keys it holds; tells *needs a password* and *protected mode* apart |
| `rdp` | RDP (3389) | host/domain names and the Windows release from nmap's NTLM info, `/etc/hosts` line for the domain, BlueKeep check command on Windows 7 / 2008 R2, `xfreerdp` for later |
| `winrm` | WinRM (5985 / 5986) | notes + the `evil-winrm` command for when you have credentials |
| `ldap` | LDAP (389 / 636 / 3268 / 3269) | AD domain and DC name from nmap, `/etc/hosts` line, `ldapsearch` anonymous-read command |
| `exploits` | any service with a product + version | `searchsploit` lookup, deduped across ports, top matches with EDB-IDs (remote exploits first) |

Each module is one small file in [`src/soul_toolkit/recon/modules/`](src/soul_toolkit/recon/modules/). Adding a service = one class with `matches()` and `run()`.

### Example output

Real run against a local test lab (an anonymous FTP server, a web server with an exposed `.git`, and a catch-all web server that answers 200 to everything). Full report: **[docs/sample-report.md](docs/sample-report.md)**.

```
[*] soul-toolkit v0.1.0 :: authorized targets only (see DISCLAIMER.md)
[*] Target: 127.0.0.1
[>] Stage 1/3: port sweep (top 1000 TCP ports)
[+] Open ports: 2121, 8080, 8081
[>] Stage 2/3: service/version scan on 3 port(s)
[*]   2121/tcp   ftp
[*]   8080/tcp   http           SimpleHTTPServer 0.6 (Python 3.13.17)
[*]   8081/tcp   http           BaseHTTPServer 0.6 (Python 3.13.17)
[>] Stage 3/3: service modules (web, ftp, ssh, smb)
[*] 2121/tcp ftp: checking anonymous login
[+] 2121/tcp ftp: anonymous login works
[*] 8080/tcp web: fingerprinting http://127.0.0.1:8080
[*] 8080/tcp web: gobuster with src/soul_toolkit/data/web-common.txt
[+] 8080/tcp web: 7 path(s) found
[*] 8081/tcp web: fingerprinting http://127.0.0.1:8081
[*] 8081/tcp web: gobuster with src/soul_toolkit/data/web-common.txt
[!] 8081/tcp web: wildcard responses (length 46), retrying with --exclude-length
[+] 8081/tcp web: 1 path(s) found
[+] Done in 34s - 3 open port(s), 9 finding(s) (4 medium/high)
[+] Report: results/127.0.0.1/report.md
```

## Install

Requires **Python 3.9+** and **Linux**. The toolkit wraps existing tools rather than reinventing them:

| Tool | Needed for | Arch / EndeavourOS | Kali |
|---|---|---|---|
| `nmap` | required | `sudo pacman -S nmap` | `sudo apt install nmap` |
| `gobuster` | `web` content discovery | `sudo pacman -S gobuster` | `sudo apt install gobuster` |
| `ffuf` | `web` vhost fuzzing (falls back to gobuster) | `sudo pacman -S ffuf` | `sudo apt install ffuf` |
| `smbclient` | `smb` share listing | `sudo pacman -S smbclient` | `sudo apt install smbclient` |
| `showmount` | `nfs` export listing | `sudo pacman -S nfs-utils` | `sudo apt install nfs-common` |
| `snmpwalk`, `onesixtyone` | `snmp` checks | `sudo pacman -S net-snmp onesixtyone` | `sudo apt install snmp onesixtyone` |
| `searchsploit` | `exploits` lookups | `yay -S exploitdb` | `sudo apt install exploitdb` |
| SecLists | better wordlists (optional) | `yay -S seclists` | `sudo apt install seclists` |

Missing optional tools are skipped with a warning, not a crash.

Not sure what you have? `toolkit doctor` checks every tool, says what each one enables, and prints
the install commands for what's missing (Arch, Debian/Kali and macOS; your platform first):

```bash
toolkit doctor          # what's installed, what's missing
toolkit doctor --all    # install commands for everything (setting up a new machine)
```

```bash
git clone https://github.com/Soulsagate/soul-toolkit.git
cd soul-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
toolkit --help
```

On the TryHackMe AttackBox the tools are already installed; just clone and `pip install -e .`.

### Running with sudo (faster SYN scans)

Without root, nmap falls back to TCP connect scans (`-sT`), which work but are slower.
Since the `toolkit` command lives in your venv, call it by path under sudo:

```bash
sudo "$(which toolkit)" recon 10.10.42.17
```

## Usage

```
toolkit recon TARGET [options]

scanning:
  -p, --ports PORTS       skip the sweep and scan these ports (22,80,8000-8010)
  --profile NAME          quick | default | thorough (see below); explicit flags still win
  --quick                 top 1000 ports instead of all 65535
  --min-rate N            nmap --min-rate for the sweep (default 1000, 0 = nmap default)
  --ping                  do host discovery (default is -Pn; lab boxes often drop ping)
  --no-scripts            skip nmap default scripts (-sC)
  --udp / --no-udp        force / skip the top-100 UDP scan (default: on as root unless -p is given)
  --resume                reuse finished nmap results from an earlier run in the output dir

modules:
  -m, --modules LIST      only run these modules (e.g. web,ftp)
  --no-modules            nmap only
  --list-modules          show available modules
  -j, --jobs N            module runs in parallel (default 4)
  --no-brute              skip content discovery and vhost fuzzing
  --no-vhost              skip vhost fuzzing only
  --vhost-wordlist FILE   vhost wordlist (default: SecLists subdomains-top1million-5000.txt, else bundled)
  -w, --wordlist FILE     gobuster wordlist (default: SecLists common.txt, else a small bundled list)
  -x, --extensions EXT    gobuster extensions, e.g. php,txt,html (default: picked from the fingerprint)
  --no-recurse            don't re-run gobuster inside found directories
  -t, --threads N         gobuster threads (default 30)
  --brute-timeout SEC     max seconds of content discovery per web port, recursion included (default 600)

output:
  -o, --output DIR        output directory (default ./results)
  --writeup               also write writeup.md (Obsidian-friendly skeleton, Recon pre-filled)
  --room NAME             room/box name for the writeup (implies --writeup)
  --config FILE           settings file (default: ~/.config/soul-toolkit/config.ini)
  -v, --verbose           print every command as it runs
  -q, --quiet             warnings and errors only
```

### Profiles

| Profile | What it does |
|---|---|
| `quick` | top 1000 TCP ports, no UDP, no vhost fuzzing, one gobuster pass, 3 min web budget per port |
| `default` | all TCP ports, top 100 UDP when root, vhost fuzzing, one level of recursion, 10 min web budget |
| `thorough` | default + UDP even with `-p` (root), SecLists' bigger lists (raft-medium, subdomains-top1million-20000) when installed, 30 min web budget |

Any flag you pass on top overrides the profile: `--profile quick --udp` is quick, plus UDP.

### Config file

Settings you'd pass every time (your wordlists, threads, where results go, a default profile) can
live in `~/.config/soul-toolkit/config.ini`:

```bash
toolkit config --init   # writes a commented example
toolkit config          # shows the file and the value + source of every setting
```

```ini
[recon]
profile = default
wordlist = ~/wordlists/raft-medium-directories.txt
output = ~/ctf/results
threads = 40
jobs = 4
```

Order of precedence: built-in defaults < profile < config file < command-line flags. Under `sudo`
the invoking user's config is read (and `~` means their home), not root's.

Common patterns:

```bash
# Full recon on a THM box over the VPN
sudo "$(which toolkit)" recon 10.10.42.17

# Fast first look, no brute-forcing
toolkit recon 10.10.42.17 --quick --no-brute

# Box redirected you to a vhost? Add it to /etc/hosts, then target the name
toolkit recon cheese.thm -p 80 -x php,txt,html

# Start your writeup while you scan: writeup.md lands next to the report
toolkit recon cheese.thm --room "Cheese CTF"

# Re-run modules (new wordlist, after an interrupt...) without waiting for nmap again
toolkit recon 10.10.42.17 --resume -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt

# Bigger wordlist for the web module only
toolkit recon 10.10.42.17 -p 80 -m web \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
```

While it runs, a live status line shows what's running and for how long (nmap stages and every
module run, in parallel). **Ctrl-C is safe**: running tools are stopped and a *partial* report is
written with everything that finished, marked as partial and listing what didn't.

### Output

```
results/<target>/
├── report.md            # human-readable report (the main thing)
├── report.html          # same report, one self-contained file: light/dark, collapsible, copy buttons
├── findings.json        # everything, machine-readable
├── writeup.md           # with --writeup: frontmatter, Recon filled in, empty Foothold/PrivEsc/Flags
├── nmap-ports.xml       # raw stage 1 output
├── nmap-services.xml    # raw stage 2 output
├── nmap-udp.xml         # raw UDP sweep (root only)
├── nmap-udp-services.xml  # raw UDP service scan
├── gobuster-<port>.txt  # raw gobuster output per web port
├── gobuster-<port>-<dir>.txt  # one per directory recursed into
└── vhosts-<port>.json   # raw ffuf vhost results (.txt when gobuster was used)
```

`writeup.md` has YAML frontmatter (room, platform, date, tags from the open services) and uses
Obsidian callouts, so it drops straight into a notes vault or a writeups repo; it renders fine on
GitHub too. An existing `writeup.md` is never overwritten - a timestamped copy is written instead.

Reports replace your home directory with `~`, so they're safe to paste into writeups.
`results/` is git-ignored so scan data never ends up in a commit.

## Development

```bash
pip install -e '.[dev]'
pytest
```

Tests use a recorded nmap XML fixture and throwaway servers on `127.0.0.1`, so they run anywhere without touching real targets.

## Roadmap

`recon` is the first command. Planned, roughly in order:

- `scan` - raw-socket port scanner
- `privesc` - Linux privilege-escalation enumeration (sudo -l, SUID, cron, writable paths)
- `report` - log commands and screenshots during a box, export an engagement report
- `web` - vhost brute-forcing and header analysis
- `hash`, `wordlist`, `shell`, `loot`, `vpn`

## License

[MIT](LICENSE). Use it, learn from it, break it, improve it. Just only on things you're allowed to.
