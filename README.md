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
| 3. Service modules | follow-ups chosen per service (see below) |
| 4. Report | `report.md` + `findings.json`: a ranked **Where to start** list (best leads across all services, each with why and a copy-paste command), then findings by severity |

### Service modules

| Module | Triggers on | Does |
|---|---|---|
| `web` | HTTP/HTTPS | fingerprint (server, title, generator), vhost-redirect detection, vhost fuzzing (`ffuf`, else `gobuster vhost`) when the target is a hostname or redirects to one - with the wildcard size filtered out and the `/etc/hosts` line to add, `robots.txt`, exposed `.git`, `gobuster` content discovery with extensions picked from the fingerprint (PHP → `php,txt,bak`, ASP.NET → `aspx,asp,txt`, Java → `jsp,do,txt`), one level of recursion into found directories, automatic wildcard handling and a time cap per port, flags interesting paths |
| `ftp` | FTP | anonymous login check + root listing (nothing is downloaded), known-backdoor version check |
| `ssh` | SSH | version notes (e.g. CVE-2018-15473 user enumeration on OpenSSH ≤ 7.7) |
| `smb` | 139 / 445 | null-session share listing via `smbclient`, message-signing check |
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
| `searchsploit` | `exploits` lookups | `yay -S exploitdb` | `sudo apt install exploitdb` |
| SecLists | better wordlists (optional) | `yay -S seclists` | `sudo apt install seclists` |

Missing optional tools are skipped with a warning, not a crash.

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
  --quick                 top 1000 ports instead of all 65535
  --min-rate N            nmap --min-rate for the sweep (default 1000, 0 = nmap default)
  --ping                  do host discovery (default is -Pn; lab boxes often drop ping)
  --no-scripts            skip nmap default scripts (-sC)

modules:
  -m, --modules LIST      only run these modules (e.g. web,ftp)
  --no-modules            nmap only
  --list-modules          show available modules
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
  -v, --verbose           print every command as it runs
  -q, --quiet             warnings and errors only
```

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

# Bigger wordlist for the web module only
toolkit recon 10.10.42.17 -p 80 -m web \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
```

### Output

```
results/<target>/
├── report.md            # human-readable report (the main thing)
├── findings.json        # everything, machine-readable
├── writeup.md           # with --writeup: frontmatter, Recon filled in, empty Foothold/PrivEsc/Flags
├── nmap-ports.xml       # raw stage 1 output
├── nmap-services.xml    # raw stage 2 output
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
