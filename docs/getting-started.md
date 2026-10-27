# Getting started

A step-by-step guide from a fresh machine to your first recon report. If you already know your
way around Linux, the [README](../README.md) is the quicker reference.

> ⚠️ Only scan machines you own or are explicitly allowed to test, such as TryHackMe or Hack The
> Box boxes. See [DISCLAIMER.md](../DISCLAIMER.md).

**Contents:** [1. What you need](#1-what-you-need) · [2. Install](#2-install) ·
[3. Your first scan](#3-your-first-scan) · [4. Reading the results](#4-reading-the-results) ·
[5. Everyday use](#5-everyday-use) · [6. Updating and uninstalling](#6-updating-and-uninstalling) ·
[7. Troubleshooting](#7-troubleshooting)

---

## 1. What you need

- **Linux.** Any modern distro works: Kali, Parrot, Arch/EndeavourOS, Debian, Ubuntu, Linux Mint,
  LMDE, or the TryHackMe AttackBox.
  - **Windows:** use **WSL2** (not WSL1) and run your VPN *inside* WSL.
  - **macOS** should work but isn't tested.
- **Python 3.9 or newer.** Check with `python3 --version`. Every distro above already has it.
- **A target you're allowed to scan.** On TryHackMe or Hack The Box that means connecting to
  their VPN (step 3).

---

## 2. Install

There are three steps: install the tools recon uses, install the toolkit, then check the setup.
Pick your distro.

### Step 1: install the tools it uses

Only **nmap** is required. The rest unlock more checks, and anything missing is skipped with a
warning instead of crashing.

**Arch / EndeavourOS / Manjaro**

```bash
sudo pacman -S --needed git python-pipx nmap gobuster ffuf smbclient nfs-utils net-snmp
yay -S exploitdb onesixtyone seclists      # optional, from the AUR
```

**Kali / Parrot**

```bash
sudo apt update
sudo apt install git pipx nmap gobuster ffuf smbclient nfs-common snmp onesixtyone exploitdb seclists
```

**Debian / Ubuntu / Linux Mint / LMDE / WSL2 (Ubuntu)**

`exploitdb` and `seclists` are Kali-only packages. Keep them **out** of the `apt` line, because apt
refuses the whole command if one package doesn't exist. Install those two from source instead:

```bash
sudo apt update
sudo apt install git pipx nmap gobuster ffuf smbclient nfs-common snmp onesixtyone

# optional: searchsploit (exploit lookups) - a large download
sudo git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# optional: SecLists (much better wordlists than the small built-in ones) - a large download
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

### Step 2: install the toolkit

[pipx](https://pipx.pypa.io/) installs Python apps into their own environment and puts the command
on your PATH. It's the cleanest way to install soul-toolkit.

```bash
pipx ensurepath          # one-time: adds ~/.local/bin to your PATH
exec $SHELL              # reload your shell (or open a new terminal)
pipx install git+https://github.com/Soulsagate/soul-toolkit
```

To install a specific release instead of the latest code, add the tag:
`pipx install git+https://github.com/Soulsagate/soul-toolkit@v0.3.0`.

### Step 3: check the setup

```bash
toolkit --version
toolkit doctor
```

`toolkit doctor` lists every tool with `[ok  ]` or `[--  ]`, what each one is for, and the exact
commands to install whatever is missing on *your* distro. Only a missing `nmap` stops recon from
running.

---

## 3. Your first scan

This example uses TryHackMe. Hack The Box works the same way with its own VPN file.

**1. Connect to the VPN** in its own terminal, and leave that terminal open:

```bash
sudo openvpn ~/Downloads/<your-username>.ovpn
```

When it prints `Initialization Sequence Completed`, you're connected. To check from another
terminal:

```bash
ip -br addr show tun0     # should show an address, usually 10.x.x.x or 192.168.x.x
```

**2. Start the room's machine** on the website and copy its IP. Give it a minute or two to boot.

**3. Run recon** in a second terminal:

```bash
sudo "$(which toolkit)" recon 10.10.42.17 --writeup --room "Room Name"
```

- **Why `sudo`?** It allows faster SYN scans and the UDP scan. Without it, recon still works with
  slower TCP-connect scans and no UDP.
- **Why `"$(which toolkit)"`?** `sudo` doesn't search your personal PATH (`~/.local/bin`), so
  you pass it the full path to the command.
- **`--writeup --room ...`** also starts a writeup file for you. It's optional.

**4. Wait.** You'll see three stages: a full port sweep, a service/version scan on the open ports,
then follow-up modules for each service (web, FTP, SMB and so on). A typical box takes 2-10
minutes. Want a faster first look? Add `--profile quick`.

---

## 4. Reading the results

At the end, recon prints a ranked **Where to start** list. These are the most promising leads,
each with a copy-paste command. Then it prints where everything was saved:

```
[+] Saved in: ~/results/10.10.42.17/
    open the report: xdg-open ~/results/10.10.42.17/report.html
```

Results go into `results/<target>/` **inside the folder you ran the command from**. Copy the
`xdg-open` line to open the report in your browser (on macOS use `open`).

| File | What it is |
|---|---|
| `report.html` | The full report: leads, open ports, findings by severity, nmap script output and every command run. Easiest to read. |
| `report.md` | The same report in Markdown, for notes or GitHub. |
| `writeup.md` | (with `--writeup`) A writeup skeleton with the recon section filled in. Drop it into Obsidian or your writeups repo. |
| `findings.json` | Everything, machine-readable, for your own scripts. |
| `nmap-*.xml`, `gobuster-*.txt`, ... | Raw output from each tool, in case you want to dig in. |

To open them in apps:

```bash
xdg-open ~/results/10.10.42.17/report.html    # browser
xdg-open ~/results/10.10.42.17/writeup.md     # your default Markdown app
xdg-open ~/results/10.10.42.17/               # file manager
```

**Tip: keep every scan in one place.** Tell recon where to save results once, and every run goes
there no matter which folder you're in:

```bash
mkdir -p ~/.config/soul-toolkit
printf '[recon]\noutput = ~/ctf/results\n' > ~/.config/soul-toolkit/config.ini
toolkit config | grep output      # check it's picked up
```

---

## 5. Everyday use

```bash
# The normal full run
sudo "$(which toolkit)" recon 10.10.42.17

# Quick first look: top 1000 ports, no UDP, lighter web checks
toolkit recon 10.10.42.17 --profile quick

# Leave it running for a while: bigger wordlists, longer web budget
sudo "$(which toolkit)" recon 10.10.42.17 --profile thorough

# You already know the ports - skip the sweep
toolkit recon 10.10.42.17 -p 21,22,80

# The site redirected to a name (e.g. box.thm): add it to /etc/hosts, then scan the name
echo '10.10.42.17 box.thm' | sudo tee -a /etc/hosts
toolkit recon box.thm -p 80

# Re-run the modules (new wordlist, after Ctrl-C...) without waiting for nmap again
toolkit recon 10.10.42.17 --resume

# Only some modules, or no brute-forcing at all
toolkit recon 10.10.42.17 -m web,ftp
toolkit recon 10.10.42.17 --no-brute

# Help
toolkit recon --help
toolkit recon --list-modules
```

**Ctrl-C is safe.** It stops the running tools and still writes a partial report that lists what
didn't finish. Run again with `--resume` to pick up where you left off.

For every setting, see `toolkit recon --help` and the README's
[Usage](../README.md#usage) and [Config file](../README.md#config-file) sections.

---

## 6. Updating and uninstalling

```bash
pipx reinstall soul-toolkit        # update to the latest version
toolkit --version                  # check which version you have
pipx uninstall soul-toolkit        # remove it
```

---

## 7. Troubleshooting

**`toolkit: command not found`**
`~/.local/bin` isn't on your PATH yet. Run `pipx ensurepath`, then open a new terminal. If you
installed with a venv instead of pipx, activate it first: `source .venv/bin/activate`.

**`sudo: toolkit: command not found`**
`sudo` doesn't search your personal PATH. Use `sudo "$(which toolkit)" recon ...`.

**`error: externally-managed-environment`** when running `pip install`
Your distro protects its system Python. Install with `pipx` (step 2), or, if you're working on
the code, activate the project's venv first (`source .venv/bin/activate`) and run pip there.

**`No open TCP ports found.`** (or very few ports)
- Is the VPN still connected? Run `ip -br addr show tun0` and check the openvpn terminal.
- Has the machine finished booting? Wait a minute and try again.
- Is it the right IP? Machines get a new IP every time you start them.
- If you scanned with `--profile quick` or `-p`, try the default full sweep: some boxes hide
  services on high ports.

**It's taking a long time**
The full port sweep plus the UDP scan (as root) is the slow part. For a faster run use
`--profile quick`, or add `--no-udp`. Long web scans are capped by `--brute-timeout`.

**`[!] <tool> not installed - skipping ...`**
That's expected for optional tools you haven't installed. `toolkit doctor` shows the install
command for your distro.

**`Permission denied` when saving results**
You ran it from a folder you can't write to. `cd` somewhere in your home folder first, or pass
`-o ~/ctf/results`.

**Results folder owned by root** (from very old versions)
Current versions hand the files back to you automatically. To fix an old folder:
`sudo chown -R "$USER:" results`.

**WSL2: no open ports / can't reach the target**
Run the VPN *inside* WSL (`sudo openvpn your.ovpn` in the WSL terminal), not with the Windows
OpenVPN client. WSL1 can't do the raw scans recon needs, so upgrade with `wsl --set-version <distro> 2`.

**Something else broke?**
Open an issue on GitHub with the full terminal output (run with `-v` to include every command)
and the output of `toolkit doctor`. Reports replace your home folder with `~`, but check for
anything else personal before you post.
