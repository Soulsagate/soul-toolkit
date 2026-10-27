# Writing a recon module

A module looks at one open service and decides what to do about it. Everything the toolkit knows
about FTP, SMB, Redis and the rest lives in one small file per service in
[`src/soul_toolkit/recon/modules/`](../src/soul_toolkit/recon/modules/). This guide builds a new
one from scratch: an `rsync` module that lists the modules an rsync daemon shares without a
password (a classic way into CTF boxes).

The example below was run against a real `rsync --daemon` before it went into this document.

## The contract

```python
class Module:
    name = "base"                  # used by -m/--modules and in reports
    description = ""               # shown by --list-modules
    protocols = ("tcp",)           # which services the engine offers you ("udp" for SNMP-style modules)

    def matches(self, svc: Service) -> bool: ...                    # cheap, no network
    def run(self, ctx: Context, svc: Service) -> list[Finding]: ...  # the actual work
```

The engine runs `run()` once for every open service where `matches()` is true, in parallel with
other modules (`--jobs`). Each run gets its own `Context`, so you never need locks unless your
module keeps state on `self` (see `exploits.py` for that case).

What `run()` gets:

| | |
|---|---|
| `svc` | the nmap result for this port: `port`, `protocol`, `name`, `product`, `version`, `extrainfo`, `tunnel` (`"ssl"`), `hostname`, `scripts` (NSE id → output), `banner`, `label` (`"873/tcp"`) |
| `ctx.target` | what the user typed (IP or hostname); `ctx.host_for_url()` brackets IPv6, `ctx.target_ip()` gives an IP for `/etc/hosts` lines |
| `ctx.run(cmd, timeout)` | run an external tool. **Always an argument list, never a shell string.** It is logged in the report's "Commands run" and stopped cleanly on Ctrl-C |
| `ctx.lead(kind, port, title, why, command)` | something worth trying next - this is what feeds **Where to start** |
| `ctx.hint(text)` | a plain idea for the "Other leads and ideas" list |
| `ctx.log` | `info` / `ok` / `warn` / `error` / `debug` console output |
| `ctx.options` | user settings: `http_timeout`, `threads`, `brute`, wordlists ... |
| `ctx.outdir` | where raw output files can go (`<tool>-<port>.txt`) |
| `ctx.result.services` | every open service on the host, read-only - for cross-service rules |

What it returns: a list of `Finding(module, port, title, severity, detail, data)`. Severity is
`info`, `low`, `medium` or `high`. `data` is anything JSON-able; two shapes are rendered by the
Markdown and HTML reports for free:

```python
{"table": {"headers": ["Module", "Comment"], "rows": [["backup", "nightly backups"]]}}
{"lines": ["raw output line", "another line"]}
```

## The rules

These are the project's hard rules, and reviews will check them:

- **Wrap existing tools, don't reimplement them.** If a tool does the job (rsync, smbclient,
  showmount, searchsploit...), run it with `ctx.run`. A short stdlib protocol probe is fine when
  no tool fits or the tool is broken (the `mysql` module's docstring explains why it doesn't use
  nmap's script).
- **A missing optional tool is a warning plus an install hint, never a crash.** Check with
  `runner.which()` first.
- **Recon only.** Listing, banners, default/anonymous access checks - yes. Exploits, brute-forcing
  logins, writing to the target - no. Leads can *suggest* the next command; the user runs it.
- **Standard library only** at runtime.
- **Every module ships with tests that run offline.**

## Step 1 - the module

`src/soul_toolkit/recon/modules/rsync.py`:

```python
"""rsync follow-ups: list the modules an rsync daemon offers without credentials."""

from __future__ import annotations

from soul_toolkit.core import runner
from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module


def parse_modules(output: str) -> list[dict]:
    """`rsync --list-only rsync://host/` prints one module per line: the name, padding, a tab, the comment."""
    mods = []
    for line in output.splitlines():
        name, _, comment = line.partition("\t")
        name = name.strip()
        if name and not name.startswith("@"):  # "@RSYNCD: ..." lines are protocol chatter
            mods.append({"name": name, "comment": comment.strip()})
    return mods


class RsyncModule(Module):
    name = "rsync"
    description = "rsync: list modules readable without credentials"

    def matches(self, svc: Service) -> bool:
        return svc.name.lower() == "rsync" or svc.port == 873

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        if not runner.which("rsync"):
            ctx.log.warn("rsync not installed - skipping rsync module listing")
            ctx.hint("Install rsync to list rsync modules.")
            return []

        url = f"rsync://{ctx.host_for_url()}:{svc.port}/"
        ctx.log.info(f"{svc.label} rsync: listing modules")
        res = ctx.run(["rsync", "--list-only", "--timeout=20", url], timeout=30)
        mods = parse_modules(res.stdout)
        if not mods:
            return [Finding(self.name, svc.port, "rsync lists no modules", "info", res.stderr.strip()[:200])]

        first = mods[0]["name"]
        ctx.lead("rsync-module", svc.port, f"Download the rsync module '{first}'",
                 "rsync modules often hold backups and home directories, readable without a password.",
                 f"rsync -av {url}{first}/ ./rsync-{first}/")
        rows = [[m["name"], m["comment"]] for m in mods]
        return [Finding(self.name, svc.port, f"rsync modules listed without credentials ({len(mods)})", "medium",
                        ", ".join(m["name"] for m in mods),
                        {"table": {"headers": ["Module", "Comment"], "rows": rows}})]
```

Things worth copying from it:

- the missing-tool check comes first and only warns;
- the parser is a plain function, so it can be tested with recorded output;
- an empty result is still a finding (`info`), so the report says the check ran;
- the lead's command is something a learner can paste as-is.

## Step 2 - register it

Add it to `all_modules()` in
[`src/soul_toolkit/recon/modules/__init__.py`](../src/soul_toolkit/recon/modules/__init__.py)
(before `ExploitsModule`, which stays last):

```python
    from soul_toolkit.recon.modules.rsync import RsyncModule
    ...
        PostgresModule(), RedisModule(), RdpModule(), WinrmModule(), LdapModule(), RsyncModule(),
```

## Step 3 - give its lead a score

Modules never choose their own rank. Add the lead kind to `SCORES` in
[`src/soul_toolkit/recon/leads.py`](../src/soul_toolkit/recon/leads.py), next to leads of similar
value - readable rsync modules are about as good as an SMB share anyone can open:

```python
    "smb-share": 75,             # a readable-looking share via null session
    "rsync-module": 75,          # rsync module readable without a password
```

An unknown kind raises an error the first time the lead is reported, so a typo can't silently
sink a lead to the bottom of the list.

## Step 4 - tests

`tests/test_rsync.py`. Feed the parser output recorded from a real run (say where it came from),
fake `runner.run` for the module, and cover the missing-tool path:

```python
from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon.modules import Context, Options
from soul_toolkit.recon.modules.rsync import RsyncModule, parse_modules

# Real `rsync --list-only rsync://127.0.0.1:18873/` output (rsync 3.2.7): name, padding, a tab, comment
# (the second module has no comment)
LISTING = "backup         \tnightly backups\nhome           \t\n"


def make_ctx(tmp_path):
    return Context(target="10.10.10.10", outdir=tmp_path, log=Logger(quiet=True),
                   result=HostResult("10.10.10.10"), options=Options())


def test_parse_modules():
    assert parse_modules(LISTING) == [{"name": "backup", "comment": "nightly backups"},
                                      {"name": "home", "comment": ""}]


def test_module_lists_and_leads(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "which", lambda tool: "/usr/bin/" + tool)
    monkeypatch.setattr(runner, "run", lambda cmd, timeout=None: runner.CommandResult(cmd, 0, LISTING, "", 0.1))
    ctx = make_ctx(tmp_path)
    [f] = RsyncModule().run(ctx, Service(873, name="rsync"))
    assert f.severity == "medium" and f.detail == "backup, home"
    assert ctx.result.leads[0].command == "rsync -av rsync://10.10.10.10:873/backup/ ./rsync-backup/"


def test_missing_rsync_is_a_warning(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "which", lambda tool: None)
    ctx = make_ctx(tmp_path)
    assert RsyncModule().run(ctx, Service(873, name="rsync")) == []
    assert ctx.result.hints == ["Install rsync to list rsync modules."]
```

Also add `"rsync"` to the expected set in `test_select_modules` (`tests/test_modules.py`) - it
pins the full module list on purpose, so a module can't appear or vanish unnoticed.

If the real tool is easy to start locally, add a test that does, and skip it when the tool isn't
installed (`pytest.mark.skipif(not shutil.which("rsync"), ...)`) - see `tests/test_snmp.py` and
`tests/test_redis.py`.

## Step 5 - tell people about it

- a row in the **Service modules** table in the README;
- if it needs a new external tool: a row in the README's tools table **and** an entry in `TOOLS` in
  [`src/soul_toolkit/doctor.py`](../src/soul_toolkit/doctor.py), with the package name for Arch,
  Debian/Kali and macOS (`toolkit doctor` prints those install commands, so check them);
- a line under "Unreleased" in [CHANGELOG.md](../CHANGELOG.md).

Then run what CI runs:

```bash
ruff check .
pytest -q
```

and try it for real: `toolkit recon <lab-ip> -m rsync -v`.
