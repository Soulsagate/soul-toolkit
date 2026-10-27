# Contributing

Thanks for wanting to make soul-toolkit better. It's a recon tool for **authorized** labs and
CTFs; every contribution has to keep it that way (see [DISCLAIMER.md](DISCLAIMER.md)).

## What we're building

Tools like AutoRecon already scan broadly. This one tries to win on two things:

1. telling the user **exactly what to try next**, ranked (the "Where to start" list), and
2. output they can **use immediately** - reports, writeups.

A good change serves one of those, or makes the tool easier to install and run.

## Ground rules

- **Python 3.9+, standard library only** at runtime. Dev tools (pytest, ruff) are fine.
- **Wrap existing tools** (nmap, gobuster, ffuf, searchsploit, smbclient, showmount, snmpwalk...)
  instead of reimplementing them. A missing optional tool is a warning plus an install hint,
  never a crash.
- **Recon only.** No exploitation, no brute-forcing logins, nothing that writes to the target.
  Suggesting the next command in a lead is fine; running it isn't.
- **Commands are argument lists**, never shell strings (`ctx.run(["tool", "-x", target])`).
- **Every feature ships with tests that run offline**: recorded output as fixtures, fakes for
  `runner.run`, or throwaway servers on `127.0.0.1`. Tests that need a real tool or Docker skip
  when it's missing.
- **No fabricated output in the README or docs.** Example output must come from a real run, e.g.
  against the lab in [`tests/lab/`](tests/lab/).
- **No personal info** in any file: no real names, emails, or home-directory paths (reports scrub
  your home directory to `~`; fixtures must too).

## Setup

```bash
git clone https://github.com/Soulsagate/soul-toolkit.git
cd soul-toolkit
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
toolkit doctor        # which external tools you have
```

## Before you open a pull request

```bash
ruff check .
pytest -q
```

CI runs the same on Python 3.9-3.13. Then try your change for real - the lab gives you a
deliberately vulnerable box on your own machine:

```bash
docker compose -f tests/lab/docker-compose.yml up -d --build
toolkit recon 172.29.99.10
```

## Adding a service module

Most contributions are a new module (one file in `src/soul_toolkit/recon/modules/`).
[docs/writing-a-module.md](docs/writing-a-module.md) walks through one end to end: the module
interface, registering it, giving its lead a score, tests, and docs.

## Commits

One focused commit per change, with a message that says what changed and **why** - note any
non-obvious decision (a default you picked, something you deliberately didn't do). Add a line to
[CHANGELOG.md](CHANGELOG.md) under "Unreleased".

## Releasing

1. Move the "Unreleased" entries into a dated `## X.Y.Z - YYYY-MM-DD` section of CHANGELOG.md and
   set the same version in `pyproject.toml` and `src/soul_toolkit/__init__.py`.
2. Once CI is green on main, push an annotated tag:
   `git tag -a vX.Y.Z -m "soul-toolkit vX.Y.Z" && git push origin vX.Y.Z`.
3. The Release workflow publishes the GitHub release, with that CHANGELOG section as its notes
   (`scripts/release_notes.py`), then uploads the same version to PyPI with trusted publishing.
   It refuses to publish if the tag and the code disagree.
