"""Print the GitHub release notes for a tag, built from CHANGELOG.md.

    python3 scripts/release_notes.py v0.3.0 > notes.md

Fails (exit 1) instead of printing anything when the tag doesn't match the version in
pyproject.toml and src/soul_toolkit/__init__.py, or when CHANGELOG.md has no dated section for
it - so the release workflow never publishes notes for the wrong version.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://github.com/Soulsagate/soul-toolkit"


def _version(path: Path, pattern: str) -> str:
    m = re.search(pattern, path.read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else ""


def changelog_section(changelog: str, version: str) -> str:
    """The body of the `## <version> - <date>` section, without its heading."""
    m = re.search(rf"^## {re.escape(version)} - \d{{4}}-\d{{2}}-\d{{2}}\n(.*?)(?=^## |\Z)", changelog, re.S | re.M)
    if not m or not m.group(1).strip():
        raise ValueError(f"CHANGELOG.md has no dated, non-empty '## {version} - YYYY-MM-DD' section")
    return m.group(1).strip()


def absolute_links(text: str, tag: str) -> str:
    """Relative Markdown links (docs/x.md) point nowhere on a release page; pin them to the tag."""
    return re.sub(r"\]\((?!https?://|#|mailto:)([^)]+)\)", rf"]({REPO}/blob/{tag}/\1)", text)


def notes(tag: str, root: Path = ROOT) -> str:
    version = tag[1:] if tag.startswith("v") else tag
    found = {
        "pyproject.toml": _version(root / "pyproject.toml", r'^version = "([^"]+)"'),
        "src/soul_toolkit/__init__.py": _version(root / "src/soul_toolkit/__init__.py", r'^__version__ = "([^"]+)"'),
    }
    wrong = [f"{f} says {v or 'nothing'}" for f, v in found.items() if v != version]
    if not tag.startswith("v") or wrong:
        raise ValueError(f"tag {tag} doesn't match the code: {'; '.join(wrong) or 'tags look like v1.2.3'}")
    body = changelog_section((root / "CHANGELOG.md").read_text(encoding="utf-8"), version)
    install = f"```bash\npipx install git+{REPO}@{tag}\n```"
    return f"{install}\n\n{absolute_links(body, tag)}\n"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: release_notes.py vX.Y.Z")
    try:
        sys.stdout.write(notes(sys.argv[1]))
    except ValueError as exc:
        sys.exit(f"release_notes: {exc}")
