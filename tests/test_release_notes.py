import importlib.util
from pathlib import Path

import pytest

from soul_toolkit import __version__

SCRIPT = Path(__file__).parent.parent / "scripts" / "release_notes.py"
spec = importlib.util.spec_from_file_location("release_notes", SCRIPT)
rn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rn)


def test_notes_for_the_current_version():
    tag = f"v{__version__}"
    out = rn.notes(tag)
    assert out.startswith(f"```bash\npipx install git+https://github.com/Soulsagate/soul-toolkit@{tag}\n```\n\n")
    assert f"## {__version__}" not in out  # heading left out: the release title already says it
    assert "](docs/" not in out            # relative links pinned to the tag


def test_wrong_tag_or_missing_section_is_refused():
    with pytest.raises(ValueError, match="doesn't match"):
        rn.notes("v9.9.9")
    with pytest.raises(ValueError, match="doesn't match"):
        rn.notes(__version__)  # no leading v
    with pytest.raises(ValueError, match="no dated"):
        rn.changelog_section("## 1.0.0\n\n- undated\n", "1.0.0")
    with pytest.raises(ValueError, match="no dated"):
        rn.changelog_section("## 1.0.0 - 2026-01-01\n\n## 0.9.0 - 2025-01-01\n- x\n", "1.0.0")


def test_section_stops_at_the_next_heading_and_links_are_pinned():
    log = ("## Unreleased\n\n## 1.0.0 - 2026-01-01\n\n- See [guide](docs/g.md) and [x](https://e.x/).\n\n"
           "## 0.9.0 - 2025-01-01\n\n- old\n")
    body = rn.changelog_section(log, "1.0.0")
    assert body == "- See [guide](docs/g.md) and [x](https://e.x/)."
    assert rn.absolute_links(body, "v1.0.0") == (
        "- See [guide](https://github.com/Soulsagate/soul-toolkit/blob/v1.0.0/docs/g.md) and [x](https://e.x/).")
