import os

import pytest

from soul_toolkit.recon import engine


def test_sudo_owner_requires_root_and_env(monkeypatch):
    monkeypatch.setattr(engine, "is_root", lambda: True)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")
    assert engine.sudo_owner() == (1000, 1000)
    monkeypatch.setenv("SUDO_UID", "0")
    assert engine.sudo_owner() is None
    monkeypatch.delenv("SUDO_UID")
    assert engine.sudo_owner() is None
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setattr(engine, "is_root", lambda: False)
    assert engine.sudo_owner() is None


def test_hand_back_noop_without_owner(tmp_path):
    engine.hand_back(None, tmp_path)  # must not raise


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to chown")
def test_hand_back_chowns_tree(tmp_path):
    base = tmp_path / "results"
    tree = base / "10.10.10.10"
    tree.mkdir(parents=True)
    (tree / "report.md").write_text("x")
    engine.hand_back((65534, 65534), tree, base)
    for p in (base, tree, tree / "report.md"):
        assert p.stat().st_uid == 65534
    assert tmp_path.stat().st_uid != 65534  # never climbs above the output dir


# ----------------------------------------------------------------- where results are saved


def test_display_path_uses_tilde_for_home(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "_home", lambda: tmp_path)
    assert engine.display_path(tmp_path / "results" / "10.10.10.10") == "~/results/10.10.10.10"
    assert engine.display_path(tmp_path) == "~"


def test_display_path_outside_home_is_absolute(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "_home", lambda: tmp_path / "somebody")
    out = tmp_path / "scans" / "box"
    assert engine.display_path(out) == str(out.resolve())


def test_display_path_resolves_relative(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "_home", lambda: tmp_path)
    monkeypatch.chdir(tmp_path)
    assert engine.display_path(engine.Path("results/box")) == "~/results/box"


def test_open_command(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "_home", lambda: tmp_path)
    monkeypatch.setattr(engine.sys, "platform", "linux")
    assert engine.open_command(tmp_path / "results" / "box" / "report.html") == \
        "xdg-open ~/results/box/report.html"
    monkeypatch.setattr(engine.sys, "platform", "darwin")
    assert engine.open_command(tmp_path / "r.html").startswith("open ~/")


def test_open_command_quotes_unsafe_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "_home", lambda: tmp_path)
    monkeypatch.setattr(engine.sys, "platform", "linux")
    cmd = engine.open_command(tmp_path / "my scans" / "report.html")
    assert cmd == f"xdg-open '{(tmp_path / 'my scans' / 'report.html').resolve()}'"
