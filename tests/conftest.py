import pytest


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch, tmp_path_factory):
    """Never let the developer's own ~/.config/soul-toolkit/config.ini change test results."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path_factory.mktemp("xdg")))
    monkeypatch.delenv("SUDO_USER", raising=False)
