from pathlib import Path
from types import SimpleNamespace

import pytest

from soul_toolkit import cli
from soul_toolkit.recon import engine, settings


@pytest.fixture
def captured(monkeypatch):
    seen = []
    monkeypatch.setattr(engine, "run_recon", lambda cfg, log: seen.append(cfg))
    return seen


def write(tmp_path, body, name="config.ini"):
    p = tmp_path / name
    p.write_text(body)
    return p


def test_missing_file_is_fine(tmp_path):
    assert settings.load_config(tmp_path / "nope.ini") == ({}, None, [])


def test_values_are_typed_and_paths_expanded(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "user_home", lambda: Path("/home/learner"))
    p = write(tmp_path, "[recon]\nprofile = thorough\nthreads = 50\nrecurse = no\nudp = auto\n"
                        "wordlist = ~/lists/dirs.txt\noutput = ~/ctf\nextensions = php,txt\nmystery = 1\n")
    values, profile, warnings = settings.load_config(p)
    assert profile == "thorough"
    assert values == {"threads": 50, "recurse": False, "udp": None, "wordlist": "/home/learner/lists/dirs.txt",
                      "output": "/home/learner/ctf", "extensions": "php,txt"}
    assert warnings == [f"{p}: unknown setting 'mystery' ignored"]
    assert settings.load_config(write(tmp_path, "[recon]\nudp = yes\n", "b.ini"))[0] == {"udp": True}


@pytest.mark.parametrize("body,match", [
    ("[recon]\nthreads = lots\n", "threads = 'lots'"),
    ("[recon]\nrecurse = maybe\n", "recurse = 'maybe'"),
    ("[recon]\nprofile = turbo\n", "profile = 'turbo'"),
    ("not an ini file", "File contains no section headers"),
])
def test_bad_values_raise(tmp_path, body, match):
    with pytest.raises(settings.ConfigError, match=match):
        settings.load_config(write(tmp_path, body))


def test_no_recon_section_warns(tmp_path):
    values, profile, warnings = settings.load_config(write(tmp_path, "[other]\nx = 1\n"))
    assert values == {} and profile is None and "no [recon] section" in warnings[0]


def test_user_home_under_sudo(monkeypatch):
    monkeypatch.setattr(settings.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "learner")
    monkeypatch.setattr(settings.pwd, "getpwnam", lambda name: SimpleNamespace(pw_dir=f"/home/{name}"))
    assert settings.user_home() == Path("/home/learner")
    assert settings.default_config_path() == Path("/home/learner/.config/soul-toolkit/config.ini")
    monkeypatch.setenv("SUDO_USER", "root")
    assert settings.user_home() == Path.home()


def test_xdg_config_home(monkeypatch, tmp_path):
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert settings.default_config_path() == tmp_path / "soul-toolkit" / "config.ini"


def test_precedence_through_the_cli(tmp_path, captured):
    p = write(tmp_path, "[recon]\nprofile = quick\nbrute_timeout = 900\nthreads = 12\noutput = /tmp/ctf\njobs = 6\n")
    cli.main(["recon", "10.10.10.10", "-q", "--config", str(p)])
    cfg = captured[-1]
    # profile from the config (quick: no UDP, top 1000), config beats profile (900 not 180)
    assert not cfg.full and cfg.udp is False and cfg.options.brute_timeout == 900
    assert cfg.options.threads == 12 and str(cfg.output) == "/tmp/ctf" and cfg.jobs == 6
    # flags beat the config, and --profile beats the config's profile
    cli.main(["recon", "10.10.10.10", "-q", "--config", str(p), "-t", "40", "--profile", "default"])
    cfg = captured[-1]
    assert cfg.full and cfg.options.threads == 40 and cfg.options.brute_timeout == 900


def test_cli_config_errors(tmp_path, captured):
    assert cli.main(["recon", "10.10.10.10", "-q", "--config", str(tmp_path / "missing.ini")]) == 2
    bad = write(tmp_path, "[recon]\njobs = many\n")
    assert cli.main(["recon", "10.10.10.10", "-q", "--config", str(bad)]) == 2
    assert captured == []


def test_config_init_and_show(tmp_path, capsys):
    p = tmp_path / "sub" / "config.ini"
    assert cli.main(["config", "--init", "--path", str(p)]) == 0
    assert cli.main(["config", "--init", "--path", str(p)]) == 1  # never overwrites
    values, profile, warnings = settings.load_config(p)
    assert values == {} and profile == "default" and warnings == []  # the example is all comments
    p.write_text(p.read_text() + "threads = 64\n")
    capsys.readouterr()
    assert cli.main(["config", "--path", str(p)]) == 0
    out = capsys.readouterr().out
    assert f"Config file: {p} (found)" in out
    assert "threads         64" in out and "(config)" in out
    assert "brute_timeout   600" in out and "(default)" in out
