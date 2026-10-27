import pytest

from soul_toolkit import cli
from soul_toolkit.recon import engine, settings


@pytest.fixture
def captured(monkeypatch):
    seen = []
    monkeypatch.setattr(engine, "run_recon", lambda cfg, log: seen.append(cfg))
    return seen


def recon(captured, *flags):
    assert cli.main(["recon", "10.10.10.10", "-q", *flags]) == 0
    return captured[-1]


def test_resolve_layers():
    none = dict.fromkeys(settings.DEFAULTS)
    assert settings.resolve(none) == settings.DEFAULTS
    quick = settings.resolve(none, "quick")
    assert quick["quick"] and quick["udp"] is False and quick["brute_timeout"] == 180
    # an explicit value beats the profile, False included
    s = settings.resolve({**none, "udp": True, "recurse": False, "threads": 50}, "quick")
    assert s["udp"] is True and s["recurse"] is False and s["threads"] == 50
    with pytest.raises(ValueError):
        settings.resolve(none, "nope")


def test_thorough_uses_bigger_lists_only_when_present(monkeypatch):
    monkeypatch.setattr(settings, "_first_file", lambda c: None)
    assert "wordlist" not in settings.profile_values("thorough")
    monkeypatch.setattr(settings, "_first_file", lambda c: c[0])
    v = settings.profile_values("thorough")
    assert v["wordlist"].endswith("raft-medium-directories.txt")
    assert v["vhost_wordlist"].endswith("subdomains-top1million-20000.txt")


def test_cli_defaults_unchanged(captured):
    cfg = recon(captured)
    assert cfg.full and cfg.udp is None and cfg.scripts and cfg.min_rate == 1000
    o = cfg.options
    assert (o.brute, o.vhosts, o.recurse, o.threads, o.brute_timeout, o.extensions) == (True, True, True, 30, 600, "")
    assert str(cfg.output) == "results"


def test_cli_profile_quick(captured):
    cfg = recon(captured, "--profile", "quick")
    assert not cfg.full and cfg.udp is False and not cfg.options.recurse and not cfg.options.vhosts
    assert cfg.options.brute_timeout == 180


def test_cli_flags_beat_profile(captured):
    cfg = recon(captured, "--profile", "quick", "--udp", "--brute-timeout", "60", "-t", "10")
    assert cfg.udp is True and cfg.options.brute_timeout == 60 and cfg.options.threads == 10
    cfg = recon(captured, "--profile", "thorough", "--no-recurse", "--no-udp", "-w", "/tmp/words.txt")
    assert cfg.options.recurse is False and cfg.udp is False and cfg.options.wordlist == "/tmp/words.txt"


def test_cli_negative_flags(captured):
    cfg = recon(captured, "--no-brute", "--no-vhost", "--no-scripts", "--quick", "--min-rate", "0")
    assert not cfg.options.brute and not cfg.options.vhosts and not cfg.scripts and not cfg.full
    assert cfg.min_rate is None


def test_cli_rejects_unknown_profile(capsys):
    with pytest.raises(SystemExit):
        cli.main(["recon", "10.10.10.10", "--profile", "turbo"])
