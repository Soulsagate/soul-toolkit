import pytest

from soul_toolkit.core import runner
from soul_toolkit.core.models import Finding, HostResult, Service
from soul_toolkit.core.target import InvalidTarget, safe_dirname, validate_target


@pytest.mark.parametrize("t", ["10.10.10.10", "127.0.0.1", "::1", "box.thm", "sub.example.com", "localhost"])
def test_valid_targets(t):
    assert validate_target(t) == t


@pytest.mark.parametrize("t", ["", "10.10.10.0/24", "bad host", "-x.thm", "a;id", "$(id)", "http://x.thm"])
def test_invalid_targets(t):
    with pytest.raises(InvalidTarget):
        validate_target(t)


def test_safe_dirname():
    assert safe_dirname("fe80::1") == "fe80__1"
    assert safe_dirname("10.10.10.10") == "10.10.10.10"


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        Finding("x", 1, "t", severity="critical")


def test_sorted_findings_order():
    r = HostResult("t")
    r.findings = [
        Finding("web", 80, "a", "info"),
        Finding("ftp", 21, "b", "high"),
        Finding("web", 80, "c", "medium"),
    ]
    assert [f.severity for f in r.sorted_findings()] == ["high", "medium", "info"]


def test_service_web_detection_by_port():
    assert Service(8080, name="").is_web
    assert Service(8080, name="http-proxy").is_web
    assert not Service(8080, name="mysql").is_web
    assert Service(443, name="https").is_tls


def test_runner_captures_output():
    res = runner.run(["python3", "-c", "import sys; print('hi'); sys.stderr.write('err'); sys.exit(3)"])
    assert res.returncode == 3 and res.stdout.strip() == "hi" and res.stderr == "err"
    assert not res.ok


def test_runner_timeout():
    res = runner.run(["python3", "-c", "import time; time.sleep(5)"], timeout=0.5)
    assert res.timed_out and not res.ok


def test_require_missing_tool():
    with pytest.raises(runner.ToolMissing):
        runner.require("definitely-not-a-real-tool-xyz")
