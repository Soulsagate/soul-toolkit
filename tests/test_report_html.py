import re
from html.parser import HTMLParser
from pathlib import Path

from soul_toolkit.core.models import Finding, HostResult, Lead
from soul_toolkit.recon import nmap
from soul_toolkit.recon.report import write_reports
from soul_toolkit.recon.report_html import render_html

FIXTURE = Path(__file__).parent / "fixtures" / "services.xml"
VOID = {"meta", "br", "img", "input", "link", "hr"}


def sample() -> HostResult:
    h = nmap.parse_xml(FIXTURE.read_text())[0]
    r = HostResult(target="10.10.10.10", address=h.address, hostnames=h.hostnames, status=h.status,
                   services=h.services, started="2026-10-27 00:00:00 UTC", duration=75)
    r.findings = [
        Finding("web", 80, "Content discovery: 1 path(s)", "info", "wordlist: test",
                {"paths": [{"path": "/admin", "status": 301, "size": 10, "redirect": "/admin/"}]}),
        Finding("ftp", 21, "Anonymous FTP login allowed", "high", "1 entry", {"listing": ["note.txt"]}),
        Finding("smb", 445, "Null session can list SMB shares", "medium", "anon",
                {"shares": [{"type": "Disk", "name": "anon", "comment": "a<b"}]}),
        Finding("web", 80, "Virtual hosts found: dev.box.thm", "medium", "Add to /etc/hosts: `x`",
                {"vhosts": [{"host": "dev.box.thm", "status": 200, "size": 47}],
                 "hosts_line": "10.10.10.10 box.thm dev.box.thm"}),
        Finding("exploits", 21, "Exploit-DB: 1 candidate(s)", "medium", "",
                {"exploits": [{"edb_id": "49757", "title": "vsftpd 2.3.4 - Backdoor Command Execution",
                               "type": "remote", "platform": "unix", "verified": True, "codes": ""}]}),
        Finding("web", 80, "<script>alert(1)</script>", "low", "x & y"),
    ]
    r.leads = [Lead("ftp-anon", 21, "Download everything", "Run `wget` now", "wget -m ftp://x/", 85)]
    r.hints = ["Install gobuster"]
    r.commands = ["nmap -sT 10.10.10.10"]
    return r


class _Balance(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack, self.errors = [], []

    def handle_starttag(self, tag, attrs):
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}> with stack {self.stack[-3:]}")
        else:
            self.stack.pop()


def test_html_is_well_formed():
    p = _Balance()
    p.feed(render_html(sample()))
    assert p.errors == [] and p.stack == []


def test_html_is_self_contained():
    out = render_html(sample())
    assert "<style>" in out and "<script>" in out
    assert not re.search(r"""<(link|script|img)[^>]+(href|src)=["']?https?:""", out)
    assert "@import" not in out


def test_html_escapes_untrusted_text():
    out = render_html(sample())
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "a&lt;b" in out and "x &amp; y" in out


def test_html_themes_and_severity():
    out = render_html(sample())
    assert "prefers-color-scheme:dark" in out and ":root[data-theme=dark]" in out
    assert '<details class="finding sev-high" open>' in out
    assert '<details class="finding sev-medium" open>' in out
    assert '<details class="finding sev-info">' in out  # low/info start collapsed
    assert '<span class="pill sev-high">high: 1</span>' in out
    # high first
    assert out.index("Anonymous FTP login allowed") < out.index("Null session") < out.index("Content discovery")


def test_html_where_to_start_and_bodies():
    out = render_html(sample())
    assert out.index('id="where-to-start"') < out.index('id="ports"')
    assert '<pre data-copy><code>wget -m ftp://x/</code></pre>' in out
    assert "Run <code>wget</code> now" in out  # Markdown backticks become <code>
    assert "<code>/admin</code>" in out and "<code>dev.box.thm</code>" in out
    assert "echo &#x27;10.10.10.10 box.thm dev.box.thm&#x27; | sudo tee -a /etc/hosts" in out
    assert "49757" in out and "vsftpd 2.3.4 - Backdoor Command Execution" in out
    assert "note.txt" in out and "Install gobuster" in out and "1m 15s" in out


def test_html_empty_result():
    out = render_html(HostResult("10.10.10.10"))
    assert "Nothing stood out" in out and "No open ports found" in out and "No findings" in out


def test_write_reports_writes_html(tmp_path):
    md, _ = write_reports(sample(), tmp_path)
    html_path = md.with_suffix(".html")
    assert html_path.name == "report.html" and html_path.read_text().startswith("<!doctype html>")
