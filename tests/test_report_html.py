import re
from html.parser import HTMLParser
from pathlib import Path

from soul_toolkit.core.models import Finding, HostResult, Lead, Service
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
    # nothing that would make the browser fetch anything: reports hold scan data and get opened offline
    assert not re.search(r"""(href|src|action|srcset)=["']?(https?:|//)""", out)
    assert "@import" not in out and "url(" not in out and "@font-face" not in out
    assert not re.search(r"<(link|img|iframe|object|embed)\b", out)


def test_html_no_urls_outside_escaped_text():
    r = sample()
    r.findings.append(Finding("web", 80, "Redirect", "info", "GET / -> 302 http://box.thm/"))
    out = render_html(r)
    # the only URL is the escaped finding text, rendered as text
    assert re.findall(r"https?://[^\s<\"]+", out) == ["http://box.thm/"]


def test_html_escapes_untrusted_text():
    r = sample()
    r.target = '"><img src=x onerror=alert(1)>'
    r.commands = ["curl '<b>'"]
    out = render_html(r)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "a&lt;b" in out and "x &amp; y" in out
    assert "<img" not in out and "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in out
    assert "curl &#x27;&lt;b&gt;&#x27;" in out


def test_html_sections_and_nav():
    out = render_html(sample())
    ids = ["summary", "where-to-start", "ports", "findings", "other", "commands"]
    positions = [out.index(f'id="{i}"') for i in ids]
    assert positions == sorted(positions)
    for i in ids:
        assert f'href="#{i}"' in out  # every section is in the sticky nav
    assert '<nav class="toc"' in out and '<main id="main">' in out
    assert "Recon report" in out and "<h1>10.10.10.10</h1>" in out and "1m 15s" in out


def test_html_themes_and_severity():
    out = render_html(sample())
    assert "prefers-color-scheme:dark" in out and ":root[data-theme=dark]" in out
    assert "prefers-reduced-motion" in out and "@media print" in out
    assert '<details class="finding card sev-high" data-sev="high" open>' in out
    assert '<details class="finding card sev-medium" data-sev="medium" open>' in out
    assert '<details class="finding card sev-low" data-sev="low" open data-fold>' in out
    assert '<a class="chip sev-high" href="#findings" data-filter="high">' in out
    assert '<a class="chip sev-high" href="#findings" data-filter="high"><span class="dot"></span>High <b>1</b>' in out
    for sev in ("all", "high", "medium", "low", "info"):
        assert f'<button class="btn" type="button" data-filter="{sev}"' in out
    assert "Expand all" in out and "Collapse all" in out
    # high first
    assert out.index("Anonymous FTP login allowed") < out.index("Null session") < out.index("Content discovery")


def test_html_readable_without_javascript():
    out = render_html(sample())
    # every collapsible starts open; only JS folds the noisy ones
    details = re.findall(r"<details[^>]*>", out)
    assert details and all(" open" in d for d in details)
    # JS-only controls are hidden until the script reveals them
    assert re.search(r'<button class="btn copy" type="button" hidden>', out)
    assert '<button class="btn theme" id="theme" type="button" hidden>' in out
    assert ".toolbar{display:none;" in out and ".js .toolbar{display:flex}" in out


def test_html_where_to_start_and_bodies():
    out = render_html(sample())
    assert out.index('id="where-to-start"') < out.index('id="ports"')
    assert '<li class="lead card"><span class="num" aria-hidden="true">1</span>' in out
    assert "<pre><code>wget -m ftp://x/</code></pre>" in out
    assert out.count('class="btn copy"') >= 2  # lead command + /etc/hosts line
    assert "Run <code>wget</code> now" in out  # Markdown backticks become <code>
    assert "<code>/admin</code>" in out and "<code>dev.box.thm</code>" in out
    assert "echo &#x27;10.10.10.10 box.thm dev.box.thm&#x27; | sudo tee -a /etc/hosts" in out
    assert "49757" in out and "vsftpd 2.3.4 - Backdoor Command Execution" in out
    assert "note.txt" in out and "Install gobuster" in out


def test_html_status_codes_and_ports():
    r = sample()
    r.findings[0].data["paths"] += [{"path": "/x", "status": 403, "size": 1}, {"path": "/y", "status": 200, "size": 2}]
    r.services.append(Service(161, "udp", name="snmp"))
    out = render_html(r)
    assert '<span class="st st-3">301</span>' in out
    assert '<span class="st st-4">403</span>' in out and '<span class="st st-2">200</span>' in out
    assert '<span class="portno">161</span>' in out and '<span class="proto udp">UDP</span>' in out
    assert out.count('class="proto udp"') == 1  # TCP is the default and gets no badge
    assert '<span class="svc">snmp</span>' in out


def test_html_partial_report_banner():
    r = sample()
    assert 'class="partial"' not in render_html(r)
    r.interrupted, r.incomplete = True, ["module runs: 80/tcp web <x>"]
    out = render_html(r)
    assert '<div class="partial" role="status">' in out and "<strong>Partial report.</strong>" in out
    assert "80/tcp web &lt;x&gt;" in out
    assert '<span class="status warn">Partial</span>' in out
    assert out.index('class="partial"') < out.index('<dl class="facts">')


def test_html_empty_result():
    out = render_html(HostResult("10.10.10.10"))
    assert "Nothing answered" in out and "No open ports found" in out and "No findings" in out
    assert "ip -br addr show tun0" in out and "--quick" not in out
    assert 'class="toolbar"' not in out  # nothing to filter
    assert 'id="scripts"' not in out and 'id="commands"' not in out
    p = _Balance()
    p.feed(out)
    assert p.errors == [] and p.stack == []


def test_html_ports_but_no_findings():
    r = sample()
    r.findings, r.leads = [], []
    out = render_html(r)
    assert "No findings." in out and "Nothing stood out" in out
    assert '<span class="portno">21</span>' in out
    assert '<span class="dot"></span>High <b>0</b>' in out and "chip sev-high zero" in out


def test_write_reports_writes_html(tmp_path):
    md, _ = write_reports(sample(), tmp_path)
    html_path = md.with_suffix(".html")
    assert html_path.name == "report.html" and html_path.read_text().startswith("<!doctype html>")
