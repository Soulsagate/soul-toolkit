import socketserver
import threading

import pytest

from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon.modules import Context, Options, smtp


def make_ctx(tmp_path):
    return Context(target="127.0.0.1", outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult("127.0.0.1"), options=Options(http_timeout=3))


def smtp_server(replies):
    """A tiny line-based SMTP server. *replies* maps a verb (or "VERB root" for the root probe)
    to a response line."""

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.wfile.write(b"220 mail.box.thm ESMTP Postfix (Ubuntu)\r\n")
            for raw in self.rfile:
                line = raw.decode().strip()
                verb = line.split(" ", 1)[0].upper()
                if verb == "QUIT":
                    self.wfile.write(b"221 2.0.0 Bye\r\n")
                    return
                key = f"{verb} root" if line.lower().endswith(" root") and f"{verb} root" in replies else verb
                self.wfile.write(replies.get(key, "502 5.5.2 Error: command not recognized").encode() + b"\r\n")

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


EHLO = "250-mail.box.thm\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-STARTTLS\r\n250 8BITMIME"


@pytest.fixture
def server():
    servers = []

    def start(replies):
        srv = smtp_server(replies)
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


def test_matches():
    m = smtp.SmtpModule()
    assert m.matches(Service(25, name="smtp")) and m.matches(Service(587, name="submission"))
    assert m.matches(Service(2525, name="")) and not m.matches(Service(25, name="http"))


def test_enumerates():
    assert smtp.enumerates(250, 250)       # "exists" is enough
    assert smtp.enumerates(252, 550)       # Postfix: known user 252, unknown 550
    assert not smtp.enumerates(252, 252)   # Exim "administrative prohibition" for everything
    assert not smtp.enumerates(502, 502)   # disabled
    assert not smtp.enumerates(530, 550)   # needs auth first
    assert not smtp.enumerates(0, 0)       # never answered


def test_vrfy_disabled_no_lead(tmp_path, server):
    port = server({"EHLO": EHLO, "VRFY": "252 2.0.0 Administrative prohibition"})
    ctx = make_ctx(tmp_path)
    findings = smtp.SmtpModule().run(ctx, Service(port, name="smtp"))
    assert [f.title for f in findings] == ["SMTP banner and capabilities"]
    rows = dict(findings[0].data["table"]["rows"])
    assert rows["Banner"] == "220 mail.box.thm ESMTP Postfix (Ubuntu)"
    assert rows["Capabilities"] == "PIPELINING, SIZE 10240000, VRFY, STARTTLS, 8BITMIME"
    assert rows["VRFY root / made-up user"] == "252 / 252"
    assert not ctx.result.leads


@pytest.mark.parametrize("root,other", [
    ("250 2.1.5 <root@box.thm>", "550 5.1.1 User unknown"),  # Sendmail style
    ("252 2.0.0 root", "550 5.1.1 <x>: Recipient address rejected: User unknown in local recipient table"),
])
def test_vrfy_enumerates(tmp_path, server, root, other):
    port = server({"EHLO": EHLO, "VRFY root": root, "VRFY": other})
    ctx = make_ctx(tmp_path)
    findings = smtp.SmtpModule().run(ctx, Service(port, name="smtp"))
    f = next(x for x in findings if x.severity == "medium")
    assert f.title == "SMTP VRFY enabled - usernames can be enumerated"
    [lead] = ctx.result.leads
    assert lead.kind == "smtp-vrfy" and lead.command.startswith("smtp-user-enum -M VRFY -U ")
    assert lead.command.endswith(f"-t 127.0.0.1 -p {port}")


def test_expn_only(tmp_path, server):
    port = server({"EHLO": EHLO, "VRFY": "502 5.5.1 VRFY command is disabled", "EXPN root": "250 root@box.thm",
                   "EXPN": "550 5.1.1 unknown"})
    ctx = make_ctx(tmp_path)
    findings = smtp.SmtpModule().run(ctx, Service(port, name="smtp"))
    assert findings[1].title == "SMTP EXPN enabled - usernames can be enumerated"
    assert "-M EXPN" in ctx.result.leads[0].command


def test_helo_fallback(tmp_path, server):
    port = server({"EHLO": "500 5.5.1 Unknown command", "HELO": "250 mail.box.thm", "VRFY root": "250 root",
                   "VRFY": "550 unknown"})
    findings = smtp.SmtpModule().run(make_ctx(tmp_path), Service(port, name="smtp"))
    assert dict(findings[0].data["table"]["rows"])["Capabilities"] == "-"
    assert any(f.severity == "medium" for f in findings)


def test_unreachable(tmp_path):
    [f] = smtp.SmtpModule().run(make_ctx(tmp_path), Service(9, name="smtp", product="Postfix smtpd"))
    assert f.title == "SMTP did not answer" and f.severity == "info"
