"""mail module. fowsniff-services.xml is the real nmap output from a TryHackMe box (Dovecot POP3 + IMAP)."""

from pathlib import Path

import pytest

from soul_toolkit.core import runner
from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon import leads, nmap
from soul_toolkit.recon.modules import Context, Options, mail, select_modules
from soul_toolkit.recon.writeup import tags_for

FIXTURE = Path(__file__).parent / "fixtures" / "fowsniff-services.xml"
TARGET = "10.64.152.7"


@pytest.fixture
def services():
    return nmap.parse_xml(FIXTURE.read_text())[0].services


@pytest.fixture(autouse=True)
def no_commands(monkeypatch):
    """Recon only: the module works from nmap's results and never runs or connects to anything."""
    def boom(*a, **k):
        raise AssertionError("mail module must not run commands")
    monkeypatch.setattr(runner, "run", boom)


def make_ctx(tmp_path, services):
    return Context(target=TARGET, outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult(TARGET, services=list(services)), options=Options())


def by_port(services, port):
    return next(s for s in services if s.port == port)


def test_matches_mail_services_only(services):
    m = mail.MailModule()
    assert [s.port for s in services if m.matches(s)] == [110, 143]
    assert m.matches(Service(995, name="pop3s")) and m.matches(Service(993, name="imaps"))
    assert m.matches(Service(143, name="unknown")) and not m.matches(Service(143, name="http"))
    assert "mail" in {x.name for x in select_modules(None)}


def test_capabilities_are_cleaned_up(services):
    assert mail.capabilities(by_port(services, 110)) == [
        "SASL(PLAIN)", "USER", "CAPA", "RESP-CODES", "PIPELINING", "UIDL", "AUTH-RESP-CODE", "TOP"]
    imap_caps = mail.capabilities(by_port(services, 143))
    assert "IMAP4rev1" in imap_caps and "AUTH=PLAIN" in imap_caps  # nmap's A0001 tag stripped
    assert not {"more", "listed", "capabilities", "have", "post-login", "OK", "Pre-login"} & set(imap_caps)


def test_fowsniff_findings_and_one_lead(tmp_path, services):
    ctx = make_ctx(tmp_path, services)
    module = mail.MailModule()
    pop3 = module.run(ctx, by_port(services, 110))
    imap = module.run(ctx, by_port(services, 143))

    assert [(f.title, f.severity) for f in pop3] == [
        ("POP3 mail server", "info"), ("POP3 accepts passwords in clear text", "low")]
    assert pop3[0].detail.startswith("Dovecot pop3d; capabilities: SASL(PLAIN), USER")
    assert "without STLS" in pop3[1].detail
    assert [(f.title, f.severity) for f in imap] == [
        ("IMAP mail server", "info"), ("IMAP accepts passwords in clear text", "low")]

    [lead] = ctx.result.leads  # one per host, not one per mail port
    assert lead.kind == "mail-later" and lead.port == 110
    assert lead.title == "Keep the mail server for when you have credentials"
    assert lead.command == f"curl -u '<user>:<password>' pop3://{TARGET}/"
    assert f"`nc {TARGET} 110`" in lead.why and "`USER <user>`" in lead.why
    assert f"imap://{TARGET}/INBOX;UID=1" in lead.why
    assert "No login is attempted" in lead.why
    assert leads.score_for("ssh-later") < leads.score_for("mail-later") < leads.score_for("web-browse")


@pytest.mark.parametrize("caps, plaintext", [
    ("SASL(PLAIN) USER CAPA STLS TOP", False),            # can upgrade to TLS first
    ("CAPA TOP UIDL", False),                             # no way to log in at all
    ("USER CAPA TOP", True),
])
def test_pop3_plaintext_check(caps, plaintext):
    svc = Service(110, name="pop3", scripts={"pop3-capabilities": caps})
    assert mail.plaintext_login("pop3", False, mail.capabilities(svc)) is plaintext


@pytest.mark.parametrize("caps, plaintext", [
    ("IMAP4rev1 STARTTLS AUTH=PLAIN", False),
    ("IMAP4rev1 LOGINDISABLED STARTTLS", False),
    ("IMAP4rev1 AUTH=PLAIN", True),
])
def test_imap_plaintext_check(caps, plaintext):
    svc = Service(143, name="imap", scripts={"imap-capabilities": caps})
    assert mail.plaintext_login("imap", False, mail.capabilities(svc)) is plaintext


def test_tls_and_unknown_capabilities_are_not_flagged(tmp_path):
    pop3s = Service(995, name="pop3s", product="Dovecot pop3d", scripts={"pop3-capabilities": "USER TOP"})
    imap = Service(143, name="imap")  # nmap didn't report capabilities -> can't tell, don't guess
    ctx = make_ctx(tmp_path, [pop3s, imap])
    assert [f.severity for f in mail.MailModule().run(ctx, pop3s)] == ["info"]
    assert [f.severity for f in mail.MailModule().run(ctx, imap)] == ["info"]
    [lead] = ctx.result.leads
    assert lead.port == 995 and lead.command == f"curl -k -u '<user>:<password>' pop3s://{TARGET}/"
    assert f"openssl s_client -connect {TARGET}:995 -quiet" in lead.why


def test_imap_only_on_an_odd_port(tmp_path):
    svc = Service(1143, name="imap", scripts={"imap-capabilities": "IMAP4rev1 AUTH=PLAIN"})
    ctx = make_ctx(tmp_path, [svc])
    mail.MailModule().run(ctx, svc)
    [lead] = ctx.result.leads
    assert lead.command == f"curl -u '<user>:<password>' imap://{TARGET}:1143/"
    assert "INBOX;UID=1" in lead.why


def test_writeup_tags_mail_once(services):
    tags = tags_for(HostResult(TARGET, services=services))
    assert tags.count("mail") == 1 and "pop3" not in tags and "imap" not in tags
