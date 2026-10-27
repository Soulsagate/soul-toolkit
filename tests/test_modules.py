import http.server
import threading
from pathlib import Path
from typing import ClassVar

import pytest

from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon.modules import Context, Options, select_modules, smb, ssh, web
from soul_toolkit.recon.modules import ftp as ftp_mod


def make_ctx(tmp_path: Path, target="127.0.0.1", **opts) -> Context:
    return Context(target=target, outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult(target), options=Options(**opts))


# ----------------------------------------------------------------- parsers

GOBUSTER_OUT = (
    "\r\x1b[2K/admin                (Status: 301) [Size: 314] [--> http://10.10.10.10/admin/]\n"
    "/index.php            (Status: 200) [Size: 10918]\n"
    "/.htpasswd            (Status: 403) [Size: 277]\n"
    "/index.php            (Status: 200) [Size: 10918]\n"
    "Progress: 4614 / 4615 (99.98%)\n"
    "garbage line\n"
)


def test_parse_gobuster():
    hits = web.parse_gobuster(GOBUSTER_OUT)
    assert [h["path"] for h in hits] == ["/admin", "/index.php", "/.htpasswd"]
    assert hits[0]["status"] == 301 and hits[0]["redirect"] == "http://10.10.10.10/admin/"
    assert hits[1]["size"] == 10918 and hits[1]["redirect"] == ""


def test_interesting_paths():
    assert web.is_interesting("/admin")
    assert web.is_interesting("/backup.zip")
    assert not web.is_interesting("/index.php")


def test_robots_entries():
    body = "User-agent: *\nDisallow: /secret-area\nDisallow:\nSitemap: http://x/sitemap.xml\n"
    assert web.robots_entries(body) == ["Disallow: /secret-area", "Sitemap: http://x/sitemap.xml"]


def test_title_and_generator():
    body = '<html><head><title>  My &amp; Site\n</title><meta name="generator" content="WordPress 5.0"></head>'
    assert web.page_title(body) == "My & Site"
    assert web.generator(body) == "WordPress 5.0"


def test_smbclient_parse():
    out = "Disk|print$|Printer Drivers\nDisk|anonymous|Public files\nIPC|IPC$|IPC Service\nWorkgroup|WORKGROUP|BOX\n"
    shares = smb.parse_smbclient_shares(out)
    assert [s["name"] for s in shares] == ["print$", "anonymous", "IPC$"]


def test_openssh_version():
    assert ssh.openssh_version(Service(22, name="ssh", product="OpenSSH", version="7.6p1 Ubuntu")) == (7, 6)
    assert ssh.openssh_version(Service(22, name="ssh", product="Dropbear sshd", version="2019")) is None


def test_ssh_module_flags_old_openssh(tmp_path):
    ctx = make_ctx(tmp_path)
    old = ssh.SshModule().run(ctx, Service(22, name="ssh", product="OpenSSH", version="7.6p1"))
    new = ssh.SshModule().run(ctx, Service(22, name="ssh", product="OpenSSH", version="9.6p1"))
    assert any("CVE-2018-15473" in f.detail for f in old)
    assert not any("CVE-2018-15473" in f.detail for f in new)


def test_select_modules():
    assert {m.name for m in select_modules(None)} == {"web", "ftp", "ssh", "smb", "exploits"}
    assert [m.name for m in select_modules(["web"])] == ["web"]
    with pytest.raises(ValueError):
        select_modules(["nope"])


def test_module_matching():
    mods = {m.name: m for m in select_modules(None)}
    assert mods["web"].matches(Service(80, name="http"))
    assert mods["ftp"].matches(Service(21, name="ftp"))
    assert mods["smb"].matches(Service(445, name="microsoft-ds"))
    assert not mods["ftp"].matches(Service(80, name="http"))


def test_ftp_uses_nmap_anon_result(tmp_path, monkeypatch):
    monkeypatch.setattr(ftp_mod, "anon_listing", lambda *a, **k: None)
    svc = Service(21, name="ftp", product="vsftpd", version="3.0.3",
                  scripts={"ftp-anon": "Anonymous FTP login allowed (FTP code 230)\n-rw-r--r-- 1 0 0 418 note.txt"})
    findings = ftp_mod.FtpModule().run(make_ctx(tmp_path), svc)
    assert findings[0].severity == "high"
    assert "note.txt" in findings[0].data["listing"][0]


def test_ftp_flags_backdoored_vsftpd(tmp_path, monkeypatch):
    monkeypatch.setattr(ftp_mod, "anon_listing", lambda *a, **k: None)
    findings = ftp_mod.FtpModule().run(make_ctx(tmp_path), Service(21, name="ftp", product="vsftpd", version="2.3.4"))
    assert any("CVE-2011-2523" in f.detail for f in findings)


# ----------------------------------------------------------------- live HTTP (localhost only)


class _Handler(http.server.BaseHTTPRequestHandler):
    routes: ClassVar[dict] = {
        "/": (200, "text/html", '<html><head><title>Hotel Login</title></head><body>hi</body></html>'),
        "/robots.txt": (200, "text/plain", "User-agent: *\nDisallow: /staff-only\n"),
        "/.git/HEAD": (200, "text/plain", "ref: refs/heads/master\n"),
    }

    def do_GET(self):
        status, ctype, body = self.routes.get(self.path, (404, "text/html", "nope"))
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "TestServer/1.0")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class _RedirectHandler(_Handler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://hotel.thm/")
        self.send_header("Content-Length", "0")
        self.end_headers()


def _serve(handler):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_web_module_live(tmp_path):
    srv = _serve(_Handler)
    try:
        port = srv.server_address[1]
        ctx = make_ctx(tmp_path, brute=False)
        findings = web.WebModule().run(ctx, Service(port, name="http"))
        titles = {f.title: f for f in findings}
        assert titles["HTTP fingerprint"].data["title"] == "Hotel Login"
        assert titles["HTTP fingerprint"].data["server"].startswith("TestServer")
        assert titles["robots.txt lists paths"].data["entries"] == ["Disallow: /staff-only"]
        assert titles["Exposed .git repository"].severity == "high"
    finally:
        srv.shutdown()


def test_web_module_detects_vhost_redirect(tmp_path):
    srv = _serve(_RedirectHandler)
    try:
        port = srv.server_address[1]
        ctx = make_ctx(tmp_path, brute=False)
        findings = web.WebModule().run(ctx, Service(port, name="http"))
        vhost = [f for f in findings if f.title.startswith("Redirects to virtual host")]
        assert vhost and vhost[0].data["vhost"] == "hotel.thm"
        lead = next(x for x in ctx.result.leads if x.kind == "web-vhost")
        assert lead.command.startswith("echo '127.0.0.1 hotel.thm' | sudo tee -a /etc/hosts")
    finally:
        srv.shutdown()


def test_wordlist_resolution(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("admin\n")
    assert web.resolve_wordlist(str(wl))[0] == str(wl)
    with pytest.raises(FileNotFoundError):
        web.resolve_wordlist(str(tmp_path / "missing.txt"))
    assert Path(web.bundled_wordlist()).is_file()


# ----------------------------------------------------------------- FTP listing analysis

FS_ROOT_LISTING = [
    "drwxr-xr-x   23 0        0            4096 Aug 11  2019 .",
    "drwxr-xr-x   23 0        0            4096 Aug 11  2019 ..",
    "drwxr-xr-x    2 0        0            4096 Aug 11  2019 bin",
    "drwxr-xr-x    3 0        0            4096 Aug 11  2019 boot",
    "drwxr-xr-x   85 0        0            4096 Aug 13  2019 etc",
    "drwxr-xr-x    3 0        0            4096 Aug 11  2019 home",
    "lrwxrwxrwx    1 0        0              30 Aug 11  2019 vmlinuz -> boot/vmlinuz-4.4.0-157-generic",
    "drwxrwxrwx    2 1000     1000         4096 Aug 11  2019 shared [NSE: writeable]",
    "drwx------    3 0        0            4096 Aug 11  2019 root",
    "dr-xr-xr-x   90 0        0               0 Oct 26 17:32 proc",
    "drwxr-xr-x   10 0        0            4096 Aug 11  2019 usr",
    "drwxr-xr-x   11 0        0            4096 Aug 11  2019 var",
    "Only 20 shown. Use --script-args ftp-anon.maxlist=-1 to see all.",
]


def test_parse_listing_drops_dots_and_noise():
    entries = ftp_mod.parse_listing(FS_ROOT_LISTING)
    names = [e.name for e in entries]
    assert "." not in names and ".." not in names
    assert "vmlinuz" in names and "shared" in names
    assert len(entries) == 10


def test_fs_root_and_writable_detection():
    entries = ftp_mod.parse_listing(FS_ROOT_LISTING)
    assert ftp_mod.looks_like_fs_root(entries)
    assert [e.name for e in entries if e.is_dir and e.world_writable] == ["shared"]
    normal = ftp_mod.parse_listing(["-rw-r--r--    1 0        0             418 Jun 07  2020 note.txt"])
    assert not ftp_mod.looks_like_fs_root(normal)
    assert not normal[0].world_writable


def test_ftp_module_fs_root_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(ftp_mod, "anon_listing", lambda *a, **k: FS_ROOT_LISTING)
    ctx = make_ctx(tmp_path, target="10.10.10.10")
    findings = ftp_mod.FtpModule().run(ctx, Service(21, name="ftp", product="vsftpd", version="3.0.3"))
    titles = {f.title: f for f in findings}
    assert titles["Anonymous FTP login allowed"].detail == "10 entries in the FTP root"
    assert titles["FTP root is the server's filesystem root (/)"].severity == "high"
    assert titles["World-writable directories in FTP root"].severity == "medium"
    assert not any("wget -m" in x.command for x in ctx.result.leads)  # never mirror a whole filesystem
    assert {x.kind for x in ctx.result.leads} >= {"ftp-fsroot", "ftp-writable"}


def test_ftp_module_normal_share_suggests_mirror(tmp_path, monkeypatch):
    monkeypatch.setattr(ftp_mod, "anon_listing",
                        lambda *a, **k: ["-rw-r--r--    1 0        0             418 Jun 07  2020 note.txt"])
    ctx = make_ctx(tmp_path, target="10.10.10.10")
    ftp_mod.FtpModule().run(ctx, Service(21, name="ftp"))
    assert "wget -m ftp://anonymous:anonymous@10.10.10.10/" in [x.command for x in ctx.result.leads]
