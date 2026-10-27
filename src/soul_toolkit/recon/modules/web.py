"""HTTP/HTTPS follow-ups: fingerprint, vhost redirects, robots.txt, exposed .git, gobuster."""

from __future__ import annotations

import html
import ipaddress
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from soul_toolkit.core import runner
from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) soul-toolkit-recon"
MAX_BODY = 200_000

SYSTEM_WORDLISTS = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
)

INTERESTING = (
    "admin", "backup", ".bak", ".git", ".svn", ".env", "config", "upload", "phpmyadmin",
    "login", "dev", "secret", "private", "database", "wp-admin", "wp-login", "api",
    "console", "dashboard", "panel", "manager", "server-status", ".htpasswd", "hidden",
    "cgi-bin", "shell", "debug", "test", "old", "staging", "internal",
)

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_GB_LINE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)\s*\[Size:\s*(?P<size>\d+)\]"
    r"(?:\s*\[-->\s*(?P<redirect>[^\]]+)\])?"
)
_GB_WILDCARD_LEN = re.compile(r"Length:\s*(\d+)")
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR = re.compile(r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)""", re.I)


# --------------------------------------------------------------------------- HTTP


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: str
    location: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # surface 3xx as HTTPError so we can inspect Location


def fetch(url: str, timeout: float) -> HttpResponse | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # lab targets use self-signed certs
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(MAX_BODY).decode("utf-8", errors="replace")
            return HttpResponse(r.status, {k.lower(): v for k, v in r.headers.items()}, body)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_BODY).decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - defensive
            body = ""
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        return HttpResponse(e.code, headers, body, headers.get("location", ""))
    except (urllib.error.URLError, OSError, ValueError):
        return None


def page_title(body: str) -> str:
    m = _TITLE.search(body)
    if not m:
        return ""
    return " ".join(html.unescape(m.group(1)).split())[:120]


def generator(body: str) -> str:
    m = _GENERATOR.search(body)
    return html.unescape(m.group(1)).strip()[:80] if m else ""


def robots_entries(body: str) -> list[str]:
    out = []
    for line in body.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() in ("disallow", "allow", "sitemap") and value.strip():
            out.append(f"{key.strip().title()}: {value.strip()}")
    return out


# --------------------------------------------------------------------------- gobuster


def parse_gobuster(output: str) -> list[dict]:
    results = []
    for raw in output.splitlines():
        line = _ANSI.sub("", raw).replace("\r", "").strip()
        m = _GB_LINE.match(line)
        if not m:
            continue
        path = m.group("path")
        if not path.startswith("/"):
            path = "/" + path
        results.append(
            {
                "path": path,
                "status": int(m.group("status")),
                "size": int(m.group("size")),
                "redirect": (m.group("redirect") or "").strip(),
            }
        )
    return results


def is_interesting(path: str) -> bool:
    p = path.lower()
    return any(k in p for k in INTERESTING)


def bundled_wordlist() -> str:
    return str(resources.files("soul_toolkit").joinpath("data", "web-common.txt"))


def resolve_wordlist(explicit: str | None) -> tuple[str, str]:
    """Return (path, label). Prefers user choice, then SecLists/dirb, then the bundled list."""
    if explicit:
        if not Path(explicit).is_file():
            raise FileNotFoundError(f"wordlist not found: {explicit}")
        return explicit, explicit
    for cand in SYSTEM_WORDLISTS:
        if Path(cand).is_file():
            return cand, cand
    return bundled_wordlist(), "bundled web-common.txt"


# --------------------------------------------------------------------------- module


class WebModule(Module):
    name = "web"
    description = "HTTP(S): fingerprint, vhost redirects, robots.txt, exposed .git, gobuster dir brute-force"

    def matches(self, svc: Service) -> bool:
        return svc.is_web

    def base_url(self, ctx: Context, svc: Service) -> str:
        scheme = "https" if svc.is_tls else "http"
        default = 443 if scheme == "https" else 80
        host = ctx.host_for_url()
        return f"{scheme}://{host}" if svc.port == default else f"{scheme}://{host}:{svc.port}"

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        base = self.base_url(ctx, svc)
        timeout = ctx.options.http_timeout
        findings: list[Finding] = []
        ctx.log.info(f"{svc.label} web: fingerprinting {base}")

        root = fetch(base + "/", timeout)
        if root is None:
            findings.append(Finding(self.name, svc.port, "Web server did not respond to HTTP request", "info",
                                    f"GET {base}/ failed; the port may need a different protocol."))
        else:
            findings.extend(self._fingerprint(ctx, svc, base, root))

        robots = fetch(base + "/robots.txt", timeout)
        if robots and robots.status == 200 and "<html" not in robots.body[:500].lower():
            entries = robots_entries(robots.body)
            if entries:
                findings.append(Finding(self.name, svc.port, "robots.txt lists paths", "low",
                                        f"{base}/robots.txt", {"entries": entries[:50]}))

        git = fetch(base + "/.git/HEAD", timeout)
        if git and git.status == 200 and git.body.lstrip().startswith("ref:"):
            findings.append(Finding(self.name, svc.port, "Exposed .git repository", "high",
                                    f"{base}/.git/HEAD is readable - the source code can likely be "
                                    "reconstructed (e.g. with git-dumper)."))
            ctx.hint(f"Dump the exposed repo: git-dumper {base}/.git/ ./{svc.port}-git")

        if ctx.options.brute:
            findings.extend(self._gobuster(ctx, svc, base))

        ctx.hint(f"Browse {base}/ by hand and read the page source - automated scans miss things.")
        return findings

    # -- helpers ---------------------------------------------------------------

    def _fingerprint(self, ctx: Context, svc: Service, base: str, resp: HttpResponse) -> list[Finding]:
        out: list[Finding] = []
        target_host = urllib.parse.urlsplit(base).hostname or ""

        if resp.location:
            loc = urllib.parse.urljoin(base + "/", resp.location)
            loc_host = urllib.parse.urlsplit(loc).hostname or ""
            if loc_host and loc_host.lower() != target_host.lower() and not _is_ip(loc_host):
                out.append(Finding(self.name, svc.port, f"Redirects to virtual host '{loc_host}'", "medium",
                                   f"GET / -> {resp.status} {loc}", {"vhost": loc_host}))
                ctx.hint(f"Add the vhost to /etc/hosts: echo '{ctx.target} {loc_host}' | sudo tee -a /etc/hosts")
                ctx.hint(f"Then re-run against the name: toolkit recon {loc_host} -p {svc.port}")
                return out
            followed = fetch(loc, ctx.options.http_timeout)
            if followed is not None:
                resp = followed

        details = {
            "status": resp.status,
            "server": resp.headers.get("server", ""),
            "x-powered-by": resp.headers.get("x-powered-by", ""),
            "title": page_title(resp.body),
            "generator": generator(resp.body),
        }
        details = {k: v for k, v in details.items() if v not in ("", None)}
        summary = ", ".join(f"{k}: {v}" for k, v in details.items())
        out.append(Finding(self.name, svc.port, "HTTP fingerprint", "info", summary, details))

        gen = details.get("generator", "").lower()
        if "wordpress" in gen or "/wp-content/" in resp.body:
            out.append(Finding(self.name, svc.port, "WordPress detected", "low", details.get("generator", "")))
            ctx.hint(f"WordPress: wpscan --url {base}/ -e vp,vt,u")
        return out

    def _gobuster(self, ctx: Context, svc: Service, base: str) -> list[Finding]:
        if not runner.which("gobuster"):
            ctx.log.warn("gobuster not installed - skipping content discovery")
            ctx.hint("Install gobuster to enable directory brute-forcing.")
            return []
        try:
            wordlist, label = resolve_wordlist(ctx.options.wordlist)
        except FileNotFoundError as exc:
            ctx.log.error(str(exc))
            return []

        outfile = ctx.outdir / f"gobuster-{svc.port}.txt"
        cmd = [
            "gobuster", "dir", "-u", base, "-w", wordlist,
            "-t", str(ctx.options.threads), "-q", "-z", "--no-error", "--no-color",
            "--timeout", f"{ctx.options.http_timeout}s", "-o", str(outfile),
        ]
        if svc.is_tls:
            cmd.append("-k")
        if ctx.options.extensions:
            cmd += ["-x", ctx.options.extensions]

        ctx.log.info(f"{svc.label} web: gobuster with {label}")
        res = ctx.run(cmd, timeout=ctx.options.brute_timeout)

        # Wildcard servers answer every path; gobuster refuses to run. Retry excluding that length.
        combined = res.stdout + res.stderr
        if not res.ok and "non existing urls" in combined:
            m = _GB_WILDCARD_LEN.search(combined)
            if m:
                ctx.log.warn(f"{svc.label} web: wildcard responses (length {m.group(1)}), "
                             "retrying with --exclude-length")
                res = ctx.run([*cmd, "--exclude-length", m.group(1)], timeout=ctx.options.brute_timeout)

        hits = parse_gobuster(res.stdout)
        if res.timed_out:
            ctx.log.warn(f"{svc.label} web: gobuster hit the {ctx.options.brute_timeout}s limit - results are partial")
        elif not res.ok and not hits:
            err = (res.stderr or res.stdout).strip().splitlines()
            ctx.log.warn(f"{svc.label} web: gobuster failed: {err[-1] if err else 'unknown error'}")
            return [Finding(self.name, svc.port, "Content discovery failed", "info",
                            err[-1] if err else "gobuster exited with an error")]

        findings: list[Finding] = []
        if hits:
            ctx.log.ok(f"{svc.label} web: {len(hits)} path(s) found")
            findings.append(Finding(self.name, svc.port, f"Content discovery: {len(hits)} path(s)", "info",
                                    f"wordlist: {label}" + (" (partial - timed out)" if res.timed_out else ""),
                                    {"paths": hits}))
            juicy = [h for h in hits if is_interesting(h["path"])]
            if juicy:
                findings.append(Finding(self.name, svc.port, "Interesting paths worth checking", "medium",
                                        ", ".join(h["path"] for h in juicy[:15]), {"paths": juicy}))
        else:
            findings.append(Finding(self.name, svc.port, "Content discovery: nothing found", "info",
                                    f"wordlist: {label}. Try a bigger list with --wordlist."))
        return findings


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
