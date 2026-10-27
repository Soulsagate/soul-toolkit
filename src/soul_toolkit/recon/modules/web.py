"""HTTP/HTTPS follow-ups: fingerprint, vhost redirects + fuzzing, robots.txt, exposed .git, gobuster."""

from __future__ import annotations

import html
import ipaddress
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from soul_toolkit.core import runner
from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon import vhosts
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
_LINK = re.compile(r"""(?:href|src|action)\s*=\s*["']?([^"'\s>]+)""", re.IGNORECASE)

# Content discovery: one level of recursion into at most this many directories, skipping
# directories that almost only ever hold static assets, and VCS metadata (git-dumper's job).
MAX_RECURSE_DIRS = 5
MIN_RUN_SECONDS = 15
NO_RECURSE_DIRS = {"css", "js", "javascript", "images", "img", "image", "fonts", "font", "icons", "static", "assets",
                   ".git", ".svn", ".hg"}

# (stack, gobuster extensions, evidence patterns per source). Sources: server/x-powered-by/
# x-aspnet-version headers, cookies, nmap's product string, the generator meta tag, and the
# extensions of links on the page.
STACKS = (
    ("PHP", "php,txt,bak", {
        "x-powered-by": r"php", "server": r"php", "nmap": r"php", "cookie": r"phpsessid",
        "generator": r"wordpress|joomla|drupal", "links": r"\bphp\b"}),
    ("ASP.NET", "aspx,asp,txt", {
        "x-powered-by": r"asp\.net", "server": r"\biis\b", "nmap": r"\biis\b", "x-aspnet-version": r".",
        "cookie": r"asp\.net_sessionid|aspxauth", "links": r"\baspx?\b"}),
    ("Java", "jsp,do,txt", {
        "server": r"tomcat|jetty|jboss|wildfly|glassfish|coyote|weblogic",
        "nmap": r"tomcat|jetty|jboss|wildfly|glassfish|coyote|weblogic",
        "x-powered-by": r"servlet|jsp", "cookie": r"jsessionid", "links": r"\b(jsp|do|action)\b"}),
    ("static HTML", "html,txt", {"nmap": r"simplehttp", "links": r"\bhtml?\b"}),
)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR = re.compile(r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)""", re.I)


# --------------------------------------------------------------------------- HTTP


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: str
    location: str = ""
    size: int = 0  # body length in bytes, as ffuf/gobuster count it


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # surface 3xx as HTTPError so we can inspect Location


def _headers(msg) -> dict[str, str]:
    """Lower-cased headers; repeated Set-Cookie headers are joined, other repeats keep the last value."""
    out: dict[str, str] = {}
    for k, v in (msg or {}).items():
        k = k.lower()
        out[k] = f"{out[k]}, {v}" if k == "set-cookie" and k in out else v
    return out


def _size(headers: dict[str, str], raw: bytes) -> int:
    length = headers.get("content-length", "")
    return int(length) if length.isdigit() else len(raw)


def fetch(url: str, timeout: float, host: str | None = None) -> HttpResponse | None:
    """GET *url* without following redirects. *host* overrides the Host header (vhost probing)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # lab targets use self-signed certs
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    headers = {"User-Agent": USER_AGENT}
    if host:
        headers["Host"] = host
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(MAX_BODY)
            hdrs = _headers(r.headers)
            return HttpResponse(r.status, hdrs, raw.decode("utf-8", errors="replace"), size=_size(hdrs, raw))
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(MAX_BODY)
        except Exception:  # pragma: no cover - defensive
            raw = b""
        hdrs = _headers(e.headers)
        return HttpResponse(e.code, hdrs, raw.decode("utf-8", errors="replace"), hdrs.get("location", ""),
                            _size(hdrs, raw))
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


def link_extensions(body: str) -> list[str]:
    """File extensions of same-site links on a page, most common first."""
    counts: dict[str, int] = {}
    for link in _LINK.findall(body):
        parts = urllib.parse.urlsplit(html.unescape(link))
        if parts.scheme not in ("", "http", "https"):
            continue
        name = parts.path.rsplit("/", 1)[-1]
        if "." in name:
            ext = name.rsplit(".", 1)[1].lower()
            if ext.isalnum() and len(ext) <= 6:
                counts[ext] = counts.get(ext, 0) + 1
    return sorted(counts, key=lambda e: (-counts[e], e))


def pick_extensions(svc: Service, page: HttpResponse | None) -> tuple[str, str]:
    """Pick gobuster -x extensions from what the server told us. Returns (extensions, reason)."""
    headers = page.headers if page else {}
    sources = {
        "server": headers.get("server", ""),
        "x-powered-by": headers.get("x-powered-by", ""),
        "x-aspnet-version": headers.get("x-aspnet-version", ""),
        "cookie": headers.get("set-cookie", ""),
        "nmap": " ".join(p for p in (svc.product, svc.version, svc.extrainfo) if p),
        "generator": generator(page.body) if page else "",
        "links": " ".join(link_extensions(page.body)) if page else "",
    }
    exts: list[str] = []
    reasons: list[str] = []
    for stack, stack_exts, patterns in STACKS:
        hit = next((src for src, pat in patterns.items() if sources[src] and re.search(pat, sources[src], re.I)),
                   None)
        if hit is None:
            continue
        evidence = "page links" if hit == "links" else f"{hit}: {sources[hit][:40]}"
        reasons.append(f"{stack} ({evidence})")
        exts += [e for e in stack_exts.split(",") if e not in exts]
    if not exts:
        return "", "no stack detected; pass -x to add extensions"
    return ",".join(exts[:6]), "; ".join(reasons)


def directories(hits: list[dict]) -> list[str]:
    """Paths gobuster found that are directories (a redirect to the same path with a trailing slash)."""
    out = []
    for h in hits:
        if h["status"] not in (301, 302, 307, 308) or not h["redirect"]:
            continue
        target = urllib.parse.urlsplit(h["redirect"]).path
        if target.endswith("/") and target.rstrip("/").lower() == h["path"].rstrip("/").lower():
            out.append(h["path"].rstrip("/"))
    return out


def recurse_candidates(hits: list[dict], limit: int = MAX_RECURSE_DIRS) -> list[str]:
    """Directories worth one more gobuster pass: interesting names first, static-asset dirs skipped."""
    dirs = {d for d in directories(hits) if d.rsplit("/", 1)[-1].lower() not in NO_RECURSE_DIRS}
    return sorted(dirs, key=lambda d: (not is_interesting(d), d))[:limit]


# --------------------------------------------------------------------------- gobuster


def parse_gobuster(output: str) -> list[dict]:
    """Parse gobuster dir output. A path is kept once even if gobuster prints it twice
    (wordlist has `index` and `index.html` while `-x html` is set)."""
    results = []
    seen: set[str] = set()
    for raw in output.splitlines():
        line = _ANSI.sub("", raw).replace("\r", "").strip()
        m = _GB_LINE.match(line)
        if not m:
            continue
        path = m.group("path")
        if not path.startswith("/"):
            path = "/" + path
        if path in seen:
            continue
        seen.add(path)
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


def _default_deny(hit: dict) -> bool:
    """A 403 on a .ht* file (or server-status) is the stock Apache config, not a finding."""
    name = hit["path"].rstrip("/").rsplit("/", 1)[-1].lower()
    return hit["status"] == 403 and (name.startswith(".ht") or name == "server-status")


def _path_priority(hit: dict) -> tuple[int, int]:
    """Paths you can actually open first: 2xx, then redirects (directories), auth prompts, 403s."""
    s = hit["status"]
    group = 0 if 200 <= s < 300 else 1 if 300 <= s < 400 else 2 if s == 401 else 3
    return group, hit["path"].count("/")


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


@dataclass
class GobusterRun:
    hits: list[dict] = field(default_factory=list)
    timed_out: bool = False
    error: str = ""


class WebModule(Module):
    name = "web"
    description = "HTTP(S): fingerprint, vhost redirects + fuzzing, robots.txt, .git, gobuster with recursion"

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
        page: HttpResponse | None = None
        redirect_vhost = None
        if root is None:
            findings.append(Finding(self.name, svc.port, "Web server did not respond to HTTP request", "info",
                                    f"GET {base}/ failed; the port may need a different protocol."))
        else:
            fp, page = self._fingerprint(ctx, svc, base, root)
            redirect_vhost = next((f.data["vhost"] for f in fp if "vhost" in f.data), None)
            findings.extend(fp)

        robots = fetch(base + "/robots.txt", timeout)
        if robots and robots.status == 200 and "<html" not in robots.body[:500].lower():
            entries = robots_entries(robots.body)
            if entries:
                findings.append(Finding(self.name, svc.port, "robots.txt lists paths", "low",
                                        f"{base}/robots.txt", {"entries": entries[:50]}))
                ctx.lead("web-robots", svc.port, "Visit the paths robots.txt asks crawlers to skip",
                         f"robots.txt has {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}, "
                         f"starting with `{entries[0]}`.", f"curl -s {base}/robots.txt")

        git = fetch(base + "/.git/HEAD", timeout)
        if git and git.status == 200 and git.body.lstrip().startswith("ref:"):
            findings.append(Finding(self.name, svc.port, "Exposed .git repository", "high",
                                    f"{base}/.git/HEAD is readable - the source code can likely be "
                                    "reconstructed (e.g. with git-dumper)."))
            ctx.lead("web-git", svc.port, "Dump the exposed .git repository",
                     "Source code and commit history often hold credentials, hidden routes and config files.",
                     f"git-dumper {base}/.git/ ./{svc.port}-git")

        if ctx.options.brute:
            findings.extend(self._content_discovery(ctx, svc, base, page))
            if ctx.options.vhosts and root is not None:
                domain = vhosts.fuzz_domain(ctx.target, redirect_vhost, _is_ip(ctx.target))
                if domain:
                    findings.extend(self._vhost_fuzz(ctx, svc, base, domain))

        ctx.lead("web-browse", svc.port, f"Browse {base}/ by hand",
                 "Read the page source, comments and JavaScript - automated scans miss things.",
                 f"curl -s {base}/ | less")
        return findings

    # -- helpers ---------------------------------------------------------------

    def _fingerprint(self, ctx: Context, svc: Service, base: str,
                     resp: HttpResponse) -> tuple[list[Finding], HttpResponse]:
        out: list[Finding] = []
        target_host = urllib.parse.urlsplit(base).hostname or ""

        if resp.location:
            loc = urllib.parse.urljoin(base + "/", resp.location)
            loc_host = urllib.parse.urlsplit(loc).hostname or ""
            if loc_host and loc_host.lower() != target_host.lower() and not _is_ip(loc_host):
                out.append(Finding(self.name, svc.port, f"Redirects to virtual host '{loc_host}'", "medium",
                                   f"GET / -> {resp.status} {loc}", {"vhost": loc_host}))
                ip = _target_ip(ctx)
                ctx.lead("web-vhost", svc.port, f"Add {loc_host} to /etc/hosts and scan it by name",
                         f"GET / redirects to {loc}; the real site is only served under that name.",
                         f"echo '{ip} {loc_host}' | sudo tee -a /etc/hosts && toolkit recon {loc_host} -p {svc.port}")
                return out, resp
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
            ctx.lead("web-wordpress", svc.port, "Enumerate WordPress plugins, themes and users",
                     "WordPress sites are usually compromised through outdated plugins or weak user passwords.",
                     f"wpscan --url {base}/ -e vp,vt,u")
        return out, resp

    def _vhost_fuzz(self, ctx: Context, svc: Service, base: str, domain: str) -> list[Finding]:
        tool = "ffuf" if runner.which("ffuf") else "gobuster" if runner.which("gobuster") else None
        if tool is None:
            ctx.log.warn("neither ffuf nor gobuster installed - skipping vhost fuzzing")
            ctx.hint("Install ffuf (or gobuster) to enable virtual-host fuzzing.")
            return []
        try:
            wordlist, label = vhosts.resolve_wordlist(ctx.options.vhost_wordlist)
        except FileNotFoundError as exc:
            ctx.log.error(str(exc))
            return []

        # Calibrate: what does a name that can't exist get back? Two probes catch dynamic pages.
        probes = [fetch(base + "/", ctx.options.http_timeout, host=f"{vhosts.random_label()}.{domain}")
                  for _ in range(2)]
        if any(p is None for p in probes):
            ctx.log.warn(f"{svc.label} web: vhost calibration requests failed - skipping vhost fuzzing")
            return []
        size = vhosts.wildcard_size([p.size for p in probes if p is not None])
        how = f"filtering wildcard size {size}" if size is not None else "wildcard size varies, auto-calibrating"
        if size is None and tool == "gobuster":
            how = "wildcard size varies, relying on gobuster's baseline"
        ctx.log.info(f"{svc.label} web: vhost fuzzing *.{domain} with {tool} ({label}; {how})")

        outfile = ctx.outdir / f"vhosts-{svc.port}.{'json' if tool == 'ffuf' else 'txt'}"
        timeout, budget = ctx.options.http_timeout, ctx.options.brute_timeout
        if tool == "ffuf":
            cmd = vhosts.build_ffuf(base, domain, wordlist, outfile, threads=ctx.options.threads,
                                    timeout=timeout, maxtime=budget, filter_size=size)
        else:
            cmd = vhosts.build_gobuster_vhost(base, domain, wordlist, outfile, threads=ctx.options.threads,
                                              timeout=timeout, filter_size=size, tls=svc.is_tls)
        res = ctx.run(cmd, timeout=budget + 30)
        text = outfile.read_text(encoding="utf-8", errors="replace") if outfile.exists() else ""
        found = vhosts.parse_ffuf(text) if tool == "ffuf" else vhosts.parse_gobuster_vhost(text or res.stdout)
        found = [v for v in found if v["host"] != domain]
        if res.timed_out:
            ctx.log.warn(f"{svc.label} web: vhost fuzzing hit the time limit - results are partial")
        elif not res.ok and not found:
            err = (res.stderr or res.stdout).strip().splitlines()
            ctx.log.warn(f"{svc.label} web: {tool} vhost fuzzing failed: {err[-1] if err else 'unknown error'}")
            return []
        if not found:
            ctx.log.info(f"{svc.label} web: no extra vhosts under {domain}")
            return [Finding(self.name, svc.port, f"Vhost fuzzing: nothing found under {domain}", "info",
                            f"wordlist: {label}. Try a bigger list with --vhost-wordlist.")]

        ip = _target_ip(ctx)
        line = vhosts.hosts_line(ip, domain, found)
        names = ", ".join(v["host"] for v in found)
        ctx.log.ok(f"{svc.label} web: {len(found)} vhost(s) found: {names}")
        ctx.log.ok(f"{svc.label} web: add to /etc/hosts: {line}")
        # This hosts line already covers the redirect target; one /etc/hosts edit is enough.
        ctx.result.leads = [x for x in ctx.result.leads if not (x.kind == "web-vhost" and x.port == svc.port)]
        ctx.lead("web-vhosts", svc.port, f"Add the new vhost(s) to /etc/hosts and enumerate them: {names}",
                 "These names serve something different from the default site - dev/admin/staging vhosts are a "
                 f"classic CTF foothold. Then run `toolkit recon <name> -p {svc.port}` on {domain} and each vhost.",
                 f"echo '{line}' | sudo tee -a /etc/hosts")
        return [Finding(self.name, svc.port, f"Virtual hosts found: {names}", "medium",
                        f"Add to /etc/hosts: `{line}`", {"vhosts": found, "hosts_line": line})]

    def _paths_lead(self, ctx: Context, svc: Service, base: str, juicy: list[dict]) -> None:
        # .git has its own (higher-ranked) lead; don't spend this one on it. Forbidden .ht* files
        # are Apache's default deny rule on every server, not a discovery.
        juicy = [h for h in juicy if not h["path"].startswith("/.git") and not _default_deny(h)]
        if not juicy:
            return
        juicy = sorted(juicy, key=_path_priority)
        names = ", ".join(h["path"] for h in juicy[:4]) + (", ..." if len(juicy) > 4 else "")
        ctx.lead("web-paths", svc.port, f"Check the interesting paths: {names}",
                 f"Content discovery found {len(juicy)} path(s) with names that usually matter "
                 "(admin panels, backups, config, uploads).",
                 f"curl -si {base}{juicy[0]['path']}")

    def _content_discovery(self, ctx: Context, svc: Service, base: str,
                           page: HttpResponse | None) -> list[Finding]:
        if not runner.which("gobuster"):
            ctx.log.warn("gobuster not installed - skipping content discovery")
            ctx.hint("Install gobuster to enable directory brute-forcing.")
            return []
        try:
            wordlist, label = resolve_wordlist(ctx.options.wordlist)
        except FileNotFoundError as exc:
            ctx.log.error(str(exc))
            return []

        if ctx.options.extensions:
            exts, why = ctx.options.extensions, "from --extensions"
        else:
            exts, why = pick_extensions(svc, page)
        budget = ctx.options.brute_timeout
        deadline = time.monotonic() + budget  # root scan + recursion share one budget per port
        ctx.log.info(f"{svc.label} web: gobuster with {label}" + (f", -x {exts} ({why})" if exts else ""))

        root = self._run_gobuster(ctx, svc, base, wordlist, exts, ctx.outdir / f"gobuster-{svc.port}.txt", deadline)
        if root.error and not root.hits:
            ctx.log.warn(f"{svc.label} web: gobuster failed: {root.error}")
            return [Finding(self.name, svc.port, "Content discovery failed", "info", root.error)]
        hits, partial = list(root.hits), root.timed_out

        recursed: list[str] = []
        todo = recurse_candidates(hits) if ctx.options.recurse and not partial else []
        for i, d in enumerate(todo):
            if deadline - time.monotonic() < MIN_RUN_SECONDS:
                ctx.log.warn(f"{svc.label} web: {budget}s budget used up - not recursing into {', '.join(todo[i:])}")
                partial = True
                break
            ctx.log.info(f"{svc.label} web: recursing into {d}/")
            slug = d.strip("/").replace("/", "_")
            sub = self._run_gobuster(ctx, svc, base + d, wordlist, exts,
                                     ctx.outdir / f"gobuster-{svc.port}-{slug}.txt", deadline)
            recursed.append(d)
            known = {h["path"] for h in hits}
            hits += [dict(h, path=d + h["path"]) for h in sub.hits if d + h["path"] not in known]
            if sub.timed_out:
                partial = True
                break
        if partial:
            ctx.log.warn(f"{svc.label} web: content discovery hit the {budget}s budget - results are partial")

        detail = f"wordlist: {label}; extensions: {exts or 'none'} ({why})"
        if recursed:
            detail += f"; recursed into {', '.join(d + '/' for d in recursed)}"
        if partial:
            detail += " (partial - time budget reached)"

        # Apache answers 403 to every .ht* name and server-status on every server - on a typical box
        # that's half the list. Keep them in the raw gobuster files, not in the report.
        hidden = sum(1 for h in hits if _default_deny(h))
        hits = [h for h in hits if not _default_deny(h)]
        if hidden:
            detail += (f"; {hidden} stock 403 response(s) (.ht*, server-status) hidden - "
                       f"the raw list is in gobuster-{svc.port}*.txt")

        findings: list[Finding] = []
        if hits:
            ctx.log.ok(f"{svc.label} web: {len(hits)} path(s) found" + (f" (+{hidden} stock 403s hidden)" if hidden else ""))
            findings.append(Finding(self.name, svc.port, f"Content discovery: {len(hits)} path(s)", "info",
                                    detail, {"paths": hits, "extensions": exts, "recursed": recursed,
                                             "hidden_default_deny": hidden}))
            juicy = sorted((h for h in hits if is_interesting(h["path"]) and not _default_deny(h)),
                           key=_path_priority)
            if juicy:
                findings.append(Finding(self.name, svc.port, "Interesting paths worth checking", "medium",
                                        ", ".join(h["path"] for h in juicy[:15]), {"paths": juicy}))
                self._paths_lead(ctx, svc, base, juicy)
        else:
            findings.append(Finding(self.name, svc.port, "Content discovery: nothing found", "info",
                                    detail + ". Try a bigger list with --wordlist."))
        return findings

    def _run_gobuster(self, ctx: Context, svc: Service, url: str, wordlist: str, exts: str, outfile: Path,
                      deadline: float) -> GobusterRun:
        cmd = [
            "gobuster", "dir", "-u", url, "-w", wordlist,
            "-t", str(ctx.options.threads), "-q", "--no-progress", "--no-error", "--no-color",
            "--timeout", f"{ctx.options.http_timeout}s", "-o", str(outfile),
        ]
        if svc.is_tls:
            cmd.append("-k")
        if exts:
            cmd += ["-x", exts]
        res = ctx.run(cmd, timeout=max(1.0, deadline - time.monotonic()))

        # Wildcard servers answer every path; gobuster refuses to run. Retry excluding that length.
        combined = res.stdout + res.stderr
        if not res.ok and not res.timed_out and "non existing urls" in combined:
            m = _GB_WILDCARD_LEN.search(combined)
            if m:
                ctx.log.warn(f"{svc.label} web: wildcard responses under {url} (length {m.group(1)}), "
                             "retrying with --exclude-length")
                res = ctx.run([*cmd, "--exclude-length", m.group(1)], timeout=max(1.0, deadline - time.monotonic()))

        hits = parse_gobuster(res.stdout)
        error = ""
        if not res.ok and not res.timed_out:
            err = (res.stderr or res.stdout).strip().splitlines()
            error = err[-1] if err else "gobuster exited with an error"
        return GobusterRun(hits, res.timed_out, error)


def _target_ip(ctx: Context) -> str:
    return ctx.target_ip()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
