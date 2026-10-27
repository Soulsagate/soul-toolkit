"""Render a HostResult as one self-contained HTML file (inline CSS + a few lines of JS, no network).

Light and dark themes follow the system setting, with a toggle. Sections and findings are
<details> elements, so everything collapses without JavaScript; JS only adds copy buttons
and the theme toggle.
"""

from __future__ import annotations

import re
from html import escape

from soul_toolkit import __version__
from soul_toolkit.core.models import Finding, HostResult
from soul_toolkit.recon import leads as leads_mod

SEV_ORDER = ("high", "medium", "low", "info")

CSS = """
:root{--bg:#f7f7f8;--panel:#fff;--text:#1d1f23;--muted:#5d6470;--border:#dcdfe4;--code:#f0f1f3;
--accent:#3b5bdb;--high:#c92a2a;--high-bg:#fdecec;--medium:#b35900;--medium-bg:#fff1e0;
--low:#8a6d00;--low-bg:#fff8d6;--info:#1c64b4;--info-bg:#e7f1fc;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#121417;--panel:#1b1e23;--text:#e6e8eb;
--muted:#9aa2ad;--border:#2e333a;--code:#23272d;--accent:#8ea6ff;--high:#ff8787;--high-bg:#3a1d1f;
--medium:#ffb066;--medium-bg:#3a2a18;--low:#ffd84d;--low-bg:#353016;--info:#74b4ff;--info-bg:#17283d;
color-scheme:dark}}
:root[data-theme=dark]{--bg:#121417;--panel:#1b1e23;--text:#e6e8eb;--muted:#9aa2ad;--border:#2e333a;
--code:#23272d;--accent:#8ea6ff;--high:#ff8787;--high-bg:#3a1d1f;--medium:#ffb066;--medium-bg:#3a2a18;
--low:#ffd84d;--low-bg:#353016;--info:#74b4ff;--info-bg:#17283d;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",
Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.15rem;margin:0}
code,pre{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
code{background:var(--code);padding:1px 5px;border-radius:4px}
pre{background:var(--code);padding:10px 12px;border-radius:6px;overflow-x:auto;margin:8px 0;position:relative}
pre code{background:none;padding:0}
a{color:var(--accent)}
.muted{color:var(--muted)}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:16px}
.meta{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px;margin:12px 0 0}
.meta dt{color:var(--muted)}.meta dd{margin:0}
section,details.section{background:var(--panel);border:1px solid var(--border);border-radius:10px;
margin:14px 0;padding:14px 16px}
details.section>summary{cursor:pointer;list-style-position:outside}
details.section[open]>summary{margin-bottom:10px}
details.section>summary h2{display:inline}
.pills{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}
.pill,.badge{display:inline-block;border-radius:999px;font-weight:600;font-size:.8rem;padding:2px 10px}
.badge{font-size:.72rem;letter-spacing:.03em;padding:1px 8px;text-transform:uppercase}
.sev-high{color:var(--high);background:var(--high-bg)}.sev-medium{color:var(--medium);background:var(--medium-bg)}
.sev-low{color:var(--low);background:var(--low-bg)}.sev-info{color:var(--info);background:var(--info-bg)}
ol.leads{margin:8px 0 0;padding-left:1.4em}
ol.leads li{margin:0 0 14px;padding-left:4px}
ol.leads li::marker{font-weight:700;color:var(--accent)}
.where{color:var(--muted);font-size:.85rem}
table{border-collapse:collapse;width:100%;font-size:.9rem;display:block;overflow-x:auto}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600}
details.finding{border:1px solid var(--border);border-left-width:4px;border-radius:8px;margin:10px 0;
padding:8px 12px}
details.finding>summary{cursor:pointer;font-weight:600}
details.finding{color:var(--text);background:none}
details.finding.sev-high{border-left-color:var(--high)}details.finding.sev-medium{border-left-color:var(--medium)}
details.finding.sev-low{border-left-color:var(--low)}details.finding.sev-info{border-left-color:var(--info)}
details.finding .badge{margin-right:6px}
details.finding>div{margin-top:8px}
button{font:inherit;font-size:.8rem;color:var(--text);background:var(--panel);border:1px solid var(--border);
border-radius:6px;padding:3px 10px;cursor:pointer}
.cmd{display:flex;align-items:center;gap:8px;margin:8px 0}.cmd pre{flex:1;min-width:0;margin:0}
footer{color:var(--muted);font-size:.85rem;text-align:center;margin-top:28px}
@media (max-width:600px){header{flex-direction:column}.meta{grid-template-columns:1fr}.meta dt{margin-top:6px}}
@media print{button{display:none}details{break-inside:avoid}}
"""

JS = """
(function(){var r=document.documentElement,b=document.getElementById('theme');
function cur(){return r.dataset.theme||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light')}
if(b){b.hidden=false;b.onclick=function(){r.dataset.theme=cur()==='dark'?'light':'dark'}}
if(!navigator.clipboard)return;
document.querySelectorAll('pre[data-copy]').forEach(function(p){var c=document.createElement('button');
c.className='copy';c.type='button';c.textContent='Copy';c.onclick=function(){
navigator.clipboard.writeText(p.querySelector('code').textContent).then(function(){c.textContent='Copied';
setTimeout(function(){c.textContent='Copy'},1500)})};p.parentNode.appendChild(c)})})();
"""


def _e(text: object) -> str:
    return escape(str(text if text is not None else ""))


_TICKS = re.compile(r"`([^`]+)`")


def _md(text: str) -> str:
    """Escape *text*, turning Markdown `inline code` (used in lead/finding text) into <code>."""
    return _TICKS.sub(r"<code>\1</code>", _e(text))


def _pre(text: str, copy: bool = False) -> str:
    if copy:  # JS puts a Copy button next to it
        return f'<div class="cmd"><pre data-copy><code>{_e(text.rstrip())}</code></pre></div>'
    return f"<pre><code>{_e(text.rstrip())}</code></pre>"


def _fmt_duration(seconds: float) -> str:
    m, s = divmod(round(seconds), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    """*rows* hold already-escaped HTML."""
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _finding_body(data: dict) -> str:
    if not data:
        return ""
    if "paths" in data:
        rows = [[f"<code>{_e(p['path'])}</code>", _e(p["status"]), _e(p["size"]), _e(p.get("redirect", ""))]
                for p in data["paths"][:500]]
        more = f"<p class=muted>... {len(data['paths']) - 500} more in findings.json</p>" \
            if len(data["paths"]) > 500 else ""
        return _table(["Path", "Status", "Size", "Redirect"], rows) + more
    if "vhosts" in data:
        rows = [[f"<code>{_e(v['host'])}</code>", _e(v["status"]), _e(v["size"])] for v in data["vhosts"]]
        return (_table(["Virtual host", "Status", "Size"], rows) + "<p>Add them to <code>/etc/hosts</code>:</p>"
                + _pre(f"echo '{data['hosts_line']}' | sudo tee -a /etc/hosts", copy=True))
    if "exploits" in data:
        rows = [[_e(x["edb_id"]), _e(x["title"]), _e(x["type"] or "-"), "yes" if x["verified"] else "no"]
                for x in data["exploits"]]
        return (_table(["EDB-ID", "Title", "Type", "Verified"], rows)
                + "<p class=muted>Read one with <code>searchsploit -x &lt;EDB-ID&gt;</code>, copy it with "
                "<code>searchsploit -m &lt;EDB-ID&gt;</code>.</p>")
    for key in ("listing", "entries"):
        if key in data:
            return _pre("\n".join(data[key]))
    if "shares" in data:
        rows = [[f"<code>{_e(s['name'])}</code>", _e(s["type"]), _e(s["comment"])] for s in data["shares"]]
        return _table(["Share", "Type", "Comment"], rows)
    return ""


def _finding(f: Finding) -> str:
    opened = " open" if f.severity in ("high", "medium") else ""
    detail = f"<p>{_md(f.detail)}</p>" if f.detail else ""
    return (f'<details class="finding sev-{f.severity}"{opened}><summary>'
            f'<span class="badge sev-{f.severity}">{f.severity}</span>{_e(f.title)} '
            f'<span class="where">{f.port}/{_e(f.protocol)} · {_e(f.module)}</span></summary>'
            f"<div>{detail}{_finding_body(f.data)}</div></details>")


def _section(title: str, body: str, open_: bool = True, sid: str = "") -> str:
    attr = f' id="{sid}"' if sid else ""
    return (f'<details class="section"{attr}{" open" if open_ else ""}><summary><h2>{_e(title)}</h2></summary>'
            f"{body}</details>")


def render_html(r: HostResult) -> str:
    findings = r.sorted_findings()
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}
    parts: list[str] = []
    add = parts.append

    meta = [("Target", f"<code>{_e(r.target)}</code>")]
    if r.address and r.address != r.target:
        meta.append(("Address", f"<code>{_e(r.address)}</code>"))
    if r.hostnames:
        meta.append(("Hostnames", _e(", ".join(r.hostnames))))
    meta.append(("Host status", _e(r.status)))
    if r.os_guess:
        meta.append(("OS guess", _e(r.os_guess)))
    meta += [("Open ports", str(len(r.services))), ("Started", _e(r.started)),
             ("Duration", _fmt_duration(r.duration))]
    pills = "".join(f'<span class="pill sev-{s}">{s}: {n}</span>' for s, n in counts.items())
    add("<header><div>")
    add(f"<h1>Recon report: <code>{_e(r.target)}</code></h1>")
    add(f'<div class="muted">Generated by soul-toolkit v{_e(__version__)} - authorized testing only.</div>')
    add('<dl class="meta">' + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in meta) + "</dl>")
    add(f'<div class="pills">{pills}</div>')
    add('</div><button id="theme" type="button" hidden>Toggle theme</button></header>')

    top = r.leads[:leads_mod.WHERE_TO_START]
    if top:
        items = []
        for lead in top:
            cmd = _pre(lead.command, copy=True) if lead.command else ""
            items.append(f"<li><strong>{_e(lead.title)}</strong> <span class=where>{_e(lead.where)}</span>"
                         f"<div>{_md(lead.why)}</div>{cmd}</li>")
        body = ('<p class="muted">The most promising leads across all services, best first.</p>'
                f'<ol class="leads">{"".join(items)}</ol>')
    else:
        body = ("<p><em>Nothing stood out.</em> Re-run without <code>--quick</code>/<code>-p</code> to sweep "
                "every port, and browse any web service by hand.</p>")
    add(f'<section id="where-to-start"><h2>Where to start</h2>{body}</section>')

    if r.services:
        rows = [[_e(s.label), _e(s.name + (" (ssl)" if s.tunnel == "ssl" else "")), _e(s.banner or "-")]
                for s in r.services]
        ports = _table(["Port", "Service", "Version"], rows)
    else:
        ports = "<p><em>No open ports found.</em> If the host is up, try <code>--ports</code> or a slower " \
                "<code>--min-rate</code>.</p>"
    add(_section("Open ports", ports, sid="ports"))

    add(_section(f"Findings ({len(findings)})",
                 "".join(_finding(f) for f in findings) or "<p><em>No findings.</em></p>", sid="findings"))

    rest = r.leads[leads_mod.WHERE_TO_START:]
    extra = leads_mod.other_hints(r)
    if rest or extra:
        items = [f"<li><strong>{_e(x.title)}</strong> <span class=where>{_e(x.where)}</span> - {_md(x.why)}"
                 + (f" <code>{_e(x.command)}</code>" if x.command else "") + "</li>" for x in rest]
        items += [f"<li>{_md(h)}</li>" for h in extra]
        add(_section("Other leads and ideas", f"<ul>{''.join(items)}</ul>", open_=False, sid="other"))

    scripted = [s for s in r.services if s.scripts]
    if scripted:
        blocks = []
        for s in scripted:
            inner = "".join(f"<p><strong>{_e(sid)}</strong></p>{_pre(out or '(no output)')}"
                            for sid, out in s.scripts.items())
            blocks.append(f'<details class="finding sev-info"><summary>{_e(s.label)} {_e(s.name)}</summary>'
                          f"<div>{inner}</div></details>")
        add(_section("Nmap script output", "".join(blocks), open_=False, sid="scripts"))

    if r.commands:
        add(_section("Commands run", _pre("\n".join(r.commands)), open_=False, sid="commands"))

    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Recon report: {_e(r.target)}</title><style>{CSS}</style></head>"
        f"<body><main>{''.join(parts)}"
        "<footer>soul-toolkit - only test machines you own or are explicitly authorized to test.</footer>"
        f"</main><script>{JS}</script></body></html>\n"
    )
