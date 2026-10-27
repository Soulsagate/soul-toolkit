"""Render a HostResult as one self-contained HTML report.

Everything is inline: CSS, a little JavaScript and SVG icons. There are no fonts, images, CDNs or
requests of any kind - reports hold scan data and get opened offline.

The page works without JavaScript: every section and finding is rendered expanded. JavaScript only
adds niceties - collapsing the noisy parts, severity filters, expand/collapse all, copy buttons,
the theme toggle, the active section in the nav, and expanding everything before printing.
"""

from __future__ import annotations

import re
from html import escape

from soul_toolkit import __version__
from soul_toolkit.core.models import Finding, HostResult, Lead, Service
from soul_toolkit.recon import leads as leads_mod

SEV_ORDER = ("high", "medium", "low", "info")
SEV_LABEL = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

# --------------------------------------------------------------------------- design tokens

# One accent colour + the four severity colours; everything else is neutral. `*-fg` colours are for
# text (checked for WCAG AA against both `surface` and their `*-bg`), `*-bar` for non-text marks.
LIGHT = {
    "bg": "#f4f6f8", "surface": "#ffffff", "surface-2": "#f3f5f8", "zebra": "#f8f9fb",
    "border": "#e2e6ec", "border-strong": "#cdd3dc", "text": "#151a21", "muted": "#566170",
    "accent": "#3d4fd1", "accent-bg": "#eef0fd", "accent-fg": "#3443c2",
    "high-fg": "#b42318", "high-bg": "#fef1f0", "high-bar": "#d92d20",
    "medium-fg": "#a3480b", "medium-bg": "#fff4ea", "medium-bar": "#e8650f",
    "low-fg": "#7e5800", "low-bg": "#fdf7e3", "low-bar": "#c99400",
    "info-fg": "#1c5bbf", "info-bg": "#edf4ff", "info-bar": "#3b82e6",
    "shadow": "0 1px 2px rgba(17,24,39,.05),0 2px 6px rgba(17,24,39,.04)",
    "scheme": "light",
}
DARK = {
    "bg": "#0d1015", "surface": "#151a21", "surface-2": "#1b2129", "zebra": "#181d25",
    "border": "#29303b", "border-strong": "#3a4351", "text": "#e5eaf0", "muted": "#9aa5b4",
    "accent": "#8d9df8", "accent-bg": "#1c2140", "accent-fg": "#a9b5fb",
    "high-fg": "#ff8a7e", "high-bg": "#2c1517", "high-bar": "#f0584c",
    "medium-fg": "#ffad72", "medium-bg": "#2c1c10", "medium-bar": "#f08a3e",
    "low-fg": "#efc95a", "low-bg": "#29230f", "low-bar": "#d6ad37",
    "info-fg": "#7fb6ff", "info-bg": "#112440", "info-bar": "#4b93ec",
    "shadow": "0 1px 2px rgba(0,0,0,.4)",
    "scheme": "dark",
}


def _tokens(t: dict[str, str]) -> str:
    return "".join(f"--{k}:{v};" for k, v in t.items() if k != "scheme") + f"color-scheme:{t['scheme']}"


CSS = f"""
:root{{{_tokens(LIGHT)};
--font:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif;
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
--s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:24px;--s6:32px;--s7:48px;--r:10px;--r-sm:6px;--nav-h:0px}}
@media screen and (prefers-color-scheme:dark){{:root:not([data-theme=light]){{{_tokens(DARK)}}}}}
@media screen{{:root[data-theme=dark]{{{_tokens(DARK)}}}}}
*,*::before,*::after{{box-sizing:border-box}}
[hidden]{{display:none!important}}
html{{-webkit-text-size-adjust:100%}}
@media (prefers-reduced-motion:no-preference){{html{{scroll-behavior:smooth}}}}
body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 var(--font);overflow-wrap:break-word}}
a{{color:var(--accent-fg)}}
h1,h2,h3{{line-height:1.25;margin:0}}
p{{margin:0 0 var(--s2)}}
:focus-visible{{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}}
.skip{{position:absolute;left:-9999px;top:var(--s2);background:var(--surface);padding:var(--s2) var(--s3);
border-radius:var(--r-sm);z-index:20}}
.skip:focus{{left:var(--s2)}}
.icon{{width:16px;height:16px;flex:none;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;
stroke-linejoin:round}}
code{{font:.875em/1.4 var(--mono);background:var(--surface-2);border:1px solid var(--border);border-radius:4px;
padding:.05em .35em;overflow-wrap:anywhere}}
.muted{{color:var(--muted)}}
.mono{{font-family:var(--mono)}}

/* layout: sidebar nav on wide screens, a sticky top bar on narrow ones */
.layout{{display:grid;grid-template-columns:200px minmax(0,1fr);gap:var(--s6);max-width:1180px;margin:0 auto;
padding:var(--s6) var(--s5) var(--s7)}}
main{{min-width:0}}
.toc{{position:sticky;top:var(--s6);align-self:start;display:flex;flex-direction:column;gap:var(--s4)}}
.brand{{display:flex;align-items:center;gap:var(--s2);font-weight:650;font-size:.9rem;color:var(--text)}}
.brand .icon{{color:var(--accent)}}
.toc ul{{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:2px}}
.toc a{{display:flex;justify-content:space-between;gap:var(--s2);padding:6px 10px;border-radius:var(--r-sm);
color:var(--muted);text-decoration:none;font-size:.875rem;transition:background .15s,color .15s}}
.toc a:hover{{background:var(--surface-2);color:var(--text)}}
.toc a[aria-current=true]{{background:var(--accent-bg);color:var(--accent-fg);font-weight:600}}
.toc .n{{font-variant-numeric:tabular-nums;font-size:.8rem}}
@media (max-width:960px){{
:root{{--nav-h:52px}}
.layout{{display:block;padding:0 var(--s4) var(--s7)}}
.toc{{position:sticky;top:0;z-index:10;flex-direction:row;align-items:center;gap:var(--s2);
margin:0 calc(-1*var(--s4)) var(--s4);padding:var(--s2) var(--s4);background:var(--bg);
border-bottom:1px solid var(--border)}}
.toc .brand{{display:none}}
.toc ul{{flex-direction:row;overflow-x:auto;flex:1;min-width:0;scrollbar-width:none}}
.toc ul::-webkit-scrollbar{{display:none}}
.toc a{{white-space:nowrap;padding:6px 10px}}
.toc .n{{display:none}}
.theme span{{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}}
.theme{{align-self:center;padding:8px}}
}}

/* cards and sections */
.card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);box-shadow:var(--shadow)}}
.section{{margin-top:var(--s7);scroll-margin-top:calc(var(--nav-h) + var(--s4))}}
.section-head{{display:flex;align-items:baseline;justify-content:space-between;gap:var(--s3);flex-wrap:wrap;
margin-bottom:var(--s4)}}
.section-head h2{{font-size:1.2rem;font-weight:650;display:flex;align-items:center;gap:var(--s2)}}
.count{{font:600 .75rem/1 var(--font);color:var(--muted);background:var(--surface-2);border:1px solid var(--border);
border-radius:999px;padding:3px 8px}}
.hint{{color:var(--muted);font-size:.875rem;margin:0}}

/* summary header */
.summary{{padding:var(--s5);scroll-margin-top:calc(var(--nav-h) + var(--s4))}}
.eyebrow{{font-size:.75rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}}
.title-row{{display:flex;justify-content:space-between;align-items:flex-start;gap:var(--s3);
margin:var(--s1) 0 var(--s5)}}
.title-row h1{{font:650 1.6rem/1.2 var(--mono);overflow-wrap:anywhere}}
.status{{display:inline-flex;align-items:center;gap:6px;font-size:.8rem;font-weight:600;padding:4px 10px;
border-radius:999px;border:1px solid var(--border);background:var(--surface-2);white-space:nowrap}}
.status::before{{content:"";width:7px;height:7px;border-radius:50%;background:var(--muted)}}
.status.up::before{{background:var(--accent)}}
.status.warn{{color:var(--medium-fg);background:var(--medium-bg);border-color:transparent}}
.status.warn::before{{background:var(--medium-bar)}}
.badges{{display:flex;flex-wrap:wrap;gap:var(--s2);justify-content:flex-end}}
.facts{{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:var(--s4) var(--s5);margin:0}}
.facts div{{min-width:0}}
.facts dt{{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;font-weight:600}}
.facts dd{{margin:2px 0 0;font-weight:500;overflow-wrap:anywhere}}
.chips{{display:flex;flex-wrap:wrap;gap:var(--s2);margin-top:var(--s5);padding-top:var(--s4);
border-top:1px solid var(--border)}}
.chip{{display:inline-flex;align-items:center;gap:var(--s2);padding:5px 12px;border-radius:999px;font-size:.85rem;
font-weight:600;text-decoration:none;border:1px solid transparent;transition:filter .15s}}
.chip b{{font-variant-numeric:tabular-nums}}
.chip.zero{{opacity:.6}}
.chip:hover{{filter:brightness(.97)}}
.dot{{width:8px;height:8px;border-radius:50%;flex:none}}
.sev-high{{--fg:var(--high-fg);--sbg:var(--high-bg);--bar:var(--high-bar)}}
.sev-medium{{--fg:var(--medium-fg);--sbg:var(--medium-bg);--bar:var(--medium-bar)}}
.sev-low{{--fg:var(--low-fg);--sbg:var(--low-bg);--bar:var(--low-bar)}}
.sev-info{{--fg:var(--info-fg);--sbg:var(--info-bg);--bar:var(--info-bar)}}
.chip,.pill{{color:var(--fg);background:var(--sbg)}}
.chip .dot{{background:var(--bar)}}
.pill{{display:inline-block;font:700 .68rem/1 var(--font);letter-spacing:.06em;text-transform:uppercase;
padding:5px 8px;border-radius:999px;white-space:nowrap}}
.partial{{display:flex;gap:var(--s3);align-items:flex-start;margin:0 0 var(--s5);padding:var(--s3) var(--s4);
border:1px solid var(--medium-bar);border-left-width:4px;border-radius:var(--r-sm);background:var(--medium-bg)}}
.partial .icon{{color:var(--medium-fg);margin-top:3px}}
.partial strong{{color:var(--medium-fg)}}

/* where to start */
.leads{{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:var(--s3)}}
.lead{{display:grid;grid-template-columns:auto minmax(0,1fr);gap:var(--s4);padding:var(--s4) var(--s5)}}
.num{{width:30px;height:30px;border-radius:50%;display:grid;place-items:center;font-weight:700;font-size:.9rem;
background:var(--accent-bg);color:var(--accent-fg);font-variant-numeric:tabular-nums}}
.lead-head{{display:flex;flex-wrap:wrap;align-items:center;gap:var(--s2) var(--s3);margin-bottom:var(--s1)}}
.lead h3{{font-size:1rem;font-weight:650}}
.port{{font:500 .78rem/1 var(--mono);color:var(--muted);background:var(--surface-2);border:1px solid var(--border);
border-radius:999px;padding:4px 8px;white-space:nowrap}}
.lead p{{color:var(--muted);margin-bottom:var(--s3)}}
.lead p code{{color:var(--text)}}
.empty{{padding:var(--s5);color:var(--muted)}}

/* code blocks */
.codeblock{{border:1px solid var(--border);border-radius:var(--r-sm);background:var(--surface-2);overflow:hidden;
min-width:0}}
.codebar{{display:flex;align-items:center;justify-content:space-between;gap:var(--s2);min-height:32px;
padding:2px 4px 2px 12px;border-bottom:1px solid var(--border);font:600 .7rem/1 var(--font);
letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}}
pre{{margin:0;padding:var(--s3) var(--s4);overflow:auto;font:13px/1.6 var(--mono);color:var(--text);
tab-size:4}}
pre code{{all:unset;font:inherit}}
.scroll pre{{max-height:420px}}

/* buttons */
.btn{{display:inline-flex;align-items:center;gap:6px;font:500 .8rem/1 var(--font);color:var(--text);
background:var(--surface);border:1px solid var(--border);border-radius:var(--r-sm);padding:7px 10px;cursor:pointer;
transition:background .15s,border-color .15s,color .15s}}
.btn:hover{{background:var(--surface-2);border-color:var(--border-strong)}}
.btn[aria-pressed=true]{{background:var(--accent-bg);border-color:var(--accent);color:var(--accent-fg)}}
.btn .n{{font-variant-numeric:tabular-nums;color:var(--muted)}}
.btn[aria-pressed=true] .n{{color:inherit}}
.copy{{border-color:transparent;background:transparent;padding:6px 8px;text-transform:none;letter-spacing:0}}
.copy.done{{color:var(--accent-fg)}}
.copy .i-ok,.copy.done .i-copy{{display:none}}
.copy.done .i-ok{{display:inline}}
.theme{{align-self:flex-start}}

/* findings */
.toolbar{{display:none;flex-wrap:wrap;justify-content:space-between;gap:var(--s2);margin-bottom:var(--s3)}}
.js .toolbar{{display:flex}}
.group{{display:flex;flex-wrap:wrap;gap:6px}}
.findings{{display:flex;flex-direction:column;gap:var(--s3)}}
.finding{{border-left:4px solid var(--bar);overflow:hidden}}
.finding>summary,.fold>summary{{list-style:none;cursor:pointer}}
.finding>summary::-webkit-details-marker,.fold>summary::-webkit-details-marker{{display:none}}
.finding>summary{{display:flex;align-items:center;gap:var(--s3);padding:var(--s3) var(--s4)}}
.finding>summary:hover{{background:var(--zebra)}}
.chev{{color:var(--muted);transition:transform .15s}}
details[open]>summary .chev{{transform:rotate(90deg)}}
.ftitle{{font-weight:600;flex:1;min-width:0}}
.fmeta{{font:.78rem/1.3 var(--mono);color:var(--muted);white-space:nowrap}}
.fbody{{padding:0 var(--s4) var(--s4) calc(var(--s4) + 16px + var(--s3));display:flex;flex-direction:column;
gap:var(--s3)}}
.fbody>p{{margin:0}}
.nomatch{{padding:var(--s4);color:var(--muted)}}
@media (max-width:640px){{
.finding>summary{{flex-wrap:wrap;row-gap:6px}}
.ftitle{{flex-basis:calc(100% - 40px);order:3;margin-left:calc(16px + var(--s3))}}
.fmeta{{margin-left:auto}}
.fbody{{padding-left:var(--s4)}}
.lead{{gap:var(--s3);padding:var(--s4)}}
.num{{width:26px;height:26px;font-size:.8rem}}
.summary{{padding:var(--s4)}}
.title-row{{flex-direction:column}}
.facts{{grid-template-columns:repeat(2,minmax(0,1fr))}}
}}

/* tables */
.table-wrap{{overflow-x:auto;border:1px solid var(--border);border-radius:var(--r-sm);background:var(--surface)}}
table{{border-collapse:collapse;width:100%;font-size:.875rem}}
th{{text-align:left;font-size:.72rem;font-weight:650;text-transform:uppercase;letter-spacing:.05em;
color:var(--muted);background:var(--surface-2);padding:8px 12px;border-bottom:1px solid var(--border);
white-space:nowrap}}
td{{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top}}
tbody tr:nth-child(even){{background:var(--zebra)}}
tbody tr:last-child td{{border-bottom:0}}
td.num-cell,th.num-cell{{text-align:right;font-variant-numeric:tabular-nums}}
td.mono,td code{{font-family:var(--mono);font-size:.82rem}}
td code,td .mono{{white-space:nowrap;overflow-wrap:normal}}
.svc{{display:inline-block;font:600 .75rem/1 var(--font);padding:4px 8px;border-radius:999px;
background:var(--accent-bg);color:var(--accent-fg);white-space:nowrap}}
.portno{{font-family:var(--mono);white-space:nowrap}}
.proto{{display:inline-block;font:700 .66rem/1 var(--font);letter-spacing:.05em;padding:3px 6px;border-radius:4px;
border:1px solid var(--border);color:var(--muted);margin-left:6px;vertical-align:1px}}
.proto.udp{{border-color:var(--accent);color:var(--accent-fg)}}
.st{{font:600 .8rem/1 var(--mono);padding:3px 6px;border-radius:4px;white-space:nowrap}}
.st-2{{color:var(--accent-fg);background:var(--accent-bg)}}
.st-3{{color:var(--muted);background:var(--surface-2)}}
.st-4{{color:var(--medium-fg);background:var(--medium-bg)}}
.st-5{{color:var(--high-fg);background:var(--high-bg)}}

/* other leads, collapsible sections */
.list{{margin:0;padding:var(--s2) 0;list-style:none}}
.list li{{padding:var(--s3) var(--s5);border-bottom:1px solid var(--border)}}
.list li:last-child{{border-bottom:0}}
.list .codeblock{{margin-top:var(--s2)}}
.fold{{margin-top:var(--s3)}}
.fold>summary{{display:flex;align-items:center;gap:var(--s3);padding:var(--s3) var(--s4);font-weight:600}}
.fold>summary .fmeta{{margin-left:auto}}
.fold>.fbody{{padding-left:var(--s4)}}
footer{{margin-top:var(--s7);padding-top:var(--s4);border-top:1px solid var(--border);color:var(--muted);
font-size:.8rem;display:flex;flex-wrap:wrap;justify-content:space-between;gap:var(--s2)}}

@media (prefers-reduced-motion:reduce){{*,*::before,*::after{{transition:none!important}}}}

@media print{{
:root{{{_tokens(LIGHT)};--nav-h:0px}}
body{{background:#fff;font-size:10.5pt}}
.toc,.toolbar,.copy,.theme,.skip,.chev,.nomatch{{display:none!important}}
.layout{{display:block;padding:0;max-width:none}}
.card{{box-shadow:none}}
.section{{margin-top:var(--s6)}}
.finding[hidden]{{display:block!important}}
details::details-content{{content-visibility:visible;display:block}}
.lead,.finding,.codeblock,tr,.summary,.fold>summary{{break-inside:avoid}}
#commands .codeblock{{break-inside:auto}}
h2,h3,.section-head,.fold>summary,.finding>summary{{break-after:avoid}}
pre{{white-space:pre-wrap;word-break:break-all;overflow:visible;max-height:none!important}}
.table-wrap{{overflow:visible}}
a{{color:inherit;text-decoration:none}}
@page{{margin:14mm}}
}}
"""

JS = """
(function(){
var d=document,r=d.documentElement;
function all(s,root){return Array.prototype.slice.call((root||d).querySelectorAll(s))}
/* theme toggle (remembered per browser when storage is allowed) */
var tb=d.getElementById('theme');
function cur(){return r.dataset.theme||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light')}
function label(){if(tb){tb.querySelector('span').textContent=cur()==='dark'?'Light theme':'Dark theme'}}
try{var saved=localStorage.getItem('soul-theme');if(saved)r.dataset.theme=saved}catch(e){}
if(tb){tb.hidden=false;label();tb.onclick=function(){r.dataset.theme=cur()==='dark'?'light':'dark';label();
try{localStorage.setItem('soul-theme',r.dataset.theme)}catch(e){}}}
/* collapse what is noisy by default (everything is open without JS) */
all('details[data-fold]').forEach(function(x){x.open=false});
/* copy buttons */
function copyText(t){if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(t);
return new Promise(function(ok,no){var a=d.createElement('textarea');a.value=t;a.setAttribute('readonly','');
a.style.position='fixed';a.style.opacity='0';d.body.appendChild(a);a.select();
try{d.execCommand('copy')?ok():no()}catch(e){no(e)}d.body.removeChild(a)})}
all('.copy').forEach(function(b){b.hidden=false;var s=b.querySelector('span'),t;
b.onclick=function(){var code=b.closest('.codeblock').querySelector('pre').textContent;
copyText(code).then(function(){b.classList.add('done');s.textContent='Copied';
clearTimeout(t);t=setTimeout(function(){b.classList.remove('done');s.textContent='Copy'},1600)},
function(){s.textContent='Select + copy'})}});
/* severity filter */
var fs=all('.finding'),none=d.getElementById('nomatch');
function filter(sev){all('[data-filter]').forEach(function(b){if(b.tagName==='BUTTON')
b.setAttribute('aria-pressed',String(b.dataset.filter===sev))});var shown=0;
fs.forEach(function(f){var ok=sev==='all'||f.dataset.sev===sev;f.hidden=!ok;if(ok)shown++});
if(none)none.hidden=shown>0}
all('[data-filter]').forEach(function(b){b.addEventListener('click',function(){filter(b.dataset.filter)})});
all('[data-expand]').forEach(function(b){b.onclick=function(){var o=b.dataset.expand==='1';
fs.forEach(function(f){if(!f.hidden)f.open=o})}});
/* print: show everything, then put it back */
var before=[];
window.addEventListener('beforeprint',function(){before=all('details').map(function(x){var o=x.open;x.open=true;
return o})});
window.addEventListener('afterprint',function(){all('details').forEach(function(x,i){if(i<before.length)
x.open=before[i]})});
/* highlight the section in view */
var links=all('.toc a');
if('IntersectionObserver' in window&&links.length){var map={};links.forEach(function(a){
map[a.getAttribute('href').slice(1)]=a});var io=new IntersectionObserver(function(es){es.forEach(function(e){
if(e.isIntersecting){links.forEach(function(a){a.removeAttribute('aria-current')});
var a=map[e.target.id];if(a)a.setAttribute('aria-current','true')}})},{rootMargin:'-20% 0px -70% 0px'});
Object.keys(map).forEach(function(id){var s=d.getElementById(id);if(s)io.observe(s)})}
})();
"""

# --------------------------------------------------------------------------- icons (inline SVG)

_ICONS = {
    "copy": '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9'
            'a2 2 0 0 1 2 2v1"/>',
    "ok": '<path d="M20 6 9 17l-5-5"/>',
    "chev": '<path d="m9 18 6-6-6-6"/>',
    "alert": '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>'
             '<path d="M12 9v4M12 17h.01"/>',
    "theme": '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
    "radar": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 19 5"/>',
}


def _icon(name: str, cls: str = "") -> str:
    classes = f"icon {cls}".strip()
    return (f'<svg class="{classes}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
            f"{_ICONS[name]}</svg>")


# --------------------------------------------------------------------------- escaping helpers


def _e(text: object) -> str:
    return escape(str(text if text is not None else ""))


_TICKS = re.compile(r"`([^`]+)`")


def _md(text: str) -> str:
    """Escape *text*, turning Markdown `inline code` (used in lead/finding text) into <code>."""
    return _TICKS.sub(r"<code>\1</code>", _e(text))


def _fmt_duration(seconds: float) -> str:
    m, s = divmod(round(seconds), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"


# --------------------------------------------------------------------------- building blocks


def _code(text: str, label: str = "", copy: bool = False, scroll: bool = False) -> str:
    """A code block with a small header bar; *copy* adds a Copy button (shown by JS)."""
    button = ""
    if copy:
        button = (f'<button class="btn copy" type="button" hidden>{_icon("copy", "i-copy")}{_icon("ok", "i-ok")}'
                  '<span aria-live="polite">Copy</span></button>')
    bar = f'<div class="codebar"><span>{_e(label)}</span>{button}</div>' if (label or copy) else ""
    cls = "codeblock scroll" if scroll else "codeblock"
    return f'<div class="{cls}">{bar}<pre><code>{_e(text.rstrip())}</code></pre></div>'


def _table(headers: list[str], rows: list[list[str]], num_cols: tuple[int, ...] = ()) -> str:
    """*rows* hold already-escaped HTML. Columns in *num_cols* are right-aligned numbers."""
    num = ' class="num-cell"'
    head = "".join(f'<th scope="col"{num if i in num_cols else ""}>{_e(h)}</th>' for i, h in enumerate(headers))
    body = "".join(
        "<tr>" + "".join(f'<td class="num-cell">{c}</td>' if i in num_cols else f"<td>{c}</td>"
                         for i, c in enumerate(row)) + "</tr>"
        for row in rows
    )
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _status(code: object) -> str:
    text = _e(code)
    first = str(code)[:1]
    cls = f" st-{first}" if first in "2345" and str(code).isdigit() else ""
    return f'<span class="st{cls}">{text}</span>'


def _access(access: str) -> str:
    """READ / NO ACCESS badge for an SMB share ("-" for ones that weren't checked, like IPC$)."""
    if not access:
        return '<span class="muted">-</span>'
    cls = {"READ": " st-2", "NO ACCESS": " st-4"}.get(access, " st-3")
    return f'<span class="st{cls}">{_e(access)}</span>'


def _finding_body(data: dict) -> str:
    if not data:
        return ""
    if "paths" in data:
        rows = [[f"<code>{_e(p['path'])}</code>", _status(p["status"]), _e(p["size"]),
                 f'<span class="mono">{_e(p.get("redirect") or "")}</span>'] for p in data["paths"][:500]]
        more = (f'<p class="muted">... {len(data["paths"]) - 500} more in findings.json</p>'
                if len(data["paths"]) > 500 else "")
        return _table(["Path", "Status", "Size", "Redirect"], rows, num_cols=(2,)) + more
    if "vhosts" in data:
        rows = [[f"<code>{_e(v['host'])}</code>", _status(v["status"]), _e(v["size"])] for v in data["vhosts"]]
        return (_table(["Virtual host", "Status", "Size"], rows, num_cols=(2,))
                + _code(f"echo '{data['hosts_line']}' | sudo tee -a /etc/hosts", "add to /etc/hosts", copy=True))
    if "exploits" in data:
        rows = [[f'<span class="mono">{_e(x["edb_id"])}</span>', _e(x["title"]), _e(x["type"] or "-"),
                 "yes" if x["verified"] else "no"] for x in data["exploits"]]
        first = _e(data["exploits"][0]["edb_id"]) if data["exploits"] else "12345"
        return (_table(["EDB-ID", "Title", "Type", "Verified"], rows)
                + f'<p class="hint">Read one with <code>searchsploit -x {first}</code>, copy it here with '
                  f"<code>searchsploit -m {first}</code> (use the EDB-ID from the table).</p>")
    for key, label in (("listing", "listing"), ("entries", "entries")):
        if key in data:
            return _code("\n".join(data[key]), label, scroll=True)
    if "shares" in data:
        if not any("access" in s for s in data["shares"]):  # findings.json from before the read check
            rows = [[f"<code>{_e(s['name'])}</code>", _e(s["type"]), _e(s["comment"])] for s in data["shares"]]
            return _table(["Share", "Type", "Comment"], rows)
        rows = [[f"<code>{_e(s['name'])}</code>", _e(s["type"]), _access(s.get("access", "")), _e(s["comment"])]
                for s in data["shares"]]
        return _table(["Share", "Type", "Access", "Comment"], rows)
    out = ""
    if "table" in data:
        out += _table(data["table"]["headers"], [[_e(c) for c in row] for row in data["table"]["rows"]])
    if "lines" in data:
        out += _code("\n".join(data["lines"]), "output", scroll=True)
    return out


def _finding(f: Finding) -> str:
    fold = "" if f.severity in ("high", "medium") else " data-fold"
    detail = f"<p>{_md(f.detail)}</p>" if f.detail else ""
    return (f'<details class="finding card sev-{f.severity}" data-sev="{f.severity}" open{fold}>'
            f'<summary>{_icon("chev", "chev")}<span class="pill">{SEV_LABEL[f.severity]}</span>'
            f'<span class="ftitle">{_e(f.title)}</span>'
            f'<span class="fmeta">{f.port}/{_e(f.protocol)} · {_e(f.module)}</span></summary>'
            f'<div class="fbody">{detail}{_finding_body(f.data)}</div></details>')


def _lead_card(i: int, lead: Lead) -> str:
    cmd = _code(lead.command, "command", copy=True) if lead.command else ""
    return (f'<li class="lead card"><span class="num" aria-hidden="true">{i}</span><div>'
            f'<div class="lead-head"><h3>{_e(lead.title)}</h3><span class="port">{_e(lead.where)}</span></div>'
            f"<p>{_md(lead.why)}</p>{cmd}</div></li>")


def _section(sid: str, title: str, body: str, count: int | None = None, hint: str = "") -> str:
    badge = f' <span class="count">{count}</span>' if count is not None else ""
    hint_html = f'<p class="hint">{hint}</p>' if hint else ""
    return (f'<section class="section" id="{sid}" aria-labelledby="{sid}-h"><div class="section-head">'
            f'<h2 id="{sid}-h">{_e(title)}{badge}</h2>{hint_html}</div>{body}</section>')


def _ports_table(services: list[Service]) -> str:
    rows = []
    for s in services:
        proto = f'<span class="proto udp">{_e(s.protocol.upper())}</span>' if s.protocol != "tcp" else ""
        name = _e(s.name or "unknown") + (" / ssl" if s.tunnel == "ssl" else "")
        rows.append([f'<span class="portno">{s.port}</span>{proto}', f'<span class="svc">{name}</span>',
                     _e(s.banner or "-")])
    return _table(["Port", "Service", "Version"], rows)


def _scripts(services: list[Service]) -> str:
    blocks = []
    for s in services:
        inner = "".join(_code(out or "(no output)", sid, scroll=True) for sid, out in s.scripts.items())
        n = len(s.scripts)
        blocks.append(f'<details class="fold card" open data-fold><summary>{_icon("chev", "chev")}'
                      f'<span>{_e(s.label)} <span class="muted">{_e(s.name)}</span></span>'
                      f'<span class="fmeta">{n} script{"s" if n != 1 else ""}</span></summary>'
                      f'<div class="fbody">{inner}</div></details>')
    return "".join(blocks)


# --------------------------------------------------------------------------- page


def render_html(r: HostResult) -> str:
    findings = r.sorted_findings()
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}
    tcp = sum(1 for s in r.services if s.protocol == "tcp")
    udp = len(r.services) - tcp
    top = r.leads[:leads_mod.WHERE_TO_START]
    rest = r.leads[leads_mod.WHERE_TO_START:]
    extra = leads_mod.other_hints(r)
    scripted = [s for s in r.services if s.scripts]

    nav: list[tuple[str, str, int | None]] = [("summary", "Overview", None), ("where-to-start", "Where to start",
                                                                                len(top))]
    nav += [("ports", "Open ports", len(r.services)), ("findings", "Findings", len(findings))]
    if rest or extra:
        nav.append(("other", "Other leads", len(rest) + len(extra)))
    if scripted:
        nav.append(("scripts", "Nmap scripts", len(scripted)))
    if r.commands:
        nav.append(("commands", "Commands", len(r.commands)))

    parts: list[str] = []
    add = parts.append

    # -- nav
    links = "".join(f'<li><a href="#{sid}">{_e(label)}{f"<span class=n>{n}</span>" if n is not None else ""}'
                    "</a></li>" for sid, label, n in nav)
    add(f'<nav class="toc" aria-label="Report sections"><div class="brand">{_icon("radar")}soul-toolkit</div>'
        f"<ul>{links}</ul>"
        f'<button class="btn theme" id="theme" type="button" hidden>{_icon("theme")}<span>Dark theme</span>'
        "</button></nav>")

    add('<main id="main">')

    # -- summary card
    facts = []
    if r.address and r.address != r.target:
        facts.append(("Address", f'<span class="mono">{_e(r.address)}</span>'))
    if r.hostnames:
        facts.append(("Hostnames", _e(", ".join(r.hostnames))))
    ports_text = f"{len(r.services)}" + (f" ({tcp} TCP, {udp} UDP)" if udp else "")
    facts += [("Open ports", ports_text), ("Findings", str(len(findings))), ("Duration", _fmt_duration(r.duration)),
              ("Started", _e(r.started or "-"))]
    if r.os_guess:
        facts.append(("OS guess", _e(r.os_guess)))
    dl = "".join(f"<div><dt>{k}</dt><dd>{v}</dd></div>" for k, v in facts)
    chips = "".join(
        f'<a class="chip sev-{s}{" zero" if counts[s] == 0 else ""}" href="#findings" data-filter="{s}">'
        f'<span class="dot"></span>{SEV_LABEL[s]} <b>{counts[s]}</b></a>' for s in SEV_ORDER)
    badges = f'<span class="status{" up" if r.status == "up" else ""}">Host {_e(r.status or "unknown")}</span>'
    if r.interrupted:
        badges += '<span class="status warn">Partial</span>'
    add(f'<header class="summary card" id="summary"><div class="eyebrow">Recon report</div>'
        f'<div class="title-row"><h1>{_e(r.target)}</h1><div class="badges">{badges}</div></div>')
    if r.interrupted:  # right under the target, before any numbers that it makes incomplete
        add(f'<div class="partial" role="status">{_icon("alert")}<div><strong>Partial report.</strong> The run was '
            f"interrupted (Ctrl-C), so this only holds what finished. Not finished: "
            f"{_e('; '.join(r.incomplete) or 'unknown')}. Re-run to complete it.</div></div>")
    add(f'<dl class="facts">{dl}</dl><div class="chips" aria-label="Findings by severity">{chips}</div></header>')

    # -- where to start
    if top:
        body = f'<ol class="leads">{"".join(_lead_card(i, x) for i, x in enumerate(top, 1))}</ol>'
    else:
        body = ('<div class="card empty"><strong>Nothing stood out.</strong> Re-run without <code>--quick</code> / '
                "<code>-p</code> to sweep every port, and browse any web service by hand.</div>")
    add(_section("where-to-start", "Where to start", body,
                 hint="The most promising leads across all services, best first."))

    # -- ports
    if r.services:
        ports = _ports_table(r.services)
    else:
        ports = ('<div class="card empty">No open ports found. If the host is up, try <code>--ports</code> or a '
                 "slower <code>--min-rate</code>.</div>")
    add(_section("ports", "Open ports", ports, count=len(r.services)))

    # -- findings
    if findings:
        buttons = '<button class="btn" type="button" data-filter="all" aria-pressed="true">All ' \
                  f'<span class="n">{len(findings)}</span></button>'
        buttons += "".join(f'<button class="btn" type="button" data-filter="{s}" aria-pressed="false">'
                           f'{SEV_LABEL[s]} <span class="n">{counts[s]}</span></button>' for s in SEV_ORDER)
        toolbar = (f'<div class="toolbar"><div class="group" role="group" aria-label="Filter by severity">{buttons}'
                   '</div><div class="group"><button class="btn" type="button" data-expand="1">Expand all</button>'
                   '<button class="btn" type="button" data-expand="0">Collapse all</button></div></div>')
        body = (toolbar + f'<div class="findings">{"".join(_finding(f) for f in findings)}'
                '<div class="card nomatch" id="nomatch" hidden>No findings at this severity.</div></div>')
    else:
        body = '<div class="card empty">No findings.</div>'
    add(_section("findings", "Findings", body, count=len(findings)))

    # -- other leads and ideas
    if rest or extra:
        items = [f'<li><div class="lead-head"><strong>{_e(x.title)}</strong><span class="port">{_e(x.where)}</span>'
                 f'</div><div class="muted">{_md(x.why)}</div>'
                 + (_code(x.command, "command", copy=True) if x.command else "") + "</li>" for x in rest]
        items += [f"<li>{_md(h)}</li>" for h in extra]
        add(_section("other", "Other leads and ideas", f'<ul class="list card">{"".join(items)}</ul>',
                     count=len(items)))

    # -- nmap scripts and commands (collapsed by JS)
    if scripted:
        add(_section("scripts", "Nmap script output", _scripts(scripted), count=len(scripted)))
    if r.commands:
        n = len(r.commands)
        fold = (f'<details class="fold card" open data-fold><summary>{_icon("chev", "chev")}<span>Command log</span>'
                f'<span class="fmeta">{n} command{"s" if n != 1 else ""}</span></summary>'
                f'<div class="fbody">{_code(chr(10).join(r.commands), "shell", scroll=True)}</div></details>')
        add(_section("commands", "Commands run", fold, count=n))

    add(f"<footer><span>Generated by soul-toolkit v{_e(__version__)}</span>"
        "<span>Authorized testing only - test machines you own or have permission to test.</span></footer>")
    add("</main>")

    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="light dark">'
        f"<title>Recon report: {_e(r.target)}</title><style>{CSS}</style>"
        "<script>document.documentElement.classList.add('js')</script></head>"
        f'<body><a class="skip" href="#main">Skip to the report</a><div class="layout">{"".join(parts)}</div>'
        f"<script>{JS}</script></body></html>\n"
    )
