"""Theme layer.

Themes are data, not markup: swap one token dict and the whole UI re-skins.
`ink` is the default. Nothing here is tied to any company or product identity -
the mark is drawn from primitives in assets.py and the icons are Lucide (ISC).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .assets import ICON_SPRITE, MARK

GF = "https://fonts.googleapis.com/css2?"
FONTS_SANS = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    f'<link href="{GF}family=Space+Grotesk:wght@500;700&'
    'family=Inter:wght@400;500;600&'
    'family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">'
)
FONTS_MONO = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    f'<link href="{GF}family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">'
)

# Semantic key -> sprite id. A theme may remap these to a different icon set
# without web.py changing at all.
ICONS = {
    "search": "i-search",       "alerts": "i-triangle-alert",
    "entities": "i-network",    "channels": "i-users",
    "coord": "i-radar",         "pivot": "i-crosshair",
    "index": "i-database",      "views": "i-eye",
    "clock": "i-clock",         "link": "i-link",
    "spread": "i-refresh-cw",   "shield": "i-shield",
    "lock": "i-lock",           "scan": "i-scan-search",
    "ok": "i-circle-check",     "warn": "i-circle-alert",
    "next": "i-arrow-right",
}


@dataclass
class Theme:
    name: str
    tokens: dict[str, str]
    fonts_head: str = FONTS_SANS
    mark: str = MARK
    sprite: str = ICON_SPRITE
    icons: dict[str, str] = field(default_factory=lambda: dict(ICONS))
    wordmark: tuple[str, str] = ("tg", "index")
    brandline: str = "Telegram collection"

    def icon(self, key: str, size: int = 18, color: str = "var(--accent)",
             cls: str = "") -> str:
        sid = self.icons.get(key)
        if not sid or not self.sprite:
            return ""
        c = f' class="{cls}"' if cls else ""
        return (f'<svg{c} width="{size}" height="{size}" viewBox="0 0 24 24" '
                f'fill="none" stroke="{color}" stroke-width="2" '
                f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
                f'<use href="#{sid}"/></svg>')

    def css_vars(self) -> str:
        return ":root{" + "".join(f"--{k}:{v};" for k, v in self.tokens.items()) + "}"


SANS = "'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif"
DISPLAY = "'Space Grotesk','Inter',system-ui,sans-serif"
MONO = "'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace"

INK = Theme(
    name="ink",
    tokens={
        "bg": "#0E1012", "bg-deep": "#08090A", "panel": "#15181B",
        "panel-soft": "rgba(255,255,255,.035)",
        "line": "rgba(255,255,255,.085)", "line-strong": "rgba(255,255,255,.16)",
        "fg": "#E8E6E3", "dim": "#8B9196",
        "accent": "#E9A23B", "accent-soft": "rgba(233,162,59,.15)",
        "support": "#5FA3A0", "signal": "#E9A23B",
        "danger": "#E05C4F", "danger-deep": "#9E372D",
        "on-accent": "#15110A",
        "font-display": DISPLAY, "font-body": SANS, "font-mono": MONO,
        "radius": "10px",
    },
)

SLATE = Theme(
    name="slate",
    tokens={
        "bg": "#0F1419", "bg-deep": "#0A0E12", "panel": "#161C23",
        "panel-soft": "rgba(255,255,255,.04)",
        "line": "rgba(255,255,255,.09)", "line-strong": "rgba(255,255,255,.17)",
        "fg": "#DDE3EA", "dim": "#7D8A99",
        "accent": "#4FC1E9", "accent-soft": "rgba(79,193,233,.15)",
        "support": "#7E8FA6", "signal": "#4FC1E9",
        "danger": "#E5695B", "danger-deep": "#9E3B30",
        "on-accent": "#06141B",
        "font-display": DISPLAY, "font-body": SANS, "font-mono": MONO,
        "radius": "9px",
    },
)

TERMINAL = Theme(
    name="terminal",
    fonts_head=FONTS_MONO,
    tokens={
        "bg": "#0A0E0A", "bg-deep": "#060906", "panel": "#101710",
        "panel-soft": "rgba(126,231,135,.05)",
        "line": "rgba(126,231,135,.16)", "line-strong": "rgba(126,231,135,.3)",
        "fg": "#CDE8CD", "dim": "#6E8A6E",
        "accent": "#7EE787", "accent-soft": "rgba(126,231,135,.14)",
        "support": "#58A6A0", "signal": "#D9F27E",
        "danger": "#FF7B72", "danger-deep": "#8E2F28",
        "on-accent": "#06120A",
        "font-display": MONO, "font-body": MONO, "font-mono": MONO,
        "radius": "4px",
    },
)

THEMES = {t.name: t for t in (INK, SLATE, TERMINAL)}
DEFAULT = "ink"


def get(name: str) -> Theme:
    return THEMES.get(name, INK)


BASE_CSS = """
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--font-body);
font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
h1{font-family:var(--font-display);font-weight:700;font-size:29px;line-height:1.18;
color:var(--fg);margin:0 0 6px;letter-spacing:-.02em}
h2,h3,h4{font-family:var(--font-body);margin:0}
.mono{font-family:var(--font-mono)}

header{position:sticky;top:0;z-index:20;background:var(--bg-deep);
border-bottom:1px solid var(--line);padding:12px 22px;
display:flex;gap:20px;align-items:center;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;flex-shrink:0}
.brand svg.mark{width:27px;height:27px;color:var(--accent);display:block}
.brand .wm{font-family:var(--font-display);font-weight:700;font-size:19px;
letter-spacing:-.025em;color:var(--fg)}
.brand .wm i{font-style:normal;color:var(--accent)}
.brand .tag{font-size:10px;letter-spacing:.15em;text-transform:uppercase;
color:var(--dim);border-left:1px solid var(--line-strong);padding-left:11px}
nav{display:flex;gap:3px;flex-wrap:wrap}
nav a{display:flex;align-items:center;gap:7px;color:var(--dim);font-size:13.5px;
font-weight:500;padding:7px 11px;border-radius:7px;line-height:1}
nav a:hover{color:var(--fg);background:var(--panel-soft);text-decoration:none}
nav a.on{color:var(--accent);background:var(--accent-soft)}
nav a .count{font-family:var(--font-mono);font-size:11px;background:var(--danger);
color:#fff;border-radius:9px;padding:1px 6px;font-weight:500}

form.search{display:flex;gap:9px;flex:1;min-width:300px}
input[type=text],select{background:var(--bg);border:1px solid var(--line-strong);
color:var(--fg);border-radius:8px;padding:9px 13px;font-size:14.5px;
font-family:var(--font-body);width:100%}
input[type=text]::placeholder{color:var(--dim);opacity:.8}
input[type=text]:focus,select:focus{outline:none;border-color:var(--accent);
box-shadow:0 0 0 3px var(--accent-soft)}
button{background:var(--accent);border:0;color:var(--on-accent);font-weight:700;
font-family:var(--font-body);border-radius:8px;padding:9px 20px;cursor:pointer;
font-size:14px;white-space:nowrap}
button:hover{filter:brightness(1.09)}

main{max-width:1240px;margin:0 auto;padding:26px 22px;display:grid;
grid-template-columns:minmax(0,1fr) 300px;gap:28px;align-items:start}
main.wide{grid-template-columns:minmax(0,1fr);max-width:1400px}
main.wide aside{display:none}
@media(max-width:940px){main{grid-template-columns:1fr}aside{order:-1}}

.pagehead{margin-bottom:18px}
.pagehead .sub{color:var(--dim);font-size:13px}
.hit{border-bottom:1px solid var(--line);padding:17px 0}
.hit:last-child{border-bottom:0}
.hit .title{display:flex;align-items:center;gap:8px;margin-bottom:5px}
.hit .title a{font-size:15.5px;font-weight:600;font-family:var(--font-mono)}
.meta{color:var(--dim);font-size:12.5px;display:flex;align-items:center;
gap:14px;flex-wrap:wrap}
.meta span{display:flex;align-items:center;gap:5px}
.snip{margin:9px 0;white-space:pre-wrap;word-break:break-word;font-size:14.5px}
.snip b{background:var(--accent-soft);color:var(--accent);font-weight:600;
padding:0 3px;border-radius:3px}
.chips{margin-top:9px;display:flex;flex-wrap:wrap;gap:5px}
.chip{display:inline-flex;align-items:center;gap:5px;background:var(--panel-soft);
border:1px solid var(--line);border-radius:7px;padding:3px 9px;font-size:11.5px;
color:var(--dim);font-family:var(--font-mono)}
a.chip:hover{border-color:var(--accent);color:var(--accent);text-decoration:none}
.chip.spread{border-color:var(--support);color:var(--accent)}
.chip.fwd{border-color:var(--line-strong)}
.chip.actor{border-color:var(--danger);color:var(--danger);font-weight:600}
a.chip.tag{border-color:var(--support);color:var(--support)}

.card{background:var(--panel);border:1px solid var(--line);
border-radius:var(--radius);padding:15px 17px;margin-bottom:16px}
.card h4{font-size:11px;text-transform:uppercase;letter-spacing:.13em;
color:var(--dim);font-weight:700;margin-bottom:11px;display:flex;
align-items:center;gap:7px}
.row{display:flex;justify-content:space-between;gap:12px;padding:4px 0;font-size:13.5px}
.row b{font-family:var(--font-mono);font-weight:500}
.row .hero{color:var(--signal);font-weight:500}
.tw{width:100%;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13.5px;table-layout:auto}
th{color:var(--dim);font-weight:700;font-size:10.5px;text-transform:uppercase;
letter-spacing:.1em;text-align:left;padding:8px 10px;border-bottom:1px solid var(--line-strong)}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
td.num{font-family:var(--font-mono);white-space:nowrap}
th.num{white-space:nowrap}
td.wrap{min-width:260px}
td.tight{white-space:nowrap}
.sev{border-radius:5px;padding:2px 8px;font-size:10.5px;font-weight:700;
text-transform:uppercase;letter-spacing:.05em;font-family:var(--font-body)}
.sev.critical{background:var(--danger);color:#fff}
.sev.high{background:var(--danger-deep);color:#fff}
.sev.medium{background:var(--support);color:#0c1211}
.sev.low{background:var(--panel-soft);color:var(--dim);border:1px solid var(--line-strong)}
.empty{color:var(--dim);padding:54px 0;text-align:center}
.empty .big{font-family:var(--font-display);font-size:27px;color:var(--fg);
margin-bottom:8px;font-weight:700;letter-spacing:-.02em}
code{background:var(--bg-deep);padding:2px 6px;border-radius:5px;
font-family:var(--font-mono);font-size:12.5px;color:var(--accent)}
footer{border-top:1px solid var(--line);margin-top:10px;padding:16px 22px;
color:var(--dim);font-size:12px;text-align:center}
"""
