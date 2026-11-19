"""Server-rendered UI. Stdlib only - no web framework dependency.

All styling comes from tgindex.theme; this module emits structure, never colour.
"""
from __future__ import annotations

import html
import json
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import query as Q
from . import theme as T
from .store import Store

NAV = [("/", "Search", "search"), ("/threats", "Threats", "shield"),
       ("/alerts", "Alerts", "alerts"), ("/entities", "Entities", "entities"),
       ("/channels", "Channels", "channels"), ("/coord", "Coordination", "coord")]


def esc(s):
    return html.escape(str(s if s is not None else ""))


def fmt_n(v):
    if v is None:
        return "-"
    for u, sz in (("B", 1e9), ("M", 1e6), ("K", 1e3)):
        if v >= sz:
            return f"{v/sz:.1f}{u}"
    return f"{int(v):,}"


def fmt_ts(v):
    return datetime.fromtimestamp(v, timezone.utc).strftime("%Y-%m-%d %H:%M") if v else "-"


class Handler(BaseHTTPRequestHandler):
    store: Store = None       # type: ignore
    theme: T.Theme = T.INK

    def log_message(self, *a):
        pass

    # ---------- shell ----------

    def page(self, path, body, q="", title="tgindex"):
        th = self.theme
        a, b = th.wordmark
        brand = f'{th.mark}<span class="wm"><i>{esc(a)}</i>{esc(b)}</span>'
        n_alerts = self.store.db.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]

        items = []
        for p, label, key in NAV:
            badge = (f'<span class="count">{n_alerts}</span>'
                     if key == "alerts" and n_alerts else "")
            on = " on" if p == path else ""
            colour = "var(--accent)" if p == path else "var(--dim)"
            items.append(f'<a class="nav{on}" href="{p}">{th.icon(key, 16, colour)}'
                         f'{esc(label)}{badge}</a>')

        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title>{th.fonts_head}
<style>{th.css_vars()}{T.BASE_CSS}</style></head>
<body>{th.sprite}
<header><div class="brand">{brand}<span class="tag">{esc(th.brandline)}</span></div>
<nav>{''.join(items)}</nav>
<form class="search" action="/"><input type="text" name="q" value="{esc(q)}"
placeholder="Search indexed messages, or paste a wallet, domain or CVE to pivot"
autocomplete="off"><button>Search</button></form></header>
{body}
<footer>tgindex &middot; own crawl of public channel previews &middot;
{self.store.stats()['messages']:,} messages indexed</footer></body></html>"""

    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        p = dict(urllib.parse.parse_qsl(u.query))
        try:
            fn = {"/": self.view_search, "/pivot": self.view_pivot,
                  "/alerts": self.view_alerts, "/entities": self.view_entities,
                  "/channels": self.view_channels, "/coord": self.view_coord,
                  "/threats": self.view_threats,
                  "/api/search": self.api_search}.get(u.path)
            if fn is None:
                self._send(self.page(u.path, self.empty("Not found", "")), 404)
                return
            fn(u.path, p)
        except Exception as exc:                      # noqa: BLE001
            self._send(self.page(u.path, self.empty("Error", esc(exc))), 500)

    # ---------- fragments ----------

    def empty(self, big, sub):
        return f'<main class="wide"><section><div class="empty"><div class="big">{big}</div>{sub}</div></section><aside></aside></main>'

    def card(self, title, inner, icon=None):
        ic = self.theme.icon(icon, 14, "var(--support)") if icon else ""
        if inner.lstrip().startswith("<table"):
            inner = f'<div class="tw">{inner}</div>'
        return f'<div class="card"><h4>{ic}{esc(title)}</h4>{inner}</div>'

    def render_hit(self, h):
        th = self.theme
        chips = []
        if h.copies > 1:
            chips.append(f'<span class="chip spread">{th.icon("spread", 12, "var(--support)")}'
                         f'{h.copies}x &middot; reach {fmt_n(h.reach)}</span>')
        if "actor_post" in h.tags:
            chips.append('<span class="chip actor">actor post</span>')
        for t in h.tags:
            if t not in ("threat", "actor_post"):
                chips.append(f'<a class="chip tag" href="/?tag={t}">{esc(t)}</a>')
        if h.is_forward:
            chips.append('<span class="chip fwd">forward</span>')
        for m in h.media:
            chips.append(f'<span class="chip">{esc(m)}</span>')
        for t, v in h.entities[:8]:
            chips.append(f'<a class="chip" href="/pivot?v={urllib.parse.quote(v)}&t={t}">'
                         f'{esc(t)}: {esc(v[:40])}</a>')
        also = ""
        if h.also_in:
            links = ", ".join(f'<a href="/?ch={esc(c)}">@{esc(c)}</a>' for c in h.also_in[:6])
            also = f'<div class="meta" style="margin-top:7px"><span>also posted in: {links}</span></div>'
        snip = esc(h.snippet).replace("《", "<b>").replace("》", "</b>")
        return f"""<div class="hit">
<div class="title">{th.icon("next", 14, "var(--support)")}
<a href="{h.url}" target="_blank" rel="noopener">@{esc(h.channel)}/{h.msg_id}</a></div>
<div class="meta"><span>{th.icon("clock", 13, "var(--dim)")}{fmt_ts(h.ts)}</span>
<span>{th.icon("views", 13, "var(--dim)")}{fmt_n(h.views)}</span>
<span>score {h.score}</span></div>
<div class="snip">{snip}</div>{also}<div class="chips">{''.join(chips)}</div></div>"""

    # ---------- views ----------

    def view_search(self, path, p):
        th = self.theme
        q = p.get("q", "")
        ch = p.get("ch") or None
        tag = p.get("tag") or None
        hits = Q.search(self.store, q, channel=ch, tag=tag,
                        limit=int(p.get("n", 25)), with_entities=True)
        f = Q.facets(self.store, q)
        s = self.store.stats()
        tag_rows = [(r["tag"], r["n"]) for r in self.store.db.execute(
            "SELECT tag, COUNT(*) n FROM tags WHERE tag != 'threat'"
            " GROUP BY tag ORDER BY n DESC LIMIT 10")]

        if hits:
            head = (f'<div class="pagehead"><div class="sub">{len(hits)} result(s)'
                    f'{" in @" + esc(ch) if ch else ""}'
                    f'{" tagged " + esc(tag) if tag else ""} &middot; '
                    f'{f["total"]} matching before forward dedup</div></div>')
            body = head + "".join(self.render_hit(h) for h in hits)
        elif not s["messages"]:
            # An empty index is a setup state, not a failed search. Say so.
            body = ('<div class="empty"><div class="big">The index is empty</div>'
                    'Nothing has been crawled yet. This UI only displays what is '
                    'already indexed &mdash; it never fetches anything itself.'
                    '<div style="margin-top:22px">Run this, then reload:</div>'
                    '<div style="margin-top:10px"><code>tgindex quickstart</code></div>'
                    '<div style="margin-top:18px;font-size:12.5px">That seeds a '
                    'channel list, crawls it, and reports what it indexed.</div></div>')
        else:
            body = ('<div class="empty"><div class="big">No results</div>'
                    'Nothing matched that query. Try a broader term, or crawl more '
                    'channels with <code>tgindex crawl</code>.</div>')

        def facet_card(title, items, link, icon):
            if not items:
                return ""
            rows = "".join(
                f'<div class="row"><a href="{link(k)}">{esc(k)}</a><b>{v:,}</b></div>'
                for k, v in items)
            return self.card(title, rows, icon)

        index_card = self.card("Index", (
            f'<div class="row"><span>messages</span><b class="hero">{s["messages"]:,}</b></div>'
            f'<div class="row"><span>unique content</span><b>{s["unique_content"]:,}</b></div>'
            f'<div class="row"><span>channels live</span><b>{s["channels_active"]:,}</b></div>'
            f'<div class="row"><span>channels queued</span><b>{s["channels_pending"]:,}</b></div>'
            f'<div class="row"><span>entities</span><b>{s["entities"]:,}</b></div>'
            f'<div class="row"><span>alerts</span><b>{s["alerts"]:,}</b></div>'), "index")

        side = (index_card
                + facet_card("Channels", f["channels"],
                             lambda k: f"/?q={urllib.parse.quote(q)}&ch={urllib.parse.quote(k)}",
                             "channels")
                + facet_card("Entity types", f["entity_types"],
                             lambda k: f"/entities?t={k}", "entities")
                + facet_card("Threat tags", tag_rows,
                             lambda k: f"/?q={urllib.parse.quote(q)}&tag={k}", "shield")
                + facet_card("Media", f["media"], lambda k: "#", "views"))
        self._send(self.page(path, f"<main><section>{body}</section><aside>{side}</aside></main>", q))

    def view_pivot(self, path, p):
        th = self.theme
        v = p.get("v", "")
        r = Q.pivot(self.store, v, type=p.get("t") or None, limit=40)
        if not r["channels"]:
            self._send(self.page(path, self.empty("Not in the index", esc(v))))
            return
        chans = "".join(
            f'<tr><td><a href="/?ch={esc(c["channel"])}">@{esc(c["channel"])}</a></td>'
            f'<td class="num">{c["n"]}</td><td class="num">{fmt_n(c["reach"])}</td>'
            f'<td class="num">{fmt_ts(c["first_seen"])}</td>'
            f'<td class="num">{fmt_ts(c["last_seen"])}</td></tr>' for c in r["channels"])
        co = "".join(
            f'<tr><td><span class="chip">{esc(c["type"])}</span></td>'
            f'<td><a href="/pivot?v={urllib.parse.quote(c["norm"])}&t={c["type"]}">'
            f'{esc(c["norm"][:66])}</a></td><td class="num">{c["n"]}</td></tr>'
            for c in r["cooccurring"])
        msgs = "".join(
            f'<tr><td class="num">{fmt_ts(m["ts"])}</td><td>@{esc(m["channel"])}</td>'
            f'<td><a href="https://t.me/{esc(m["channel"])}/{m["msg_id"]}" target="_blank" '
            f'rel="noopener">{esc((m["preview"] or "")[:104])}</a></td></tr>'
            for m in r["messages"][:25])

        body = f"""<main><section>
<div class="pagehead"><h1>{esc(v)}</h1>
<div class="sub">seen in {r['total_channels']} channel(s) across
{r['total_messages']} message(s){' &middot; ' + esc(p.get('t')) if p.get('t') else ''}</div></div>
{self.card("Channels", f'<table><tr><th>channel</th><th>posts</th><th>reach</th>'
           f'<th>first seen</th><th>last seen</th></tr>{chans}</table>', "channels")}
{self.card("Co-occurring entities",
           f'<table><tr><th>type</th><th>value</th><th>msgs</th></tr>{co}</table>', "entities")}
{self.card("Messages",
           f'<table><tr><th>when</th><th>channel</th><th>preview</th></tr>{msgs}</table>', "search")}
</section><aside>{self.card("Pivot",
'<div class="meta"><span>Every channel that ever carried this value, when each '
'first posted it, and what else travels alongside it. This is the query a '
'site-restricted web search cannot express.</span></div>', "pivot")}</aside></main>"""
        self._send(self.page(path, body, title=f"{v} - tgindex"))

    def view_alerts(self, path, p):
        rows = Q.alerts(self.store, limit=100)
        if not rows:
            self._send(self.page(path, self.empty(
                "No alerts", "Add targets with <code>tgindex watch add</code>.")))
            return
        trs = "".join(
            f'<tr><td><span class="sev {esc(r["severity"])}">{esc(r["severity"])}</span></td>'
            f'<td class="wrap" style="min-width:150px">{esc(r["label"])}</td>'
            f'<td><a class="mono" href="/pivot?v={urllib.parse.quote(r["entity_norm"])}'
            f'&t={esc(r["entity_type"])}">{esc(r["entity_type"])}: '
            f'{esc(r["entity_norm"][:34])}</a></td>'
            f'<td><a href="{esc(r["url"])}" target="_blank" rel="noopener">'
            f'@{esc(r["channel"])}</a></td>'
            f'<td class="num">{fmt_ts(r["ts"])}</td><td class="num">{fmt_n(r["views"])}</td>'
            f'<td class="wrap">{esc((r["preview"] or "")[:150])}</td></tr>' for r in rows)
        body = (f'<main class="wide"><section><div class="pagehead"><h1>Alerts</h1>'
                f'<div class="sub">{len(rows)} match(es) against the watchlist</div></div>'
                + self.card("Feed", f'<table><tr><th>sev</th><th>watch</th><th>matched</th>'
                            f'<th>channel</th><th class="num">when</th><th class="num">views</th><th>preview</th></tr>'
                            f'{trs}</table>', "alerts")
                + '</section></main>')
        self._send(self.page(path, body, title="Alerts - tgindex"))

    def view_entities(self, path, p):
        t = p.get("t") or None
        rows = Q.top_entities(self.store, type=t, limit=120)
        trs = "".join(
            f'<tr><td><span class="chip">{esc(r["type"])}</span></td>'
            f'<td><a class="mono" href="/pivot?v={urllib.parse.quote(r["norm"])}'
            f'&t={esc(r["type"])}">{esc(r["norm"][:74])}</a></td>'
            f'<td class="num">{r["messages"]}</td><td class="num">{r["channels"]}</td></tr>'
            for r in rows)
        body = (f'<main class="wide"><section><div class="pagehead"><h1>Entities</h1>'
                f'<div class="sub">Validated values, ranked by how many channels carry them'
                f'{" &middot; " + esc(t) if t else ""}</div></div>'
                + self.card("Top entities", f'<table><tr><th>type</th><th>value</th>'
                            f'<th>msgs</th><th>channels</th></tr>{trs}</table>', "entities")
                + '</section></main>')
        self._send(self.page(path, body, title="Entities - tgindex"))

    def view_channels(self, path, p):
        rows = self.store.db.execute(
            "SELECT username,title,subscribers,msg_count,status,backfill_done,discovered_via "
            "FROM channels ORDER BY msg_count DESC, subscribers DESC LIMIT 200").fetchall()
        trs = "".join(
            f'<tr><td><a href="/?ch={esc(r["username"])}">@{esc(r["username"])}</a></td>'
            f'<td>{esc((r["title"] or "")[:38])}</td>'
            f'<td class="num">{fmt_n(r["subscribers"])}</td>'
            f'<td class="num">{r["msg_count"]}</td><td>{esc(r["status"])}</td>'
            f'<td>{"complete" if r["backfill_done"] else "partial"}</td>'
            f'<td class="mono">{esc((r["discovered_via"] or "")[:24])}</td></tr>' for r in rows)
        body = (f'<main class="wide"><section><div class="pagehead"><h1>Channels</h1>'
                f'<div class="sub">Seeded and snowball-discovered sources</div></div>'
                + self.card("Sources", f'<table><tr><th>channel</th><th>title</th><th>subs</th>'
                            f'<th>indexed</th><th>status</th><th>backfill</th>'
                            f'<th>found via</th></tr>{trs}</table>', "channels")
                + '</section></main>')
        self._send(self.page(path, body, title="Channels - tgindex"))

    def view_coord(self, path, p):
        rows = Q.coordination(self.store, min_shared=2)
        inner = ("".join(
            f'<tr><td><a href="/?ch={esc(r["c1"])}">@{esc(r["c1"])}</a></td>'
            f'<td><a href="/?ch={esc(r["c2"])}">@{esc(r["c2"])}</a></td>'
            f'<td class="num">{r["shared"]}</td>'
            f'<td class="num">{r["avg_gap"]:.0f}s</td></tr>' for r in rows)
            or '<tr><td colspan="4">No pairs at this threshold.</td></tr>')
        body = (f'<main><section><div class="pagehead"><h1>Coordination</h1>'
                f'<div class="sub">Channels repeatedly posting identical content '
                f'within a short window</div></div>'
                + self.card("Channel pairs", f'<table><tr><th>channel A</th><th>channel B</th>'
                            f'<th>shared posts</th><th>avg gap</th></tr>{inner}</table>', "coord")
                + '</section><aside>'
                + self.card("Method", '<div class="meta"><span>Pairs sharing a content hash '
                            'inside the window. A cheap proxy for one operator running '
                            'several channels.</span></div>', "scan")
                + '</aside></main>')
        self._send(self.page(path, body, title="Coordination - tgindex"))

    def view_threats(self, path, p):
        r = Q.threats(self.store, limit=20)
        if not r["by_tag"]:
            self._send(self.page(path, self.empty(
                "Nothing tagged", "Crawl channels that carry threat content.")))
            return

        def tbl(title, rows, headers, cells, icon):
            if not rows:
                return ""
            head = "".join(f"<th>{esc(h)}</th>" for h in headers)
            body = "".join("<tr>" + "".join(c(x) for c in cells) + "</tr>" for x in rows)
            return self.card(title, f"<table><tr>{head}</tr>{body}</table>", icon)

        ent_link = lambda t: (lambda x:
            f'<td><a href="/pivot?v={urllib.parse.quote(x["norm"])}&t={t}">'
            f'{esc(x["norm"][:52])}</a></td>')
        num = lambda k: (lambda x: f'<td class="num">{x[k]}</td>')

        tags_tbl = tbl("Tag distribution", r["by_tag"], ["tag", "messages"],
                       [lambda x: f'<td><a href="/?tag={esc(x["tag"])}">{esc(x["tag"])}</a></td>',
                        num("n")], "shield")
        fam = tbl("Ransomware families", r["families"], ["family", "msgs", "channels"],
                  [ent_link("ransom_family"), num("msgs"), num("channels")], "lock")
        stl = tbl("Infostealers", r["stealers"], ["family", "msgs"],
                  [ent_link("stealer"), num("msgs")], "scan")
        hosts = tbl("Leak hosts", r["leak_hosts"], ["host", "msgs"],
                    [ent_link("leak_host"), num("msgs")], "link")
        vics = tbl("Affected / victim domain candidates", r["victims"],
                   ["domain", "msgs", "channels"],
                   [ent_link("victim_domain"), num("msgs"), num("channels")], "warn")
        cons = tbl("Operator contact IDs", r["contacts"], ["type", "id", "msgs"],
                   [lambda x: f'<td><span class="chip">{esc(x["type"])}</span></td>',
                    lambda x: f'<td class="mono">{esc(x["norm"][:60])}</td>', num("msgs")],
                   "lock")
        claims = tbl("Largest claimed record counts", r["biggest_claims"],
                     ["records", "source"],
                     [lambda x: f'<td class="num">{int(x["norm"]):,}</td>',
                      lambda x: f'<td><a href="https://t.me/{esc(x["channel"])}/'
                                f'{x["msg_id"]}" target="_blank" rel="noopener">'
                                f'@{esc(x["channel"])}/{x["msg_id"]}</a></td>'], "index")

        actors = ""
        if r["actor_posts"]:
            rows = "".join(
                f'<tr><td class="num">{fmt_ts(a["ts"])}</td>'
                f'<td><a href="https://t.me/{esc(a["channel"])}/{a["msg_id"]}" '
                f'target="_blank" rel="noopener">@{esc(a["channel"])}</a></td>'
                f'<td class="wrap">{esc((a["preview"] or "")[:160])}</td></tr>'
                for a in r["actor_posts"])
            actors = self.card("Actor posts (two or more structural signals)",
                               f'<table><tr><th>when</th><th>channel</th>'
                               f'<th>preview</th></tr>{rows}</table>', "alerts")
        else:
            actors = self.card("Actor posts",
                '<div class="meta"><span>None found. The crawled channels report '
                'on threats rather than originate them - seed actor and market '
                'channels to populate this.</span></div>', "alerts")

        body = (f'<main class="wide"><section><div class="pagehead"><h1>Threats</h1>'
                f'<div class="sub">Ransomware, leaks, credential dumps and access '
                f'brokering across the index</div></div>'
                f'{tags_tbl}{actors}{fam}{stl}{vics}{hosts}{cons}{claims}'
                f'</section></main>')
        self._send(self.page(path, body, title="Threats - tgindex"))

    def api_search(self, path, p):
        hits = Q.search(self.store, p.get("q", ""), limit=int(p.get("n", 25)),
                        with_entities=True)
        self._send(json.dumps([h.__dict__ for h in hits], default=str, indent=2),
                   ctype="application/json")


def serve(store: Store, host="127.0.0.1", port=8000, theme=T.DEFAULT):
    Handler.store = store
    Handler.theme = T.get(theme)
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"tgindex UI on http://{host}:{port}  (theme: {Handler.theme.name})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
