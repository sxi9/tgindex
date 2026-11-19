"""Command line for tgindex."""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import query as Q
from .crawl import poll_heads, run
from .fetch import Fetcher
from .store import Store

DEFAULT_DB = "tgindex.db"


def _ts(v):
    if not v:
        return "-"
    return datetime.fromtimestamp(v, timezone.utc).strftime("%Y-%m-%d %H:%M")


def _n(v):
    if v is None:
        return "-"
    for unit, size in (("B", 1e9), ("M", 1e6), ("K", 1e3)):
        if v >= size:
            return f"{v/size:.1f}{unit}"
    return str(int(v))


def _since(spec):
    if not spec:
        return None
    units = {"h": 3600, "d": 86400, "w": 604800}
    if spec[-1] in units and spec[:-1].isdigit():
        return int(time.time()) - int(spec[:-1]) * units[spec[-1]]
    return int(spec)


def cmd_seed(a, st):
    names = []
    for item in a.names:
        p = Path(item)
        if p.exists():
            names += [ln.strip() for ln in p.read_text().splitlines()
                      if ln.strip() and not ln.startswith("#")]
        else:
            names.append(item)
    added = sum(st.add_channel(n, via="seed", depth=0) for n in names)
    print(f"seeded {added} new channels ({len(names)} given)")


def cmd_crawl(a, st):
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    f = Fetcher(rps=a.rps)
    t0 = time.time()
    totals = run(st, f, max_channels=a.channels, max_pages=a.pages,
                 max_depth=a.depth, workers=a.workers)
    print(f"\n{'-'*64}\ncrawled in {time.time()-t0:.1f}s  |  http: {f.stats}")
    print(json.dumps(totals, indent=2))


def cmd_poll(a, st):
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    f = Fetcher(rps=a.rps)
    print(json.dumps(poll_heads(st, f, limit=a.limit, workers=a.workers), indent=2))


def cmd_search(a, st):
    hits = Q.search(st, a.query, channel=a.channel, since=_since(a.since),
                    media=a.media, min_views=a.min_views, has_entity=a.has,
                    tag=a.tag, dedup=not a.no_dedup, limit=a.limit,
                    with_entities=a.entities)
    if not hits:
        print("no results")
        return
    print(f"{len(hits)} results for {a.query!r}\n")
    for i, h in enumerate(hits, 1):
        flags = []
        if h.copies > 1:
            flags.append(f"{h.copies}x copies, reach {_n(h.reach)}")
        if h.is_forward:
            flags.append("forward")
        if h.media:
            flags.append("+".join(h.media))
        if "actor_post" in h.tags:
            flags.append("ACTOR POST")
        tag = f"  [{', '.join(flags)}]" if flags else ""
        print(f"{i:2}. @{h.channel}  {_ts(h.ts)}  views {_n(h.views)}  score {h.score}{tag}")
        print(f"    {h.snippet[:300]}")
        if h.also_in:
            print(f"    also posted in: {', '.join('@'+c for c in h.also_in[:6])}")
        if h.tags:
            print(f"    tags: {', '.join(t for t in h.tags if t != 'threat')}")
        if h.entities:
            shown = [f"{t}:{v}" for t, v in h.entities[:6]]
            print(f"    entities: {', '.join(shown)}")
        print(f"    {h.url}\n")


def cmd_pivot(a, st):
    r = Q.pivot(st, a.value, type=a.type, limit=a.limit)
    print(f"pivot on {r['value']!r}"
          f"{' (type=' + a.type + ')' if a.type else ''}\n")
    if not r["channels"]:
        print("not seen in the index")
        return
    print(f"seen in {r['total_channels']} channel(s), {r['total_messages']} message(s)"
          f" (showing {r['shown_messages']})\n")
    print(f"  {'channel':<28} {'posts':>5} {'reach':>8}  {'first seen':<17} {'last seen'}")
    for c in r["channels"]:
        print(f"  @{c['channel']:<27} {c['n']:>5} {_n(c['reach']):>8}  "
              f"{_ts(c['first_seen']):<17} {_ts(c['last_seen'])}")
    if r["cooccurring"]:
        print("\n  co-occurring entities (pivot targets):")
        for c in r["cooccurring"][:10]:
            print(f"    {c['type']:<12} {c['norm'][:60]:<60} {c['n']} msg")
    print("\n  messages:")
    for m in r["messages"][:10]:
        print(f"    {_ts(m['ts'])}  @{m['channel']}  https://t.me/{m['channel']}/{m['msg_id']}")
        print(f"      {(m['preview'] or '').strip()[:140]}")


def cmd_spread(a, st):
    r = Q.spread(st, a.uid)
    print(f"{r['canonical_uid']}: {r['copies']} copies across "
          f"{len(r['channels'])} channels, reach {_n(r['reach'])}\n")
    for e in r["timeline"]:
        origin = "ORIGIN" if not e["fwd_channel"] else f"fwd<-{e['fwd_channel']}"
        print(f"  +{e['lag_minutes']:>8.1f} min  @{e['channel']:<24} views {_n(e['views']):>7}  {origin}")


def cmd_watch(a, st):
    if a.action == "preset":
        try:
            r = st.watch_preset(a.value)
        except KeyError as exc:
            print(exc); return
        print(f"preset {r['preset']}: {r['targets']} targets "
              f"({r['added']} new), {r['alerts_backfilled']} alert(s) from existing index")
        return
    if a.action == "add":
        wid = st.watch(a.value, type=a.type, label=a.label or a.value, severity=a.severity)
        n = st.backfill_alerts()
        print(f"watch #{wid} added ({a.type}:{a.value}); {n} alert(s) from existing index")
    elif a.action == "list":
        rows = st.db.execute("SELECT * FROM watchlist ORDER BY id").fetchall()
        if not rows:
            print("watchlist empty")
        for r in rows:
            n = st.db.execute("SELECT COUNT(*) c FROM alerts WHERE watch_id=?", (r["id"],)).fetchone()["c"]
            print(f"  #{r['id']:<3} [{r['severity']:<6}] {r['type']:<12} {r['norm'][:50]:<50} "
                  f"{n} alert(s)  {r['label'] or ''}")
    elif a.action == "rm":
        st.db.execute("DELETE FROM watchlist WHERE id=?", (int(a.value),))
        st.db.commit(); st.reload_watchlist()
        print(f"removed watch #{a.value}")


def cmd_alerts(a, st):
    rows = Q.alerts(st, limit=a.limit, since=_since(a.since))
    if not rows:
        print("no alerts")
        return
    print(f"{len(rows)} alert(s)\n")
    for r in rows:
        print(f"  [{r['severity']:<6}] {r['label']}")
        print(f"    matched {r['entity_type']}:{r['entity_norm']}")
        print(f"    @{r['channel']}  {_ts(r['ts'])}  views {_n(r['views'])}  {r['url']}")
        print(f"    {(r['preview'] or '').strip()[:160]}\n")


def cmd_stats(a, st):
    s = st.stats()
    width = max(len(k) for k in s)
    for k, v in s.items():
        print(f"  {k:<{width}} : {v:,}" if isinstance(v, int) else f"  {k:<{width}} : {v}")
    print("\n  top channels by messages indexed:")
    for r in st.db.execute(
        "SELECT username, msg_count, subscribers, backfill_done FROM channels "
        "WHERE msg_count>0 ORDER BY msg_count DESC LIMIT 12"
    ):
        done = "complete" if r["backfill_done"] else "partial"
        print(f"    @{r['username']:<28} {r['msg_count']:>6} msg  "
              f"{_n(r['subscribers']):>7} subs  backfill {done}")


def cmd_facets(a, st):
    f = Q.facets(st, a.query)
    print(f"{f['total']} messages matching {a.query!r}\n")
    for name in ("channels", "media", "entity_types"):
        if f[name]:
            print(f"  {name}:")
            for k, v in f[name]:
                print(f"    {str(k):<30} {v}")
            print()


def cmd_entities(a, st):
    rows = Q.top_entities(st, type=a.type, limit=a.limit)
    print(f"  {'type':<12} {'value':<58} {'msgs':>6} {'chans':>6}")
    for r in rows:
        print(f"  {r['type']:<12} {r['norm'][:58]:<58} {r['messages']:>6} {r['channels']:>6}")


def cmd_coord(a, st):
    rows = Q.coordination(st, window_seconds=a.window, min_shared=a.min_shared)
    if not rows:
        print("no coordinated pairs found at this threshold")
        return
    print(f"  {'channel A':<26} {'channel B':<26} {'shared':>6} {'avg gap':>9}")
    for r in rows:
        print(f"  @{r['c1']:<25} @{r['c2']:<25} {r['shared']:>6} {r['avg_gap']:>7.0f}s")


def cmd_verify(a, st):
    """Check candidate handles before spending crawl budget on them."""
    names = []
    for item in a.names:
        p = Path(item)
        if p.exists():
            names += [ln.strip() for ln in p.read_text().splitlines()
                      if ln.strip() and not ln.startswith("#")]
        else:
            names.append(item)
    from .crawl import verify
    rows = verify(Fetcher(rps=a.rps), names, workers=a.workers)
    print(f"{'handle':<26} {'status':<20} {'subs':>8}  title")
    print("-" * 78)
    for r in rows:
        print(f"{r['username']:<26} {r['status']:<20} "
              f"{_n(r['subscribers']):>8}  {(r['title'] or '')[:26]}")
    good = [r['username'] for r in rows if r['crawlable']]
    print(f"\n{len(good)}/{len(rows)} crawlable")
    if good and a.seed:
        added = sum(st.add_channel(n, via='verified', depth=0) for n in good)
        print(f"seeded {added} new channel(s)")
    elif good:
        print("re-run with --seed to add these to the crawl queue")


def cmd_leads(a, st):
    rows = Q.discovery_leads(st, limit=a.limit)
    if not rows:
        print("no queued leads - crawl more channels first")
        return
    print(f"{'candidate':<28} {'score':>5} {'actor':>5} {'threat':>6} "
          f"{'refs':>5} {'depth':>5}  tags")
    print("-" * 86)
    for r in rows:
        print(f"@{r['username']:<27} {r['score']:>5} {r['actor_refs']:>5} "
              f"{r['threat_refs']:>6} {r['refs']:>5} {r['depth']:>5}  "
              f"{','.join(r['tags'][:4])}")
    print("\nHighest-scoring candidates were referenced from threat content.")
    print("Crawl them first: tgindex crawl --channels N")


def cmd_threats(a, st):
    r = Q.threats(st, limit=a.limit)
    if not r["by_tag"]:
        print("nothing tagged yet - crawl some channels first")
        return

    def table(title, rows, cols):
        if not rows:
            return
        print(f"\n  {title}")
        for row in rows:
            print("    " + "  ".join(fmt(row) for fmt in cols))

    print("TAG DISTRIBUTION")
    for t in r["by_tag"]:
        print(f"    {t['tag']:<18} {t['n']:>6} messages")

    table("RANSOMWARE FAMILIES", r["families"],
          [lambda x: f"{x['norm']:<24}", lambda x: f"{x['msgs']:>4} msg",
           lambda x: f"{x['channels']:>3} chan"])
    table("INFOSTEALERS", r["stealers"],
          [lambda x: f"{x['norm']:<24}", lambda x: f"{x['msgs']:>4} msg"])
    table("LEAK HOSTS", r["leak_hosts"],
          [lambda x: f"{x['norm']:<24}", lambda x: f"{x['msgs']:>4} msg"])
    table("AFFECTED / VICTIM DOMAIN CANDIDATES", r["victims"],
          [lambda x: f"{x['norm'][:44]:<44}", lambda x: f"{x['msgs']:>4} msg",
           lambda x: f"{x['channels']:>3} chan"])
    table("OPERATOR CONTACT IDs", r["contacts"],
          [lambda x: f"{x['type']:<11}", lambda x: f"{x['norm'][:50]:<50}",
           lambda x: f"{x['msgs']:>3} msg"])
    table("LARGEST CLAIMED RECORD COUNTS", r["biggest_claims"],
          [lambda x: f"{int(x['norm']):>12,} records",
           lambda x: f"@{x['channel']}/{x['msg_id']}"])
    table("MOST TAGGED CHANNELS", r["channels"],
          [lambda x: f"@{x['channel']:<28}", lambda x: f"{x['tagged']:>4} tagged"])

    if r["actor_posts"]:
        print(f"\n  RECENT ACTOR POSTS ({len(r['actor_posts'])})")
        for a_ in r["actor_posts"][:8]:
            print(f"    {_ts(a_['ts'])}  @{a_['channel']}  "
                  f"https://t.me/{a_['channel']}/{a_['msg_id']}")
            print(f"      {(a_['preview'] or '').strip()[:120]}")


def cmd_serve(a, st):
    from .web import serve
    serve(st, host=a.host, port=a.port, theme=a.theme)


def main(argv=None):
    p = argparse.ArgumentParser(prog="tgindex", description="Telegram public-channel search and monitoring")
    p.add_argument("--db", default=DEFAULT_DB)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seed", help="add channels to the crawl queue")
    s.add_argument("names", nargs="+", help="usernames or a file of usernames")
    s.set_defaults(fn=cmd_seed)

    s = sub.add_parser("crawl", help="crawl pending channels, snowballing outward")
    s.add_argument("--channels", type=int, default=25)
    s.add_argument("--pages", type=int, default=3, help="pages of history per channel")
    s.add_argument("--depth", type=int, default=1, help="snowball depth from seeds")
    s.add_argument("--workers", type=int, default=4)
    s.add_argument("--rps", type=float, default=2.0)
    s.set_defaults(fn=cmd_crawl)

    s = sub.add_parser("poll", help="re-fetch page 1 of active channels for new posts")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--workers", type=int, default=4)
    s.add_argument("--rps", type=float, default=2.0)
    s.set_defaults(fn=cmd_poll)

    s = sub.add_parser("search")
    s.add_argument("query", nargs="?", default="")
    s.add_argument("--channel"); s.add_argument("--since", help="24h, 7d, 2w")
    s.add_argument("--media", help="photo|video|document|voice|poll")
    s.add_argument("--min-views", type=int, dest="min_views")
    s.add_argument("--has", help="only messages containing this entity type")
    s.add_argument("--tag", help="only messages with this threat tag "
                                 "(ransomware, credentials, data_leak, "
                                 "initial_access, malware, exploit, carding, "
                                 "actor_post, darkweb, operator_contact)")
    s.add_argument("--no-dedup", action="store_true")
    s.add_argument("--entities", action="store_true", help="show extracted entities")
    s.add_argument("--limit", type=int, default=15)
    s.set_defaults(fn=cmd_search)

    s = sub.add_parser("pivot", help="every channel that posted this entity")
    s.add_argument("value"); s.add_argument("--type"); s.add_argument("--limit", type=int, default=50)
    s.set_defaults(fn=cmd_pivot)

    s = sub.add_parser("spread", help="forward timeline for a canonical message")
    s.add_argument("uid"); s.set_defaults(fn=cmd_spread)

    s = sub.add_parser("watch")
    s.add_argument("action", choices=["add", "list", "rm", "preset"],
                   help="preset: ransomware | stealers | malware | leak-hosts | operator-contact")
    s.add_argument("value", nargs="?", default="")
    s.add_argument("--type", default="*"); s.add_argument("--label", default="")
    s.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])
    s.set_defaults(fn=cmd_watch)

    s = sub.add_parser("alerts")
    s.add_argument("--limit", type=int, default=25); s.add_argument("--since")
    s.set_defaults(fn=cmd_alerts)

    s = sub.add_parser("stats"); s.set_defaults(fn=cmd_stats)

    s = sub.add_parser("facets"); s.add_argument("query", nargs="?", default="")
    s.set_defaults(fn=cmd_facets)

    s = sub.add_parser("entities"); s.add_argument("--type"); s.add_argument("--limit", type=int, default=25)
    s.set_defaults(fn=cmd_entities)

    s = sub.add_parser("coord", help="channels repeatedly posting identical content")
    s.add_argument("--window", type=int, default=300); s.add_argument("--min-shared", type=int, default=2, dest="min_shared")
    s.set_defaults(fn=cmd_coord)

    s = sub.add_parser("verify", help="check handles are crawlable public channels")
    s.add_argument("names", nargs="+", help="usernames or a file of usernames")
    s.add_argument("--seed", action="store_true", help="queue the crawlable ones")
    s.add_argument("--workers", type=int, default=4)
    s.add_argument("--rps", type=float, default=2.0)
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("leads", help="rank the queue by threat relevance")
    s.add_argument("--limit", type=int, default=40)
    s.set_defaults(fn=cmd_leads)

    s = sub.add_parser("threats", help="threat-vertical overview")
    s.add_argument("--limit", type=int, default=12)
    s.set_defaults(fn=cmd_threats)

    s = sub.add_parser("serve", help="minimal web UI")
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000)
    s.add_argument("--theme", default="ink", choices=["ink", "slate", "terminal"])
    s.set_defaults(fn=cmd_serve)

    a = p.parse_args(argv)
    st = Store(a.db)
    try:
        a.fn(a, st)
    finally:
        st.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
