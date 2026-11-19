"""Read layer: search, entity pivot, spread, facets, alerts."""
from __future__ import annotations

import json
import math
import re
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .store import Store

_FTS_KEYWORDS = {"AND", "OR", "NOT", "NEAR"}
_TOKEN_RE = re.compile(r'"[^"]*"|\S+')


def fts_query(raw: str) -> str:
    """Turn user input into valid FTS5 syntax.

    Bare user text frequently contains characters FTS5 treats as operators;
    quoting each term keeps a stray apostrophe or colon from raising
    OperationalError mid-search. AND/OR/NOT and trailing * are preserved.
    """
    out = []
    for tok in _TOKEN_RE.findall(raw.strip()):
        if tok.upper() in _FTS_KEYWORDS:
            out.append(tok.upper())
            continue
        if tok.startswith('"') and tok.endswith('"') and len(tok) > 1:
            out.append(tok)
            continue
        prefix = tok.endswith("*")
        body = tok[:-1] if prefix else tok
        body = body.replace('"', "")
        if not body:
            continue
        out.append(f'"{body}"' + ("*" if prefix else ""))
    return " ".join(out) or '""'


@dataclass
class Hit:
    uid: str
    channel: str
    msg_id: int
    ts: Optional[int]
    date: Optional[str]
    text: str
    snippet: str
    views: Optional[int]
    media: list[str]
    canonical_uid: str
    is_forward: bool
    score: float
    copies: int = 1
    reach: int = 0
    also_in: list[str] = field(default_factory=list)
    entities: list[tuple[str, str]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @property
    def url(self) -> str:
        return f"https://t.me/{self.channel}/{self.msg_id}"


def _filters(channel, since, until, media, min_views, has_entity, tag=None):
    where, args = [], []
    if channel:
        where.append("m.channel = ?"); args.append(channel.lower().lstrip("@"))
    if since:
        where.append("m.ts >= ?"); args.append(int(since))
    if until:
        where.append("m.ts <= ?"); args.append(int(until))
    if media:
        where.append("m.media LIKE ?"); args.append(f'%"{media}"%')
    if min_views:
        where.append("m.views >= ?"); args.append(int(min_views))
    if has_entity:
        where.append("EXISTS (SELECT 1 FROM entities e WHERE e.uid=m.uid AND e.type=?)")
        args.append(has_entity)
    if tag:
        where.append("EXISTS (SELECT 1 FROM tags g WHERE g.uid=m.uid AND g.tag=?)")
        args.append(tag)
    return where, args


def search(store: Store, q: str = "", *, channel: Optional[str] = None,
           since: Optional[int] = None, until: Optional[int] = None,
           media: Optional[str] = None, min_views: Optional[int] = None,
           has_entity: Optional[str] = None, tag: Optional[str] = None,
           dedup: bool = True,
           recency_weight: float = 0.35, limit: int = 20,
           with_entities: bool = False) -> list[Hit]:
    """Full-text search with BM25, blended with recency and reach."""
    where, args = _filters(channel, since, until, media, min_views, has_entity, tag)
    pool = max(limit * 6, 120)

    if q.strip():
        sql = (
            "SELECT m.rowid, m.uid, m.channel, m.msg_id, m.ts, m.date, m.text, m.views,"
            " m.media, m.canonical_uid, m.fwd_channel,"
            " snippet(messages_fts, 0, '《', '》', ' … ', 16) AS snip,"
            " bm25(messages_fts) AS bm"
            " FROM messages_fts JOIN messages m ON m.rowid = messages_fts.rowid"
            " WHERE messages_fts MATCH ?"
        )
        params: list[Any] = [fts_query(q)]
        if where:
            sql += " AND " + " AND ".join(where); params += args
        sql += " ORDER BY bm ASC LIMIT ?"; params.append(pool)
    else:
        sql = (
            "SELECT m.rowid, m.uid, m.channel, m.msg_id, m.ts, m.date, m.text, m.views,"
            " m.media, m.canonical_uid, m.fwd_channel,"
            " substr(m.text,1,240) AS snip, 0.0 AS bm"
            " FROM messages m"
        )
        params = []
        if where:
            sql += " WHERE " + " AND ".join(where); params += args
        sql += " ORDER BY m.ts DESC LIMIT ?"; params.append(pool)

    rows = store.db.execute(sql, params).fetchall()
    if not rows:
        return []

    now = time.time()
    hits: list[Hit] = []
    for r in rows:
        # bm25() is negative, more-negative = better. Flip it to positive relevance.
        rel = -float(r["bm"])
        age_days = max((now - (r["ts"] or now)) / 86400.0, 0.0)
        recency = 1.0 / (1.0 + math.log1p(age_days))
        reach = math.log10((r["views"] or 0) + 10) / 6.0
        score = rel + recency_weight * recency * (abs(rel) or 1.0) + reach
        hits.append(Hit(
            uid=r["uid"], channel=r["channel"], msg_id=r["msg_id"], ts=r["ts"],
            date=r["date"], text=r["text"] or "", snippet=(r["snip"] or "").strip(),
            views=r["views"], media=json.loads(r["media"] or "[]"),
            canonical_uid=r["canonical_uid"], is_forward=bool(r["fwd_channel"]),
            score=round(score, 4),
        ))

    if dedup:
        best: dict[str, Hit] = {}
        for h in hits:
            cur = best.get(h.canonical_uid)
            # Always surface the origin post when it is in the index: provenance
            # beats reach. A high-view forward would otherwise bury the source,
            # which is the opposite of what an analyst needs. Reach is not lost -
            # it is reported separately as copies/reach.
            rank = (h.uid == h.canonical_uid, h.score)
            cur_rank = (cur.uid == cur.canonical_uid, cur.score) if cur else None
            if cur is None or rank > cur_rank:
                best[h.canonical_uid] = h
        hits = list(best.values())

    hits.sort(key=lambda h: h.score, reverse=True)
    hits = hits[:limit]

    if hits:
        canon = list({h.canonical_uid for h in hits})
        marks = ",".join("?" * len(canon))
        spread = {
            r["canonical_uid"]: r for r in store.db.execute(
                f"SELECT canonical_uid, COUNT(*) copies, COALESCE(SUM(views),0) reach,"
                f" GROUP_CONCAT(DISTINCT channel) chans"
                f" FROM messages WHERE canonical_uid IN ({marks}) GROUP BY canonical_uid", canon
            )
        }
        for h in hits:
            s = spread.get(h.canonical_uid)
            if s:
                h.copies = s["copies"]
                h.reach = s["reach"]
                h.also_in = sorted(set((s["chans"] or "").split(",")) - {h.channel})
        uids = [h.uid for h in hits]
        marks = ",".join("?" * len(uids))
        tmap: dict[str, list[str]] = {}
        for r in store.db.execute(
            f"SELECT uid, tag FROM tags WHERE uid IN ({marks})", uids
        ):
            tmap.setdefault(r["uid"], []).append(r["tag"])
        for h in hits:
            h.tags = sorted(tmap.get(h.uid, []))

        if with_entities:
            uids = [h.uid for h in hits]
            marks = ",".join("?" * len(uids))
            ent: dict[str, list[tuple[str, str]]] = {}
            for r in store.db.execute(
                f"SELECT uid, type, norm FROM entities WHERE uid IN ({marks})", uids
            ):
                ent.setdefault(r["uid"], []).append((r["type"], r["norm"]))
            for h in hits:
                h.entities = sorted(ent.get(h.uid, []))
    return hits


def pivot(store: Store, value: str, *, type: Optional[str] = None,
          limit: int = 50) -> dict:
    """Every message and channel that ever carried this entity.

    This is the interaction the Google-CSE version structurally cannot do.
    """
    value = value.strip()
    where = "(e.norm = ? OR lower(e.norm) = ?)"
    args: list[Any] = [value, value.lower()]
    if type:
        where += " AND e.type = ?"; args.append(type)

    rows = store.db.execute(
        f"SELECT m.uid, m.channel, m.msg_id, m.ts, m.date, m.views, e.type, e.value,"
        f" substr(m.text,1,200) preview"
        f" FROM entities e JOIN messages m ON m.uid = e.uid"
        f" WHERE {where} ORDER BY m.ts DESC LIMIT ?", args + [limit]
    ).fetchall()

    channels = store.db.execute(
        f"SELECT m.channel, COUNT(*) n, MIN(m.ts) first_seen, MAX(m.ts) last_seen,"
        f" COALESCE(SUM(m.views),0) reach"
        f" FROM entities e JOIN messages m ON m.uid = e.uid"
        f" WHERE {where} GROUP BY m.channel ORDER BY n DESC", args
    ).fetchall()

    cooccur = store.db.execute(
        f"SELECT e2.type, e2.norm, COUNT(DISTINCT e2.uid) n"
        f" FROM entities e JOIN entities e2 ON e2.uid = e.uid"
        f" WHERE {where} AND NOT (e2.norm = e.norm AND e2.type = e.type)"
        f" GROUP BY e2.type, e2.norm ORDER BY n DESC LIMIT 15", args
    ).fetchall()

    # Count separately: `rows` is capped by `limit` and would under-report.
    total_messages = store.db.execute(
        f"SELECT COUNT(DISTINCT e.uid) n FROM entities e WHERE {where}", args
    ).fetchone()["n"]

    return {
        "value": value,
        "type": type,
        "messages": [dict(r) for r in rows],
        "channels": [dict(r) for r in channels],
        "cooccurring": [dict(r) for r in cooccur],
        "shown_messages": len(rows),
        "total_messages": total_messages,
        "total_channels": len(channels),
    }


def spread(store: Store, canonical_uid: str) -> dict:
    """Who posted this content, in what order, with what reach."""
    rows = store.db.execute(
        "SELECT uid, channel, msg_id, ts, date, views, fwd_channel, fwd_name"
        " FROM messages WHERE canonical_uid = ? ORDER BY COALESCE(ts, 0) ASC",
        (canonical_uid,)
    ).fetchall()
    out = [dict(r) for r in rows]
    if out:
        t0 = out[0]["ts"] or 0
        for r in out:
            r["lag_minutes"] = round(((r["ts"] or t0) - t0) / 60.0, 1)
    return {
        "canonical_uid": canonical_uid,
        "copies": len(out),
        "reach": sum(r["views"] or 0 for r in out),
        "channels": sorted({r["channel"] for r in out}),
        "timeline": out,
    }


def facets(store: Store, q: str = "", *, limit: int = 10) -> dict:
    """Counts by channel, media type, and entity type for the current result set."""
    if q.strip():
        base = ("SELECT m.channel, m.media, m.uid FROM messages_fts"
                " JOIN messages m ON m.rowid = messages_fts.rowid"
                " WHERE messages_fts MATCH ?")
        rows = store.db.execute(base, (fts_query(q),)).fetchall()
    else:
        rows = store.db.execute("SELECT channel, media, uid FROM messages").fetchall()

    ch: dict[str, int] = {}
    md: dict[str, int] = {}
    for r in rows:
        ch[r["channel"]] = ch.get(r["channel"], 0) + 1
        for m in json.loads(r["media"] or "[]"):
            md[m] = md.get(m, 0) + 1

    uids = [r["uid"] for r in rows]
    et: dict[str, int] = {}
    if uids:
        for i in range(0, len(uids), 500):
            chunk = uids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for r in store.db.execute(
                f"SELECT type, COUNT(*) n FROM entities WHERE uid IN ({marks}) GROUP BY type",
                chunk
            ):
                et[r["type"]] = et.get(r["type"], 0) + r["n"]

    top = lambda d: sorted(d.items(), key=lambda kv: -kv[1])[:limit]
    return {"total": len(rows), "channels": top(ch), "media": top(md), "entity_types": top(et)}


def top_entities(store: Store, *, type: Optional[str] = None, limit: int = 25) -> list[dict]:
    sql = ("SELECT type, norm, COUNT(DISTINCT uid) messages,"
           " COUNT(DISTINCT substr(uid,1,instr(uid,'/')-1)) channels FROM entities")
    args: list[Any] = []
    if type:
        sql += " WHERE type = ?"; args.append(type)
    sql += " GROUP BY type, norm ORDER BY channels DESC, messages DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in store.db.execute(sql, args)]


def alerts(store: Store, *, limit: int = 50, since: Optional[int] = None) -> list[dict]:
    sql = ("SELECT a.id, a.created_at, a.entity_type, a.entity_norm,"
           " w.label, w.severity, m.channel, m.msg_id, m.uid, m.ts, m.views,"
           " substr(m.text,1,220) preview"
           " FROM alerts a JOIN watchlist w ON w.id = a.watch_id"
           " JOIN messages m ON m.uid = a.uid")
    args: list[Any] = []
    if since:
        sql += " WHERE a.created_at >= ?"; args.append(int(since))
    sql += " ORDER BY a.created_at DESC, m.ts DESC LIMIT ?"; args.append(limit)
    out = []
    for r in store.db.execute(sql, args):
        d = dict(r)
        d["url"] = f"https://t.me/{d['channel']}/{d['msg_id']}"
        out.append(d)
    return out


def threats(store: Store, *, limit: int = 12) -> dict:
    """Threat-vertical overview: what is being leaked, by whom, affecting whom."""
    q = lambda sql, a=(): [dict(r) for r in store.db.execute(sql, a)]

    by_tag = q("SELECT tag, COUNT(*) n FROM tags GROUP BY tag ORDER BY n DESC")
    families = q("SELECT norm, COUNT(DISTINCT uid) msgs,"
                 " COUNT(DISTINCT substr(uid,1,instr(uid,'/')-1)) channels"
                 " FROM entities WHERE type='ransom_family'"
                 " GROUP BY norm ORDER BY msgs DESC LIMIT ?", (limit,))
    stealers = q("SELECT norm, COUNT(DISTINCT uid) msgs FROM entities"
                 " WHERE type='stealer' GROUP BY norm ORDER BY msgs DESC LIMIT ?", (limit,))
    hosts = q("SELECT norm, COUNT(DISTINCT uid) msgs FROM entities"
              " WHERE type='leak_host' GROUP BY norm ORDER BY msgs DESC LIMIT ?", (limit,))
    victims = q("SELECT norm, COUNT(DISTINCT uid) msgs,"
                " COUNT(DISTINCT substr(uid,1,instr(uid,'/')-1)) channels"
                " FROM entities WHERE type='victim_domain'"
                " GROUP BY norm ORDER BY msgs DESC LIMIT ?", (limit * 2,))
    contacts = q("SELECT type, norm, COUNT(DISTINCT uid) msgs FROM entities"
                 " WHERE type IN ('tox_id','session_id')"
                 " GROUP BY type, norm ORDER BY msgs DESC LIMIT ?", (limit,))
    biggest = q("SELECT e.norm, e.uid, m.channel, m.msg_id, m.ts,"
                " substr(m.text,1,160) preview FROM entities e"
                " JOIN messages m ON m.uid=e.uid WHERE e.type='record_count'"
                " ORDER BY CAST(e.norm AS INTEGER) DESC LIMIT ?", (limit,))
    actors = q("SELECT m.uid, m.channel, m.msg_id, m.ts, m.views,"
               " substr(m.text,1,200) preview FROM tags g"
               " JOIN messages m ON m.uid=g.uid WHERE g.tag='actor_post'"
               " ORDER BY m.ts DESC LIMIT ?", (limit * 2,))
    chans = q("SELECT substr(g.uid,1,instr(g.uid,'/')-1) channel,"
              " COUNT(DISTINCT g.uid) tagged FROM tags g WHERE g.tag='threat'"
              " GROUP BY channel ORDER BY tagged DESC LIMIT ?", (limit,))
    return {"by_tag": by_tag, "families": families, "stealers": stealers,
            "leak_hosts": hosts, "victims": victims, "contacts": contacts,
            "biggest_claims": biggest, "actor_posts": actors, "channels": chans}


def discovery_leads(store: Store, *, limit: int = 40) -> list[dict]:
    """Rank the un-crawled queue by how threat-relevant the content that
    mentioned each candidate was.

    Discovery finds everything linked; this decides what to crawl FIRST.
    A channel referenced from ransomware or credential-dump posts is a far
    better lead than one referenced from a design-contest post.
    """
    rows = store.db.execute("""
        SELECT c.username, c.depth, c.discovered_via,
               COUNT(DISTINCT e.uid) refs,
               COUNT(DISTINCT CASE WHEN g.tag NOT IN ('threat') THEN g.uid END) threat_refs,
               GROUP_CONCAT(DISTINCT g.tag) tags,
               COUNT(DISTINCT CASE WHEN g.tag='actor_post' THEN g.uid END) actor_refs
        FROM channels c
        JOIN entities e ON e.type='tme_channel' AND e.norm = c.username
        LEFT JOIN tags g ON g.uid = e.uid
        WHERE c.status = 'pending'
        GROUP BY c.username
        ORDER BY actor_refs DESC, threat_refs DESC, refs DESC
        LIMIT ?""", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["tags"] = sorted(t for t in (d["tags"] or "").split(",") if t and t != "threat")
        d["score"] = d["actor_refs"] * 10 + d["threat_refs"] * 3 + min(d["refs"], 5)
        out.append(d)
    return sorted(out, key=lambda x: -x["score"])


def coordination(store: Store, *, window_seconds: int = 300, min_shared: int = 2) -> list[dict]:
    """Channel pairs that repeatedly post identical content within a short window.

    Cheap proxy for a coordinated network - a phase-two signal, included here
    because content_hash makes it nearly free.
    """
    rows = store.db.execute(
        "SELECT a.channel c1, b.channel c2, COUNT(*) shared,"
        " AVG(ABS(COALESCE(a.ts,0) - COALESCE(b.ts,0))) avg_gap"
        " FROM messages a JOIN messages b"
        "   ON a.content_hash = b.content_hash AND a.channel < b.channel"
        " WHERE a.text != '' AND ABS(COALESCE(a.ts,0) - COALESCE(b.ts,0)) <= ?"
        " GROUP BY a.channel, b.channel HAVING shared >= ?"
        " ORDER BY shared DESC LIMIT 25",
        (window_seconds, min_shared)
    ).fetchall()
    return [dict(r) for r in rows]
