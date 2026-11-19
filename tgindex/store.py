"""SQLite + FTS5 store.

Stands in for OpenSearch in the prototype: same document shape, same fields,
same dedup key. FTS5 gives real BM25 ranking with zero infrastructure.
See README for the production port path.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Iterable, Optional, Sequence

from . import threat as TH
from .entities import discover_channels, extract
from .parse import ChannelInfo, Message, to_epoch

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS channels (
  username       TEXT PRIMARY KEY,
  title          TEXT,
  description    TEXT,
  subscribers    INTEGER,
  photo          TEXT,
  status         TEXT NOT NULL DEFAULT 'pending',   -- pending|active|blocked
  discovered_at  INTEGER,
  discovered_via TEXT,
  depth          INTEGER NOT NULL DEFAULT 0,
  last_crawled   INTEGER,
  oldest_seen    INTEGER,
  backfill_done  INTEGER NOT NULL DEFAULT 0,
  msg_count      INTEGER NOT NULL DEFAULT 0,
  error          TEXT
);
CREATE INDEX IF NOT EXISTS ix_ch_status ON channels(status, depth);

CREATE TABLE IF NOT EXISTS messages (
  uid           TEXT PRIMARY KEY,
  channel       TEXT NOT NULL,
  msg_id        INTEGER NOT NULL,
  ts            INTEGER,
  date          TEXT,
  text          TEXT,
  views         INTEGER,
  author        TEXT,
  fwd_channel   TEXT,
  fwd_msg_id    INTEGER,
  fwd_name      TEXT,
  reply_uid     TEXT,
  media         TEXT,
  preview_url   TEXT,
  preview_title TEXT,
  preview_site  TEXT,
  preview_desc  TEXT,
  outlinks      TEXT,
  canonical_uid TEXT NOT NULL,
  content_hash  TEXT,
  crawled_at    INTEGER
);
CREATE INDEX IF NOT EXISTS ix_msg_channel ON messages(channel, msg_id);
CREATE INDEX IF NOT EXISTS ix_msg_ts      ON messages(ts DESC);
CREATE INDEX IF NOT EXISTS ix_msg_canon   ON messages(canonical_uid);
CREATE INDEX IF NOT EXISTS ix_msg_hash    ON messages(content_hash);

CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
  text,
  content='messages',
  content_rowid='rowid',
  tokenize="unicode61 remove_diacritics 2"
);
CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
  INSERT INTO messages_fts(rowid, text) VALUES (new.rowid, new.text);
END;
CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, text) VALUES('delete', old.rowid, old.text);
END;
CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
  INSERT INTO messages_fts(messages_fts, rowid, text) VALUES('delete', old.rowid, old.text);
  INSERT INTO messages_fts(rowid, text) VALUES (new.rowid, new.text);
END;

CREATE TABLE IF NOT EXISTS entities (
  uid   TEXT NOT NULL,
  type  TEXT NOT NULL,
  value TEXT NOT NULL,
  norm  TEXT NOT NULL,
  PRIMARY KEY (uid, type, norm)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_ent_pivot ON entities(type, norm);
CREATE INDEX IF NOT EXISTS ix_ent_norm  ON entities(norm);

CREATE TABLE IF NOT EXISTS watchlist (
  id         INTEGER PRIMARY KEY,
  type       TEXT NOT NULL DEFAULT '*',
  norm       TEXT NOT NULL,
  label      TEXT,
  severity   TEXT NOT NULL DEFAULT 'medium',
  enabled    INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER,
  UNIQUE(type, norm)
);

CREATE TABLE IF NOT EXISTS alerts (
  id          INTEGER PRIMARY KEY,
  watch_id    INTEGER NOT NULL REFERENCES watchlist(id) ON DELETE CASCADE,
  uid         TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_norm TEXT NOT NULL,
  created_at  INTEGER,
  UNIQUE(watch_id, uid, entity_norm)
);
CREATE INDEX IF NOT EXISTS ix_alert_time ON alerts(created_at DESC);

CREATE TABLE IF NOT EXISTS tags (
  uid TEXT NOT NULL,
  tag TEXT NOT NULL,
  PRIMARY KEY (uid, tag)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_tags_tag ON tags(tag);

CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        # check_same_thread=False so the read-only web UI can serve from worker
        # threads; _lock serializes the writers.
        self.db = sqlite3.connect(self.path, timeout=30.0, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self.db.executescript(SCHEMA)
        self.db.commit()
        self._watch: dict[tuple[str, str], list[tuple[int, str]]] = {}
        self.reload_watchlist()

    # ---------- channels ----------

    def add_channel(self, username: str, *, via: str = "seed", depth: int = 0) -> bool:
        """Register a channel as pending. Returns True if newly added."""
        username = username.lower().strip().lstrip("@")
        if not username:
            return False
        cur = self.db.execute(
            "INSERT OR IGNORE INTO channels(username, discovered_at, discovered_via, depth) "
            "VALUES (?,?,?,?)",
            (username, int(time.time()), via, depth),
        )
        return cur.rowcount > 0

    def update_channel_info(self, info: ChannelInfo) -> None:
        if not info.username:
            return
        self.db.execute(
            "UPDATE channels SET title=COALESCE(?,title), description=COALESCE(?,description),"
            " subscribers=COALESCE(?,subscribers), photo=COALESCE(?,photo), status='active'"
            " WHERE username=?",
            (info.title, info.description, info.subscribers, info.photo, info.username),
        )

    def mark_channel(self, username: str, *, status: Optional[str] = None,
                     oldest_seen: Optional[int] = None, backfill_done: Optional[bool] = None,
                     error: Optional[str] = None) -> None:
        sets, args = ["last_crawled=?"], [int(time.time())]
        if status is not None:
            sets.append("status=?"); args.append(status)
        if oldest_seen is not None:
            sets.append("oldest_seen=?"); args.append(oldest_seen)
        if backfill_done is not None:
            sets.append("backfill_done=?"); args.append(1 if backfill_done else 0)
        if error is not None:
            sets.append("error=?"); args.append(error)
        args.append(username)
        self.db.execute(f"UPDATE channels SET {','.join(sets)} WHERE username=?", args)
        self.db.commit()

    def pending_channels(self, limit: int, max_depth: int) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM channels WHERE status='pending' AND depth<=? "
            "ORDER BY depth ASC, discovered_at ASC LIMIT ?",
            (max_depth, limit),
        ).fetchall()

    def refresh_counts(self) -> None:
        self.db.execute(
            "UPDATE channels SET msg_count = "
            "(SELECT COUNT(*) FROM messages m WHERE m.channel = channels.username)"
        )
        self.db.commit()

    # ---------- ingest ----------

    def ingest(self, messages: Sequence[Message], *, depth: int = 0,
               discover: bool = True) -> dict:
        """Insert messages, extract entities, fire watchlist alerts, snowball channels."""
        with self._lock:
            return self._ingest(messages, depth=depth, discover=discover)

    def _ingest(self, messages: Sequence[Message], *, depth: int = 0,
                discover: bool = True) -> dict:
        if not messages:
            return {"new": 0, "entities": 0, "alerts": 0, "discovered": 0}
        now = int(time.time())
        rows, ent_rows, tag_rows, found_channels = [], [], [], set()

        for m in messages:
            rows.append((
                m.uid, m.channel, m.msg_id, to_epoch(m.date), m.date, m.text, m.views,
                m.author, m.fwd_channel, m.fwd_msg_id, m.fwd_name,
                f"{m.reply_channel}/{m.reply_msg_id}" if m.reply_channel else None,
                json.dumps(m.media), m.preview_url, m.preview_title, m.preview_site,
                m.preview_desc, json.dumps(m.outlinks), m.canonical_uid, m.content_hash, now,
            ))
            blob = "\n".join(filter(None, [m.text, m.preview_title, m.preview_desc, m.preview_url]))
            generic = extract(blob, extra_urls=m.outlinks)
            for e in generic:
                ent_rows.append((m.uid, e.type, e.value[:512], e.norm[:512]))

            # --- threat layer ---
            doms = [e.norm for e in generic if e.type == "domain"]
            has_onion = any(e.type == "onion" for e in generic)
            tents = TH.extract(blob, domains=doms)
            for e in tents:
                ent_rows.append((m.uid, e.type, e.value[:512], e.norm[:512]))
            msg_tags = TH.classify(blob, threat_entities=tents, onion=has_onion)
            struct = TH.structural_signals(tents)
            for v in TH.victim_candidates(doms, msg_tags, structural=struct)[:8]:
                ent_rows.append((m.uid, "victim_domain", v[:512], v[:512]))
            for t in msg_tags:
                tag_rows.append((m.uid, t))
            if discover:
                found_channels |= discover_channels(blob, outlinks=m.outlinks)
                if m.fwd_channel:
                    found_channels.add(m.fwd_channel)

        cur = self.db.executemany(
            "INSERT OR IGNORE INTO messages VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
        )
        new_msgs = cur.rowcount
        self.db.executemany(
            "INSERT OR IGNORE INTO entities(uid,type,value,norm) VALUES (?,?,?,?)", ent_rows
        )
        self.db.executemany(
            "INSERT OR IGNORE INTO tags(uid,tag) VALUES (?,?)", tag_rows
        )

        n_alerts = self._match_watchlist(ent_rows, now)
        n_alerts += self._match_keywords([m.uid for m in messages], now)

        discovered = 0
        known = {m.channel for m in messages}
        for name in known:
            self.add_channel(name, via="observed", depth=depth)
        for name in found_channels - known:
            if self.add_channel(name, via=f"snowball:{messages[0].channel}", depth=depth + 1):
                discovered += 1

        self.db.commit()
        return {"new": new_msgs, "entities": len(ent_rows), "tags": len(tag_rows),
                "alerts": n_alerts, "discovered": discovered}

    # ---------- watchlist ----------

    def reload_watchlist(self) -> None:
        """Index each entry under both its verbatim and lowercased form, so a
        watchlist entry matches regardless of the case the analyst typed."""
        self._watch.clear()
        for r in self.db.execute("SELECT id, type, norm, label FROM watchlist WHERE enabled=1"):
            for key in {(r["type"], r["norm"]), (r["type"], r["norm"].lower())}:
                self._watch.setdefault(key, []).append((r["id"], r["label"]))

    def watch(self, norm: str, *, type: str = "*", label: str = "",
              severity: str = "medium") -> int:
        # Stored verbatim: base58 (BTC/TRON) is case-sensitive, so lowercasing
        # here would silently stop those watchlist entries ever matching.
        # Matching compensates by also trying the lowercased form.
        norm = norm.strip()
        self.db.execute(
            "INSERT OR IGNORE INTO watchlist(type,norm,label,severity,created_at) VALUES (?,?,?,?,?)",
            (type, norm, label, severity, int(time.time())),
        )
        self.db.commit()
        self.reload_watchlist()
        return self.db.execute(
            "SELECT id FROM watchlist WHERE type=? AND norm=?", (type, norm)
        ).fetchone()["id"]

    def _match_watchlist(self, ent_rows: Iterable[tuple], now: int) -> int:
        """O(1) dict lookup per entity. Percolation is reserved for complex queries."""
        if not self._watch:
            return 0
        hits = []
        for uid, etype, _value, norm in ent_rows:
            lower = norm.lower()
            keys = {(etype, norm), ("*", norm), (etype, lower), ("*", lower)}
            for key in keys:
                for wid, _label in self._watch.get(key, ()):
                    hits.append((wid, uid, etype, norm, now))
        if not hits:
            return 0
        cur = self.db.executemany(
            "INSERT OR IGNORE INTO alerts(watch_id,uid,entity_type,entity_norm,created_at) "
            "VALUES (?,?,?,?,?)", hits
        )
        return cur.rowcount

    def _match_keywords(self, uids: list[str], now: int) -> int:
        """Percolate keyword watches over a batch via FTS.

        Entity watches are exact-match on structured values; this covers the
        other half - free-text brand/term monitoring - by running each saved
        keyword query against just-ingested rows.
        """
        kws = self.db.execute(
            "SELECT id, norm FROM watchlist WHERE enabled=1 AND type='keyword'"
        ).fetchall()
        if not kws or not uids:
            return 0
        from .query import fts_query

        total = 0
        for i in range(0, len(uids), 400):
            chunk = uids[i:i + 400]
            marks = ",".join("?" * len(chunk))
            for w in kws:
                rows = self.db.execute(
                    f"SELECT m.uid FROM messages_fts JOIN messages m"
                    f" ON m.rowid = messages_fts.rowid"
                    f" WHERE messages_fts MATCH ? AND m.uid IN ({marks})",
                    [fts_query(w["norm"])] + chunk,
                ).fetchall()
                if rows:
                    cur = self.db.executemany(
                        "INSERT OR IGNORE INTO alerts"
                        "(watch_id,uid,entity_type,entity_norm,created_at) VALUES (?,?,?,?,?)",
                        [(w["id"], r["uid"], "keyword", w["norm"], now) for r in rows],
                    )
                    total += cur.rowcount
        return total

    def backfill_alerts(self) -> int:
        """Re-run the current watchlist over everything already indexed."""
        total = 0
        now = int(time.time())
        all_uids = [r["uid"] for r in self.db.execute("SELECT uid FROM messages")]
        total += self._match_keywords(all_uids, now)
        for (wtype, norm), entries in self._watch.items():
            if wtype == "keyword":
                continue
            if wtype == "*":
                rows = self.db.execute(
                    "SELECT uid, type, norm FROM entities WHERE norm=? OR lower(norm)=?",
                    (norm, norm.lower())).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT uid, type, norm FROM entities WHERE type=? AND (norm=? OR lower(norm)=?)",
                    (wtype, norm, norm.lower())).fetchall()
            for wid, _label in entries:
                cur = self.db.executemany(
                    "INSERT OR IGNORE INTO alerts(watch_id,uid,entity_type,entity_norm,created_at)"
                    " VALUES (?,?,?,?,?)",
                    [(wid, r["uid"], r["type"], r["norm"], now) for r in rows],
                )
                total += cur.rowcount
        self.db.commit()
        return total

    def watch_preset(self, preset: str) -> dict:
        """Load a bundle of watch targets for a vertical."""
        presets = {
            "ransomware": [("ransom_family", f, f"ransomware family: {f}")
                           for f in sorted(TH.RANSOM_FAMILIES)],
            "stealers": [("stealer", f, f"infostealer: {f}")
                         for f in sorted(TH.INFOSTEALERS)],
            "malware": [("malware_tool", f, f"loader/C2: {f}")
                        for f in sorted(TH.LOADERS_BOTNETS)],
            "leak-hosts": [("leak_host", h, f"leak host: {h}")
                           for h in sorted(TH.LEAK_HOSTS)],
            "operator-contact": [("keyword", t, f"operator contact: {t}")
                                 for t in ("tox id", "session id", "qtox")],
        }
        if preset not in presets:
            raise KeyError(f"unknown preset {preset!r}; have {sorted(presets)}")
        added = 0
        for etype, value, label in presets[preset]:
            before = self.db.total_changes
            self.watch(value, type=etype, label=label, severity="high")
            added += int(self.db.total_changes != before)
        n = self.backfill_alerts()
        return {"preset": preset, "targets": len(presets[preset]),
                "added": added, "alerts_backfilled": n}

    def stats(self) -> dict:
        q = lambda s: self.db.execute(s).fetchone()[0]
        return {
            "channels_total":  q("SELECT COUNT(*) FROM channels"),
            "channels_active": q("SELECT COUNT(*) FROM channels WHERE status='active'"),
            "channels_pending": q("SELECT COUNT(*) FROM channels WHERE status='pending'"),
            "messages":        q("SELECT COUNT(*) FROM messages"),
            "forwards":        q("SELECT COUNT(*) FROM messages WHERE fwd_channel IS NOT NULL"),
            "unique_content":  q("SELECT COUNT(DISTINCT canonical_uid) FROM messages"),
            "entities":        q("SELECT COUNT(*) FROM entities"),
            "tagged_messages": q("SELECT COUNT(DISTINCT uid) FROM tags"),
            "entity_values":   q("SELECT COUNT(DISTINCT norm) FROM entities"),
            "watchlist":       q("SELECT COUNT(*) FROM watchlist WHERE enabled=1"),
            "alerts":          q("SELECT COUNT(*) FROM alerts"),
            "db_bytes":        Path(self.path).stat().st_size if Path(self.path).exists() else 0,
        }

    def close(self) -> None:
        self.db.commit()
        self.db.close()
