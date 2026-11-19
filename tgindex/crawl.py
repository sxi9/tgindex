"""Crawl orchestration: backfill, head polling, and discovery snowball.

Network work happens in a thread pool; all database writes happen on the main
thread. That keeps SQLite single-writer and mirrors the shape you want in
production anyway (fetch workers -> bus -> single ingest consumer).
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from .fetch import Blocked, Fetcher
from .parse import ChannelInfo, Message, parse_page
from .store import Store

log = logging.getLogger("tgindex.crawl")


@dataclass
class ChannelResult:
    username: str
    info: Optional[ChannelInfo] = None
    messages: list[Message] = field(default_factory=list)
    pages: int = 0
    oldest_seen: Optional[int] = None
    backfill_done: bool = False
    error: Optional[str] = None


def crawl_channel(fetcher: Fetcher, username: str, *, max_pages: int = 3,
                  start_before: Optional[int] = None) -> ChannelResult:
    """Walk one channel backwards through history via the ?before= cursor."""
    res = ChannelResult(username=username)
    before = start_before
    seen_cursors: set[int] = set()

    for page in range(max_pages):
        try:
            resp = fetcher.channel_page(username, before=before)
        except Blocked as exc:
            # 404 on page 1 means no public preview; later it just ends the walk.
            if page == 0:
                res.error = str(exc)
            else:
                res.backfill_done = True
            break
        except Exception as exc:                     # noqa: BLE001
            res.error = f"{type(exc).__name__}: {exc}"
            break

        try:
            info, msgs, next_before = parse_page(resp.text)
        except Exception as exc:                     # noqa: BLE001
            res.error = f"parse failed: {type(exc).__name__}: {exc}"
            break

        if res.info is None:
            res.info = info
        res.pages += 1
        res.messages.extend(msgs)

        if msgs:
            res.oldest_seen = min(m.msg_id for m in msgs)

        if next_before is None or next_before in seen_cursors:
            res.backfill_done = True
            break
        seen_cursors.add(next_before)
        before = next_before

    return res


def live_search(fetcher: Fetcher, username: str, query: str, *,
                max_pages: int = 3) -> ChannelResult:
    """Search one channel's history live, without indexing anything.

    Telegram serves in-channel search at t.me/s/<channel>?q=<term>. It only
    works for a channel you name - there is no cross-channel search endpoint,
    which is why the index exists. This is the live escape hatch for the case
    where you already know which channel to look in.
    """
    res = ChannelResult(username=username)
    before = None
    seen: set[int] = set()
    for page in range(max_pages):
        try:
            resp = fetcher.channel_page(username, before=before, q=query)
        except Blocked as exc:
            if page == 0:
                res.error = str(exc)
            break
        except Exception as exc:                     # noqa: BLE001
            res.error = f"{type(exc).__name__}: {exc}"
            break
        try:
            info, msgs, nxt = parse_page(resp.text)
        except Exception as exc:                     # noqa: BLE001
            res.error = f"parse failed: {exc}"
            break
        if res.info is None:
            res.info = info
        res.pages += 1
        res.messages.extend(msgs)
        if nxt is None or nxt in seen:
            break
        seen.add(nxt)
        before = nxt
    return res


def verify(fetcher: Fetcher, usernames: list[str], workers: int = 4) -> list[dict]:
    """Check whether handles are crawlable public channels.

    t.me/s/ only serves channels that are public AND have web preview enabled.
    Private, invite-only, preview-disabled channels and user accounts all return
    a bare contact page - they exist, but this collection method cannot see them.
    Worth checking before spending a crawl budget on a candidate list.
    """
    def probe(name: str) -> dict:
        out = {"username": name, "status": "unknown", "subscribers": None,
               "title": None, "messages": 0, "crawlable": False}
        try:
            resp = fetcher.channel_page(name)
        except Blocked as exc:
            out["status"] = "not found" if "404" in str(exc) else "blocked"
            return out
        except Exception as exc:                     # noqa: BLE001
            out["status"] = f"error: {type(exc).__name__}"
            return out
        try:
            info, msgs, _ = parse_page(resp.text)
        except Exception:                            # noqa: BLE001
            out["status"] = "unparseable"
            return out
        out["title"] = info.title
        out["subscribers"] = info.subscribers
        out["messages"] = len(msgs)
        if msgs:
            out["status"] = "public, crawlable"
            out["crawlable"] = True
        else:
            # Exists, but serves no message history to the open web.
            out["status"] = "no public preview"
        return out

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(probe, n.strip().lstrip("@")): n for n in usernames if n.strip()}
        for fut in as_completed(futs):
            results.append(fut.result())
    return sorted(results, key=lambda r: (not r["crawlable"], r["username"]))


def run(store: Store, fetcher: Fetcher, *, max_channels: int = 25, max_pages: int = 3,
        max_depth: int = 1, workers: int = 4, verbose: bool = True) -> dict:
    """Drain the pending-channel queue, snowballing outward up to max_depth."""
    totals = {"channels": 0, "pages": 0, "messages": 0, "new": 0,
              "entities": 0, "alerts": 0, "discovered": 0, "blocked": 0}
    processed = 0

    while processed < max_channels:
        batch = store.pending_channels(
            limit=min(workers * 2, max_channels - processed), max_depth=max_depth
        )
        if not batch:
            break

        # Claim them so a crash doesn't re-crawl the same rows forever.
        for row in batch:
            store.db.execute(
                "UPDATE channels SET status='crawling' WHERE username=?", (row["username"],))
        store.db.commit()

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(crawl_channel, fetcher, row["username"], max_pages=max_pages): row
                for row in batch
            }
            for fut in as_completed(futures):
                row = futures[fut]
                processed += 1
                try:
                    res = fut.result()
                except Exception as exc:              # noqa: BLE001
                    store.mark_channel(row["username"], status="blocked", error=str(exc))
                    totals["blocked"] += 1
                    continue

                if res.error and not res.messages:
                    store.mark_channel(row["username"], status="blocked", error=res.error)
                    totals["blocked"] += 1
                    if verbose:
                        log.info("  %-28s BLOCKED (%s)", row["username"], res.error[:60])
                    continue

                if res.info:
                    store.update_channel_info(res.info)
                out = store.ingest(res.messages, depth=row["depth"])
                store.mark_channel(row["username"], status="active",
                                   oldest_seen=res.oldest_seen,
                                   backfill_done=res.backfill_done)

                totals["channels"] += 1
                totals["pages"] += res.pages
                totals["messages"] += len(res.messages)
                for k in ("new", "entities", "alerts", "discovered"):
                    totals[k] += out[k]

                if verbose:
                    log.info(
                        "  %-28s %2dp  %4d msg  %4d new  %4d ent  %2d alert  +%d chan",
                        row["username"], res.pages, len(res.messages),
                        out["new"], out["entities"], out["alerts"], out["discovered"],
                    )

    store.refresh_counts()
    return totals


def poll_heads(store: Store, fetcher: Fetcher, *, limit: int = 50, workers: int = 4) -> dict:
    """Re-fetch page 1 of active channels to pick up new posts (the real-time loop)."""
    rows = store.db.execute(
        "SELECT username FROM channels WHERE status='active' "
        "ORDER BY COALESCE(last_crawled,0) ASC LIMIT ?", (limit,)
    ).fetchall()
    totals = {"channels": 0, "new": 0, "alerts": 0, "discovered": 0}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(crawl_channel, fetcher, r["username"], max_pages=1): r
                   for r in rows}
        for fut in as_completed(futures):
            r = futures[fut]
            try:
                res = fut.result()
            except Exception:                        # noqa: BLE001
                continue
            if res.info:
                store.update_channel_info(res.info)
            out = store.ingest(res.messages)
            store.mark_channel(r["username"], status="active")
            totals["channels"] += 1
            for k in ("new", "alerts", "discovered"):
                totals[k] += out[k]
    store.refresh_counts()
    return totals
