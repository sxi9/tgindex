"""Rate-limited HTTP fetcher for t.me/s/ preview pages."""
from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass
from typing import Optional

import requests

log = logging.getLogger("tgindex.fetch")

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


class RateLimiter:
    """Token bucket shared across threads.

    Telegram throttles aggressively per-IP. In production you spread this
    across an egress pool; here one bucket governs the whole process.
    """

    def __init__(self, rps: float, burst: int = 4):
        self.rps = max(rps, 0.01)
        self.capacity = max(burst, 1)
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._last) * self.rps
                )
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = (1.0 - self._tokens) / self.rps
            time.sleep(deficit + random.uniform(0, 0.05))


class Blocked(Exception):
    """Raised when Telegram refuses the page outright (404/451/private)."""


@dataclass
class Response:
    url: str
    status: int
    text: str


class Fetcher:
    def __init__(
        self,
        rps: float = 2.0,
        timeout: float = 20.0,
        max_retries: int = 4,
        session: Optional[requests.Session] = None,
    ):
        self.limiter = RateLimiter(rps)
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "User-Agent": UA,
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml",
            }
        )
        self.stats = {"requests": 0, "retries": 0, "blocked": 0, "errors": 0}

    def get(self, url: str, params: Optional[dict] = None) -> Response:
        last_exc: Optional[Exception] = None
        for attempt in range(self.max_retries):
            self.limiter.acquire()
            try:
                self.stats["requests"] += 1
                r = self.session.get(url, params=params, timeout=self.timeout)
            except requests.RequestException as exc:
                last_exc = exc
                self.stats["errors"] += 1
                self._backoff(attempt)
                continue

            if r.status_code in (404, 451):
                self.stats["blocked"] += 1
                raise Blocked(f"{r.status_code} for {r.url}")
            if r.status_code == 429 or r.status_code >= 500:
                self.stats["retries"] += 1
                retry_after = r.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    time.sleep(min(int(retry_after), 60))
                else:
                    self._backoff(attempt)
                continue
            if r.status_code != 200:
                raise Blocked(f"{r.status_code} for {r.url}")
            return Response(url=r.url, status=r.status_code, text=r.text)

        raise Blocked(f"exhausted retries for {url}: {last_exc}")

    @staticmethod
    def _backoff(attempt: int) -> None:
        time.sleep(min(2 ** attempt, 30) + random.uniform(0, 0.75))

    def channel_page(
        self, username: str, before: Optional[int] = None, q: Optional[str] = None
    ) -> Response:
        params = {}
        if before is not None:
            params["before"] = before
        if q:
            params["q"] = q
        return self.get(f"https://t.me/s/{username}", params=params or None)
