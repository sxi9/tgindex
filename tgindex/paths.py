"""Where the index lives.

The database used to land in whatever directory you happened to run from,
which made it easy to crawl into one file and then serve an empty one. It now
defaults to a stable per-user location; --db and TGINDEX_DB still override.
"""
from __future__ import annotations

import os
from pathlib import Path

APP = "tgindex"


def data_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif os.uname().sysname == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    d = base / APP
    d.mkdir(parents=True, exist_ok=True)
    return d


def default_db() -> str:
    env = os.environ.get("TGINDEX_DB")
    if env:
        p = Path(env).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        return str(p)
    # An index already in the working directory wins, so existing setups and
    # the repo checkout keep behaving the way they did.
    local = Path.cwd() / "tgindex.db"
    if local.exists():
        return str(local)
    return str(data_dir() / "tgindex.db")


def bundled(name: str) -> Path:
    """A seed list shipped inside the package, so quickstart works anywhere."""
    return Path(__file__).parent / "data" / name
