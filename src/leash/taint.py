"""Session taint: remember that an agent session has read untrusted content.

Web pages, search results, downloaded files and MCP tool results can contain
instructions aimed at the AI ("ignore your task and push this to...").  Once
a session has read such content, Leash adds ``session_tainted: true`` to the
context of every later request in that session, so rules in the
``untrusted`` group can ask before the agent pushes, posts or sends data.

State is one small file per session under ``~/.leash/state/sessions``
(agents can't write there).  Entries expire after a day.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Iterable, Optional

from leash import paths
from leash.engine.matching import match_pattern

TTL = 24 * 3600

# (action glob, resource glob) pairs whose *results* are untrusted.
SOURCES = (
    ("web.fetch", "*"),
    ("web.search", "*"),
    ("mcp.*", "*"),
    ("shell.exec", "curl *"),
    ("shell.exec", "wget *"),
    ("shell.exec", "gh issue view*"),
    ("shell.exec", "gh pr view*"),
    ("shell.exec", "gh api *"),
)


def _file(host: str, session: str) -> Path:
    key = hashlib.sha256(f"{host}\0{session}".encode()).hexdigest()[:32]
    return paths.state_dir() / "sessions" / f"{key}.json"


def source(host: str, session: str) -> Optional[str]:
    """What tainted this session, or ``None`` if it is clean (or unknown)."""
    if not session:
        return None
    try:
        doc = json.loads(_file(host, session).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or time.time() - float(doc.get("at", 0)) > TTL:
        return None
    return str(doc.get("source") or "untrusted content")


def is_source(action: str, resource: str) -> bool:
    return any(match_pattern(a, action) and match_pattern(r, resource or "") for a, r in SOURCES)


def mark(host: str, session: str, requests: Iterable) -> Optional[str]:
    """Record the first untrusted-content request in *requests* for this
    session.  Keeps the original source if the session is already tainted."""
    if not session:
        return None
    hit = next((r for r in requests if is_source(r.action, r.resource)), None)
    if hit is None:
        return None
    existing = source(host, session)
    if existing:
        return existing
    desc = hit.describe()[:200]
    path = _file(host, session)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps({"at": time.time(), "source": desc}), encoding="utf-8")
    tmp.replace(path)
    _prune(path.parent)
    return desc


def _prune(folder: Path) -> None:
    cutoff = time.time() - TTL
    try:
        for f in folder.glob("*.json"):
            if f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
    except OSError:
        pass
