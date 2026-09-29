"""Local, append-only, hash-chained decision log.

Each line of ``~/.leash/audit/audit.jsonl`` is a JSON object whose ``hash``
is ``sha256(prev_hash + canonical_json(entry_without_hash))``.  Editing or
deleting a line breaks the chain, which ``leash audit verify`` reports.  The
log is written under an exclusive lock, so concurrent hook processes can't
interleave or fork the chain.

This is tamper-*evident*, not tamper-proof: someone who can rewrite the whole
file can rebuild the chain.  Team mode (Phase 4) ships entries off-host.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from leash import paths
from leash.filelock import locked

GENESIS = "0" * 64


def _canonical(entry: Dict[str, Any]) -> str:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _digest(prev: str, entry: Dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256((prev + _canonical(body)).encode("utf-8")).hexdigest()


def _last_line(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            if end == 0:
                return None
            block, data = 4096, b""
            pos = end
            while pos > 0:
                step = min(block, pos)
                pos -= step
                fh.seek(pos)
                data = fh.read(step) + data
                stripped = data.rstrip(b"\n")
                if b"\n" in stripped:
                    return stripped.rsplit(b"\n", 1)[1].decode("utf-8", "replace")
            return data.rstrip(b"\n").decode("utf-8", "replace") or None
    except FileNotFoundError:
        return None


def append(record: Dict[str, Any], path: Optional[Path] = None) -> Dict[str, Any]:
    """Append *record* to the chain and return the stored entry."""
    path = Path(path or paths.audit_log_file())
    path.parent.mkdir(parents=True, exist_ok=True)
    with locked(path.with_name(path.name + ".lock")):
        prev = GENESIS
        last = _last_line(path)
        if last:
            try:
                prev = json.loads(last).get("hash") or GENESIS
            except ValueError:
                prev = hashlib.sha256(last.encode("utf-8")).hexdigest()
        entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **record, "prev": prev}
        entry["hash"] = _digest(prev, entry)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(_canonical(entry) + "\n")
    return entry


def read(path: Optional[Path] = None) -> Iterator[Dict[str, Any]]:
    path = Path(path or paths.audit_log_file())
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    yield {"_corrupt": line}
    except FileNotFoundError:
        return


def tail(n: int = 20, path: Optional[Path] = None) -> List[Dict[str, Any]]:
    from collections import deque

    return list(deque(read(path), maxlen=max(n, 0)))


def verify(path: Optional[Path] = None) -> Tuple[bool, int, str]:
    """Check the whole chain.  Returns ``(ok, valid_entries, problem)``, where
    *valid_entries* counts the intact entries before the first problem."""
    prev = GENESIS
    count = 0
    for count, entry in enumerate(read(path), start=1):
        if "_corrupt" in entry:
            return False, count - 1, f"line {count}: not valid JSON"
        if entry.get("prev") != prev:
            return False, count - 1, f"line {count}: chain broken (entry was removed, reordered or inserted)"
        if entry.get("hash") != _digest(prev, entry):
            return False, count - 1, f"line {count}: hash mismatch (entry was modified)"
        prev = entry["hash"]
    return True, count, ""
