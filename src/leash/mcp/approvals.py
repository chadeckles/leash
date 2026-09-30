"""One-time approvals for MCP apps that can't show Leash's prompts.

When an ``ask`` rule matches in an app without MCP elicitation (Claude
Desktop, Windsurf), the proxy refuses the call and logs a fingerprint of it
(app, server, tool, arguments).  ``leash allow --once`` saves an approval
for that fingerprint under ``~/.leash/state/approvals`` (agents can't write
there); the next identical call within :data:`TTL` seconds uses it up.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict

from leash import paths

TTL = 600


def key(client: str, server: str, tool: str, args: Dict[str, Any]) -> str:
    blob = json.dumps([client, server, tool, args], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:32]


def _file(k: str) -> Path:
    return paths.state_dir() / "approvals" / f"{k}.json"


def grant(k: str) -> None:
    path = _file(k)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"until": time.time() + TTL}), encoding="utf-8")


def take(k: str) -> bool:
    """Use up the approval for *k*; ``True`` if there was a valid one."""
    path = _file(k)
    try:
        until = float(json.loads(path.read_text(encoding="utf-8")).get("until", 0))
        os.remove(path)  # only one caller can remove it
    except (OSError, ValueError, AttributeError):
        return False
    return time.time() <= until
