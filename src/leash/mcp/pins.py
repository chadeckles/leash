"""Pin MCP tool descriptions so a server can't quietly change what its tools
tell the AI ("tool poisoning" / "rug pull").

The first time Leash sees a server, it trusts the tools it offers, unless a
description looks like it is giving the AI instructions.  After that:

* a tool whose description or input schema changed is withheld until you run
  ``leash mcp trust <server>``;
* a new tool is trusted automatically unless its description looks suspicious.

Withheld tools are hidden from the AI, and calls to them are refused.
Pins live in ``~/.leash/mcp/pins/<client>__<server>.json``.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from leash import paths

# Phrases that address the AI rather than describe the tool.
_SUSPICIOUS = [
    (re.compile(p, re.I), why) for p, why in (
        (r"ignore (all |any )?(previous|prior|above|earlier) (instructions|prompts)", "tells the AI to ignore its instructions"),
        (r"(do not|don't|never) (tell|inform|mention|reveal|show)[^.]{0,40}\b(user|human)", "tells the AI to hide something from you"),
        (r"<\s*(important|system|instructions?)\s*>", "contains hidden instruction tags"),
        (r"~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.netrc|mcp\.json|private key", "mentions secret or config files"),
        (r"\b(send|forward|upload|post|exfiltrate)\b[^.]{0,60}\b(to|at)\s+(https?://|\S+@\S+)", "tells the AI to send data somewhere"),
    )
]


def fingerprint(tool: Dict[str, Any]) -> str:
    body = json.dumps({"d": tool.get("description") or "", "s": tool.get("inputSchema") or {}}, sort_keys=True)
    return hashlib.sha256(body.encode()).hexdigest()


def _texts(value: Any) -> List[str]:
    """Every description/title string in a tool (schemas can hide text too)."""
    if isinstance(value, dict):
        out = [v for k, v in value.items() if k in ("description", "title") and isinstance(v, str)]
        for v in value.values():
            out += _texts(v)
        return out
    if isinstance(value, list):
        return [t for v in value for t in _texts(v)]
    return []


def suspicious(tool: Dict[str, Any]) -> Optional[str]:
    text = "\n".join(_texts(tool))
    return next((why for rx, why in _SUSPICIOUS if rx.search(text)), None)


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:80] or "_"


def pins_dir() -> Path:
    return paths.leash_home() / "mcp" / "pins"


@dataclass
class Pins:
    client: str
    server: str
    tools: Dict[str, Dict[str, str]] = field(default_factory=dict)
    pending: Dict[str, Dict[str, str]] = field(default_factory=dict)

    @property
    def path(self) -> Path:
        return pins_dir() / f"{_safe(self.client)}__{_safe(self.server)}.json"

    @classmethod
    def load(cls, client: str, server: str) -> "Pins":
        pins = cls(client, server)
        try:
            doc = json.loads(pins.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return pins
        if isinstance(doc, dict):
            pins.tools = dict(doc.get("tools") or {})
            pins.pending = dict(doc.get("pending") or {})
        return pins

    @classmethod
    def all(cls) -> List["Pins"]:
        out = []
        for f in sorted(pins_dir().glob("*__*.json")):
            try:
                doc = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(doc, dict):
                out.append(cls(str(doc.get("client", "")), str(doc.get("server", "")),
                               dict(doc.get("tools") or {}), dict(doc.get("pending") or {})))
        return out

    def save(self) -> None:
        doc = {"client": self.client, "server": self.server, "updated": time.time(),
               "tools": self.tools, "pending": self.pending}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.{time.time_ns()}.tmp")
        tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def review(self, tools: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
        """Split a ``tools/list`` result into (tools to show, withheld name → why)."""
        visible, withheld, changed = [], {}, False
        for tool in tools:
            name = str(tool.get("name") or "")
            h = fingerprint(tool)
            pinned = self.tools.get(name)
            if pinned and pinned.get("hash") == h:
                visible.append(tool)
                if self.pending.pop(name, None):
                    changed = True
                continue
            why = suspicious(tool)
            if why:
                why = f"its description {why}"
            elif pinned:
                why = "its description changed since you trusted it"
            if why:
                withheld[name] = why
                entry = {"hash": h, "description": str(tool.get("description") or ""), "why": why}
                if self.pending.get(name) != entry:
                    self.pending[name] = entry
                    changed = True
            else:
                self.tools[name] = {"hash": h, "description": str(tool.get("description") or "")}
                visible.append(tool)
                changed = True
        if changed:
            self.save()
        return visible, withheld

    def trust(self, names: Optional[List[str]] = None) -> List[str]:
        chosen = [n for n in (names or list(self.pending)) if n in self.pending]
        for name in chosen:
            entry = self.pending.pop(name)
            self.tools[name] = {"hash": entry["hash"], "description": entry.get("description", "")}
        if chosen:
            self.save()
        return chosen
