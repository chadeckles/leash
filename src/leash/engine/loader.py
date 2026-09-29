"""Loading policies from YAML files."""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from leash.engine.core import Policy, compile_policy, sort_policies

_logger = logging.getLogger("leash.engine")


def _policy_files(path: Path) -> List[Path]:
    return sorted(path.glob("*.y*ml")) if path.is_dir() else []


def load_policy_dir(path) -> List[Dict[str, Any]]:
    """Parse every ``*.yaml``/``*.yml`` file in *path*; malformed files are skipped."""
    docs: List[Dict[str, Any]] = []
    for fpath in _policy_files(Path(path).expanduser()):
        try:
            doc = yaml.safe_load(fpath.read_text())
        except (OSError, yaml.YAMLError) as exc:
            _logger.warning("Skipping malformed YAML policy %s: %s", fpath.name, exc)
            continue
        if isinstance(doc, dict):
            doc["_source"] = "yaml"
            docs.append(doc)
    return docs


class PolicyDirectory:
    """Compiled policies from a directory, reloaded when files change.

    The directory is re-scanned at most every *check_interval* seconds, so the
    hot path doesn't ``stat()`` every file on every evaluation.
    """

    def __init__(self, path, check_interval: float = 1.0) -> None:
        self.path = Path(path).expanduser()
        self.check_interval = check_interval
        self._lock = threading.Lock()
        self._signature: Optional[Tuple] = None
        self._checked_at = float("-inf")
        self._docs: List[Dict[str, Any]] = []
        self._compiled: List[Policy] = []

    def _current_signature(self) -> Tuple:
        if not self.path.is_dir():
            return ()
        sig = [self.path.stat().st_mtime_ns]
        for f in _policy_files(self.path):
            st = f.stat()
            sig.append((f.name, st.st_mtime_ns, st.st_size))
        return tuple(sig)

    def _refresh(self) -> None:
        now = time.monotonic()
        if now - self._checked_at < self.check_interval and self._signature is not None:
            return
        with self._lock:
            self._checked_at = now
            sig = self._current_signature()
            if sig == self._signature:
                return
            docs, compiled = [], []
            for d in load_policy_dir(self.path):
                try:
                    compiled.append(compile_policy(d, "yaml"))
                except (AttributeError, TypeError, ValueError) as exc:
                    _logger.warning("Skipping invalid policy %s: %s", d.get("name", "?"), exc)
                    continue
                docs.append(d)
            self._docs = docs
            self._compiled = sort_policies(compiled)
            self._signature = sig

    def invalidate(self) -> None:
        with self._lock:
            self._signature = None
            self._checked_at = float("-inf")

    @property
    def policies(self) -> List[Policy]:
        """Compiled policies, highest priority first."""
        self._refresh()
        return list(self._compiled)

    @property
    def documents(self) -> List[Dict[str, Any]]:
        self._refresh()
        return [dict(d) for d in self._docs]
