"""Pattern matching primitives shared by the engine, server and scanner."""

from __future__ import annotations

import posixpath
import re
from fnmatch import translate
from functools import lru_cache
from typing import Any, Mapping, Optional
from urllib.parse import unquote

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_GLOB_CHARS = frozenset("*?[")


def looks_like_agent_id(value: str) -> bool:
    return bool(_UUID_RE.match(value or ""))


@lru_cache(maxsize=4096)
def _compile_glob(pattern: str) -> "re.Pattern[str]":
    return re.compile(translate(pattern))


def match_pattern(pattern: str, value: str) -> bool:
    """Case-sensitive glob match (``*``, ``?``, ``[...]``) of *value* against *pattern*.

    ``"*"`` matches everything; patterns without glob characters must match
    exactly.  Compiled patterns are cached.
    """
    if pattern == "*" or pattern == value:
        return True
    if _GLOB_CHARS.isdisjoint(pattern):
        return False
    return _compile_glob(pattern).match(value) is not None


def normalize_resource(resource: str) -> str:
    """Canonicalize a resource path so traversal can't bypass glob rules.

    ``/data/../../etc/passwd`` → ``/etc/passwd``;
    ``/data/%2e%2e/etc/passwd`` → ``/etc/passwd``;
    ``/data//etc/passwd`` → ``/data/etc/passwd``.
    """
    if not resource:
        return resource
    decoded = unquote(resource)
    normalized = posixpath.normpath(decoded)
    if decoded.startswith("/") and not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def match_agent(policy: Mapping[str, Any], agent_id: str, agent_name: str = "") -> bool:
    """Return True if *policy* applies to the agent.

    ``agents`` entries may be ``"*"``/``"all"``, an exact agent ID, or a
    name/glob such as ``"crewai-*"``.  Entries shaped like an agent ID never
    match by name, so an agent can't rename itself into another's rules.
    """
    agents = policy.get("agents", [])
    if agents == "*":
        return True
    for pattern in agents or ():
        if pattern in ("*", "all") or pattern == agent_id:
            return True
        if looks_like_agent_id(pattern):
            continue
        if agent_name and match_pattern(pattern, agent_name):
            return True
    return False


def check_conditions(rule: Mapping[str, Any], context: Optional[Mapping[str, Any]]) -> bool:
    """Every key in ``rule["conditions"]`` must be present in *context* and match
    (glob for strings, equality otherwise).  Rules without conditions always match."""
    conditions = rule.get("conditions")
    if not conditions:
        return True
    if not context:
        return False
    for key, expected in conditions.items():
        actual = context.get(key)
        if actual is None:
            return False
        if isinstance(expected, str) and isinstance(actual, str):
            if not match_pattern(expected, actual):
                return False
        elif actual != expected:
            return False
    return True
