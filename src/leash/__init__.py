"""Leash – authorization and audit for AI agents.

Public SDK names are imported lazily so that lightweight entry points (the
CLI, the policy engine, agent hooks) don't pay for importing httpx.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

__version__ = "0.4.0.dev0"

_LAZY = {
    "LeashAgent": "leash.client",
    "LeashDenied": "leash.client",
    "LeashRevoked": "leash.client",
    "MCPScanner": "leash.scanner",
    "classify_tools": "leash.scanner",
    "analyze_policy_coverage": "leash.scanner",
    "generate_policy": "leash.scanner",
}

__all__ = [
    "__version__",
    "LeashAgent",
    "LeashDenied",
    "LeashRevoked",
    "MCPScanner",
    "analyze_policy_coverage",
    "classify_tools",
    "generate_policy",
]

if TYPE_CHECKING:
    from leash.client import LeashAgent, LeashDenied, LeashRevoked
    from leash.scanner import MCPScanner, analyze_policy_coverage, classify_tools, generate_policy


def __getattr__(name: str):
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module 'leash' has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module), name)
    globals()[name] = value
    return value
