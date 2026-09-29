"""Leash policy engine – a pure, in-process library.

Depends only on the standard library and PyYAML (no web framework or
database), so it can run inside agent hooks, the CLI, the SDK and the server.

>>> from leash.engine import PolicyEngine
>>> engine = PolicyEngine([{"name": "p", "agents": ["*"],
...     "rules": [{"action": "email.*", "effect": "allow", "reason": "ok"}]}])
>>> engine.evaluate("agent-1", "email.send").decision
'allow'
"""

from leash.engine.core import (
    DEFAULT_DENY_REASON,
    Decision,
    Policy,
    PolicyEngine,
    Rule,
    compile_policy,
    evaluate_policies,
    sort_policies,
)
from leash.engine.loader import PolicyDirectory, load_policy_dir
from leash.engine.matching import (
    check_conditions,
    looks_like_agent_id,
    match_agent,
    match_pattern,
    normalize_resource,
)
from leash.engine.ratelimit import InMemoryRateLimiter, RateLimiter
from leash.engine.validator import validate_policy, validate_policy_file, validate_policy_yaml

__all__ = [
    "DEFAULT_DENY_REASON",
    "Decision",
    "InMemoryRateLimiter",
    "Policy",
    "PolicyDirectory",
    "PolicyEngine",
    "RateLimiter",
    "Rule",
    "check_conditions",
    "compile_policy",
    "evaluate_policies",
    "load_policy_dir",
    "looks_like_agent_id",
    "match_agent",
    "match_pattern",
    "normalize_resource",
    "sort_policies",
    "validate_policy",
    "validate_policy_file",
    "validate_policy_yaml",
]
