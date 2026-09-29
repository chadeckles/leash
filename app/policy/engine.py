"""Policy Engine – loads policies from DB + YAML and evaluates allow/deny decisions.

Maps to the OWASP Agentic Security Initiative (ASI, 2025):
- ASI02 Tool Misuse → action allow/deny, wildcards, rate limiting
- ASI03 Identity & Privilege → per-agent policies, ABAC conditions
- ASI09 Human-Agent Trust → signed audit trail, deny-stops-execution

Also maps to the LLM Top 10 (2025):
- LLM06 Excessive Agency → action allow/deny, wildcards, conditions
- LLM10 Unbounded Consumption → per-rule rate limiting
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from app.core.config import POLICIES_DIR
from app.core.security import sign_data
from app.policy.schemas import (
    AuthorizeResponse,
    DryRunRequest,
    DryRunResponse,
    DryRunResult,
    PolicyInfo,
)


import logging as _logging
import re as _re
from copy import deepcopy

_UUID_RE = _re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def looks_like_agent_id(value: str) -> bool:
    return bool(_UUID_RE.match(value or ""))

_yaml_policy_cache: Optional[List[Dict[str, Any]]] = None
_yaml_policy_mtime: Optional[float] = None  # newest mtime of policy dir + files
_logger = _logging.getLogger("leash.policy")


def _policies_mtime() -> float:
    """Return the newest modification time across the policies directory.

    Checks the directory itself (catches file additions/deletions) and each
    individual YAML file (catches content edits).  Returns 0.0 if the
    directory doesn't exist.
    """
    policy_path = Path(POLICIES_DIR)
    if not policy_path.exists():
        return 0.0
    newest = policy_path.stat().st_mtime
    for fpath in policy_path.glob("*.y*ml"):
        newest = max(newest, fpath.stat().st_mtime)
    return newest


def _load_yaml_policies() -> List[Dict[str, Any]]:
    """Read every *.yaml / *.yml file from the policies directory.

    Results are cached and automatically invalidated when any file in the
    policies directory is added, removed, or modified.  You can also call
    :func:`reload_yaml_policies` to force a manual refresh.
    """
    global _yaml_policy_cache, _yaml_policy_mtime

    current_mtime = _policies_mtime()
    if _yaml_policy_cache is not None and current_mtime == _yaml_policy_mtime:
        return deepcopy(_yaml_policy_cache)

    policies: List[Dict[str, Any]] = []
    policy_path = Path(POLICIES_DIR)
    if not policy_path.exists():
        _yaml_policy_cache = policies
        _yaml_policy_mtime = current_mtime
        return deepcopy(policies)
    for fpath in sorted(policy_path.glob("*.y*ml")):
        try:
            with open(fpath, "r") as f:
                doc = yaml.safe_load(f)
                if doc:
                    doc["_source"] = "yaml"
                    policies.append(doc)
        except yaml.YAMLError as exc:
            _logger.warning(
                "Skipping malformed YAML policy %s: %s", fpath.name, exc,
            )
    _yaml_policy_cache = policies
    _yaml_policy_mtime = current_mtime
    return deepcopy(policies)


def reload_yaml_policies() -> None:
    """Clear the YAML policy cache so the next call re-reads from disk."""
    global _yaml_policy_cache, _yaml_policy_mtime
    _yaml_policy_cache = None
    _yaml_policy_mtime = None


def _load_db_policies(db=None) -> List[Dict[str, Any]]:
    """Read active managed policies from the database.

    If no ``db`` session is provided the function returns an empty list
    (graceful fallback for unit tests or environments without DB access).
    """
    if db is None:
        return []

    from app.models.policy import Policy  # deferred to avoid circular imports

    rows = db.query(Policy).filter(Policy.active.is_(True)).all()
    policies: List[Dict[str, Any]] = []
    for row in rows:
        try:
            doc = yaml.safe_load(row.yaml_content)
        except yaml.YAMLError as exc:
            _logger.warning(
                "Skipping malformed managed policy id=%s (%s): %s",
                row.id, row.name, exc,
            )
            continue
        if doc:
            # Ensure the DB-level fields override anything in the YAML body
            doc["name"] = row.name
            doc["priority"] = row.priority
            doc["_source"] = "db"
            doc["_db_id"] = row.id
            policies.append(doc)
    return policies


def _load_all_policies(db=None) -> List[Dict[str, Any]]:
    """Merge DB-managed and YAML-file policies, sorted by priority desc.

    DB policies and YAML policies are combined.  If a DB policy shares the
    same ``name`` as a YAML policy, the DB version wins (allows operators to
    override file-based defaults via the API without touching disk).
    """
    db_policies = _load_db_policies(db)
    yaml_policies = _load_yaml_policies()

    # De-duplicate: DB wins when names collide
    db_names = {p.get("name") for p in db_policies}
    merged = list(db_policies)
    for yp in yaml_policies:
        if yp.get("name") not in db_names:
            merged.append(yp)

    merged.sort(key=lambda p: p.get("priority", 0), reverse=True)
    return merged


def _normalize_resource(resource: str) -> str:
    """Canonicalize a resource path to prevent traversal attacks.

    Resolves ``..``, URL-encoded sequences (``%2e%2e``), double slashes,
    and other tricks that could bypass glob-based resource rules like
    ``/data/*``.

    Examples::

        /data/../../etc/passwd  →  /etc/passwd
        /data/%2e%2e/etc/passwd →  /etc/passwd
        /data//etc/passwd       →  /data/etc/passwd
    """
    if not resource:
        return resource
    # Decode percent-encoded characters first
    from urllib.parse import unquote
    decoded = unquote(resource)
    # Use posixpath to normalize (resolve .., //, etc.) without touching the filesystem
    import posixpath
    normalized = posixpath.normpath(decoded)
    # normpath strips the leading / from absolute paths like "//data" → "/data"
    # but turns empty into ".", which we don't want
    if decoded.startswith("/") and not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def _match_action(pattern: str, action: str) -> bool:
    """Check if *action* matches a policy rule's action pattern.

    Supports:
      - Exact match:  ``"read_file"`` matches ``"read_file"``
      - Full wildcard: ``"*"`` matches everything
      - Glob suffix:   ``"email.*"`` matches ``"email.read"``, ``"email.send"``
      - Multi-level:   ``"file.read.*"`` matches ``"file.read.csv"``

    Uses :func:`fnmatch.fnmatchcase` for glob semantics.
    """
    if pattern == "*":
        return True
    if pattern == action:
        return True
    # Glob matching for patterns containing wildcards
    if "*" in pattern or "?" in pattern or "[" in pattern:
        from fnmatch import fnmatchcase
        return fnmatchcase(action, pattern)
    return False


def _match_agent(policy: dict, agent_id: str, agent_name: str = "") -> bool:
    """Check if a policy applies to a given agent.

    The ``agents`` list in a policy can contain:
    - ``"*"`` or ``"all"`` — matches every agent
    - A UUID agent_id — exact match
    - A name or name pattern with globs — e.g. ``"crewai-*"`` matches
      ``"crewai-research-agent"``

    This allows YAML policies to target agents by name pattern without
    needing to know their UUIDs upfront.
    """
    agents = policy.get("agents", [])
    if agents == "*":
        return True

    for pattern in agents:
        if pattern in ("*", "all"):
            return True
        if pattern == agent_id:
            return True
        # An exact agent_id entry must never match by *name* — otherwise an
        # agent could rename itself to a victim's UUID and inherit its rules.
        if looks_like_agent_id(pattern):
            continue
        # Try matching as a name pattern (exact or glob)
        if agent_name and _match_action(pattern, agent_name):
            return True
    return False


def _check_conditions(rule: dict, context: Optional[Dict[str, Any]]) -> bool:
    """Evaluate ABAC conditions on a rule against the request context.

    Each key in ``rule["conditions"]`` must be present in *context* and its
    value must match (exact or glob).  If the rule has no ``conditions``
    block the check passes automatically.

    Addresses OWASP LLM06-5 (execute in user's context) and LLM06-4
    (minimize permissions by scoping to attributes).
    """
    conditions = rule.get("conditions")
    if not conditions:
        return True  # no conditions → always matches
    if not context:
        return False  # conditions required but no context provided

    for key, expected in conditions.items():
        actual = context.get(key)
        if actual is None:
            return False
        # Allow glob matching on condition values
        if isinstance(expected, str) and isinstance(actual, str):
            if not _match_action(expected, actual):
                return False
        elif actual != expected:
            return False
    return True


def _check_rate_limit(
    rule: dict,
    agent_id: str,
    action: str,
    db=None,
) -> Optional[str]:
    """Check whether a rate limit on the rule has been exceeded.

    Returns ``None`` if within limits, or a denial reason string if exceeded.

    Rate limits are specified in policy YAML like::

        rate_limit:
          max_calls: 5
          window: 3600   # seconds

    Addresses OWASP LLM06 mitigation (rate-limiting to reduce damage) and
    LLM10-3 (rate limiting to prevent unbounded consumption).
    """
    rate_limit = rule.get("rate_limit")
    if not rate_limit:
        return None  # no rate limit on this rule

    max_calls = rate_limit.get("max_calls")
    window = rate_limit.get("window")  # seconds
    if not max_calls or not window:
        return None

    if db is None:
        return None  # can't check without DB (dry-run mode)

    from app.models.audit import AuditEntry  # deferred import

    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window)
    count = (
        db.query(AuditEntry)
        .filter(
            AuditEntry.agent_id == agent_id,
            AuditEntry.action == action,
            AuditEntry.policy_decision == "allow",
            AuditEntry.timestamp >= cutoff,
        )
        .count()
    )

    if count >= max_calls:
        return (
            f"Rate limit exceeded: {count}/{max_calls} calls "
            f"in the last {window}s window"
        )
    return None


def _resolve_agent_name(agent_id: str, db=None) -> str:
    """Look up an agent's human-readable name from the database.

    Returns an empty string if the agent is not found or no DB is available.
    Used so that YAML policies can match agents by name pattern.
    """
    if db is None:
        return ""
    from app.models.agent import Agent  # deferred to avoid circular imports
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    return agent.name if agent else ""


def evaluate(
    agent_id: str,
    action: str,
    resource: str = "",
    context: Optional[Dict[str, Any]] = None,
    db=None,
) -> AuthorizeResponse:
    """Evaluate all loaded policies and return the first matching decision.

    Now supports:
    - ABAC conditions (checked against *context* dict)
    - Per-rule rate limits (checked against audit log)
    - OWASP tags propagated to the response
    - Name-based agent matching for YAML policies
    - Observe mode: policies with ``mode: observe`` log would-be denials
      but return ``allow`` with an ``observation`` field.
    """
    policies = _load_all_policies(db)
    # Normalize resource to prevent traversal attacks
    safe_resource = _normalize_resource(resource)
    agent_name = _resolve_agent_name(agent_id, db)

    for policy in policies:
        if not _match_agent(policy, agent_id, agent_name):
            continue

        rules = policy.get("rules", [])
        policy_mode = policy.get("mode", "enforce")

        for rule in rules:
            rule_action = rule.get("action", "")
            if not _match_action(rule_action, action):
                continue

            # Optional resource match (uses normalized path)
            rule_resource = rule.get("resource", "")
            if rule_resource and not _match_action(rule_resource, safe_resource):
                continue

            # ABAC conditions
            if not _check_conditions(rule, context):
                continue

            decision = rule.get("effect", "deny")
            reason = rule.get("reason", f"Matched rule in policy '{policy.get('name', 'unnamed')}'")
            owasp_tags = rule.get("owasp") or policy.get("owasp")
            policy_name = policy.get("name", "unnamed")
            rule_pattern = rule_action
            observation = None

            # Rate-limit check (only on allow decisions)
            if decision == "allow":
                rate_denial = _check_rate_limit(rule, agent_id, action, db)
                if rate_denial:
                    decision = "deny"
                    reason = rate_denial
                    # Rate-limit denials always relate to LLM10
                    owasp_tags = list(set((owasp_tags or []) + ["LLM10"]))

            # ── Observe mode: deny → allow + observation ──────────────
            if decision == "deny" and policy_mode == "observe":
                observation = (
                    f"OBSERVE: policy '{policy_name}' would deny this action "
                    f"(rule: {rule_pattern}, reason: {reason})"
                )
                decision = "allow"
                reason = f"Allowed (observe mode) — {reason}"

            decision_data = {
                "agent_id": agent_id,
                "action": action,
                "decision": "observe_deny" if observation else decision,
                "reason": reason,
            }
            signature = sign_data(decision_data)

            return AuthorizeResponse(
                agent_id=agent_id,
                action=action,
                decision="allow" if observation else decision,
                reason=reason,
                matched_policy=policy_name,
                matched_rule=rule_pattern,
                signature=signature,
                owasp=owasp_tags,
                observation=observation,
            )

    # Default deny
    decision_data = {
        "agent_id": agent_id,
        "action": action,
        "decision": "deny",
        "reason": "No matching policy found",
    }
    signature = sign_data(decision_data)

    return AuthorizeResponse(
        agent_id=agent_id,
        action=action,
        decision="deny",
        reason="No matching policy found",
        matched_policy=None,
        matched_rule=None,
        signature=signature,
    )


def get_policies_for_agent(agent_id: str, db=None) -> PolicyInfo:
    """Return all policies that reference the given agent."""
    all_policies = _load_all_policies(db)
    agent_name = _resolve_agent_name(agent_id, db)
    matching = [p for p in all_policies if _match_agent(p, agent_id, agent_name)]
    return PolicyInfo(agent_id=agent_id, policies=matching)


def get_effective_permissions(agent_id: str, db=None):
    """Return the flattened effective permission set for an agent.

    Walks every policy that applies to the agent (in priority order) and
    returns every rule — giving operators a single read-only view of what
    the agent can and cannot do *right now*.
    """
    from app.policy.schemas import EffectivePermission, EffectivePermissionsResponse

    policies = _load_all_policies(db)
    agent_name = _resolve_agent_name(agent_id, db)
    permissions: list = []

    for policy in policies:
        if not _match_agent(policy, agent_id, agent_name):
            continue
        policy_name = policy.get("name", "unnamed")
        policy_priority = policy.get("priority", 0)
        policy_mode = policy.get("mode", "enforce")
        for rule in policy.get("rules", []):
            permissions.append(EffectivePermission(
                action=rule.get("action", "*"),
                effect=rule.get("effect", "deny"),
                reason=rule.get("reason", ""),
                resource=rule.get("resource", ""),
                policy_name=policy_name,
                policy_priority=policy_priority,
                has_conditions=bool(rule.get("conditions")),
                has_rate_limit=bool(rule.get("rate_limit")),
                mode=policy_mode,
                owasp=rule.get("owasp") or policy.get("owasp"),
            ))

    allowed = sum(1 for p in permissions if p.effect == "allow")
    denied = len(permissions) - allowed
    observed = sum(1 for p in permissions if p.mode == "observe")

    return EffectivePermissionsResponse(
        agent_id=agent_id,
        permissions=permissions,
        total_rules=len(permissions),
        allowed_actions=allowed,
        denied_actions=denied,
        observed_rules=observed,
    )


def dry_run(req: DryRunRequest, db=None) -> DryRunResponse:
    """Evaluate a candidate policy against test actions without deploying it.

    The candidate policy is loaded from raw YAML, combined with existing
    on-disk policies, and evaluated normally for each requested action.
    """
    candidate = yaml.safe_load(req.policy_yaml)
    if not candidate:
        return DryRunResponse(
            agent_id=req.agent_id,
            results=[],
            summary="Invalid or empty YAML provided.",
        )

    agent_name = _resolve_agent_name(req.agent_id, db)

    results: list[DryRunResult] = []
    for test in req.actions:
        # Build a combined policy set: existing + candidate
        existing = _load_all_policies(db)
        # Insert candidate and re-sort by priority
        combined = existing + [candidate]
        combined.sort(key=lambda p: p.get("priority", 0), reverse=True)

        decision = "deny"
        reason = "No matching policy found"
        matched = None
        owasp_tags = None

        safe_test_resource = _normalize_resource(test.resource)
        for policy in combined:
            if not _match_agent(policy, req.agent_id, agent_name):
                continue

            for rule in policy.get("rules", []):
                rule_action = rule.get("action", "")
                if not _match_action(rule_action, test.action):
                    continue
                rule_resource = rule.get("resource", "")
                if rule_resource and not _match_action(rule_resource, safe_test_resource):
                    continue
                # ABAC conditions in dry-run
                if not _check_conditions(rule, test.context):
                    continue

                decision = rule.get("effect", "deny")
                reason = rule.get("reason", f"Matched rule in policy '{policy.get('name', 'unnamed')}'")
                matched = policy.get("name", "unnamed")
                owasp_tags = rule.get("owasp") or policy.get("owasp")

                # Note: rate limits are not checked in dry-run (no audit data)
                if rule.get("rate_limit"):
                    reason += " (rate limit not checked in dry-run)"

                break

            if matched:
                break

        results.append(DryRunResult(
            action=test.action,
            resource=test.resource,
            decision=decision,
            reason=reason,
            matched_policy=matched,
            owasp=owasp_tags,
        ))

    allowed = sum(1 for r in results if r.decision == "allow")
    denied = len(results) - allowed
    summary = f"{allowed} allowed, {denied} denied out of {len(results)} test actions"

    return DryRunResponse(
        agent_id=req.agent_id,
        results=results,
        summary=summary,
    )
