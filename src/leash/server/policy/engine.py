"""Server adapter for the policy engine.

Merges YAML policies (``POLICIES_DIR``) with DB-managed policies, evaluates
them with :mod:`leash.engine`, and signs decisions.

Maps to the OWASP Agentic Security Initiative (ASI, 2025):
- ASI02 Tool Misuse → action allow/deny, wildcards, rate limiting
- ASI03 Identity & Privilege → per-agent policies, ABAC conditions
- ASI09 Human-Agent Trust → signed audit trail, deny-stops-execution

Also maps to the LLM Top 10 (2025):
- LLM06 Excessive Agency → action allow/deny, wildcards, conditions
- LLM10 Unbounded Consumption → per-rule rate limiting
"""

from __future__ import annotations

import logging
import threading
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

import yaml

from leash.engine import (
    InMemoryRateLimiter,
    Policy,
    PolicyDirectory,
    compile_policy,
    evaluate_policies,
    sort_policies,
)
from leash.engine.matching import looks_like_agent_id  # noqa: F401  (re-export)
from leash.engine.matching import match_agent as _match_agent  # noqa: F401  (re-export)
from leash.server.core.config import POLICIES_DIR
from leash.server.core.security import sign_data
from leash.server.policy.schemas import (
    AuthorizeResponse,
    DryRunRequest,
    DryRunResponse,
    DryRunResult,
    PolicyInfo,
)

_logger = logging.getLogger("leash.policy")

YAML_POLICIES = PolicyDirectory(POLICIES_DIR)
# Per-process: counts reset on restart and aren't shared across workers.
RATE_LIMITER = InMemoryRateLimiter()

_db_cache: Dict[int, Tuple[Tuple, Policy]] = {}
_db_cache_lock = threading.Lock()


def reload_yaml_policies() -> None:
    """Force the next evaluation to re-read YAML policies from disk."""
    YAML_POLICIES.invalidate()


def _load_db_policies(db=None) -> List[Policy]:
    """Compile active managed policies, reusing compiled results for unchanged rows."""
    if db is None:
        return []
    from leash.server.models.policy import Policy as PolicyRow

    compiled: List[Policy] = []
    seen = set()
    for row in db.query(PolicyRow).filter(PolicyRow.active.is_(True)).all():
        key = (row.name, row.priority, row.yaml_content)
        seen.add(row.id)
        cached = _db_cache.get(row.id)
        if cached and cached[0] == key:
            compiled.append(cached[1])
            continue
        try:
            doc = yaml.safe_load(row.yaml_content)
        except yaml.YAMLError as exc:
            _logger.warning("Skipping malformed managed policy id=%s (%s): %s", row.id, row.name, exc)
            continue
        if not isinstance(doc, dict):
            continue
        # DB-level fields override anything in the YAML body
        doc.update(name=row.name, priority=row.priority, _source="db", _db_id=row.id)
        try:
            policy = compile_policy(doc, "db")
        except (AttributeError, TypeError, ValueError) as exc:
            _logger.warning("Skipping invalid managed policy id=%s (%s): %s", row.id, row.name, exc)
            continue
        with _db_cache_lock:
            _db_cache[row.id] = (key, policy)
        compiled.append(policy)
    with _db_cache_lock:
        for stale in set(_db_cache) - seen:
            _db_cache.pop(stale, None)
    return compiled


def load_policies(db=None) -> List[Policy]:
    """All active policies, highest priority first.  A DB policy replaces a
    YAML policy with the same name (operators can override file defaults)."""
    db_policies = _load_db_policies(db)
    db_names = {p.name for p in db_policies}
    merged = db_policies + [p for p in YAML_POLICIES.policies if p.name not in db_names]
    return sort_policies(merged)


def _load_all_policies(db=None) -> List[Dict[str, Any]]:
    """Raw policy documents (copies), highest priority first."""
    return [deepcopy(dict(p.doc)) for p in load_policies(db)]


def _resolve_agent_name(agent_id: str, db=None) -> str:
    if db is None:
        return ""
    from leash.server.models.agent import Agent

    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    return agent.name if agent else ""


def evaluate(
    agent_id: str,
    action: str,
    resource: str = "",
    context: Optional[Dict[str, Any]] = None,
    db=None,
) -> AuthorizeResponse:
    """Evaluate policies for one request and return a signed decision."""
    result = evaluate_policies(
        load_policies(db), agent_id, action, resource, context,
        agent_name=_resolve_agent_name(agent_id, db),
        rate_limiter=RATE_LIMITER if db is not None else None,
    )
    if result.needs_approval:
        # API callers have no interactive approver, so "ask" fails closed.
        result.decision = "deny"
        result.reason = f"Requires human approval: {result.reason}"
    signature = sign_data({
        "agent_id": agent_id,
        "action": action,
        "decision": result.audit_decision,
        "reason": result.reason,
    })
    return AuthorizeResponse(
        agent_id=agent_id,
        action=action,
        decision=result.decision,
        reason=result.reason,
        matched_policy=result.matched_policy,
        matched_rule=result.matched_rule,
        signature=signature,
        owasp=result.owasp,
        observation=result.observation,
    )


def get_policies_for_agent(agent_id: str, db=None) -> PolicyInfo:
    """Return all policies that reference the given agent."""
    agent_name = _resolve_agent_name(agent_id, db)
    matching = [deepcopy(dict(p.doc)) for p in load_policies(db) if p.applies_to(agent_id, agent_name)]
    return PolicyInfo(agent_id=agent_id, policies=matching)


def get_effective_permissions(agent_id: str, db=None):
    """Flattened view of every rule that applies to the agent, in priority order."""
    from leash.server.policy.schemas import EffectivePermission, EffectivePermissionsResponse

    agent_name = _resolve_agent_name(agent_id, db)
    permissions: list = []
    for policy in load_policies(db):
        if not policy.applies_to(agent_id, agent_name):
            continue
        for rule in policy.doc.get("rules", []):
            permissions.append(EffectivePermission(
                action=rule.get("action", "*"),
                effect=rule.get("effect", "deny"),
                reason=rule.get("reason", ""),
                resource=rule.get("resource", ""),
                policy_name=policy.name,
                policy_priority=policy.priority,
                has_conditions=bool(rule.get("conditions")),
                has_rate_limit=bool(rule.get("rate_limit")),
                mode=policy.mode,
                owasp=rule.get("owasp") or policy.owasp,
            ))

    allowed = sum(1 for p in permissions if p.effect == "allow")
    return EffectivePermissionsResponse(
        agent_id=agent_id,
        permissions=permissions,
        total_rules=len(permissions),
        allowed_actions=allowed,
        denied_actions=len(permissions) - allowed,
        observed_rules=sum(1 for p in permissions if p.mode == "observe"),
    )


def dry_run(req: DryRunRequest, db=None) -> DryRunResponse:
    """Evaluate a candidate policy alongside the live ones without deploying it."""
    candidate = yaml.safe_load(req.policy_yaml)
    if not candidate or not isinstance(candidate, dict):
        return DryRunResponse(agent_id=req.agent_id, results=[], summary="Invalid or empty YAML provided.")

    combined = sort_policies(load_policies(db) + [compile_policy(candidate, "candidate")])
    agent_name = _resolve_agent_name(req.agent_id, db)

    results: list[DryRunResult] = []
    for test in req.actions:
        result = evaluate_policies(
            combined, req.agent_id, test.action, test.resource, test.context,
            agent_name=agent_name, dry_run=True,
        )
        results.append(DryRunResult(
            action=test.action,
            resource=test.resource,
            decision=result.decision,
            reason=result.reason,
            matched_policy=result.matched_policy,
            owasp=result.owasp,
        ))

    allowed = sum(1 for r in results if r.decision == "allow")
    return DryRunResponse(
        agent_id=req.agent_id,
        results=results,
        summary=f"{allowed} allowed, {len(results) - allowed} denied out of {len(results)} test actions",
    )
