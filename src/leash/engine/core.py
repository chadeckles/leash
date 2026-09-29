"""Policy compilation and evaluation.

Policies are plain YAML documents::

    name: email-agent
    priority: 50
    agents: ["email-*"]
    mode: enforce            # or observe
    rules:
      - action: "email.send"
        effect: allow          # allow | deny | ask (escalate to a human)
        reason: "Can send mail"
        resource: "/outbox/*"
        conditions: {env: prod}
        rate_limit: {max_calls: 10, window: 3600}

Evaluation is deny-by-default: policies are checked in descending priority
and the first rule that matches (action, resource, conditions) wins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from leash.engine.matching import check_conditions, match_agent, match_pattern, normalize_resource
from leash.engine.ratelimit import InMemoryRateLimiter, RateLimiter

DEFAULT_DENY_REASON = "No matching policy found"
EFFECTS = ("allow", "deny", "ask")


@dataclass(frozen=True)
class Rule:
    action: str
    effect: str
    reason: str
    resource: str = ""
    conditions: Optional[Mapping[str, Any]] = None
    rate_limit: Optional[Tuple[int, float]] = None
    owasp: Optional[List[str]] = None

    def matches(self, action: str, resource: str, context: Optional[Mapping[str, Any]]) -> bool:
        if not match_pattern(self.action, action):
            return False
        if self.resource and not match_pattern(self.resource, resource):
            return False
        return check_conditions({"conditions": self.conditions}, context)


@dataclass(frozen=True)
class Policy:
    name: str
    priority: int
    agents: Any
    mode: str
    rules: Tuple[Rule, ...]
    owasp: Optional[List[str]] = None
    source: str = ""
    doc: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def applies_to(self, agent_id: str, agent_name: str = "") -> bool:
        return match_agent({"agents": self.agents}, agent_id, agent_name)


@dataclass
class Decision:
    decision: str
    reason: str
    matched_policy: Optional[str] = None
    matched_rule: Optional[str] = None
    owasp: Optional[List[str]] = None
    observation: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"

    @property
    def needs_approval(self) -> bool:
        """True when the matched rule asks for a human to confirm (``effect: ask``)."""
        return self.decision == "ask"

    @property
    def audit_decision(self) -> str:
        """Decision as recorded in audit/signatures (``observe_deny`` for observe mode)."""
        return "observe_deny" if self.observation else self.decision


def _rate_limit(raw: Any) -> Optional[Tuple[int, float]]:
    if not isinstance(raw, Mapping):
        return None
    max_calls, window = raw.get("max_calls"), raw.get("window")
    if not max_calls or not window:
        return None
    return int(max_calls), float(window)


def compile_policy(doc: Mapping[str, Any], source: str = "") -> Policy:
    """Turn a parsed policy document into an immutable :class:`Policy`."""
    name = doc.get("name", "unnamed")
    rules = []
    for raw in doc.get("rules") or ():
        action = raw.get("action", "")
        rules.append(Rule(
            action=action,
            effect=raw.get("effect", "deny"),
            reason=raw.get("reason") or f"Matched rule in policy '{name}'",
            resource=raw.get("resource", "") or "",
            conditions=raw.get("conditions") or None,
            rate_limit=_rate_limit(raw.get("rate_limit")),
            owasp=raw.get("owasp") or doc.get("owasp"),
        ))
    return Policy(
        name=name,
        priority=int(doc.get("priority", 0) or 0),
        agents=doc.get("agents", []),
        mode=doc.get("mode", "enforce"),
        rules=tuple(rules),
        owasp=doc.get("owasp"),
        source=source or doc.get("_source", ""),
        doc=doc,
    )


def sort_policies(policies: Iterable[Policy]) -> List[Policy]:
    return sorted(policies, key=lambda p: p.priority, reverse=True)


def evaluate_policies(
    policies: Sequence[Policy],
    agent_id: str,
    action: str,
    resource: str = "",
    context: Optional[Mapping[str, Any]] = None,
    *,
    agent_name: str = "",
    rate_limiter: Optional[RateLimiter] = None,
    dry_run: bool = False,
    normalize: bool = True,
) -> Decision:
    """Evaluate *policies* (already sorted by priority, highest first).

    ``dry_run`` skips rate limiting and reports the raw effect of observe-mode
    policies instead of converting denials into allows.  ``normalize=False``
    matches *resource* verbatim (for shell commands and URLs, which are not
    filesystem paths); callers are then responsible for canonicalizing paths.
    """
    safe_resource = normalize_resource(resource) if normalize else (resource or "")
    for policy in policies:
        if not policy.applies_to(agent_id, agent_name):
            continue
        for rule in policy.rules:
            if not rule.matches(action, safe_resource, context):
                continue

            decision, reason, owasp = rule.effect, rule.reason, rule.owasp
            if rule.rate_limit and dry_run:
                reason += " (rate limit not checked in dry-run)"
            elif rule.rate_limit and decision == "allow":
                if rate_limiter is not None:
                    max_calls, window = rule.rate_limit
                    ok, count = rate_limiter.acquire((agent_id, action), max_calls, window)
                    if not ok:
                        decision = "deny"
                        reason = f"Rate limit exceeded: {count}/{max_calls} calls in the last {window:g}s window"
                        owasp = sorted(set((owasp or []) + ["LLM10"]))

            if decision not in EFFECTS:
                decision = "deny"

            observation = None
            if decision in ("deny", "ask") and policy.mode == "observe" and not dry_run:
                verb = "deny" if decision == "deny" else "require approval for"
                observation = (
                    f"OBSERVE: policy '{policy.name}' would {verb} this action "
                    f"(rule: {rule.action}, reason: {reason})"
                )
                decision = "allow"
                reason = f"Allowed (observe mode) — {reason}"

            return Decision(decision, reason, policy.name, rule.action, owasp, observation)

    return Decision("deny", DEFAULT_DENY_REASON)


class PolicyEngine:
    """In-process, deny-by-default policy evaluator.

    >>> engine = PolicyEngine.from_directory("~/.leash/policies")
    >>> engine.evaluate("agent-1", "email.send", agent_name="email-bot").allowed
    """

    def __init__(
        self,
        policies: Iterable[Mapping[str, Any] | Policy] = (),
        *,
        rate_limiter: Optional[RateLimiter] = None,
    ) -> None:
        self.rate_limiter = rate_limiter if rate_limiter is not None else InMemoryRateLimiter()
        self.load(policies)

    @classmethod
    def from_directory(cls, path, **kwargs) -> "PolicyEngine":
        from leash.engine.loader import load_policy_dir

        return cls(load_policy_dir(path), **kwargs)

    def load(self, policies: Iterable[Mapping[str, Any] | Policy]) -> None:
        self.policies = sort_policies(
            p if isinstance(p, Policy) else compile_policy(p) for p in policies
        )

    def applicable(self, agent_id: str, agent_name: str = "") -> List[Policy]:
        return [p for p in self.policies if p.applies_to(agent_id, agent_name)]

    def evaluate(
        self,
        agent_id: str,
        action: str,
        resource: str = "",
        context: Optional[Dict[str, Any]] = None,
        *,
        agent_name: str = "",
        dry_run: bool = False,
        normalize: bool = True,
    ) -> Decision:
        return evaluate_policies(
            self.policies, agent_id, action, resource, context,
            agent_name=agent_name, rate_limiter=self.rate_limiter, dry_run=dry_run,
            normalize=normalize,
        )
