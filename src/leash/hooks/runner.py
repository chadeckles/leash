"""``leash hook <host>``: evaluate one tool call locally and answer the host.

Reads the host's JSON payload on stdin, evaluates every normalized request
against ``~/.leash/policies`` in-process (no server), appends the result to
the local audit chain, and writes the host-specific decision to stdout.

Failure handling is fail-closed: if Leash itself errors, it prints the reason
to stderr and exits 2, which every supported host treats as "block".  Set
``LEASH_FAIL_OPEN=1`` to let tool calls through on internal errors instead.
``LEASH_MODE=observe`` records decisions without ever blocking (for rollout).
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, TextIO

from leash.hooks import hosts
from leash.hooks.actions import ActionRequest, ToolCall, requests_for
from leash.hooks.hosts import DEFER, Verdict

_RANK = {"allow": 0, "ask": 1, "deny": 2}
NO_POLICY_HINT = "run `leash init --preset coding-agent` or add a policy for this agent to ~/.leash/policies"


def agent_name_for(host: str) -> str:
    return os.getenv("LEASH_AGENT") or host


def load_local_policies():
    from leash import paths
    from leash.engine import PolicyDirectory

    target = paths.policies_dir()
    if not target.exists():
        paths.seed_policies(target)
    return PolicyDirectory(target).policies


def evaluate_call(
    call: ToolCall,
    policies: Sequence[Any],
    *,
    agent: Optional[str] = None,
    rate_limiter: Any = None,
) -> tuple[Verdict, List[Dict[str, Any]]]:
    """Evaluate every request for *call*; the strictest decision wins."""
    from leash.engine import DEFAULT_DENY_REASON, evaluate_policies

    agent = agent or agent_name_for(call.host)
    limiter = _OncePerCall(rate_limiter) if rate_limiter is not None else None
    verdict: Optional[Verdict] = None
    observations: List[Dict[str, Any]] = []
    for req in requests_for(call):
        d = evaluate_policies(
            policies, agent, req.action, req.resource, req.context,
            agent_name=agent, rate_limiter=limiter, normalize=False,
        )
        if d.observation:
            observations.append({"request": req.describe(), "observation": d.observation})
        reason = d.reason
        if d.decision != "allow" and (d.reason == DEFAULT_DENY_REASON or d.matched_policy == "default"):
            reason = f"no Leash policy allows {req.action} for agent '{agent}' — {NO_POLICY_HINT}"
        candidate = Verdict(d.decision, reason, d.matched_policy, d.matched_rule, req.describe())
        if verdict is None or _RANK.get(candidate.decision, 2) > _RANK.get(verdict.decision, 2):
            verdict = candidate
        if verdict.decision == "deny":
            break
    return verdict or Verdict("allow"), observations


class _OncePerCall:
    """A tool call can expand to several requests (e.g. each sub-command);
    count it once per rate-limit key."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.seen: Dict[Any, tuple] = {}

    def acquire(self, key, max_calls, window):
        if key not in self.seen:
            self.seen[key] = self.inner.acquire(key, max_calls, window)
        return self.seen[key]


def _emit(out: Optional[Dict[str, Any]], stdout: TextIO) -> None:
    if out is not None:
        stdout.write(json.dumps(out) + "\n")
        stdout.flush()


def run(
    host: str,
    stdin: Optional[TextIO] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    stdin, stdout, stderr = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    started = time.perf_counter()
    fail_open = os.getenv("LEASH_FAIL_OPEN", "").lower() in ("1", "true", "yes")
    observe = os.getenv("LEASH_MODE", "").lower() == "observe"
    payload: Mapping[str, Any] = {}
    try:
        raw = stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            raise ValueError("hook input is not a JSON object")
        if host == "auto":
            host = hosts.detect_host(payload)

        call = hosts.parse(host, payload)
        if call is None or call is DEFER:
            out, code = hosts.passthrough(host, payload)
            _emit(out, stdout)
            return code

        from leash import paths
        from leash.engine import FileRateLimiter

        verdict, observations = evaluate_call(
            call, load_local_policies(),
            rate_limiter=FileRateLimiter(paths.state_dir() / "ratelimit.json"),
        )
        enforced = verdict
        if observe and verdict.decision != "allow":
            enforced = Verdict("allow")

        _audit(host, call, verdict, observations, observe, started, stderr)
        out, code = hosts.render(host, enforced, payload)
        _emit(out, stdout)
        return code
    except Exception as exc:  # noqa: BLE001 — any failure must produce a decision
        msg = f"Leash hook error ({type(exc).__name__}: {exc})"
        if fail_open:
            stderr.write(msg + "; allowing because LEASH_FAIL_OPEN is set\n")
            out, code = hosts.passthrough(host if host in hosts.HOSTS else "claude-code", payload)
            _emit(out, stdout)
            return code
        stderr.write(msg + "; blocking the tool call (fail-closed). Run `leash doctor` to diagnose.\n")
        return 2


def _audit(host: str, call: ToolCall, verdict: Verdict, observations, observe: bool, started: float, stderr: TextIO) -> None:
    from leash import auditlog

    decision = verdict.decision
    if observe and decision != "allow":
        decision = f"observe_{decision}"
    record = {
        "host": host,
        "agent": agent_name_for(host),
        "session": call.session,
        "cwd": call.cwd,
        "tool": call.tool,
        "request": verdict.request[:2000] if verdict.request else _summary(call),
        "decision": decision,
        "reason": verdict.reason,
        "policy": verdict.policy,
        "rule": verdict.rule,
        "ms": round((time.perf_counter() - started) * 1000, 1),
    }
    if observations:
        record["observations"] = observations
    try:
        auditlog.append(record)
    except OSError as exc:
        stderr.write(f"Leash: could not write audit log ({exc})\n")


def _summary(call: ToolCall) -> str:
    reqs: List[ActionRequest] = requests_for(call)
    return reqs[0].describe()[:2000] if reqs else call.tool
