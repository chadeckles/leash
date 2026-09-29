"""Audit Log Service – append-only logging with cryptographic signatures."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from leash.server.core.security import hash_data, sign_data
from leash.server.models.audit import AuditEntry
from leash.server.audit.schemas import (
    ActionBreakdown,
    AgentActivity,
    AuditCreateRequest,
    AuditEntryResponse,
    AuditExportEntry,
    AuditListResponse,
    AuditScanRequest,
    AuditScanResponse,
    AuditSummaryResponse,
    ChainDetectionRequest,
    ChainDetectionResponse,
    ChainMatch,
    ChainPattern,
    ScanCheckResult,
    ScanFinding,
)
from leash.server.core.metrics import METRICS


def log_authorize_decision(db: Session, request, result) -> None:
    """Auto-log an authorize decision to the audit trail.

    Called by the authorize route after every policy evaluation so that
    the audit table stays in sync with actual usage.  This is fire-and-forget:
    errors are swallowed to avoid breaking the authorize response.

    Observe-mode denials are logged with ``policy_decision='observe_deny'``
    so they are distinguishable from real allows and real denies.
    """
    try:
        now = datetime.now(timezone.utc)
        prev_hash = _get_last_entry_hash(db)

        resource = getattr(request, "resource", "") or ""
        action_str = request.action
        if resource:
            action_str = f"{request.action} {resource}"

        # Determine the audit decision: if the result carries an observation,
        # the policy engine allowed it in observe mode — record as observe_deny.
        observation = getattr(result, "observation", None)
        audit_decision = "observe_deny" if observation else result.decision

        outputs = {
            "reason": result.reason,
            "matched_policy": getattr(result, "matched_policy", None),
        }
        if observation:
            outputs["observation"] = observation

        context = getattr(request, "context", None)
        entry_data = {
            "agent_id": request.agent_id,
            "timestamp": now.isoformat(),
            "action": action_str,
            "inputs": {"resource": resource, "context": context} if (resource or context) else None,
            "outputs": outputs,
            "policy_decision": audit_decision,
            "prev_hash": prev_hash,
        }
        signature = sign_data(entry_data)

        entry = AuditEntry(
            agent_id=request.agent_id,
            timestamp=now,
            action=action_str,
            inputs=json.dumps(entry_data["inputs"]) if entry_data["inputs"] else None,
            outputs=json.dumps(entry_data["outputs"]),
            policy_decision=audit_decision,
            signature=signature,
            prev_hash=prev_hash,
        )
        db.add(entry)
        db.commit()
        METRICS.inc("audit_entries_total")

        # Dispatch to webhook / file sink (fire-and-forget)
        try:
            db.refresh(entry)
            export_evt = _entry_to_export(entry)
            from leash.server.audit.dispatcher import dispatch_audit_event
            dispatch_audit_event(export_evt.model_dump_json())
        except Exception:
            pass  # never let dispatch break the response
    except Exception:
        # Never let audit logging break the authorize response
        db.rollback()


def _get_last_entry_hash(db: Session) -> Optional[str]:
    """Return the SHA-256 hash of the most recent audit entry, or None.

    This forms the backbone of the tamper-evident hash chain: each new
    entry records the hash of its predecessor.  If an entry is deleted
    or modified, the chain breaks and the gap is detectable.
    """
    last = (
        db.query(AuditEntry)
        .order_by(AuditEntry.id.desc())
        .first()
    )
    if last is None:
        return None
    chain_data = {
        "id": last.id,
        "agent_id": last.agent_id,
        "timestamp": last.timestamp.isoformat() if last.timestamp else "",
        "action": last.action,
        "policy_decision": last.policy_decision,
        "signature": last.signature,
    }
    return hash_data(chain_data)


def create_audit_entry(db: Session, req: AuditCreateRequest) -> AuditEntryResponse:
    """Append a new signed audit entry with a hash-chain link."""
    now = datetime.now(timezone.utc)

    # Hash chain: link to previous entry
    prev_hash = _get_last_entry_hash(db)

    entry_data = {
        "agent_id": req.agent_id,
        "timestamp": now.isoformat(),
        "action": req.action,
        "inputs": req.inputs,
        "outputs": req.outputs,
        "policy_decision": req.policy_decision,
        "prev_hash": prev_hash,
    }
    signature = sign_data(entry_data)

    entry = AuditEntry(
        agent_id=req.agent_id,
        timestamp=now,
        action=req.action,
        inputs=json.dumps(req.inputs) if req.inputs else None,
        outputs=json.dumps(req.outputs) if req.outputs else None,
        policy_decision=req.policy_decision,
        signature=signature,
        prev_hash=prev_hash,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    # Dispatch to webhook / file sink (fire-and-forget)
    try:
        export_evt = _entry_to_export(entry)
        from leash.server.audit.dispatcher import dispatch_audit_event
        dispatch_audit_event(export_evt.model_dump_json())
    except Exception:
        pass

    return _to_response(entry)


def get_audit_entries(
    db: Session,
    agent_id: Optional[str] = None,
    decision: Optional[str] = None,
    action: Optional[str] = None,
    offset: int = 0,
    limit: int = 50,
) -> AuditListResponse:
    """Retrieve audit entries with optional filters and pagination."""
    query = db.query(AuditEntry)
    if agent_id:
        query = query.filter(AuditEntry.agent_id == agent_id)
    if decision:
        query = query.filter(AuditEntry.policy_decision == decision)
    if action:
        query = query.filter(AuditEntry.action == action)

    total = query.count()
    entries = (
        query.order_by(AuditEntry.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return AuditListResponse(
        entries=[_to_response(e) for e in entries],
        total=total,
        offset=offset,
        limit=limit,
    )


def _to_response(entry: AuditEntry) -> AuditEntryResponse:
    return AuditEntryResponse(
        id=entry.id,
        agent_id=entry.agent_id,
        timestamp=entry.timestamp,
        action=entry.action,
        inputs=json.loads(entry.inputs) if entry.inputs else None,
        outputs=json.loads(entry.outputs) if entry.outputs else None,
        policy_decision=entry.policy_decision,
        signature=entry.signature,
        prev_hash=entry.prev_hash,
    )


def get_audit_summary(db: Session, top_n: int = 10) -> AuditSummaryResponse:
    """Compute aggregate stats across the entire audit log."""
    total = db.query(func.count(AuditEntry.id)).scalar() or 0
    allowed = (
        db.query(func.count(AuditEntry.id))
        .filter(AuditEntry.policy_decision == "allow")
        .scalar() or 0
    )
    denied = (
        db.query(func.count(AuditEntry.id))
        .filter(AuditEntry.policy_decision == "deny")
        .scalar() or 0
    )
    deny_rate = round(denied / total, 4) if total > 0 else 0.0

    # SQLite-friendly aggregation: group by (action, decision)
    action_stats = (
        db.query(AuditEntry.action, AuditEntry.policy_decision, func.count(AuditEntry.id))
        .group_by(AuditEntry.action, AuditEntry.policy_decision)
        .all()
    )
    action_map: dict = {}
    for action, decision, count in action_stats:
        if action not in action_map:
            action_map[action] = {"count": 0, "allowed": 0, "denied": 0}
        action_map[action]["count"] += count
        if decision == "allow":
            action_map[action]["allowed"] += count
        else:
            action_map[action]["denied"] += count

    actions = sorted(
        [ActionBreakdown(action=a, **v) for a, v in action_map.items()],
        key=lambda x: x.count,
        reverse=True,
    )

    # Most active agents
    agent_stats = (
        db.query(AuditEntry.agent_id, AuditEntry.policy_decision, func.count(AuditEntry.id))
        .group_by(AuditEntry.agent_id, AuditEntry.policy_decision)
        .all()
    )
    agent_map: dict = {}
    for agent_id, decision, count in agent_stats:
        if agent_id not in agent_map:
            agent_map[agent_id] = {"total_actions": 0, "denied_actions": 0}
        agent_map[agent_id]["total_actions"] += count
        if decision == "deny":
            agent_map[agent_id]["denied_actions"] += count

    most_active = sorted(
        [AgentActivity(agent_id=a, **v) for a, v in agent_map.items()],
        key=lambda x: x.total_actions,
        reverse=True,
    )[:top_n]

    most_denied = sorted(
        [AgentActivity(agent_id=a, **v) for a, v in agent_map.items()],
        key=lambda x: x.denied_actions,
        reverse=True,
    )[:top_n]

    return AuditSummaryResponse(
        total_entries=total,
        total_allowed=allowed,
        total_denied=denied,
        deny_rate=deny_rate,
        actions=actions,
        most_active_agents=most_active,
        most_denied_agents=most_denied,
    )


# ── JSONL export ──────────────────────────────────────────────────────────────

def _entry_to_export(entry: AuditEntry, chain_intact: bool = True) -> AuditExportEntry:
    """Convert a DB audit entry to a flat export event."""
    outputs = json.loads(entry.outputs) if entry.outputs else {}
    inputs = json.loads(entry.inputs) if entry.inputs else None

    # Extract structured fields from the stored JSON
    resource = None
    if inputs and "resource" in inputs:
        resource = inputs["resource"]

    return AuditExportEntry(
        event_id=entry.id,
        timestamp=entry.timestamp.isoformat() + "Z" if entry.timestamp else "",
        agent_id=entry.agent_id,
        action=entry.action,
        resource=resource,
        decision=entry.policy_decision,
        matched_policy=outputs.get("matched_policy"),
        reason=outputs.get("reason"),
        observation=outputs.get("observation"),
        inputs=inputs,
        outputs=outputs,
        signature=entry.signature,
        prev_hash=entry.prev_hash,
        chain_intact=chain_intact,
    )


def export_audit_entries(
    db: Session,
    *,
    since: Optional[datetime] = None,
    agent_id: Optional[str] = None,
    decision: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 10000,
) -> List[AuditExportEntry]:
    """Return audit entries as flat export events for JSONL output.

    Includes chain integrity verification: each entry is checked to see
    if its ``prev_hash`` matches the computed hash of the predecessor.
    """
    query = db.query(AuditEntry).order_by(AuditEntry.id.asc())

    if since:
        query = query.filter(AuditEntry.timestamp >= since)
    if agent_id:
        query = query.filter(AuditEntry.agent_id == agent_id)
    if decision:
        query = query.filter(AuditEntry.policy_decision == decision)
    if action:
        query = query.filter(AuditEntry.action == action)

    entries = query.limit(limit).all()

    results: List[AuditExportEntry] = []
    prev_computed_hash: Optional[str] = None

    for entry in entries:
        # Verify chain integrity: does this entry's prev_hash match
        # the hash we computed from the previous entry?
        if entry.prev_hash is None:
            chain_ok = True  # first entry in the chain
        elif prev_computed_hash is None:
            chain_ok = True  # first entry in our query window
        else:
            chain_ok = entry.prev_hash == prev_computed_hash

        results.append(_entry_to_export(entry, chain_intact=chain_ok))

        # Compute this entry's hash for the next iteration
        chain_data = {
            "id": entry.id,
            "agent_id": entry.agent_id,
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else "",
            "action": entry.action,
            "policy_decision": entry.policy_decision,
            "signature": entry.signature,
        }
        prev_computed_hash = hash_data(chain_data)

    return results


# ── Built-in suspicious chain patterns ────────────────────────────────────────

BUILTIN_CHAIN_PATTERNS: List[ChainPattern] = [
    ChainPattern(
        name="data-exfiltration",
        actions=["file.read*", "email.send*"],
        description="Read a file then send email — possible data exfiltration",
    ),
    ChainPattern(
        name="read-then-upload",
        actions=["file.read*", "web.*"],
        description="Read a file then make a web request — possible data leak",
    ),
    ChainPattern(
        name="recon-then-delete",
        actions=["*.read*", "*.delete*"],
        description="Read resources then delete — possible destructive recon",
    ),
    ChainPattern(
        name="credential-harvest",
        actions=["file.read*", "db.query*"],
        description="Read files then query database — possible credential use",
    ),
    ChainPattern(
        name="search-then-send",
        actions=["*search*", "email.send*"],
        description="Search then send email — possible info gathering and exfil",
    ),
    ChainPattern(
        name="read-then-execute",
        actions=["*.read*", "*.execute*"],
        description="Read then execute — possible code injection",
    ),
]


def detect_chains(
    db: Session,
    req: ChainDetectionRequest,
) -> ChainDetectionResponse:
    """Scan the audit log for suspicious multi-step action chains.

    Uses a sliding-window approach per agent: for each agent's ordered
    action sequence, check if any contiguous subsequence matches a chain
    pattern within the time window.

    Maps to OWASP ASI02 (Tool Misuse) and ASI09 (Human-Agent Trust).
    """
    patterns = req.patterns or BUILTIN_CHAIN_PATTERNS

    # Fetch recent audit entries
    query = db.query(AuditEntry).order_by(AuditEntry.timestamp.asc())
    if req.agent_id:
        query = query.filter(AuditEntry.agent_id == req.agent_id)
    entries = query.limit(req.limit).all()

    # Group entries by agent
    by_agent: dict[str, list[AuditEntry]] = {}
    for e in entries:
        by_agent.setdefault(e.agent_id, []).append(e)

    matches: list[ChainMatch] = []

    for agent_id, agent_entries in by_agent.items():
        for pattern in patterns:
            chain_len = len(pattern.actions)
            if chain_len > len(agent_entries):
                continue

            # Sliding window over this agent's entries
            for i in range(len(agent_entries) - chain_len + 1):
                window = agent_entries[i : i + chain_len]
                # Check time constraint
                t0 = window[0].timestamp
                t1 = window[-1].timestamp
                delta = (t1 - t0).total_seconds()
                if delta > req.window:
                    continue

                # Check if actions match the pattern in order
                if all(
                    fnmatch(window[j].action, pattern.actions[j])
                    for j in range(chain_len)
                ):
                    matches.append(
                        ChainMatch(
                            pattern=pattern.name,
                            agent_id=agent_id,
                            actions=[w.action for w in window],
                            timestamps=[w.timestamp for w in window],
                            window_seconds=round(delta, 2),
                        )
                    )

    return ChainDetectionResponse(
        matches=matches,
        patterns_checked=len(patterns),
        entries_scanned=len(entries),
    )


# ══════════════════════════════════════════════════════════════════════════════
# Full audit security scan — multi-check engine
# ══════════════════════════════════════════════════════════════════════════════

def _check_chain_detection(entries: List[AuditEntry], window: int) -> ScanCheckResult:
    """Check 1: Suspicious multi-step action chains."""
    patterns = BUILTIN_CHAIN_PATTERNS
    by_agent: dict[str, list[AuditEntry]] = {}
    for e in entries:
        by_agent.setdefault(e.agent_id, []).append(e)

    findings: List[ScanFinding] = []
    for agent_id, agent_entries in by_agent.items():
        for pattern in patterns:
            chain_len = len(pattern.actions)
            if chain_len > len(agent_entries):
                continue
            for i in range(len(agent_entries) - chain_len + 1):
                win = agent_entries[i : i + chain_len]
                delta = (win[-1].timestamp - win[0].timestamp).total_seconds()
                if delta > window:
                    continue
                if all(fnmatch(win[j].action, pattern.actions[j]) for j in range(chain_len)):
                    actions = [w.action for w in win]
                    findings.append(ScanFinding(
                        check="chain-detection",
                        severity="high",
                        title=pattern.name,
                        detail=f"{' → '.join(actions)} ({pattern.description})",
                        agent_id=agent_id,
                        metadata={"actions": actions, "window_seconds": round(delta, 2)},
                    ))

    return ScanCheckResult(
        check="chain-detection",
        title="Suspicious Action Chains",
        status="warn" if findings else "pass",
        findings=findings,
        summary=f"{len(findings)} chain(s) detected across {len(patterns)} patterns"
        if findings else f"No suspicious chains ({len(patterns)} patterns checked)",
    )


def _check_hash_integrity(entries: List[AuditEntry]) -> ScanCheckResult:
    """Check 2: Hash-chain integrity — detect tampered or deleted entries."""
    findings: List[ScanFinding] = []
    prev_computed_hash: Optional[str] = None

    for entry in entries:
        if entry.prev_hash is not None and prev_computed_hash is not None:
            if entry.prev_hash != prev_computed_hash:
                findings.append(ScanFinding(
                    check="hash-integrity",
                    severity="critical",
                    title="Hash chain break",
                    detail=f"Entry #{entry.id} prev_hash does not match computed hash of entry before it — possible tampering or deletion",
                    agent_id=entry.agent_id,
                    metadata={"entry_id": entry.id, "expected": prev_computed_hash, "actual": entry.prev_hash},
                ))

        # Compute hash of this entry for the next iteration
        chain_data = {
            "id": entry.id,
            "agent_id": entry.agent_id,
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else "",
            "action": entry.action,
            "policy_decision": entry.policy_decision,
            "signature": entry.signature,
        }
        prev_computed_hash = hash_data(chain_data)

    return ScanCheckResult(
        check="hash-integrity",
        title="Audit Log Integrity",
        status="fail" if findings else "pass",
        findings=findings,
        summary=f"{len(findings)} hash chain break(s) — possible tampering"
        if findings else f"Hash chain intact across {len(entries)} entries",
    )


def _check_deny_storms(entries: List[AuditEntry], window: int) -> ScanCheckResult:
    """Check 3: Deny storms — rapid bursts of denied actions from a single agent.

    A sudden spike of denials can indicate prompt injection, confused agent
    behavior, or a brute-force attempt to find allowed actions.
    """
    STORM_THRESHOLD = 5  # denials within the window to trigger

    by_agent: dict[str, list[AuditEntry]] = {}
    for e in entries:
        if e.policy_decision == "deny":
            by_agent.setdefault(e.agent_id, []).append(e)

    findings: List[ScanFinding] = []
    for agent_id, denials in by_agent.items():
        if len(denials) < STORM_THRESHOLD:
            continue
        # Sliding window: find the densest burst
        for i in range(len(denials) - STORM_THRESHOLD + 1):
            burst = denials[i : i + STORM_THRESHOLD]
            delta = (burst[-1].timestamp - burst[0].timestamp).total_seconds()
            if delta <= window:
                actions = list(dict.fromkeys(d.action for d in burst))  # unique, ordered
                findings.append(ScanFinding(
                    check="deny-storm",
                    severity="high",
                    title=f"Deny storm: {len(burst)} denials",
                    detail=f"Agent denied {len(burst)}× in {delta:.0f}s — actions: {', '.join(actions[:5])}",
                    agent_id=agent_id,
                    metadata={"deny_count": len(burst), "window_seconds": round(delta, 2), "actions": actions},
                ))
                break  # one finding per agent is enough

    return ScanCheckResult(
        check="deny-storm",
        title="Deny Storm Detection",
        status="warn" if findings else "pass",
        findings=findings,
        summary=f"{len(findings)} agent(s) with denial bursts"
        if findings else "No deny storms detected",
    )


def _check_observe_shadows(entries: List[AuditEntry]) -> ScanCheckResult:
    """Check 4: Observe-mode shadow denials — actions that would be blocked if enforced.

    Surfaces how many observe_deny decisions are piling up, grouped by agent
    and action. This helps operators decide when to flip observe → enforce.
    """
    shadows: dict[str, dict[str, int]] = {}  # agent_id -> action -> count
    total = 0

    for e in entries:
        if e.policy_decision == "observe_deny":
            shadows.setdefault(e.agent_id, {})
            shadows[e.agent_id][e.action] = shadows[e.agent_id].get(e.action, 0) + 1
            total += 1

    findings: List[ScanFinding] = []
    for agent_id, actions in shadows.items():
        top_actions = sorted(actions.items(), key=lambda x: x[1], reverse=True)[:5]
        count = sum(actions.values())
        action_list = ", ".join(f"{a} ({n}×)" for a, n in top_actions)
        findings.append(ScanFinding(
            check="observe-shadow",
            severity="medium" if count >= 10 else "low",
            title=f"{count} shadow denial(s)",
            detail=f"Would be blocked if enforced: {action_list}",
            agent_id=agent_id,
            metadata={"total": count, "actions": dict(actions)},
        ))

    return ScanCheckResult(
        check="observe-shadow",
        title="Observe-Mode Shadows",
        status="warn" if findings else "pass",
        findings=findings,
        summary=f"{total} observe-deny event(s) across {len(findings)} agent(s)"
        if findings else "No observe-mode shadow denials",
    )


def _check_permission_gaps(entries: List[AuditEntry], db: Session) -> ScanCheckResult:
    """Check 5: Permission Gap Analysis — compare actual usage against policy.

    Uses the policy engine as the source of truth, not historical behavior.
    Detects:
    - **Unused allows**: policy permits an action the agent never uses →
      over-permissioned, tighten the policy to reduce attack surface.
    - **Repeated denied probing**: agent keeps attempting actions the policy
      blocks → suspicious intent, prompt injection, or misconfiguration.
    - **Broad wildcard exposure**: agent has wide-open allow rules but
      only uses a small subset → unnecessary blast radius.

    This cannot be gamed by slowly introducing malicious actions — the
    policy is the ground truth, not past behavior.
    """
    from leash.server.policy.engine import get_effective_permissions
    from fnmatch import fnmatch as _fnm

    if not entries:
        return ScanCheckResult(
            check="permission-gaps",
            title="Permission Gap Analysis",
            status="pass",
            findings=[],
            summary="No audit entries to analyze",
        )

    # ── Collect per-agent usage from the audit log ──────────────────────
    agent_used_actions: dict[str, set[str]] = {}     # actions actually attempted
    agent_denied_actions: dict[str, dict[str, int]] = {}  # denied action → count

    for e in entries:
        agent_used_actions.setdefault(e.agent_id, set()).add(e.action)
        if e.policy_decision == "deny":
            agent_denied_actions.setdefault(e.agent_id, {})
            agent_denied_actions[e.agent_id][e.action] = \
                agent_denied_actions[e.agent_id].get(e.action, 0) + 1

    findings: List[ScanFinding] = []
    agents_checked = 0

    for agent_id in agent_used_actions:
        try:
            perms = get_effective_permissions(agent_id, db=db)
        except Exception:
            continue
        agents_checked += 1

        used = agent_used_actions[agent_id]
        denied_map = agent_denied_actions.get(agent_id, {})

        # ── Explicit allow rules the agent never used ───────────────────
        allow_rules = [p for p in perms.permissions
                       if p.effect == "allow" and p.action != "*"]
        unused_allows: list[str] = []
        for rule in allow_rules:
            # Check if any used action matches this allow rule
            if not any(_fnm(a, rule.action) for a in used):
                unused_allows.append(rule.action)

        if unused_allows:
            label = ", ".join(unused_allows[:6])
            if len(unused_allows) > 6:
                label += f" (+{len(unused_allows) - 6} more)"
            findings.append(ScanFinding(
                check="permission-gaps",
                severity="medium",
                title=f"{len(unused_allows)} unused permission(s)",
                detail=f"Allowed but never used: {label} — consider removing to reduce attack surface",
                agent_id=agent_id,
                metadata={"unused_allows": unused_allows},
            ))

        # ── Broad wildcard allows ───────────────────────────────────────
        wildcard_allows = [p for p in allow_rules if "*" in p.action]
        for wc in wildcard_allows:
            # How many distinct actions does this wildcard cover?
            matched_used = [a for a in used if _fnm(a, wc.action)]
            if len(matched_used) <= 2 and wc.action.count("*") > 0:
                findings.append(ScanFinding(
                    check="permission-gaps",
                    severity="low",
                    title=f"Broad wildcard: {wc.action}",
                    detail=f"Wildcard allows '{wc.action}' but agent only uses {len(matched_used)} matching action(s) — narrow the rule",
                    agent_id=agent_id,
                    metadata={"wildcard": wc.action, "matched_used": matched_used},
                ))

        # ── Repeated denied probing ─────────────────────────────────────
        PROBE_THRESHOLD = 3
        for action, count in denied_map.items():
            if count >= PROBE_THRESHOLD:
                findings.append(ScanFinding(
                    check="permission-gaps",
                    severity="high" if count >= 5 else "medium",
                    title=f"Repeated denied action: {action} ({count}×)",
                    detail=f"Agent attempted '{action}' {count} times and was denied every time — possible probing or prompt injection",
                    agent_id=agent_id,
                    metadata={"action": action, "deny_count": count},
                ))

    return ScanCheckResult(
        check="permission-gaps",
        title="Permission Gap Analysis",
        status="warn" if findings else "pass",
        findings=findings,
        summary=f"{len(findings)} gap(s) across {agents_checked} agent(s)"
        if findings else f"Permissions well-scoped across {agents_checked} agent(s)",
    )


def run_audit_scan(db: Session, req: AuditScanRequest) -> AuditScanResponse:
    """Run the full multi-check security scan against the audit log."""
    query = db.query(AuditEntry).order_by(AuditEntry.id.asc())
    if req.agent_id:
        query = query.filter(AuditEntry.agent_id == req.agent_id)
    entries = query.limit(req.limit).all()

    checks = [
        _check_hash_integrity(entries),
        _check_chain_detection(entries, req.window),
        _check_deny_storms(entries, req.window),
        _check_observe_shadows(entries),
        _check_permission_gaps(entries, db),
    ]

    all_findings: List[ScanFinding] = []
    for c in checks:
        all_findings.extend(c.findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        severity_counts[f.severity] += 1

    # Overall status
    if severity_counts["critical"] > 0:
        status = "critical"
    elif any(c.status != "pass" for c in checks):
        status = "warnings"
    else:
        status = "clean"

    return AuditScanResponse(
        status=status,
        checks_run=len(checks),
        total_findings=len(all_findings),
        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
        medium_count=severity_counts["medium"],
        low_count=severity_counts["low"],
        info_count=severity_counts["info"],
        entries_scanned=len(entries),
        checks=checks,
    )
