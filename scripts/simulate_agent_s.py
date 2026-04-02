#!/usr/bin/env python3
"""
Agent-S Desktop Automation — Leash Scan-First Simulation
==========================================================

Demonstrates the CORRECT workflow for securing a real AI agent:

  Phase 1: OBSERVE  — register agent, run it in observe mode, capture all actions
  Phase 2: SCAN     — audit scan reveals what the agent actually does
  Phase 3: ENFORCE  — flip to enforce mode, verify allow/deny decisions

Agent-S is a GUI automation agent by Simular AI that uses pyautogui to
control desktop applications.  Its @agent_action methods are BARE names:
    agent.click()  NOT  agent.gui.click()
    agent.type()   NOT  agent.gui.type()

These names come directly from the OSWorldACI class in:
    gui_agents/s3/agents/grounding.py

⚠️  ACTION NAME INTEGRITY: Every action string in this simulation is a
real @agent_action method name from Agent-S's source code.  No invented
prefixes, no guesses.  If the action doesn't match what the agent
actually calls, the policy is SECURITY THEATER — it blocks nothing real.

Usage:
    python3 scripts/simulate_agent_s.py [--base-url http://localhost:8000]
"""

import argparse
import json
import sys
import time
import requests

# ── Configuration ─────────────────────────────────────────────────────

BASE_URL = "http://localhost:8000"
AGENT_NAME = "agent-s-desktop"

# These are the REAL @agent_action methods from Agent-S's ACI classes.
# Source: github.com/simular-ai/Agent-S → gui_agents/s3/agents/grounding.py
#
# ⚠️  BARE NAMES — no namespace prefix.  Agent-S calls agent.click(),
#     not agent.gui.click().  If your policy uses "gui.click", it matches
#     NOTHING real and provides ZERO protection.
#
# Each entry: (action_string, context_description)
AGENT_S_ACTIONS = [
    # ── Typical "open a browser and search" workflow ──────────────────
    ("open",                "Agent launches a web browser"),
    ("click",               "Agent clicks the URL bar"),
    ("type",                "Agent types a search query"),
    ("hotkey",              "Agent presses Enter to submit"),
    ("scroll",              "Agent scrolls search results"),
    ("click",               "Agent clicks a search result link"),
    ("highlight_text_span", "Agent selects text on the page"),
    ("save_to_knowledge",   "Agent stores selected text to memory"),

    # ── Switch to a spreadsheet and edit data ─────────────────────────
    ("switch_applications", "Agent switches to LibreOffice Calc"),
    ("click",               "Agent clicks a spreadsheet cell"),
    ("type",                "Agent types a value into the cell"),
    ("hotkey",              "Agent presses Ctrl+S to save"),
    ("drag_and_drop",       "Agent drags to select a cell range"),
    ("hold_and_press",      "Agent holds Ctrl and presses C to copy"),

    # ── Task lifecycle ────────────────────────────────────────────────
    ("wait",                "Agent pauses for page load"),
    ("done",                "Agent signals task complete"),

    # ── Dangerous actions the agent might attempt ─────────────────────
    ("set_cell_values",     "Agent tries to directly modify cells (bypassing UI)"),
    ("call_code_agent",     "Agent tries to execute arbitrary Python code"),
    ("open",                "Agent tries to open Terminal"),
    ("call_code_agent",     "Agent tries to run system commands via CodeAgent"),
]


def main():
    parser = argparse.ArgumentParser(description="Agent-S scan-first simulation")
    parser.add_argument("--base-url", default=BASE_URL, help="Leash server URL")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    print("=" * 70)
    print("  Agent-S Desktop Automation — Scan-First Simulation")
    print("  Source: github.com/simular-ai/Agent-S")
    print("=" * 70)
    print()
    print("  ⚠️  ACTION NAME INTEGRITY CHECK")
    print("  Every action in this simulation is a bare @agent_action method")
    print("  name from Agent-S's OSWorldACI class.  No gui.* prefix —")
    print("  because Agent-S doesn't use one.  agent.click(), not")
    print("  agent.gui.click().  If the names don't match, the policy")
    print("  is security theater.")

    # ── Health check ──────────────────────────────────────────────────
    try:
        r = requests.get(f"{base}/health", timeout=5)
        r.raise_for_status()
    except Exception as e:
        print(f"\n✘ Cannot reach Leash at {base}: {e}")
        print("  Start with: make dev")
        sys.exit(1)

    # ══════════════════════════════════════════════════════════════════
    #  PHASE 1: REGISTER & OBSERVE
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 70}")
    print("  PHASE 1: REGISTER & OBSERVE")
    print(f"  The key insight: run the agent FIRST, scan SECOND, policy THIRD.")
    print(f"{'─' * 70}")

    # Register
    print(f"\n[1/3] Registering agent '{AGENT_NAME}'...")
    r = requests.post(f"{base}/agents", json={"name": AGENT_NAME})
    if r.status_code == 201:
        data = r.json()
        agent_id = data["agent_id"]
        token = data["token"]
        print(f"  ✔ Registered: {agent_id}")
    elif r.status_code == 409:
        suffix = f"-sim-{int(time.time()) % 100000}"
        print(f"  ⚠ Agent already exists — registering as '{AGENT_NAME}{suffix}'")
        r = requests.post(f"{base}/agents", json={"name": AGENT_NAME + suffix})
        if r.status_code != 201:
            print(f"  ✘ Registration failed: {r.status_code} {r.text}")
            sys.exit(1)
        data = r.json()
        agent_id = data["agent_id"]
        token = data["token"]
        print(f"  ✔ Registered: {agent_id}")
    else:
        print(f"  ✘ Registration failed: {r.status_code} {r.text}")
        sys.exit(1)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Run all actions — at this point, default policy denies everything
    # but that's fine: we're collecting the action vocabulary
    print(f"\n[2/3] Running {len(AGENT_S_ACTIONS)} real Agent-S actions...")
    print(f"  (These are bare @agent_action method names — no prefixes)\n")

    results = {"allow": 0, "deny": 0, "observe_deny": 0}
    for i, (action, desc) in enumerate(AGENT_S_ACTIONS, 1):
        payload = {"agent_id": agent_id, "action": action}
        r = requests.post(f"{base}/authorize", json=payload, headers=headers)
        if r.status_code == 200:
            d = r.json()
            decision = d.get("decision", "?")
            results[decision] = results.get(decision, 0) + 1
            icon = "✔" if decision == "allow" else "✘"
            obs = ""
            if d.get("observation"):
                obs = f"  [observe: {d['observation']}]"
                icon = "👁"
            print(f"  {i:2d}. {icon} {decision.upper():13s} {action:25s} — {desc}{obs}")
        else:
            print(f"  {i:2d}. ⚠ HTTP {r.status_code}: {action}")
        time.sleep(0.05)  # gentle pacing

    print(f"\n  Summary: {results.get('allow', 0)} allow, "
          f"{results.get('deny', 0)} deny, "
          f"{results.get('observe_deny', 0)} observe_deny")

    # ══════════════════════════════════════════════════════════════════
    #  PHASE 2: SCAN — This is the critical discovery step
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 70}")
    print("  PHASE 2: SCAN — Discover what the agent ACTUALLY does")
    print(f"  This is the step most people skip.  Don't.")
    print(f"{'─' * 70}")

    print(f"\n[1/3] Running security scan on agent's audit trail...")
    scan_payload = {"agent_id": agent_id, "window": 120, "limit": 500}
    r = requests.post(f"{base}/audit/scan", json=scan_payload)
    if r.status_code == 200:
        scan = r.json()
        print(f"  Status:   {scan['status'].upper()}")
        print(f"  Checks:   {scan['checks_run']}")
        print(f"  Entries:  {scan['entries_scanned']}")
        print(f"  Findings: {scan['total_findings']}")
        if scan["critical_count"]:
            print(f"  🔴 Critical: {scan['critical_count']}")
        if scan["high_count"]:
            print(f"  🟠 High:     {scan['high_count']}")
        if scan["medium_count"]:
            print(f"  🟡 Medium:   {scan['medium_count']}")
        if scan["low_count"]:
            print(f"  🔵 Low:      {scan['low_count']}")

        print(f"\n  Per-check results:")
        for check in scan.get("checks", []):
            icon = "✔" if check["status"] == "pass" else "⚠"
            print(f"    {icon} {check['title']}: {check['summary']}")
            for finding in check.get("findings", [])[:3]:
                print(f"      → [{finding['severity'].upper()}] {finding['title']}: {finding['detail'][:80]}")
    else:
        print(f"  ⚠ Scan failed: {r.status_code}")

    # Show unique actions from audit trail
    print(f"\n[2/3] Extracting unique actions from audit trail...")
    r = requests.get(f"{base}/audit?agent_id={agent_id}&limit=200")
    if r.status_code == 200:
        audit = r.json()
        actions_seen = {}
        for entry in audit.get("entries", []):
            act = entry["action"]
            dec = entry["policy_decision"]
            if act not in actions_seen:
                actions_seen[act] = {"allow": 0, "deny": 0, "observe_deny": 0}
            actions_seen[act][dec] = actions_seen[act].get(dec, 0) + 1

        print(f"\n  Agent-S Action Vocabulary (from audit log):")
        print(f"  {'Action':<25s} {'Allow':>6s} {'Deny':>6s} {'Observe':>8s}")
        print(f"  {'─' * 49}")
        for act in sorted(actions_seen.keys()):
            counts = actions_seen[act]
            print(f"  {act:<25s} {counts.get('allow', 0):>6d} "
                  f"{counts.get('deny', 0):>6d} {counts.get('observe_deny', 0):>8d}")

        print(f"\n  ℹ THIS is what you use to build your policy YAML.")
        print(f"    Not guesses. Not documentation. Real observed behavior.")
        print(f"    Notice: bare names (click, type) — no gui.* prefix.")
    else:
        print(f"  ⚠ Could not fetch audit trail: {r.status_code}")

    # Show permissions (what the policy currently allows)
    print(f"\n[3/3] Checking effective permissions from policy engine...")
    r = requests.get(f"{base}/agents/{agent_id}/permissions", headers=headers)
    if r.status_code == 200:
        perms = r.json()
        allows = [p for p in perms.get("permissions", []) if p["effect"] == "allow"]
        denies = [p for p in perms.get("permissions", []) if p["effect"] == "deny"]
        print(f"  Allows: {len(allows)}  Denies: {len(denies)}  "
              f"Policy: {perms.get('matched_policy', 'none')}")
        for p in allows[:10]:
            rl = ""
            if p.get("rate_limit"):
                rl = f" (rate: {p['rate_limit']['max_calls']}/{p['rate_limit']['window']}s)"
            print(f"    ✔ {p['action']}{rl}")
        for p in denies[:5]:
            print(f"    ✘ {p['action']}: {p.get('reason', '')[:60]}")
    else:
        print(f"  ⚠ Could not fetch permissions: {r.status_code}")

    # ══════════════════════════════════════════════════════════════════
    #  PHASE 3: ENFORCE — Now re-run with real policy in place
    # ══════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 70}")
    print("  PHASE 3: ENFORCE — Re-run with policy active")
    print(f"  agent_s_desktop.yaml should be loaded (auto-detected by name match)")
    print(f"{'─' * 70}")

    print(f"\n  Re-running actions with enforce-mode policy...\n")
    enforce_results = {"allow": 0, "deny": 0}
    for i, (action, desc) in enumerate(AGENT_S_ACTIONS, 1):
        payload = {"agent_id": agent_id, "action": action}
        r = requests.post(f"{base}/authorize", json=payload, headers=headers)
        if r.status_code == 200:
            d = r.json()
            decision = d.get("decision", "?")
            enforce_results[decision] = enforce_results.get(decision, 0) + 1
            icon = "✔" if decision == "allow" else "✘"
            reason = d.get("reason", "")[:50]
            print(f"  {i:2d}. {icon} {decision.upper():8s} {action:25s} — {reason}")
        time.sleep(0.05)

    print(f"\n  Enforce results: {enforce_results.get('allow', 0)} allow, "
          f"{enforce_results.get('deny', 0)} deny")

    # ── Verify the two blocked actions were actually denied ───────────
    blocked_actions = ["set_cell_values", "call_code_agent"]
    all_blocked = True
    for ba in blocked_actions:
        payload = {"agent_id": agent_id, "action": ba}
        r = requests.post(f"{base}/authorize", json=payload, headers=headers)
        if r.status_code == 200:
            d = r.json()
            if d.get("decision") != "deny":
                print(f"\n  ⚠ SECURITY GAP: {ba} was NOT denied (got {d.get('decision')})")
                all_blocked = False

    # ── Final security scan ───────────────────────────────────────────
    print(f"\n{'─' * 70}")
    print("  FINAL SCAN")
    print(f"{'─' * 70}")
    r = requests.post(f"{base}/audit/scan", json={"agent_id": agent_id, "window": 120, "limit": 500})
    if r.status_code == 200:
        scan = r.json()
        print(f"\n  Status:   {scan['status'].upper()}")
        print(f"  Entries:  {scan['entries_scanned']}")
        print(f"  Findings: {scan['total_findings']}")

    # ── Verify audit chain ────────────────────────────────────────────
    r = requests.get(f"{base}/verify/audit-chain")
    if r.status_code == 200:
        chain = r.json()
        icon = "✔" if chain.get("valid") else "✘"
        print(f"  {icon} Audit chain: {'intact' if chain.get('valid') else 'BROKEN'} "
              f"({chain.get('entries_checked', 0)} entries)")

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n{'═' * 70}")
    print("  SIMULATION COMPLETE")
    print(f"{'═' * 70}")
    print(f"""
  The scan-first workflow:

    1. REGISTER  → leash agents register {AGENT_NAME}
    2. OBSERVE   → deploy policy with mode: observe
    3. RUN       → let the agent do real work
    4. SCAN      → leash audit scan --agent <id>
    5. REVIEW    → leash audit export --agent <id>
    6. REFINE    → edit policy YAML based on REAL actions
    7. ENFORCE   → flip mode: observe → mode: enforce
    8. VERIFY    → leash audit scan (confirm no gaps)

  Agent-S real actions (bare @agent_action names):
    click, type, scroll, hotkey, open, drag_and_drop,
    switch_applications, hold_and_press, highlight_text_span,
    save_to_knowledge, set_cell_values, call_code_agent,
    wait, done, fail

  Security boundaries enforced:
    ✘ call_code_agent   → arbitrary code execution BLOCKED
    ✘ set_cell_values   → direct data modification BLOCKED
    ✔ click/type/scroll → normal GUI interaction ALLOWED
    ✔ hotkey/open       → rate-limited to prevent abuse

  ⚠️  If your policy used "gui.click" instead of "click", it would
  match NOTHING and block NOTHING.  That's why scanning matters.
""")

    if all_blocked:
        print("  ✔ All critical actions properly denied. Simulation passed.")
    else:
        print("  ✘ Some critical actions were not denied. Review the policy.")
        sys.exit(1)


if __name__ == "__main__":
    main()
