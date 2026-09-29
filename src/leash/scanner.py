"""Leash Security Surface Scanner – discover, classify, and cover MCP tool surfaces.

Connects to an MCP server via stdio, calls ``tools/list``, classifies each
tool by risk category, cross-references against loaded Leash policies,
and optionally generates a starter YAML policy.

Usage::

    # CLI (via leash.cli):
    leash scan -- npx -y @modelcontextprotocol/server-filesystem /data
    leash scan --generate-policy -- npx -y @modelcontextprotocol/server-filesystem /data
    leash scan --format json -- npx -y @modelcontextprotocol/server-filesystem /data

    # Programmatic:
    from leash.scanner import MCPScanner, classify_tools, generate_policy

    scanner = MCPScanner(["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"])
    tools = scanner.discover()
    classified = classify_tools(tools)
    policy_yaml = generate_policy(classified, agent_pattern="fs-*")

Maps to OWASP ASI:
- ASI02 (Tool Misuse) → surfaces tools that could be weaponised
- ASI03 (Identity & Privilege) → identifies policy gaps before deployment
- ASI04 (Supply Chain) → inventories the tool surface (AIBOM foundation)
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

logger = logging.getLogger("leash.scanner")


# ═══════════════════════════════════════════════════════════════════════════
# Risk classification
# ═══════════════════════════════════════════════════════════════════════════

# Pattern → (category, risk_level, description)
# Categories are matched against tool name + description (case-insensitive).
# First match wins within each category; a tool can match multiple categories.

RISK_PATTERNS: List[Dict[str, Any]] = [
    # ── Destructive (HIGH) ─────────────────────────────────────────────
    {
        "category": "destructive",
        "risk": "high",
        "patterns": [
            r"\bdelete\b", r"\bremove\b", r"\bdrop\b", r"\btruncate\b",
            r"\bpurge\b", r"\bwipe\b", r"\bdestroy\b", r"\bunlink\b",
            r"\boverwrite\b", r"\breplace\b", r"\brm\b",
        ],
        "description": "can permanently destroy or overwrite data",
    },
    # ── Execution (HIGH) ───────────────────────────────────────────────
    {
        "category": "execution",
        "risk": "high",
        "patterns": [
            r"\bexec\b", r"\bexecute\b", r"\brun\b", r"\bshell\b",
            r"\beval\b", r"\bspawn\b", r"\bcommand\b", r"\bsubprocess\b",
            r"\bbash\b", r"\bscript\b", r"\binterpreter\b",
        ],
        "description": "can execute arbitrary code or system commands",
    },
    # ── Exfiltration (HIGH) ────────────────────────────────────────────
    {
        "category": "exfiltration",
        "risk": "high",
        "patterns": [
            r"\bsend\b", r"\bemail\b", r"\bpost\b", r"\bupload\b",
            r"\bwebhook\b", r"\bpublish\b", r"\bnotif", r"\bforward\b",
            r"\btransfer\b", r"\bexport\b", r"\bsubmit\b",
        ],
        "description": "can send data to external destinations",
    },
    # ── Write / Mutate (MEDIUM) ────────────────────────────────────────
    {
        "category": "write",
        "risk": "medium",
        "patterns": [
            r"\bwrite\b", r"\bcreate\b", r"\binsert\b", r"\bupdate\b",
            r"\bpatch\b", r"\bput\b", r"\bset\b", r"\bmodify\b",
            r"\bedit\b", r"\bappend\b", r"\bmove\b", r"\brename\b",
            r"\bcopy\b",
        ],
        "description": "can create or modify data",
    },
    # ── Network (MEDIUM) ───────────────────────────────────────────────
    {
        "category": "network",
        "risk": "medium",
        "patterns": [
            r"\bfetch\b", r"\brequest\b", r"\bconnect\b", r"\bhttp\b",
            r"\bapi\b", r"\bdownload\b", r"\bsocket\b", r"\bcurl\b",
            r"\burl\b",
        ],
        "description": "can make network requests",
    },
    # ── Filesystem read (MEDIUM) ───────────────────────────────────────
    {
        "category": "filesystem",
        "risk": "medium",
        "patterns": [
            r"\bread_file\b", r"\blist_dir", r"\blist_allowed",
            r"\bdirectory\b", r"\bglob\b", r"\bfind\b",
            r"\bls\b", r"\btree\b", r"\bstat\b",
        ],
        "description": "can read files or enumerate filesystem structure",
    },
    # ── Read-only / safe (LOW) ─────────────────────────────────────────
    {
        "category": "read-only",
        "risk": "low",
        "patterns": [
            r"\bget\b", r"\bread\b", r"\bsearch\b", r"\bquery\b",
            r"\blist\b", r"\blookup\b", r"\binfo\b", r"\bshow\b",
            r"\bdescribe\b", r"\bstatus\b", r"\bcount\b", r"\bexist",
            r"\bping\b", r"\bversion\b", r"\bhelp\b",
        ],
        "description": "read-only, informational, or safe operations",
    },
]


@dataclass
class ToolRisk:
    """Risk assessment for a single MCP tool."""
    name: str
    description: str
    risk: str  # "high", "medium", "low", "unknown"
    categories: List[str] = field(default_factory=list)
    risk_reason: str = ""
    input_schema: Dict[str, Any] = field(default_factory=dict)
    has_policy_coverage: bool = False
    matching_policies: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete scan result for an MCP server."""
    target: str
    tools_discovered: int
    tools: List[ToolRisk]
    high_risk: List[ToolRisk] = field(default_factory=list)
    medium_risk: List[ToolRisk] = field(default_factory=list)
    low_risk: List[ToolRisk] = field(default_factory=list)
    unknown_risk: List[ToolRisk] = field(default_factory=list)
    policy_coverage: float = 0.0  # 0.0 – 1.0
    covered_count: int = 0
    uncovered_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a JSON-friendly dict (AIBOM output)."""
        return {
            "target": self.target,
            "tools_discovered": self.tools_discovered,
            "policy_coverage": round(self.policy_coverage * 100, 1),
            "covered_count": self.covered_count,
            "uncovered_count": self.uncovered_count,
            "tools": [asdict(t) for t in self.tools],
            "high_risk": [asdict(t) for t in self.high_risk],
            "medium_risk": [asdict(t) for t in self.medium_risk],
            "low_risk": [asdict(t) for t in self.low_risk],
            "unknown_risk": [asdict(t) for t in self.unknown_risk],
        }


def classify_tool(name: str, description: str, input_schema: Optional[Dict] = None) -> ToolRisk:
    """Classify a single tool by name + description against risk patterns.

    A tool can match multiple categories (e.g. ``move_file`` is both
    ``write`` and ``destructive``).  The highest-severity match wins.
    """
    text = f"{name} {description}".lower()
    matched_categories: List[str] = []
    highest_risk = "low"
    reasons: List[str] = []

    risk_order = {"high": 3, "medium": 2, "low": 1, "unknown": 0}

    for rp in RISK_PATTERNS:
        for pat in rp["patterns"]:
            if re.search(pat, text):
                cat = rp["category"]
                if cat not in matched_categories:
                    matched_categories.append(cat)
                    reasons.append(f"{cat}: {rp['description']}")
                if risk_order.get(rp["risk"], 0) > risk_order.get(highest_risk, 0):
                    highest_risk = rp["risk"]
                break  # first pattern match in this category is enough

    if not matched_categories:
        return ToolRisk(
            name=name,
            description=description,
            risk="unknown",
            categories=["unclassified"],
            risk_reason="Could not classify automatically — manual review recommended",
            input_schema=input_schema or {},
        )

    return ToolRisk(
        name=name,
        description=description,
        risk=highest_risk,
        categories=matched_categories,
        risk_reason="; ".join(reasons),
        input_schema=input_schema or {},
    )


def classify_tools(tools: List[Dict[str, Any]]) -> List[ToolRisk]:
    """Classify a list of MCP tool manifests."""
    return [
        classify_tool(
            t.get("name", "unknown"),
            t.get("description", ""),
            t.get("inputSchema"),
        )
        for t in tools
    ]


def analyze_policy_coverage(
    classified_tools: List[ToolRisk],
    agent_id: str = "",
    agent_name: str = "",
    policies: Optional[List[Dict[str, Any]]] = None,
) -> ScanResult:
    """Cross-reference classified tools against Leash policies.

    For each tool, checks whether any policy has a rule matching the tool's
    action name.  *policies* defaults to the local policies directory.
    Returns a :class:`ScanResult` with coverage statistics.
    """
    from leash.engine import load_policy_dir, match_agent as _match_agent, match_pattern as _match_action

    if policies is None:
        from leash import paths

        policies = load_policy_dir(paths.policies_dir())

    for tool in classified_tools:
        matching_policy_names: List[str] = []

        for policy in policies:
            # If agent is specified, only consider policies that match
            if agent_id or agent_name:
                if not _match_agent(policy, agent_id, agent_name):
                    continue

            for rule in policy.get("rules", []):
                rule_action = rule.get("action", "")
                if _match_action(rule_action, tool.name):
                    pname = policy.get("name", "unnamed")
                    if pname not in matching_policy_names:
                        matching_policy_names.append(pname)

        tool.has_policy_coverage = len(matching_policy_names) > 0
        tool.matching_policies = matching_policy_names

    # Build the ScanResult
    high = [t for t in classified_tools if t.risk == "high"]
    medium = [t for t in classified_tools if t.risk == "medium"]
    low = [t for t in classified_tools if t.risk == "low"]
    unknown = [t for t in classified_tools if t.risk == "unknown"]
    covered = sum(1 for t in classified_tools if t.has_policy_coverage)
    total = len(classified_tools) or 1

    return ScanResult(
        target="",
        tools_discovered=len(classified_tools),
        tools=classified_tools,
        high_risk=high,
        medium_risk=medium,
        low_risk=low,
        unknown_risk=unknown,
        policy_coverage=covered / total,
        covered_count=covered,
        uncovered_count=len(classified_tools) - covered,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Policy generation
# ═══════════════════════════════════════════════════════════════════════════

def generate_policy(
    scan: ScanResult,
    *,
    policy_name: str = "auto-scan-policy",
    agent_pattern: str = '"*"',
    include_observe: bool = True,
) -> str:
    """Generate a starter YAML policy from a scan result.

    Strategy:
    - **High-risk** tools → ``deny``
    - **Medium-risk** tools → ``observe`` (if include_observe) else ``deny``
    - **Low-risk** tools → ``allow``
    - **Unknown** tools → ``deny`` (safe default)
    """
    lines = [
        "# Auto-generated by Leash Security Surface Scanner",
        f"# Target: {scan.target}",
        f"# Tools discovered: {scan.tools_discovered}",
        f"# Coverage before this policy: {scan.policy_coverage * 100:.0f}%",
        "#",
        "# Review and customise before deploying in enforce mode.",
        "",
        f"name: {policy_name}",
    ]

    # If there are medium-risk tools and we're using observe mode,
    # start the whole policy in observe mode for safety
    if include_observe and scan.medium_risk:
        lines.append("mode: observe")

    lines += [
        "priority: 10",
        "agents:",
        f"  - {agent_pattern}",
        "rules:",
    ]

    def _add_rule(tool: ToolRisk, effect: str, note: str) -> None:
        lines.append(f'  - action: "{tool.name}"')
        lines.append(f"    effect: {effect}")
        reason = f"{note} ({', '.join(tool.categories)})"
        lines.append(f'    reason: "{reason}"')

    # High risk → deny
    if scan.high_risk:
        lines.append("  # ── HIGH RISK: deny ────────────────────────────────────")
        for t in scan.high_risk:
            _add_rule(t, "deny", "High-risk tool — blocked by default")

    # Medium risk → observe (or deny)
    if scan.medium_risk:
        label = "observe-mode deny" if include_observe else "deny"
        lines.append(f"  # ── MEDIUM RISK: {label} ─────────────────────────────")
        for t in scan.medium_risk:
            _add_rule(t, "deny", "Medium-risk tool — review before allowing")

    # Low risk → allow
    if scan.low_risk:
        lines.append("  # ── LOW RISK: allow ───────────────────────────────────")
        for t in scan.low_risk:
            _add_rule(t, "allow", "Low-risk tool — allowed")

    # Unknown → deny
    if scan.unknown_risk:
        lines.append("  # ── UNKNOWN: deny (manual review needed) ──────────────")
        for t in scan.unknown_risk:
            _add_rule(t, "deny", "Unclassified tool — manual review required")

    # Catch-all
    lines.append("  # ── Catch-all ─────────────────────────────────────────")
    lines.append('  - action: "*"')
    lines.append("    effect: deny")
    lines.append('    reason: "Catch-all deny for undeclared actions"')

    return "\n".join(lines) + "\n"


# ═══════════════════════════════════════════════════════════════════════════
# MCP server connection
# ═══════════════════════════════════════════════════════════════════════════

class MCPScanner:
    """Connect to an MCP server and discover its tool surface.

    Launches the MCP server as a subprocess, sends the JSON-RPC
    ``initialize`` + ``tools/list`` handshake, captures the response,
    and shuts down.  Does NOT proxy traffic — this is discovery-only.
    """

    def __init__(self, upstream_cmd: List[str], timeout: float = 30.0):
        self.upstream_cmd = upstream_cmd
        self.timeout = timeout
        self._proc: Optional[subprocess.Popen] = None

    def discover(self) -> List[Dict[str, Any]]:
        """Launch the MCP server, discover tools, and return the tool list.

        Returns a list of tool manifests (name, description, inputSchema).
        Raises RuntimeError if the server fails to respond.
        """
        try:
            self._proc = subprocess.Popen(
                self.upstream_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"Cannot start MCP server: {' '.join(self.upstream_cmd)} — {exc}"
            ) from exc

        try:
            # Step 1: Send initialize request
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "leash-scanner", "version": "0.1.0"},
                },
            }
            self._send(init_req)

            # Read the initialize response
            init_resp = self._read_response(expected_id=1)
            if init_resp is None:
                raise RuntimeError("MCP server did not respond to initialize")

            # Step 2: Send initialized notification
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

            # Step 3: Send tools/list request
            tools_req = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            }
            self._send(tools_req)

            # Read the tools/list response
            tools_resp = self._read_response(expected_id=2)
            if tools_resp is None:
                raise RuntimeError("MCP server did not respond to tools/list")

            tools = tools_resp.get("result", {}).get("tools", [])
            logger.info("Discovered %d tools from %s", len(tools), " ".join(self.upstream_cmd))
            return tools

        finally:
            self._shutdown()

    def _send(self, msg: dict) -> None:
        """Send a JSON-RPC message to the MCP server."""
        assert self._proc and self._proc.stdin
        data = json.dumps(msg) + "\n"
        self._proc.stdin.write(data.encode("utf-8"))
        self._proc.stdin.flush()

    def _read_response(self, expected_id: int) -> Optional[dict]:
        """Read lines from the MCP server until we get the expected response ID."""
        assert self._proc and self._proc.stdout
        deadline = time.monotonic() + self.timeout

        while time.monotonic() < deadline:
            # Use a short select-like timeout per line
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            try:
                line = self._proc.stdout.readline()
            except Exception:
                break

            if not line:
                break

            decoded = line.decode("utf-8", errors="replace").strip()
            if not decoded:
                continue

            try:
                msg = json.loads(decoded)
            except json.JSONDecodeError:
                continue

            # Skip notifications (no id)
            if msg.get("id") == expected_id:
                return msg

        return None

    def _shutdown(self) -> None:
        """Terminate the MCP server subprocess."""
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None


# ═══════════════════════════════════════════════════════════════════════════
# Formatting
# ═══════════════════════════════════════════════════════════════════════════

_RISK_ICONS = {"high": "🔴", "medium": "🟡", "low": "🟢", "unknown": "⚪"}
_RISK_LABELS = {"high": "HIGH RISK", "medium": "MEDIUM RISK", "low": "LOW RISK", "unknown": "UNKNOWN"}


def format_scan_table(scan: ScanResult) -> str:
    """Format a scan result as a human-readable table for terminal display."""
    w = 66
    lines = [
        f"╔{'═' * w}╗",
        f"║  Leash Security Surface Scan{' ' * (w - 31)}║",
        f"║  Target: {scan.target[:w - 12]:<{w - 11}}║",
        f"╠{'═' * w}╣",
        f"║{' ' * w}║",
        f"║  Tools discovered: {scan.tools_discovered:<{w - 21}}║",
        f"║{' ' * w}║",
    ]

    def _section(label: str, tools: List[ToolRisk], icon: str) -> None:
        if not tools:
            return
        coverage_note = ""
        uncovered = [t for t in tools if not t.has_policy_coverage]
        if uncovered:
            coverage_note = f" — {len(uncovered)} uncovered"
        elif tools:
            coverage_note = " — all covered"

        header = f"  {icon} {label} ({len(tools)} tool{'s' if len(tools) != 1 else ''}{coverage_note})"
        lines.append(f"║{header:<{w}}║")
        for t in tools:
            cov = "✔" if t.has_policy_coverage else "✘"
            desc_max = w - len(t.name) - 12
            desc = t.description[:desc_max] if t.description else ""
            tool_line = f"    {cov} {t.name:<20s} — {desc}"
            lines.append(f"║{tool_line:<{w}}║")
        lines.append(f"║{' ' * w}║")

    _section("HIGH RISK", scan.high_risk, "🔴")
    _section("MEDIUM RISK", scan.medium_risk, "🟡")
    _section("LOW RISK", scan.low_risk, "🟢")
    _section("UNKNOWN", scan.unknown_risk, "⚪")

    pct = f"{scan.policy_coverage * 100:.0f}%"
    cov_line = f"  Policy coverage: {pct} ({scan.covered_count}/{scan.tools_discovered} tools have matching rules)"
    lines.append(f"║{cov_line:<{w}}║")
    lines.append(f"║{' ' * w}║")
    lines.append(f"╚{'═' * w}╝")

    if scan.uncovered_count > 0:
        lines.append("")
        lines.append(
            "  💡 Run with --generate-policy to create a starter policy "
            "covering all discovered tools."
        )

    return "\n".join(lines)
