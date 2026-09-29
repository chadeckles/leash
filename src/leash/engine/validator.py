"""Policy YAML schema validation.

Validates that a policy YAML file conforms to Leash's expected structure.
Used by the CLI ``leash policy validate`` command and can be imported
directly for programmatic use.

Usage::

    from leash.engine import validate_policy_yaml, validate_policy_file
    errors = validate_policy_file("~/.leash/policies/email_agent.yaml")
    if errors:
        for e in errors:
            print(f"  ✘ {e}")
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import yaml


# ── Known fields and their types ───────────────────────────────────────────

_VALID_EFFECTS = {"allow", "deny"}
_VALID_MODES = {"enforce", "observe"}
_VALID_TOP_KEYS = {"name", "description", "priority", "agents", "rules", "owasp", "mode"}
_VALID_RULE_KEYS = {
    "action", "effect", "reason", "resource", "conditions",
    "rate_limit", "owasp",
}
_VALID_RATE_LIMIT_KEYS = {"max_calls", "window"}


def validate_policy(doc: Dict[str, Any], source: str = "<inline>") -> List[str]:
    """Validate a parsed policy document and return a list of errors.

    Parameters
    ----------
    doc:
        A parsed YAML document (dict).
    source:
        Label for error messages (e.g. filename).

    Returns
    -------
    list[str]
        Empty list means the policy is valid.
    """
    errors: List[str] = []

    if not isinstance(doc, dict):
        return [f"{source}: expected a YAML mapping, got {type(doc).__name__}"]

    # ── Top-level required fields ──
    if "name" not in doc:
        errors.append(f"{source}: missing required field 'name'")
    elif not isinstance(doc["name"], str) or not doc["name"].strip():
        errors.append(f"{source}: 'name' must be a non-empty string")

    if "rules" not in doc:
        errors.append(f"{source}: missing required field 'rules'")

    # ── Top-level unknown keys ──
    for key in doc:
        if key.startswith("_"):
            continue  # internal keys like _source
        if key not in _VALID_TOP_KEYS:
            errors.append(f"{source}: unknown top-level key '{key}' (valid: {sorted(_VALID_TOP_KEYS)})")

    # ── priority ──
    if "priority" in doc:
        p = doc["priority"]
        if not isinstance(p, int) or isinstance(p, bool):
            errors.append(f"{source}: 'priority' must be an integer, got {type(p).__name__}")
        elif p < 0:
            errors.append(f"{source}: 'priority' must be >= 0, got {p}")

    # ── mode ──
    if "mode" in doc:
        m = doc["mode"]
        if not isinstance(m, str) or m not in _VALID_MODES:
            errors.append(
                f"{source}: 'mode' must be 'enforce' or 'observe', "
                f"got '{m}'"
            )

    # ── owasp (policy-level) ──
    if "owasp" in doc:
        ow = doc["owasp"]
        if not isinstance(ow, list):
            errors.append(f"{source}: 'owasp' must be a list, got {type(ow).__name__}")
        else:
            for j, tag in enumerate(ow):
                if not isinstance(tag, str):
                    errors.append(f"{source}: owasp[{j}] must be a string, got {type(tag).__name__}")

    # ── agents ──
    if "agents" in doc:
        agents = doc["agents"]
        if not isinstance(agents, list):
            errors.append(f"{source}: 'agents' must be a list, got {type(agents).__name__}")
        elif not agents:
            errors.append(f"{source}: 'agents' is empty — policy won't match any agent")
        else:
            for i, a in enumerate(agents):
                if not isinstance(a, str):
                    errors.append(f"{source}: agents[{i}] must be a string, got {type(a).__name__}")
    else:
        errors.append(f"{source}: missing 'agents' field — policy won't match any agent")

    # ── rules ──
    rules = doc.get("rules")
    if isinstance(rules, list):
        if not rules:
            errors.append(f"{source}: 'rules' is empty — policy has no effect")

        for i, rule in enumerate(rules):
            prefix = f"{source}: rules[{i}]"

            if not isinstance(rule, dict):
                errors.append(f"{prefix}: expected a mapping, got {type(rule).__name__}")
                continue

            # Required: action
            if "action" not in rule:
                errors.append(f"{prefix}: missing required field 'action'")
            elif not isinstance(rule["action"], str) or not rule["action"].strip():
                errors.append(f"{prefix}: 'action' must be a non-empty string")

            # Required: effect
            if "effect" not in rule:
                errors.append(f"{prefix}: missing required field 'effect'")
            elif rule["effect"] not in _VALID_EFFECTS:
                errors.append(
                    f"{prefix}: 'effect' must be 'allow' or 'deny', "
                    f"got '{rule['effect']}'"
                )

            # Optional: reason (warn if missing)
            if "reason" not in rule:
                errors.append(f"{prefix}: missing 'reason' — recommended for auditability")

            # Optional: resource
            if "resource" in rule and not isinstance(rule["resource"], str):
                errors.append(f"{prefix}: 'resource' must be a string")

            # Optional: conditions
            if "conditions" in rule:
                cond = rule["conditions"]
                if not isinstance(cond, dict):
                    errors.append(f"{prefix}: 'conditions' must be a mapping, got {type(cond).__name__}")

            # Optional: rate_limit
            if "rate_limit" in rule:
                rl = rule["rate_limit"]
                if not isinstance(rl, dict):
                    errors.append(f"{prefix}: 'rate_limit' must be a mapping")
                else:
                    for rk in rl:
                        if rk not in _VALID_RATE_LIMIT_KEYS:
                            errors.append(f"{prefix}: unknown rate_limit key '{rk}'")
                    if "max_calls" not in rl:
                        errors.append(f"{prefix}: rate_limit missing 'max_calls'")
                    elif not isinstance(rl["max_calls"], int):
                        errors.append(f"{prefix}: rate_limit.max_calls must be int")
                    if "window" not in rl:
                        errors.append(f"{prefix}: rate_limit missing 'window'")
                    elif not isinstance(rl["window"], int):
                        errors.append(f"{prefix}: rate_limit.window must be int")

            # Optional: owasp
            if "owasp" in rule:
                ow = rule["owasp"]
                if not isinstance(ow, list):
                    errors.append(f"{prefix}: 'owasp' must be a list")
                else:
                    for j, tag in enumerate(ow):
                        if not isinstance(tag, str):
                            errors.append(f"{prefix}: owasp[{j}] must be a string")

            # Unknown rule keys
            for key in rule:
                if key not in _VALID_RULE_KEYS:
                    errors.append(f"{prefix}: unknown key '{key}' (valid: {sorted(_VALID_RULE_KEYS)})")

    elif rules is not None:
        errors.append(f"{source}: 'rules' must be a list, got {type(rules).__name__}")

    return errors


def validate_policy_yaml(yaml_content: str, source: str = "<inline>") -> List[str]:
    """Parse a YAML string and validate it as a Leash policy.

    Returns
    -------
    list[str]
        Empty list means the policy is valid.
    """
    try:
        doc = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        return [f"{source}: YAML parse error: {e}"]

    if doc is None:
        return [f"{source}: empty YAML document"]

    return validate_policy(doc, source)


def validate_policy_file(path: str | Path) -> List[str]:
    """Load a YAML file from disk and validate it.

    Returns
    -------
    list[str]
        Empty list means the policy is valid.
    """
    p = Path(path).expanduser()
    if not p.exists():
        return [f"{path}: file not found"]
    if p.suffix.lower() not in (".yaml", ".yml"):
        return [f"{path}: expected .yaml or .yml extension"]

    try:
        content = p.read_text()
    except OSError as e:
        return [f"{path}: read error: {e}"]

    return validate_policy_yaml(content, source=str(path))
