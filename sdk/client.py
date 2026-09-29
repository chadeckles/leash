"""Leash SDK – wraps the authorize → execute → audit cycle in a decorator.

Usage::

    from sdk import LeashAgent

    agent = LeashAgent("http://localhost:8000", name="email-bot")

    @agent.tool("email.read")
    def read_inbox(mailbox: str):
        return gmail.read(mailbox)

    @agent.tool("email.send")
    def send_reply(to: str, body: str):
        return gmail.send(to, body)

    # Call as normal – Leash checks permission automatically:
    result = read_inbox("user@example.com")

One-line wrapping for existing tool lists::

    # Wrap any list of callables:
    guarded = agent.guard([search, calculator, wiki])

    # Or wrap LangChain tools:
    guarded = agent.guard(langchain_tools)
"""

from __future__ import annotations

import functools
import json
import logging
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

logger = logging.getLogger("leash.sdk")


class LeashDenied(PermissionError):
    """Raised when Leash denies an action."""

    def __init__(self, action: str, reason: str, response: dict):
        self.action = action
        self.reason = reason
        self.response = response
        self.matched_policy = response.get("matched_policy")
        self.matched_rule = response.get("matched_rule")
        parts = [f"Leash denied '{action}': {reason}"]
        if self.matched_policy:
            parts.append(f"(policy={self.matched_policy}")
            if self.matched_rule:
                parts[-1] += f", rule={self.matched_rule})"
            else:
                parts[-1] += ")"
        super().__init__(" ".join(parts))


class LeashRevoked(LeashDenied):
    """Raised when the server reports this agent's token has been revoked.

    The SDK deliberately does **not** re-register in this case — doing so
    would let a revoked agent mint itself a fresh identity.  An operator
    must re-register or rotate the agent.
    """


_REVOKED_MARKER = "Token has been revoked"


def _is_revoked(resp: httpx.Response) -> bool:
    try:
        detail = resp.json().get("detail", "")
    except Exception:
        return False
    return isinstance(detail, str) and detail.startswith(_REVOKED_MARKER)


class LeashAgent:
    """Client that registers with Leash and wraps tool functions.

    Parameters
    ----------
    base_url:
        Leash server URL (e.g. ``http://localhost:8000``).
    name:
        Human-readable agent name used for registration.
    vendor:
        Optional vendor label (e.g. ``"openai"``, ``"anthropic"``).
    agent_type:
        Optional type label (e.g. ``"coding"``, ``"research"``).
    tags:
        Optional list of tags for grouping.
    token_file:
        Path to cache the agent identity on disk.  Pass ``None`` to skip
        caching (useful in tests or ephemeral environments).
    auto_register:
        If ``True`` (default), the agent registers with Leash on first
        use.  Set to ``False`` and call :meth:`connect` manually if you
        need more control.
    fail_closed:
        If ``True`` (default), actions are **denied** when Leash is
        unreachable.  Set to ``False`` to allow actions when the server
        is down (fail-open).  Fail-closed is strongly recommended for
        production.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        *,
        name: str = "leash-agent",
        vendor: Optional[str] = None,
        agent_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        token_file: Optional[str | Path] = ".leash_identity.json",
        auto_register: bool = True,
        fail_closed: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.name = name
        self.vendor = vendor
        self.agent_type = agent_type
        self.tags = tags or []
        self.token_file = Path(token_file) if token_file else None
        self._auto_register = auto_register
        self.fail_closed = fail_closed

        # Populated after connect()
        self.agent_id: Optional[str] = None
        self.token: Optional[str] = None
        self._tools: Dict[str, Callable] = {}
        self._client: Optional[httpx.Client] = None

    # ── Connection / Registration ────────────────────────────────────────

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(base_url=self.base_url, timeout=30)
        return self._client

    def _headers(self) -> dict:
        if not self.token:
            raise RuntimeError("Agent not connected. Call agent.connect() first.")
        return {"Authorization": f"Bearer {self.token}"}

    def _load_cached_identity(self) -> bool:
        """Try to load a cached identity from disk."""
        if self.token_file and self.token_file.exists():
            try:
                data = json.loads(self.token_file.read_text())
                self.agent_id = data["agent_id"]
                self.token = data["token"]
                logger.info("Loaded cached identity: %s", self.agent_id)
                return True
            except (KeyError, json.JSONDecodeError):
                pass
        return False

    def _save_identity(self) -> None:
        if self.token_file and self.agent_id and self.token:
            self.token_file.parent.mkdir(parents=True, exist_ok=True)
            self.token_file.write_text(json.dumps({
                "agent_id": self.agent_id,
                "token": self.token,
                "name": self.name,
            }, indent=2))
            try:
                os.chmod(self.token_file, 0o600)
            except OSError:
                pass

    def connect(self) -> "LeashAgent":
        """Register with Leash (or load cached identity). Returns self."""
        if self._load_cached_identity():
            return self

        client = self._get_client()
        payload: Dict[str, Any] = {"name": self.name}
        if self.vendor:
            payload["vendor"] = self.vendor
        if self.agent_type:
            payload["agent_type"] = self.agent_type
        if self.tags:
            payload["tags"] = self.tags

        try:
            resp = client.post("/agents", json=payload)
            resp.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
            raise ConnectionError(
                f"Cannot reach Leash server at {self.base_url} — "
                f"is the server running? ({type(exc).__name__}: {exc})"
            ) from exc
        data = resp.json()

        self.agent_id = data["agent_id"]
        self.token = data["token"]
        self._save_identity()
        logger.info("Registered as %s (%s)", self.name, self.agent_id)
        return self

    def _ensure_connected(self) -> None:
        if not self.agent_id and self._auto_register:
            self.connect()
        if not self.agent_id:
            raise RuntimeError("Agent not connected. Call agent.connect() first.")

    def _reconnect(self, resp: Optional[httpx.Response] = None, action: str = "") -> None:
        """Silently re-register with Leash and get a fresh JWT.

        Called automatically when a 401 is received because the token
        expired or is otherwise invalid.  If the server says the token was
        **revoked**, raises :class:`LeashRevoked` instead of re-registering.
        """
        if resp is not None and _is_revoked(resp):
            reason = resp.json().get("detail", "Token has been revoked")
            logger.error("Leash token for '%s' was revoked — not re-registering", self.name)
            raise LeashRevoked(action, reason, {})
        logger.info("Token expired or invalid — auto-refreshing for '%s'", self.name)
        # Clear cached identity so connect() does a fresh registration
        self.agent_id = None
        self.token = None
        if self.token_file and self.token_file.exists():
            self.token_file.unlink(missing_ok=True)
        self.connect()

    # ── Core: authorize / audit ──────────────────────────────────────────

    def authorize(self, action: str, resource: str = "", context: Optional[Dict[str, Any]] = None) -> dict:
        """Ask Leash for permission. Returns the full response dict.

        Parameters
        ----------
        action:
            The action name (e.g. ``"email.read"``).
        resource:
            Optional resource identifier for resource-scoped rules.
        context:
            Optional ABAC context dict (e.g. ``{"user_role": "analyst"}``).
            Addresses OWASP LLM06-5 (execute in user's context).
        """
        self._ensure_connected()
        client = self._get_client()
        payload: Dict[str, Any] = {"agent_id": self.agent_id, "action": action}
        if resource:
            payload["resource"] = resource
        if context:
            payload["context"] = context
        resp = client.post("/authorize", json=payload, headers=self._headers())

        # Transparent token refresh: if the server says 401 (expired), re-register
        # and retry exactly once.  Revoked tokens raise LeashRevoked instead.
        if resp.status_code == 401:
            self._reconnect(resp, action)
            payload["agent_id"] = self.agent_id
            resp = client.post("/authorize", json=payload, headers=self._headers())

        resp.raise_for_status()
        return resp.json()

    def audit(
        self,
        action: str,
        decision: str,
        inputs: Optional[Dict[str, Any]] = None,
        outputs: Optional[Dict[str, Any]] = None,
    ) -> dict:
        """Log an action to the Leash audit trail."""
        self._ensure_connected()
        client = self._get_client()
        body = {
            "agent_id": self.agent_id,
            "action": action,
            "policy_decision": decision,
            "inputs": inputs,
            "outputs": outputs,
        }
        resp = client.post("/audit", json=body, headers=self._headers())

        # Transparent token refresh on 401 (revoked tokens raise LeashRevoked)
        if resp.status_code == 401:
            self._reconnect(resp, action)
            body["agent_id"] = self.agent_id
            resp = client.post("/audit", json=body, headers=self._headers())

        resp.raise_for_status()
        return resp.json()

    def get_audit_trail(self, limit: int = 50) -> dict:
        """Retrieve this agent's audit trail."""
        self._ensure_connected()
        client = self._get_client()
        resp = client.get(
            "/audit",
            params={"agent_id": self.agent_id, "limit": limit},
            headers=self._headers(),
        )
        resp.raise_for_status()
        return resp.json()

    # ── The decorator ────────────────────────────────────────────────────

    def tool(
        self,
        action: str,
        *,
        resource: str = "",
        context: Optional[Dict[str, Any]] = None,
        on_deny: str = "raise",
    ) -> Callable:
        """Decorator that wraps a function with Leash authorize → execute → audit.

        Parameters
        ----------
        action:
            The action name sent to Leash (e.g. ``"email.read"``).
        resource:
            Optional resource identifier for ABAC-style matching.
        context:
            Optional ABAC context dict (e.g. ``{"user_role": "analyst"}``).
            Used for attribute-based conditions in policies.
            Addresses OWASP LLM06-5.
        on_deny:
            What to do when denied.  ``"raise"`` (default) raises
            :class:`LeashDenied`.  ``"return_none"`` returns ``None``
            silently.  ``"log"`` logs a warning and returns ``None``.

        Example::

            @agent.tool("email.read")
            def read_inbox(mailbox: str):
                return gmail.read(mailbox)

            # With ABAC context:
            @agent.tool("db.query", context={"user_role": "analyst"})
            def run_query(sql: str):
                return db.execute(sql)
        """

        def decorator(func: Callable) -> Callable:
            # Track registered tools
            self._tools[action] = func

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                self._ensure_connected()

                # 1. Authorize (with fail-closed/fail-open on connectivity errors)
                try:
                    auth = self.authorize(action, resource, context=context)
                except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
                    if self.fail_closed:
                        logger.error("Leash unreachable, fail-closed denying '%s': %s", action, exc)
                        try:
                            self.audit(action, "deny", inputs=_safe_inputs(args, kwargs))
                        except Exception:
                            pass
                        if on_deny == "raise":
                            raise LeashDenied(action, f"Leash unreachable (fail-closed): {exc}", {})
                        return None
                    else:
                        logger.warning("Leash unreachable, fail-open allowing '%s': %s", action, exc)
                        # Execute without authorization — log locally
                        result = func(*args, **kwargs)
                        return result

                decision = auth.get("decision", "deny")

                if decision != "allow":
                    # Log the denied attempt
                    try:
                        self.audit(action, "deny", inputs=_safe_inputs(args, kwargs))
                    except Exception:
                        logger.warning("Failed to log denied action %s", action)

                    reason = auth.get("reason", "denied")
                    if on_deny == "raise":
                        raise LeashDenied(action, reason, auth)
                    elif on_deny == "log":
                        logger.warning("Leash denied '%s': %s", action, reason)
                    return None

                # 2. Execute
                try:
                    result = func(*args, **kwargs)
                except Exception as exc:
                    # Log the failed execution
                    try:
                        self.audit(
                            action, "allow",
                            inputs=_safe_inputs(args, kwargs),
                            outputs={"error": str(exc)},
                        )
                    except Exception:
                        logger.warning("Failed to log errored action %s", action)
                    raise

                # 3. Audit
                try:
                    self.audit(
                        action, "allow",
                        inputs=_safe_inputs(args, kwargs),
                        outputs=_safe_outputs(result),
                    )
                except Exception:
                    logger.warning("Failed to log action %s", action)

                return result

            # Attach metadata for introspection
            wrapper._leash_action = action  # type: ignore[attr-defined]
            wrapper._leash_resource = resource  # type: ignore[attr-defined]
            return wrapper

        return decorator

    @property
    def registered_tools(self) -> List[str]:
        """Return a list of action names registered via ``@agent.tool()``."""
        return list(self._tools.keys())

    # ── guard() – one-line wrapping of existing tools ────────────────────

    def guard(
        self,
        tools: List[Any],
        *,
        on_deny: str = "raise",
        action_prefix: str = "",
    ) -> List[Any]:
        """Wrap a list of existing callables or LangChain tools with Leash.

        Returns a *new* list with each tool wrapped in authorize → execute
        → audit.  The original tools are not modified.

        Supports:
        - Plain callables (uses ``func.__name__`` as the action name)
        - LangChain ``BaseTool`` objects (uses ``tool.name``)
        - Any object with ``.name`` and ``._run`` or ``.__call__``

        Parameters
        ----------
        tools:
            List of tool objects or callables to wrap.
        on_deny:
            Behaviour when denied (``"raise"``, ``"return_none"``, ``"log"``).
        action_prefix:
            Optional prefix for action names (e.g. ``"myagent."`` turns
            ``"search"`` into ``"myagent.search"``).

        Example::

            tools = agent.guard([search, calculator, wiki])
            # Each tool now checks Leash before executing.

            # With LangChain:
            tools = agent.guard(langchain_tools)
        """
        guarded: List[Any] = []
        for t in tools:
            wrapped = self._guard_single(t, on_deny=on_deny, action_prefix=action_prefix)
            guarded.append(wrapped)
        return guarded

    def _guard_single(self, tool: Any, *, on_deny: str, action_prefix: str) -> Any:
        """Wrap a single tool with Leash authorization."""
        # Detect tool type
        name = self._extract_tool_name(tool)
        action = f"{action_prefix}{name}" if action_prefix else name

        # LangChain BaseTool (has .name and ._run)
        if hasattr(tool, "_run") and hasattr(tool, "name"):
            return self._guard_langchain_tool(tool, action, on_deny)

        # Plain callable
        if callable(tool):
            wrapped = self.tool(action, on_deny=on_deny)(tool)
            return wrapped

        raise TypeError(f"Cannot guard {type(tool).__name__}: not callable and not a LangChain tool")

    def _extract_tool_name(self, tool: Any) -> str:
        """Get a usable action name from a tool."""
        # LangChain tool
        if hasattr(tool, "name"):
            return tool.name
        # Plain callable
        if callable(tool) and hasattr(tool, "__name__"):
            return tool.__name__
        return str(type(tool).__name__).lower()

    def _guard_langchain_tool(self, tool: Any, action: str, on_deny: str) -> Any:
        """Wrap a LangChain BaseTool's _run method with Leash authorization.

        Returns a copy-like wrapper that delegates to the original tool but
        intercepts ``_run`` / ``invoke`` with authorization.
        """
        import copy
        original_run = tool._run
        agent_ref = self
        self._tools[action] = original_run

        def guarded_run(*args: Any, **kwargs: Any) -> Any:
            agent_ref._ensure_connected()

            # Authorize (with fail-closed/fail-open on connectivity errors)
            try:
                auth = agent_ref.authorize(action)
            except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
                if agent_ref.fail_closed:
                    logger.error("Leash unreachable, fail-closed denying '%s': %s", action, exc)
                    try:
                        agent_ref.audit(action, "deny", inputs=_safe_inputs(args, kwargs))
                    except Exception:
                        pass
                    if on_deny == "raise":
                        raise LeashDenied(action, f"Leash unreachable (fail-closed): {exc}", {})
                    return None
                else:
                    logger.warning("Leash unreachable, fail-open allowing '%s': %s", action, exc)
                    return original_run(*args, **kwargs)

            decision = auth.get("decision", "deny")

            if decision != "allow":
                try:
                    agent_ref.audit(action, "deny", inputs=_safe_inputs(args, kwargs))
                except Exception:
                    logger.warning("Failed to log denied action %s", action)
                reason = auth.get("reason", "denied")
                if on_deny == "raise":
                    raise LeashDenied(action, reason, auth)
                elif on_deny == "log":
                    logger.warning("Leash denied '%s': %s", action, reason)
                return None

            try:
                result = original_run(*args, **kwargs)
            except Exception as exc:
                try:
                    agent_ref.audit(action, "allow", inputs=_safe_inputs(args, kwargs), outputs={"error": str(exc)})
                except Exception:
                    pass
                raise

            try:
                agent_ref.audit(action, "allow", inputs=_safe_inputs(args, kwargs), outputs=_safe_outputs(result))
            except Exception:
                logger.warning("Failed to log action %s", action)
            return result

        # Replace _run on a shallow copy so we don't mutate the original
        try:
            guarded = copy.copy(tool)
            guarded._run = guarded_run
        except Exception:
            # If copy fails, monkey-patch in place (last resort)
            tool._run = guarded_run
            guarded = tool

        return guarded

    # ── Auto-discovery ───────────────────────────────────────────────────

    def discover(
        self,
        *,
        default_effect: str = "deny",
        policy_name: Optional[str] = None,
        policy_priority: int = 0,
    ) -> dict:
        """Declare this agent's registered tools to Leash and create a
        starter policy.

        Call this *after* all ``@agent.tool()`` or ``agent.guard()`` calls
        so the full tool list is known.  Leash creates a managed policy
        with one rule per tool (defaulting to ``deny`` so the operator can
        review and flip to ``allow``).

        Parameters
        ----------
        default_effect:
            Effect for generated rules (``"deny"`` or ``"allow"``).
        policy_name:
            Name for the generated policy.  Defaults to
            ``"auto-{agent_name}"``.
        policy_priority:
            Priority for the generated policy.

        Returns
        -------
        dict
            The Leash policy API response.
        """
        self._ensure_connected()
        if not self._tools:
            logger.warning("No tools registered — nothing to discover")
            return {}

        name = policy_name or f"auto-{self.name}"
        rules_yaml = "\n".join(
            f'  - action: "{action}"\n    effect: {default_effect}\n    reason: "Auto-discovered from {self.name}"'
            for action in sorted(self._tools.keys())
        )
        yaml_content = (
            f'agents:\n  - "{self.agent_id}"\n'
            f"rules:\n{rules_yaml}\n"
            f'  - action: "*"\n    effect: deny\n    reason: "Catch-all deny for undeclared actions"'
        )

        client = self._get_client()
        resp = client.post("/policies/managed", json={
            "name": name,
            "priority": policy_priority,
            "yaml_content": yaml_content,
        }, headers=self._headers())

        if resp.status_code == 409:
            logger.info("Policy '%s' already exists — skipping creation", name)
            return {"status": "exists", "name": name}

        resp.raise_for_status()
        logger.info("Created auto-discovery policy '%s' with %d tools", name, len(self._tools))
        return resp.json()

    # ── Cleanup ──────────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> "LeashAgent":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        status = f"connected={self.agent_id}" if self.agent_id else "disconnected"
        tools = ", ".join(self._tools) if self._tools else "none"
        return f"<LeashAgent name={self.name!r} {status} tools=[{tools}]>"


# ── Helpers ──────────────────────────────────────────────────────────────

def _safe_inputs(args: tuple, kwargs: dict) -> Optional[Dict[str, Any]]:
    """Best-effort serialisation of function arguments for audit logging."""
    try:
        result: Dict[str, Any] = {}
        if args:
            result["args"] = [_to_json_safe(a) for a in args]
        if kwargs:
            result.update({k: _to_json_safe(v) for k, v in kwargs.items()})
        return result or None
    except Exception:
        return None


def _safe_outputs(value: Any) -> Optional[Dict[str, Any]]:
    """Best-effort serialisation of a return value for audit logging."""
    if value is None:
        return None
    try:
        return {"result": _to_json_safe(value)}
    except Exception:
        return {"result": str(value)}


def _to_json_safe(obj: Any) -> Any:
    """Convert an object to something JSON-serialisable."""
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    if isinstance(obj, (list, tuple)):
        return [_to_json_safe(i) for i in obj]
    if isinstance(obj, dict):
        return {str(k): _to_json_safe(v) for k, v in obj.items()}
    return str(obj)
