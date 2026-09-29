"""Audit event dispatcher – webhook delivery and JSONL file sink.

Dispatches audit events to external systems in real time:

- **Webhook:** POST every audit event as JSON to ``LEASH_WEBHOOK_URL``
- **File sink:** Append every audit event as one JSONL line to ``LEASH_AUDIT_SINK``

Both are fire-and-forget: failures are logged but never block the
authorize response or audit write.  The webhook uses a background
thread with a simple retry (1 retry after 2s delay).
"""

from __future__ import annotations

import logging
import threading

logger = logging.getLogger("leash.audit.dispatcher")


def _post_webhook(url: str, payload: str) -> None:
    """POST JSON payload to the webhook URL with one retry."""
    import httpx

    for attempt in range(2):
        try:
            resp = httpx.post(
                url,
                content=payload,
                headers={"Content-Type": "application/json"},
                timeout=5.0,
            )
            if resp.is_success:
                return
            logger.warning(
                "Webhook %s returned %d (attempt %d)",
                url, resp.status_code, attempt + 1,
            )
        except Exception as exc:
            logger.warning(
                "Webhook %s failed (attempt %d): %s",
                url, attempt + 1, exc,
            )
        if attempt == 0:
            import time
            time.sleep(2)


def _append_file(path: str, line: str) -> None:
    """Append a single line to the JSONL sink file."""
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
            if not line.endswith("\n"):
                f.write("\n")
    except OSError as exc:
        logger.warning("Audit sink %s write failed: %s", path, exc)


def dispatch_audit_event(event_json: str) -> None:
    """Send an audit event to all configured external sinks.

    Called from the audit service after every entry is committed.
    Both webhook and file sink are optional — if neither env var is set,
    this is a no-op.

    Parameters
    ----------
    event_json:
        A JSON string representing one :class:`AuditExportEntry`.
    """
    from leash.server.core.config import WEBHOOK_URL, AUDIT_SINK

    if WEBHOOK_URL:
        # Fire in background thread so we never block the response
        t = threading.Thread(
            target=_post_webhook,
            args=(WEBHOOK_URL, event_json),
            daemon=True,
        )
        t.start()

    if AUDIT_SINK:
        # File append is fast enough to do inline
        _append_file(AUDIT_SINK, event_json)
