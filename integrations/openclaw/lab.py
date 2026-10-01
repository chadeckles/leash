#!/usr/bin/env python3
"""OpenClaw + Leash lab helper. Python stdlib only.

    python3 integrations/openclaw/lab.py setup    # one time (Leash must be running)
    python3 integrations/openclaw/lab.py allow    # 3 tool calls Leash allows
    python3 integrations/openclaw/lab.py deny     # 3 tool calls Leash blocks

Every step prints ✔ or ✘ with a one-line fix.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

LEASH_URL = os.getenv("LEASH_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT = "openclaw-agent"
PLUGIN_DIR = Path(__file__).resolve().parent / "leash-gate"
CONFIG = Path(os.getenv("OPENCLAW_CONFIG_PATH", Path.home() / ".openclaw" / "openclaw.json"))

ALLOW_CALLS = [
    ("session_status", {}),
    ("sessions_list", {}),
    ("read", {"path": "hello.txt"}),
]
DENY_CALLS = [
    ("write", {"path": "pwned.txt", "content": "owned by the agent"}),
    ("edit", {"path": "hello.txt", "oldText": "Hello", "newText": "Goodbye"}),
    ("browser", {"action": "open", "url": "https://example.com"}),
]

_tty = sys.stdout.isatty() and not os.getenv("NO_COLOR")
GREEN, RED, DIM, BOLD, RESET = (
    ("\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m") if _tty else ("",) * 5
)


def ok(msg: str) -> None:
    print(f"  {GREEN}✔{RESET} {msg}")


def fail(msg: str, fix: str) -> None:
    print(f"  {RED}✘{RESET} {msg}\n    {DIM}→ {fix}{RESET}")
    sys.exit(1)


def http(method: str, url: str, body: dict | None = None, token: str = "") -> tuple[int, dict]:
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body else None)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    try:
        return status, json.loads(raw or b"{}")
    except json.JSONDecodeError:
        return status, {"raw": raw.decode(errors="replace")[:300]}


def openclaw_config() -> dict:
    try:
        return json.loads(CONFIG.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def gateway_url(cfg: dict) -> str:
    port = (cfg.get("gateway") or {}).get("port") or 18789
    return f"http://127.0.0.1:{port}"


def gateway_secret(cfg: dict) -> str:
    auth = (cfg.get("gateway") or {}).get("auth") or {}
    return (
        os.getenv("OPENCLAW_GATEWAY_TOKEN")
        or auth.get("token")
        or os.getenv("OPENCLAW_GATEWAY_PASSWORD")
        or auth.get("password")
        or ""
    )


def workspace(cfg: dict) -> Path:
    ws = ((cfg.get("agents") or {}).get("defaults") or {}).get("workspace")
    return Path(ws).expanduser() if ws else Path.home() / ".openclaw" / "workspace"


def run(cmd: list[str], what: str, fix: str) -> None:
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        detail = (res.stderr or res.stdout).strip().splitlines()[-1:] or ["(no output)"]
        fail(f"{what} failed: {detail[0]}", fix)
    ok(what)


# ── setup ──────────────────────────────────────────────────────────────────

def setup() -> None:
    print(f"\n  {BOLD}Leash + OpenClaw setup{RESET}\n")

    try:
        status, _ = http("GET", f"{LEASH_URL}/health")
    except OSError:
        status = 0
    if status != 200:
        fail(f"Leash is not running at {LEASH_URL}", "Open another terminal and run: leash start")
    ok(f"Leash is running at {LEASH_URL}")

    leash = shutil.which("leash")
    leash_cmd = [leash] if leash else [sys.executable, "-m", "sdk.cli"]
    run(
        [*leash_cmd, "agents", "register", "--name", AGENT, "--vendor", "openclaw",
         "--type", "assistant", "--force"],
        f"Registered '{AGENT}' (identity → ~/.leash/{AGENT}.json)",
        "Activate the venv where you installed Leash (source .venv/bin/activate) and retry",
    )

    if not shutil.which("openclaw"):
        fail("OpenClaw is not installed", "npm install -g openclaw@latest   (needs Node 24+)")
    ok("OpenClaw is installed")

    run(["openclaw", "plugins", "install", "--link", str(PLUGIN_DIR), "--force"],
        "Installed the leash-gate plugin", "Run `openclaw doctor`, then retry")
    run(["openclaw", "plugins", "enable", "leash-gate"],
        "Enabled the leash-gate plugin", "Run `openclaw doctor`, then retry")

    cfg = openclaw_config()
    gw = cfg.get("gateway") or {}
    if gw.get("mode") != "local":
        run(["openclaw", "config", "set", "gateway.mode", "local"],
            "Set gateway.mode = local", "Run `openclaw onboard --mode local`, then retry")
    else:
        ok("Gateway mode is local")

    if not gateway_secret(cfg) and (gw.get("auth") or {}).get("mode") != "none":
        run(["openclaw", "config", "set", "gateway.auth.mode", "token"],
            "Set gateway.auth.mode = token", "Run `openclaw onboard --mode local`, then retry")
        run(["openclaw", "config", "set", "gateway.auth.token", secrets.token_hex(24)],
            "Generated a gateway token", "Run `openclaw onboard --mode local`, then retry")
    else:
        ok("Gateway auth is configured")

    ws = workspace(openclaw_config())
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "hello.txt").write_text("Hello, Cyber Lab Night!\n")
    (ws / "pwned.txt").unlink(missing_ok=True)
    ok(f"Wrote {ws / 'hello.txt'}")

    print(f"""
  {BOLD}Done.{RESET} Next:
    1. In a new terminal:  {BOLD}openclaw gateway run{RESET}   {DIM}(restart it if it was already running){RESET}
    2. Back here:          {BOLD}python3 {_rel(__file__)} allow{RESET}
                           {BOLD}python3 {_rel(__file__)} deny{RESET}
""")


# ── allow / deny ───────────────────────────────────────────────────────────

def invoke(calls: list[tuple[str, dict]], expect: str) -> None:
    cfg = openclaw_config()
    url = gateway_url(cfg)
    token = gateway_secret(cfg)
    print()
    passed = 0
    for tool, args in calls:
        target = next((v for v in args.values() if isinstance(v, str) and v not in ("open",)), "")
        label = f"{BOLD}{tool}{RESET} {DIM}{target}{RESET}".rstrip()
        try:
            status, body = http("POST", f"{url}/tools/invoke", {"tool": tool, "args": args}, token)
        except OSError:
            fail(f"Can't reach the OpenClaw gateway at {url}",
                 "In another terminal run: openclaw gateway run")
        err = (body.get("error") or {}) if isinstance(body.get("error"), dict) else {}
        msg = err.get("message") or body.get("raw") or ""

        if status == 200:
            print(f"  {GREEN}{BOLD}✔ ALLOWED{RESET}  {label}")
            preview = json.dumps(body.get("result"))[:90]
            print(f"             {DIM}tool ran → {preview}{RESET}")
            passed += expect == "allow"
        elif status == 403 and "Leash" in msg:
            reason = msg.split(":", 1)[-1].strip()
            print(f"  {RED}{BOLD}✘ BLOCKED{RESET}  {label}")
            print(f"             {DIM}Leash: {reason}{RESET}")
            passed += expect == "deny"
        elif status == 401:
            fail("The gateway rejected our token (HTTP 401)",
                 "Restart the gateway (openclaw gateway run) so it picks up the token from setup")
        elif status == 404:
            print(f"  ? SKIPPED  {label}")
            print(f"             {DIM}OpenClaw's tool profile doesn't expose '{tool}' — Leash was never asked{RESET}")
        else:
            print(f"  ? HTTP {status}  {label}")
            print(f"             {DIM}{msg or body}{RESET}")

    word = "allowed" if expect == "allow" else "blocked by Leash"
    print(f"\n  {passed}/{len(calls)} {word}. "
          f"{DIM}The gateway terminal shows a 🐕 Leash line for each call.{RESET}")
    if expect == "deny":
        pwned = workspace(cfg) / "pwned.txt"
        print(f"  {DIM}pwned.txt exists? {'YES ✘' if pwned.exists() else 'no — the write never ran'}{RESET}")
    print(f"  {DIM}See the evidence: leash audit log{RESET}\n")
    sys.exit(0 if passed == len(calls) else 1)


def _rel(path: str) -> str:
    try:
        return os.path.relpath(path)
    except ValueError:
        return path


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "setup":
        setup()
    elif cmd == "allow":
        invoke(ALLOW_CALLS, "allow")
    elif cmd == "deny":
        invoke(DENY_CALLS, "deny")
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
