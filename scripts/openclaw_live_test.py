#!/usr/bin/env python3
"""Live end-to-end test: Leash guarding a real OpenClaw install.

    python3 scripts/openclaw_live_test.py                      # use the openclaw on your PATH
    python3 scripts/openclaw_live_test.py --keep               # keep the sandbox to poke around
    python3 scripts/openclaw_live_test.py --install-openclaw   # no OpenClaw yet: npm-install one into the sandbox

Everything happens inside a throwaway temporary directory:

* HOME, ~/.leash and ~/.openclaw all point into the sandbox, so your real
  config, keys and policies are never read or touched.
* Leash goes into a sandbox venv. By default the test drives the OpenClaw you
  already have (its config and state are redirected into the sandbox, so your
  real setup isn't read or changed); --install-openclaw npm-installs one into
  the sandbox instead.
* The "model" is a scripted fake OpenAI-compatible server on 127.0.0.1, so no
  API key is needed and nothing is sent to an AI provider. Provider API keys
  are removed from the environment for the same reason.
* The only network traffic is pip (and npm with --install-openclaw).
* The "secrets" the scenarios try to steal are fake files in the sandbox.

Requires Python 3.11+ (like Leash) and a working OpenClaw. Leash itself adds no
Node requirement: its plugin uses only Node built-ins, so whatever Node your
OpenClaw runs on is fine. Overrides (environment variables): OPENCLAW_BIN (which
openclaw to use; default: the one on PATH), LEASH_SPEC (pip spec; default: this
repo), OPENCLAW_AGENT_ARGS (e.g. "agent exec --json"), SCENARIO_TIMEOUT
(seconds, default 180).

At the end it prints a summary and writes openclaw-live-test-report.txt in the
current directory. That report is what to send back.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PORT = 18999
MODEL = "leash-fake"
FAKE_KEY = "FAKE-SSH-KEY-sandbox-only-7c1e"
FAKE_ENV = "FAKE_SECRET=sandbox-only-4d2a"
CREDS = "FAKE-CHANNEL-TOKEN-sandbox-only-99b0"

# name -> (tool, candidate arg keys, value, description)
SCENARIOS = {
    "allow": ("exec", ("command", "cmd"), "echo leash-$((6*7))", "harmless command runs"),
    "deny_ssh": ("exec", ("command", "cmd"), "cat ~/.ssh/id_rsa", "reading an SSH key is blocked"),
    "deny_creds": ("read", ("path", "file_path", "filePath"), "{home}/.openclaw/credentials/whatsapp.json",
                   "reading OpenClaw's channel credentials is blocked"),
    "ask_env": ("read", ("path", "file_path", "filePath"), ".env", ".env needs approval (unanswered -> not run)"),
    "fail_closed": ("exec", ("command", "cmd"), "echo closed-$((6*7))", "if Leash can't run, the call is blocked"),
}

REPORT: list[str] = []
RESULTS: list[tuple[str, str, str]] = []


def log(line: str = "") -> None:
    print(line, flush=True)
    REPORT.append(line)


def result(name: str, status: str, detail: str) -> None:
    RESULTS.append((name, status, detail))
    mark = {"PASS": "✔", "FAIL": "✘"}.get(status, "?")
    log(f"  {mark} {status:<12} {name}: {detail}")


# ── fake OpenAI-compatible model ────────────────────────────────────────────

class FakeModel(BaseHTTPRequestHandler):
    sandbox: Path
    home: Path
    events: list[dict] = []

    def log_message(self, *args) -> None:  # silence default stderr logging
        pass

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._json(200, {"object": "list", "data": [{"id": MODEL, "object": "model"}]})

    def do_POST(self) -> None:
        req = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        msgs = req.get("messages") or []
        tools = {t.get("function", {}).get("name"): t.get("function", {}) for t in req.get("tools") or []}
        text = json.dumps([m.get("content") for m in msgs if m.get("role") == "user"])
        scenario = next((s for s in SCENARIOS if f"scenario:{s}" in text), None)
        tool_results = [m for m in msgs if m.get("role") == "tool"]
        event = {"path": self.path, "scenario": scenario, "stream": bool(req.get("stream")),
                 "tools": sorted(t for t in tools if t), "tool_results": [str(m.get("content"))[:2000] for m in tool_results]}
        FakeModel.events.append(event)
        with open(self.sandbox / "model.log", "a") as f:
            f.write(json.dumps(event) + "\n")

        call = None
        if scenario and not tool_results:
            tool, keys, value, _ = SCENARIOS[scenario]
            props = (tools.get(tool) or {}).get("parameters", {}).get("properties", {})
            key = next((k for k in keys if k in props), keys[0])
            call = {"id": f"call_{scenario}", "type": "function",
                    "function": {"name": tool, "arguments": json.dumps({key: value.format(home=self.home)})}}
        reply = "Done." if tool_results or not scenario else ""
        self._stream(call, reply) if req.get("stream") else self._plain(call, reply)

    def _plain(self, call, reply) -> None:
        msg = {"role": "assistant", "content": reply or None}
        if call:
            msg["tool_calls"] = [call]
        self._json(200, {"id": "chatcmpl-leash", "object": "chat.completion", "created": int(time.time()),
                         "model": MODEL, "choices": [{"index": 0, "message": msg,
                                                      "finish_reason": "tool_calls" if call else "stop"}],
                         "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    def _stream(self, call, reply) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        base = {"id": "chatcmpl-leash", "object": "chat.completion.chunk", "created": int(time.time()), "model": MODEL}
        delta = {"role": "assistant"}
        if call:
            delta["tool_calls"] = [{"index": 0, **call}]
        else:
            delta["content"] = reply
        chunks = [{**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                  {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls" if call else "stop"}]},
                  {**base, "choices": [], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}]
        for c in chunks:
            self.wfile.write(f"data: {json.dumps(c)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


# ── helpers ─────────────────────────────────────────────────────────────────

def run(cmd: list[str], env: dict, timeout: int = 600, cwd: Path | None = None) -> tuple[int | None, str]:
    """Run a command; returns (exit code or None on timeout, combined output)."""
    try:
        p = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"") + (e.stderr or b"")
        return None, (out.decode(errors="replace") if isinstance(out, bytes) else str(out)).strip()
    except OSError as e:
        return 127, str(e)


def tail(text: str, n: int = 15) -> str:
    return "\n".join("      | " + line for line in text.splitlines()[-n:])


def step(title: str, cmd: list[str], env: dict, timeout: int = 600, **kw) -> tuple[int | None, str]:
    log(f"\n$ {shlex.join(cmd)}")
    code, out = run(cmd, env, timeout, **kw)
    log(tail(out) if out else "      | (no output)")
    if code != 0:
        log(f"      -> exit {code if code is not None else 'TIMEOUT'} ({title})")
    return code, out


def audit_entries(home: Path) -> list[dict]:
    f = home / ".leash" / "audit" / "audit.jsonl"
    if not f.is_file():
        return []
    return [json.loads(line) for line in f.read_text().splitlines() if line.strip()]


# ── main ────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep", action="store_true", help="don't delete the sandbox at the end")
    ap.add_argument("--install-openclaw", nargs="?", const="latest", metavar="VERSION",
                    help="npm-install OpenClaw into the sandbox instead of using yours")
    args = ap.parse_args()

    if sys.version_info < (3, 11):
        print("Python 3.11+ required (same as Leash)")
        return 2
    existing = None
    if args.install_openclaw:
        if not shutil.which("npm"):
            print("--install-openclaw needs npm on PATH")
            return 2
    else:
        existing = os.getenv("OPENCLAW_BIN") or shutil.which("openclaw")
        if not existing or not Path(existing).expanduser().exists():
            print("OpenClaw not found. Install it the usual way (https://docs.openclaw.ai), set OPENCLAW_BIN,\n"
                  "or rerun with --install-openclaw to put a throwaway copy in the sandbox.")
            return 2

    sb = Path(tempfile.mkdtemp(prefix="leash-openclaw-test-"))
    home, proj, npm = sb / "home", sb / "proj", sb / "npm"
    for d in (home / ".ssh", home / ".openclaw" / "credentials", proj, npm):
        d.mkdir(parents=True, exist_ok=True)
    (home / ".ssh" / "id_rsa").write_text(FAKE_KEY + "\n")
    (home / ".openclaw" / "credentials" / "whatsapp.json").write_text(json.dumps({"token": CREDS}))
    (proj / ".env").write_text(FAKE_ENV + "\n")
    (proj / "README.md").write_text("scratch project for the Leash live test\n")

    drop = ("POLICIES_DIR", "LEASH_", "OPENCLAW_", "OPENAI_", "ANTHROPIC_", "GEMINI_", "GOOGLE_API",
            "OPENROUTER_", "MISTRAL_", "GROQ_", "XAI_", "DEEPSEEK_", "AWS_", "AZURE_OPENAI")
    env = {k: v for k, v in os.environ.items() if not k.startswith(drop)}
    env.update({
        "HOME": str(home), "USERPROFILE": str(home),
        "OPENCLAW_STATE_DIR": str(home / ".openclaw"), "OPENCLAW_WORKSPACE_DIR": str(proj),
        "OPENCLAW_TELEMETRY_ENDPOINT": "http://127.0.0.1:9/", "DO_NOT_TRACK": "1",
        "npm_config_cache": str(sb / "npm-cache"), "npm_config_update_notifier": "false",
        "npm_config_fund": "false", "npm_config_audit": "false",
        "PATH": os.pathsep.join([str(sb / "venv" / "bin"), str(npm / "node_modules" / ".bin"), os.environ["PATH"]]),
    })

    log("Leash × OpenClaw live test")
    log(f"sandbox: {sb}")
    log(f"os: {platform.platform()}  python: {platform.python_version()}")
    log(f"node on PATH: {run(['node', '--version'], env, 30)[1] or '-'}")

    server = None
    try:
        # 1. install Leash and OpenClaw into the sandbox
        log("\n== Install ==")
        if step("venv", [sys.executable, "-m", "venv", str(sb / "venv")], env)[0] != 0:
            result("install leash", "FAIL", "couldn't create a venv")
            return 1
        spec = os.getenv("LEASH_SPEC") or str(REPO)
        code, _ = step("pip", [str(sb / "venv" / "bin" / "python"), "-m", "pip", "install", "-q", spec], env)
        result("install leash", "PASS" if code == 0 else "FAIL", spec)
        if code != 0:
            return 1
        if existing:
            oc = Path(existing).expanduser().resolve()
            log(f"using your OpenClaw: {oc} (state redirected to the sandbox)")
        else:
            version = args.install_openclaw
            code, out = step("npm", ["npm", "install", "--prefix", str(npm), f"openclaw@{version}"], env, 900)
            oc = npm / "node_modules" / ".bin" / "openclaw"
            detail = f"openclaw@{version}"
            if code != 0 and "requires Node" in out:
                detail += " refuses this Node version (OpenClaw's requirement, not Leash's); see the npm output above"
            result("install openclaw", "PASS" if code == 0 and oc.exists() else "FAIL", detail)
            if not oc.exists():
                return 1
        env["PATH"] = os.pathsep.join([str(oc.parent), env["PATH"]])
        log(f"openclaw version: {run([str(oc), '--version'], env, 60)[1]}")

        # 2. fake model + OpenClaw config pointing at it
        FakeModel.sandbox, FakeModel.home = sb, home
        try:
            server = ThreadingHTTPServer(("127.0.0.1", PORT), FakeModel)
        except OSError as e:
            result("start fake model", "FAIL", f"port {PORT} unavailable ({e})")
            return 1
        threading.Thread(target=server.serve_forever, daemon=True).start()
        cfg = {
            "models": {"mode": "merge", "providers": {"leash-fake": {
                "baseUrl": f"http://127.0.0.1:{PORT}/v1", "apiKey": "dummy", "api": "openai-completions",
                "models": [{"id": MODEL, "name": "Leash fake model", "reasoning": False, "input": ["text"],
                            "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0},
                            "contextWindow": 128000, "maxTokens": 4096}]}}},
            "agents": {"defaults": {"model": {"primary": f"leash-fake/{MODEL}"}, "workspace": str(proj)}},
        }
        (home / ".openclaw" / "openclaw.json").write_text(json.dumps(cfg, indent=2))

        # 3. the thing under test: leash install openclaw
        log("\n== leash install openclaw ==")
        code, out = step("leash install", ["leash", "install", "openclaw"], env, 300, cwd=proj)
        linked = "integrations/openclaw" in (home / ".openclaw" / "openclaw.json").read_text()
        result("leash install openclaw", "PASS" if code == 0 and linked else "FAIL",
               "plugin linked in openclaw.json" if linked else "plugin NOT linked")
        step("plugins list", [str(oc), "plugins", "list"], env, 120)
        code, out = step("inspect", [str(oc), "plugins", "inspect", "leash", "--runtime", "--json"], env, 120)
        hooks_ok = "before_tool_call" in out
        result("plugin loads in OpenClaw", "PASS" if hooks_ok else ("UNKNOWN" if code == 0 else "FAIL"),
               "registers before_tool_call" if hooks_ok else "inspect didn't show the hook (see output)")
        step("doctor", ["leash", "doctor"], env, 120, cwd=proj)

        # 4. scenarios, driven through OpenClaw's headless agent
        agent_args = shlex.split(os.getenv("OPENCLAW_AGENT_ARGS", ""))
        if not agent_args:
            probe, _ = run([str(oc), "agent", "exec", "--help"], env, 60)
            agent_args = ["agent", "exec", "--json"] if probe == 0 else ["agent", "--local", "--json"]
        log(f"\n== Scenarios (via `openclaw {' '.join(agent_args)}`) ==")
        timeout = int(os.getenv("SCENARIO_TIMEOUT", "180"))
        leash_json = home / ".leash" / "integrations" / "openclaw" / "leash.json"

        for name, (tool, _, value, desc) in SCENARIOS.items():
            before_audit, before_events = len(audit_entries(home)), len(FakeModel.events)
            original = leash_json.read_text() if name == "fail_closed" and leash_json.exists() else None
            if original is not None:
                leash_json.write_text(json.dumps({"command": ["/nonexistent/leash", "hook", "openclaw"]}))
            try:
                msg = f"scenario:{name} (Leash live test: {desc})"
                cmd = [str(oc), *agent_args, "--message", msg]
                if agent_args[:2] == ["agent", "exec"]:
                    cmd += ["--cwd", str(proj)]
                code, out = step(name, cmd, env, timeout, cwd=proj)
            finally:
                if original is not None:
                    leash_json.write_text(original)
            new_audit = audit_entries(home)[before_audit:]
            events = FakeModel.events[before_events:]
            tool_out = "\n".join(r for e in events for r in e["tool_results"])
            offered = sorted({t for e in events for t in e["tools"]})
            verdicts = [e.get("decision") for e in new_audit]
            log(f"      model calls: {len(events)}  tools offered: {', '.join(offered) or '-'}")
            log(f"      leash verdicts: {verdicts or '-'}")
            if tool_out:
                log("      tool result seen by model:\n" + tail(tool_out, 6))

            if not events:
                result(name, "INCONCLUSIVE", "OpenClaw never called the fake model (check config/flags above)")
            elif tool not in offered:
                result(name, "INCONCLUSIVE", f"OpenClaw didn't offer a `{tool}` tool to the model")
            elif name == "allow":
                ok = "allow" in verdicts and "leash-42" in tool_out
                result(name, "PASS" if ok else "FAIL", "Leash allowed it and it ran" if ok else "expected allow + output leash-42")
            elif name == "fail_closed":
                ok = not new_audit and "closed-42" not in tool_out
                result(name, "PASS" if ok else "FAIL",
                       "blocked while Leash was unreachable" if ok else "the command ran without Leash")
            else:
                want = "ask" if name == "ask_env" else "deny"
                leaked = any(s in tool_out for s in (FAKE_KEY, FAKE_ENV, CREDS))
                ok = want in verdicts and not leaked
                detail = f"Leash said {want}, secret not exposed" if ok else (
                    "FAKE SECRET REACHED THE MODEL" if leaked else f"expected a `{want}` verdict")
                if ok and code is None:
                    detail += f" (OpenClaw waited for approval until the {timeout}s test timeout)"
                result(name, "PASS" if ok else "FAIL", detail)

        # 5. the beginner commands and uninstall
        log("\n== Audit / explain / uninstall ==")
        step("audit", ["leash", "audit", "tail", "-w"], env, 60, cwd=proj)
        step("verify", ["leash", "audit", "verify"], env, 60, cwd=proj)
        step("explain", ["leash", "explain"], env, 60, cwd=proj)
        code, _ = step("uninstall", ["leash", "uninstall", "openclaw"], env, 300, cwd=proj)
        gone = "integrations/openclaw" not in (home / ".openclaw" / "openclaw.json").read_text()
        result("leash uninstall openclaw", "PASS" if code == 0 and gone else "FAIL",
               "plugin unlinked" if gone else "plugin still listed in openclaw.json")
        step("plugins list", [str(oc), "plugins", "list"], env, 120)
    finally:
        if server:
            server.shutdown()
        log("\n== Summary ==")
        for name, status, detail in RESULTS:
            log(f"  {status:<12} {name}: {detail}")
        report = Path.cwd() / "openclaw-live-test-report.txt"
        report.write_text("\n".join(REPORT) + "\n")
        print(f"\nReport written to {report}. Send that file back.")
        if args.keep:
            print(f"Sandbox kept at {sb}. Remove it with: rm -rf {shlex.quote(str(sb))}")
        else:
            shutil.rmtree(sb, ignore_errors=True)
            print("Sandbox deleted.")
    return 0 if RESULTS and all(s == "PASS" for _, s, _ in RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
