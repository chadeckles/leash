// Leash guardrails for OpenClaw.
//
// Installed by `leash install openclaw`; re-run that command instead of
// editing this file.  Before every tool call, OpenClaw hands the call to
// `leash hook openclaw`, which checks it against ~/.leash/policies, writes it
// to the local audit log and answers allow / ask / deny:
//
//   deny  -> the tool call is blocked and the agent is told why
//   ask   -> OpenClaw pauses and asks you to approve (e.g. /approve)
//   allow -> OpenClaw's own permission rules still apply
//
// Any failure (Leash missing, crash, timeout) blocks the call: fail-closed.

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const TIMEOUT_MS = 10_000;

function loadCommand() {
  try {
    const cfg = JSON.parse(readFileSync(join(HERE, "leash.json"), "utf8"));
    if (Array.isArray(cfg.command) && cfg.command.length > 0) return cfg.command.map(String);
  } catch {
    // fall through to PATH lookup
  }
  return ["leash", "hook", "openclaw"];
}

function defaultWorkspace() {
  if (process.env.OPENCLAW_WORKSPACE_DIR) return process.env.OPENCLAW_WORKSPACE_DIR;
  const profile = process.env.OPENCLAW_PROFILE;
  const base = profile && profile !== "default" ? `.openclaw-${profile}` : ".openclaw";
  return join(homedir(), base, "workspace");
}

function denied(reason) {
  return { decision: "deny", reason: `Blocked by Leash (fail-closed): ${reason}. Run \`leash doctor\` to diagnose.` };
}

export function checkWithLeash(command, payload, timeoutMs = TIMEOUT_MS) {
  return new Promise((done) => {
    let child;
    try {
      child = spawn(command[0], command.slice(1), { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    } catch (err) {
      done(denied(`could not start Leash (${err.message})`));
      return;
    }
    let out = "";
    let errText = "";
    let finished = false;
    const finish = (verdict) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      done(verdict);
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(denied(`no answer within ${timeoutMs} ms`));
    }, timeoutMs);
    child.stdout.on("data", (chunk) => (out += chunk));
    child.stderr.on("data", (chunk) => (errText += chunk));
    child.on("error", (err) => finish(denied(`could not start Leash (${err.message})`)));
    child.on("close", (code) => {
      if (code !== 0) {
        finish(denied(errText.trim() || `leash exited with code ${code}`));
        return;
      }
      try {
        const verdict = JSON.parse(out.trim() || "{}");
        finish(typeof verdict.decision === "string" ? verdict : denied("unexpected answer from Leash"));
      } catch {
        finish(denied("unreadable answer from Leash"));
      }
    });
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(payload));
  });
}

export function toHookResult(verdict) {
  if (verdict.decision === "allow") return undefined;
  if (verdict.decision === "ask") {
    return {
      requireApproval: {
        title: "Leash: approval needed",
        description: verdict.reason || "Leash policy requires your approval for this tool call.",
        severity: "warning",
        allowedDecisions: ["allow-once", "deny"],
      },
    };
  }
  return { block: true, blockReason: verdict.reason || "Blocked by Leash policy." };
}

export default {
  id: "leash",
  name: "Leash",
  description: "Checks every OpenClaw tool call against your Leash policies before it runs.",
  register(api) {
    const command = loadCommand();
    const workspace = defaultWorkspace();
    api.on(
      "before_tool_call",
      async (event, ctx) => {
        const params = event?.params ?? {};
        const workdir = typeof params.workdir === "string" && params.workdir ? params.workdir : "";
        const payload = {
          hook_event_name: "before_tool_call",
          tool_name: event?.toolName ?? "",
          tool_kind: event?.toolKind ?? ctx?.toolKind ?? null,
          tool_input: params,
          cwd: workdir ? (isAbsolute(workdir) ? workdir : resolve(workspace, workdir)) : workspace,
          session_id: ctx?.sessionId ?? ctx?.sessionKey ?? "",
          agent_id: ctx?.agentId ?? "",
        };
        return toHookResult(await checkWithLeash(command, payload));
      },
      { priority: 1000 },
    );
  },
};
