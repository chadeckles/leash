// Leash authorization gate for OpenClaw tool calls.
//
// Pure logic with no OpenClaw SDK imports, so it can be unit-tested with plain
// Node (`node gate.test.ts`) and reused by index.ts inside the Gateway.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export type GateConfig = {
  leashUrl?: string;
  identityFile?: string;
  timeoutMs?: number;
};

export type Logger = {
  info: (msg: string) => void;
  warn: (msg: string) => void;
};

export type ToolCallEvent = {
  toolName: string;
  params?: Record<string, unknown>;
};

export type ToolCallCtx = {
  agentId?: string;
  sessionKey?: string;
  abortSignal?: AbortSignal;
};

export type GateResult = { block: true; blockReason: string } | undefined;

type Identity = { agent_id: string; token: string; name?: string };

const RESOURCE_KEYS = ["command", "path", "file_path", "filePath", "url", "query", "target"];

/** Pick the most meaningful argument so the audit log reads like "exec whoami". */
export function resourceFor(params: Record<string, unknown> | undefined): string {
  if (!params) return "";
  for (const key of RESOURCE_KEYS) {
    const value = params[key];
    if (typeof value === "string" && value.trim()) return value.trim().slice(0, 512);
  }
  return "";
}

export function createLeashGate(config: GateConfig, log: Logger) {
  const leashUrl = (config.leashUrl || "http://127.0.0.1:8000").replace(/\/+$/, "");
  const configured = config.identityFile?.replace(/^~(?=$|[\\/])/, homedir());
  const identityFile = configured || join(homedir(), ".leash", "openclaw-agent.json");
  const timeoutMs = config.timeoutMs ?? 5000;
  let identity: Identity | undefined;

  function loadIdentity(force = false): Identity {
    if (!identity || force) {
      const raw = JSON.parse(readFileSync(identityFile, "utf8"));
      if (!raw.agent_id || !raw.token) throw new Error(`${identityFile} is missing agent_id/token`);
      identity = { agent_id: raw.agent_id, token: raw.token, name: raw.name };
    }
    return identity;
  }

  async function authorize(event: ToolCallEvent, ctx: ToolCallCtx, retry = true): Promise<GateResult> {
    const id = loadIdentity(!retry);
    const resource = resourceFor(event.params);
    const signals = [AbortSignal.timeout(timeoutMs)];
    if (ctx.abortSignal) signals.push(ctx.abortSignal);

    const res = await fetch(`${leashUrl}/authorize`, {
      method: "POST",
      headers: { Authorization: `Bearer ${id.token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        agent_id: id.agent_id,
        action: event.toolName,
        resource,
        context: { source: "openclaw", openclaw_agent: ctx.agentId, session: ctx.sessionKey },
      }),
      signal: AbortSignal.any(signals),
    });

    // Re-read the identity file once in case the agent was re-registered.
    if (res.status === 401 && retry) return authorize(event, ctx, false);
    if (!res.ok) throw new Error(`Leash returned HTTP ${res.status}`);

    const body = (await res.json()) as {
      decision: string;
      reason: string;
      matched_policy?: string;
      matched_rule?: string;
    };
    const via = body.matched_policy ? ` [${body.matched_policy}/${body.matched_rule ?? "*"}]` : "";
    const shown = resource ? `${event.toolName} ${resource}` : event.toolName;

    if (body.decision === "deny") {
      log.warn(`🐕 Leash DENY  ${shown}${via} — ${body.reason}`);
      return { block: true, blockReason: `🐕 Blocked by Leash${via}: ${body.reason}` };
    }
    // "allow" and observe-mode allows both let the call through.
    log.info(`🐕 Leash ALLOW ${shown}${via} — ${body.reason}`);
    return undefined;
  }

  /** before_tool_call handler. Fails closed: any error blocks the tool call. */
  return async function gate(event: ToolCallEvent, ctx: ToolCallCtx = {}): Promise<GateResult> {
    try {
      return await authorize(event, ctx);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log.warn(`🐕 Leash UNREACHABLE — blocking ${event.toolName} (fail-closed): ${msg}`);
      return { block: true, blockReason: `🐕 Blocked by Leash (fail-closed): ${msg}` };
    }
  };
}
