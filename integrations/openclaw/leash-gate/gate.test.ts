// Drives the gate exactly like OpenClaw's before_tool_call would, against a
// live Leash server. Needs a registered agent:
//   leash agents register --name openclaw-agent
//   node --experimental-strip-types gate.test.ts
// Env: LEASH_URL (default http://127.0.0.1:8000), LEASH_IDENTITY (identity file).

import assert from "node:assert/strict";
import { createLeashGate, resourceFor } from "./gate.ts";

const lines: string[] = [];
const log = { info: (m: string) => lines.push(m), warn: (m: string) => lines.push(m) };
const config = { leashUrl: process.env.LEASH_URL, identityFile: process.env.LEASH_IDENTITY };
const gate = createLeashGate(config, log);

assert.equal(resourceFor({ command: "whoami" }), "whoami");
assert.equal(resourceFor({ path: "README.md", content: "x" }), "README.md");
assert.equal(resourceFor({}), "");

const allowed = [
  { toolName: "read", params: { path: "README.md" } },
  { toolName: "web_search", params: { query: "Cyber Lab Night Colorado Springs" } },
  { toolName: "session_status", params: {} },
];
const denied = [
  { toolName: "exec", params: { command: "whoami" } },
  { toolName: "write", params: { path: "notes.txt", content: "pwned" } },
  { toolName: "browser", params: { url: "https://example.com" } },
];

for (const ev of allowed) {
  assert.equal(await gate(ev, { agentId: "main" }), undefined, `${ev.toolName} should be allowed`);
}
for (const ev of denied) {
  const res = await gate(ev, { agentId: "main" });
  assert.equal(res?.block, true, `${ev.toolName} should be blocked`);
  assert.match(res!.blockReason, /Blocked by Leash/);
}

const offline = createLeashGate({ ...config, leashUrl: "http://127.0.0.1:1", timeoutMs: 500 }, log);
const res = await offline({ toolName: "read", params: { path: "README.md" } });
assert.equal(res?.block, true, "unreachable Leash must fail closed");

console.log(lines.join("\n"));
console.log("\n✔ leash-gate: 3 allowed, 3 blocked, fail-closed verified");
