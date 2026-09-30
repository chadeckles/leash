import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { createLeashGate, type GateConfig } from "./gate.ts";

export default definePluginEntry({
  id: "leash-gate",
  name: "Leash Gate",
  description: "Authorize every OpenClaw tool call with Leash before it runs.",
  register(api) {
    const log = {
      info: (m: string) => (api.logger?.info ?? console.log)(m),
      warn: (m: string) => (api.logger?.warn ?? console.warn)(m),
    };
    const gate = createLeashGate((api.pluginConfig ?? {}) as GateConfig, log);

    // No matcher: every tool call goes through Leash. High priority so Leash
    // decides before other policy plugins.
    api.on("before_tool_call", (event, ctx) => gate(event, ctx), { priority: 100 });
  },
});
