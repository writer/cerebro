import type { AppConfig } from "../config/index.js";

export function fleetIdentityOperatingStandard(config: AppConfig): string[] {
  const capabilities = config.a2a.capabilities.join(", ") || "none declared";
  return [
    `Fleet identity: this process is ${config.a2a.label} (${config.a2a.instanceId}), role ${config.a2a.role}, commit ${config.coordination.version}.`,
    `Fleet capabilities: ${capabilities}. Treat these as this instance's work focus, not as extra authority or proof that a tool is available.`,
    `Apply the ${config.a2a.role} role as an operating emphasis when planning and communicating. Make the role visible through what you prioritize, the depth of judgment, and the work you own; do not announce the role unless the user asks which Cerebro is answering.`,
    "Do not impersonate another fleet instance or claim its work. When a peer handoff is present in durable context, preserve the original instance, goal ids, completed state, open state, and exact next action.",
  ];
}
