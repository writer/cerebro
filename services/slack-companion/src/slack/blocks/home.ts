import type { Finding, RuntimeHealth } from "../../cerebro/types.js";
import type { AppConfig } from "../../config/index.js";
import { runtimeId, runtimeStatusLine } from "../format.js";
import { actionIds } from "./action-ids.js";
import { findingCard } from "./findings.js";
import { actions, button, context, divider, escapeMrkdwn, header, section, type SlackBlock } from "./primitives.js";
import type { A2AInstance } from "../../a2a/index.js";

export function homeBlocks(input: {
  runtimes: RuntimeHealth[];
  findingsByRuntime: Array<{ runtimeId: string; findings: Finding[] }>;
  fleet?: A2AInstance[];
  sourceFailures?: string[];
  config: AppConfig;
}): SlackBlock[] {
  const findingCount = input.findingsByRuntime.reduce((count, item) => count + item.findings.length, 0);
  return [
    header("Cerebro"),
    context([`${findingCount} open findings shown`, `${input.runtimes.length} runtimes checked`]),
    actions([button("Refresh", actionIds.refreshHome, "refresh")]),
    ...(input.sourceFailures?.length
      ? [section(`*Data unavailable:* ${escapeMrkdwn(input.sourceFailures.join("; "))}. Other Home data is current.`)]
      : []),
    divider(),
    header("Cerebro fleet"),
    ...(input.fleet?.length
      ? input.fleet.slice(0, 10).map((instance) => section(
        `*${escapeMrkdwn(instance.label)}* · ${escapeMrkdwn(instance.role)} · ${escapeMrkdwn(instance.state)}\n${escapeMrkdwn(instance.commit)} · ${escapeMrkdwn(instance.instanceId)} · heartbeat ${escapeMrkdwn(relativeHeartbeat(instance.heartbeatAt))}`,
      ))
      : [section("Shared fleet status is unavailable for this process.")]),
    divider(),
    header("Runtime health"),
    ...input.runtimes.slice(0, 6).flatMap((runtime) => [
      section(`*${escapeMrkdwn(runtimeId(runtime))}*\n${escapeMrkdwn(runtimeStatusLine(runtime))}`),
    ]),
    divider(),
    header("Open findings"),
    ...input.findingsByRuntime.flatMap((item) => item.findings.slice(0, 3).flatMap((finding) => findingCard(item.runtimeId, finding, input.config))),
  ];
}

function relativeHeartbeat(value: string): string {
  const ageMs = Date.now() - Date.parse(value);
  if (!Number.isFinite(ageMs) || ageMs < 0) return value;
  if (ageMs < 10_000) return "now";
  if (ageMs < 60_000) return `${Math.round(ageMs / 1_000)}s ago`;
  return `${Math.round(ageMs / 60_000)}m ago`;
}
