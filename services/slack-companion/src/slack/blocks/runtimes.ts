import type { RuntimeHealth } from "../../cerebro/types.js";
import { encodeAction } from "../action-codec.js";
import { runtimeId, runtimeStatusLine, text } from "../format.js";
import { actionIds } from "./action-ids.js";
import { actions, button, context, divider, escapeMrkdwn, header, section, type SlackBlock } from "./primitives.js";

export function runtimeHealthBlocks(runtimes: RuntimeHealth[]): SlackBlock[] {
  if (runtimes.length === 0) {
    return [header("Runtime health"), section("No runtimes matched the request.")];
  }
  return [
    header("Runtime health"),
    ...runtimes.flatMap((runtime) => [
      section(`*${escapeMrkdwn(runtimeId(runtime))}*\n${escapeMrkdwn(runtimeStatusLine(runtime))}`),
      actions([
        button("Sync", actionIds.runtimeSync, encodeAction({ kind: "runtime_sync", runtimeId: runtimeId(runtime) })),
        button("Ingest", actionIds.runtimeIngest, encodeAction({ kind: "runtime_ingest", runtimeId: runtimeId(runtime) })),
        button("Evaluate", actionIds.runtimeEvaluate, encodeAction({ kind: "runtime_evaluate", runtimeId: runtimeId(runtime) })),
      ]),
      context([`Last sync: ${text(runtime.last_sync_at, "unknown")}`, `Open findings: ${text(runtime.open_finding_count, "unknown")}`]),
      divider(),
    ]),
  ];
}
