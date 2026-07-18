import type { DailyNoteInput } from "../../learning/daily-notes.js";
import { logger } from "../../logger.js";
import type { CommandDeps } from "./types.js";

export async function recordRuntimeCommand(deps: CommandDeps, channelId: string | undefined, action: string, runtimeId: string): Promise<void> {
  await recordDailyNote(deps, {
    kind: "runtime_action",
    title: `/cerebro ${action}`,
    summary: `${action} started for ${runtimeId}.`,
    details: `Runtime: ${runtimeId}`,
    tags: ["slash-command", "runtime-action", action],
    channelId,
    outcome: "started",
  });
}

export async function recordDailyNote(deps: CommandDeps, input: DailyNoteInput): Promise<void> {
  await deps.notes.record(input).catch((error) => logger.warn("daily note write failed", { error: String(error), kind: input.kind }));
}
