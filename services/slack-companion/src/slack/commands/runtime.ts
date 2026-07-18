import { recordRuntimeCommand } from "./notes.js";
import { plainBlocks, respondEphemeral } from "./response.js";
import type { CommandByName, CommandContext } from "./types.js";

export async function handleSync(context: CommandContext<CommandByName<"sync">>): Promise<void> {
  await handleRuntimeWrite(context, "sync");
}

export async function handleIngest(context: CommandContext<CommandByName<"ingest">>): Promise<void> {
  await handleRuntimeWrite(context, "ingest");
}

export async function handleEvaluate(context: CommandContext<CommandByName<"evaluate">>): Promise<void> {
  await handleRuntimeWrite(context, "evaluate");
}

async function handleRuntimeWrite(
  { deps, command, respond, parsed }: CommandContext<CommandByName<"sync" | "ingest" | "evaluate">>,
  action: "sync" | "ingest" | "evaluate",
): Promise<void> {
  deps.auth.requireWrite(command.user_id, "source");
  if (action === "sync") {
    await deps.cerebro.syncRuntime(parsed.runtimeId);
    await respondEphemeral(respond, plainBlocks(`Sync started for ${parsed.runtimeId}.`));
  } else if (action === "ingest") {
    await deps.cerebro.runGraphIngest(parsed.runtimeId);
    await respondEphemeral(respond, plainBlocks(`Graph ingest started for ${parsed.runtimeId}.`));
  } else {
    await deps.cerebro.evaluateFindings(parsed.runtimeId);
    await respondEphemeral(respond, plainBlocks(`Finding evaluation started for ${parsed.runtimeId}.`));
  }
  await recordRuntimeCommand(deps, command.channel_id, action, parsed.runtimeId);
}
