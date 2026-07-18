import { logger } from "../../logger.js";
import { parseCommand } from "../command-parser.js";
import { commandHandlers } from "./handlers.js";
import { recordDailyNote } from "./notes.js";
import { plainBlocks, respondEphemeral } from "./response.js";
import type { CommandContext, CommandDeps, CommandHandler } from "./types.js";
import { assertAllowedTeam, errorMessage } from "./utils.js";

export type { CommandDeps } from "./types.js";

export function registerCommandHandlers(app: any, deps: CommandDeps): void {
  app.command("/cerebro", async ({ command, ack, respond, client }: any) => {
    await ack();
    const actor = deps.auth.actorFor(command.user_id);
    try {
      assertAllowedTeam(deps.config, command.team_id);
      const parsed = parseCommand(command.text ?? "");
      await deps.cerebro.recordInteraction({
        actor,
        action: `slash.${parsed.name}`,
        channelId: command.channel_id,
        status: "received",
      }).catch((error) => logger.warn("interaction claim write failed", { error: String(error) }));
      await dispatchCommand({ deps, command, respond, client, actor, parsed });
    } catch (error) {
      logger.warn("slash command failed", { error: String(error), user: command.user_id });
      await respondEphemeral(respond, plainBlocks(errorMessage(error)));
      await deps.cerebro.recordInteraction({
        actor,
        action: "slash.error",
        channelId: command.channel_id,
        status: "failed",
        details: { error: errorMessage(error) },
      }).catch(() => undefined);
      await recordDailyNote(deps, {
        kind: "failure",
        title: "/cerebro command failed",
        summary: errorMessage(error),
        details: `Command text: ${command.text ?? ""}`,
        tags: ["slash-command", "failure"],
        channelId: command.channel_id,
        outcome: "failed",
      });
    }
  });
}

async function dispatchCommand(context: CommandContext): Promise<void> {
  const handler = commandHandlers[context.parsed.name] as CommandHandler;
  await handler(context);
}
