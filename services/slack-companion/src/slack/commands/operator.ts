import { collectRuntimeHealth, recordRuntimeHealthMetrics, runtimeHealthSlackText } from "../../runtime/health.js";
import { recordDailyNote } from "./notes.js";
import { plainBlocks, respondEphemeral } from "./response.js";
import type { CommandByName, CommandContext } from "./types.js";

export async function handleOperator({ deps, command, respond, actor, parsed }: CommandContext<CommandByName<"operator">>): Promise<void> {
  deps.auth.requireOperator(command.user_id);
  const message = parsed.action === "deploy"
    ? deployPolicyText(deps.config.coordination.deploymentFenceEnabled)
    : parsed.action === "health"
      ? await healthText(deps)
      : identityText(actor);

  await respondEphemeral(respond, plainBlocks(message));
  await recordDailyNote(deps, {
    kind: "slash_command",
    title: `/cerebro operator ${parsed.action}`,
    summary: `Returned operator ${parsed.action} context for ${actor.actorId}.`,
    tags: ["slash-command", "operator", parsed.action],
    channelId: command.channel_id,
    outcome: "completed",
  });
}

function identityText(actor: CommandContext["actor"]): string {
  const display = actor.displayName ? `${actor.displayName} (${actor.actorId})` : actor.actorId;
  const writeCapabilities = actor.writeCapabilities ?? [];
  const scopes = writeCapabilities.length > 0 ? writeCapabilities.join(", ") : "none";
  return [
    `Cerebro sees you as ${display}.`,
    `Slack user: ${actor.slackUserId}.`,
    `Operator commands: ${actor.operator ? "allowed" : "blocked"}.`,
    `Write scopes: ${scopes}.`,
  ].join("\n");
}

function deployPolicyText(deploymentFenceEnabled: boolean): string {
  return [
    "Auto-deploy is enabled for main.",
    "CI runs on every push to main. When CI passes, Deploy sec-dev classifies the merge as skip, direct ECS image deploy, or Pulumi infra deploy.",
    "Container input changes build an image and register a new ECS task definition. Infra program/config changes run Pulumi. Docs, tests, and workflow-only changes skip ECS.",
    "The deploy job checks that it is deploying the latest main SHA before build and again before service update.",
    `ECS deployment fence: ${deploymentFenceEnabled ? "enabled" : "disabled"}.`,
  ].join("\n");
}

async function healthText(deps: CommandContext["deps"]): Promise<string> {
  const snapshot = await collectRuntimeHealth(deps);
  recordRuntimeHealthMetrics(snapshot);
  return runtimeHealthSlackText(snapshot);
}
