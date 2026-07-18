import { assessDangerousIntent } from "../../security/safety.js";
import { goalBlocks, goalCreatedBlocks, goalsBlocks } from "../blocks/index.js";
import { recordDailyNote } from "./notes.js";
import { plainBlocks, respondEphemeral } from "./response.js";
import type { CommandByName, CommandContext } from "./types.js";

export async function handleGoalCreate({ deps, command, respond, actor, parsed }: CommandContext<CommandByName<"goal_create">>): Promise<void> {
  const safety = assessDangerousIntent(parsed.text);
  if (!safety.allowed) {
    await respondEphemeral(respond, plainBlocks(safety.refusal ?? "I cannot create that goal."));
    await recordDailyNote(deps, {
      kind: "safety_refusal",
      title: "/cerebro goal refused",
      summary: safety.reason ?? "Cerebro refused an unsafe autonomous goal.",
      details: [`Category: ${safety.category ?? "unsafe_request"}`, `Goal: ${parsed.text}`].join("\n"),
      tags: ["safety-refusal", safety.category ?? "unsafe-request", "goal"],
      channelId: command.channel_id,
      outcome: "refused",
    });
    return;
  }
  const goal = await deps.goals.createFromText({
    text: parsed.text,
    actor,
    channelId: command.channel_id,
  });
  await respondEphemeral(respond, goalCreatedBlocks(goal));
  await recordDailyNote(deps, {
    kind: "maintenance",
    title: "/cerebro goal",
    summary: `Created autonomy goal ${goal.id}.`,
    details: goal.objective,
    tags: ["slash-command", "goal", "create"],
    channelId: command.channel_id,
    outcome: "created",
  });
}

export async function handleGoals({ deps, respond, parsed }: CommandContext<CommandByName<"goals">>): Promise<void> {
  const goals = await deps.goals.list(parsed.status);
  await respondEphemeral(respond, goalsBlocks(goals));
}

export async function handleGoalShow({ deps, respond, parsed }: CommandContext<CommandByName<"goal_show">>): Promise<void> {
  const goal = await deps.goals.get(parsed.goalId);
  if (!goal) throw new Error(`No autonomy goal matched ${parsed.goalId}.`);
  await respondEphemeral(respond, goalBlocks(goal));
}

export async function handleGoalPause({ deps, respond, actor, parsed }: CommandContext<CommandByName<"goal_pause">>): Promise<void> {
  const goal = await deps.goals.setStatus({ goalId: parsed.goalId, status: "paused", actor });
  await respondEphemeral(respond, goalBlocks(goal));
}

export async function handleGoalResume({ deps, respond, actor, parsed }: CommandContext<CommandByName<"goal_resume">>): Promise<void> {
  const goal = await deps.goals.setStatus({ goalId: parsed.goalId, status: "active", actor });
  await respondEphemeral(respond, goalBlocks(goal));
}

export async function handleGoalCancel({ deps, respond, actor, parsed }: CommandContext<CommandByName<"goal_cancel">>): Promise<void> {
  const goal = await deps.goals.setStatus({ goalId: parsed.goalId, status: "cancelled", actor });
  await respondEphemeral(respond, goalBlocks(goal));
}

export async function handleGoalComplete({ deps, respond, actor, parsed }: CommandContext<CommandByName<"goal_complete">>): Promise<void> {
  const goal = await deps.goals.setStatus({ goalId: parsed.goalId, status: "completed", actor, reason: parsed.summary });
  await respondEphemeral(respond, goalBlocks(goal));
}
