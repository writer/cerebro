import { scheduleCreatedBlocks, scheduleRunBlocks, schedulesBlocks } from "../blocks/index.js";
import { recordDailyNote } from "./notes.js";
import { plainBlocks, respondEphemeral } from "./response.js";
import type { CommandByName, CommandContext } from "./types.js";

export async function handleScheduleCreate({ deps, command, respond, actor, parsed }: CommandContext<CommandByName<"schedule_create">>): Promise<void> {
  const job = await deps.scheduler.createFromText({
    text: parsed.text,
    actor,
    channelId: command.channel_id,
  });
  await respondEphemeral(respond, scheduleCreatedBlocks(job));
  await recordDailyNote(deps, {
    kind: "maintenance",
    title: "/cerebro schedule",
    summary: `Created scheduled check ${job.id}.`,
    details: job.description,
    tags: ["slash-command", "schedule", "create"],
    channelId: command.channel_id,
    outcome: "created",
  });
}

export async function handleSchedules({ deps, respond }: CommandContext<CommandByName<"schedules">>): Promise<void> {
  const jobs = await deps.scheduler.list();
  await respondEphemeral(respond, schedulesBlocks(jobs));
}

export async function handleScheduleRun({ deps, respond, parsed }: CommandContext<CommandByName<"schedule_run">>): Promise<void> {
  const result = await deps.scheduler.runNow(parsed.jobId);
  await respondEphemeral(respond, scheduleRunBlocks(result));
}

export async function handleSchedulePause({ deps, respond, parsed }: CommandContext<CommandByName<"schedule_pause">>): Promise<void> {
  const job = await deps.scheduler.setStatus(parsed.jobId, "paused");
  await respondEphemeral(respond, plainBlocks(`Paused scheduled check ${job.id}.`));
}

export async function handleScheduleResume({ deps, respond, parsed }: CommandContext<CommandByName<"schedule_resume">>): Promise<void> {
  const job = await deps.scheduler.setStatus(parsed.jobId, "active");
  await respondEphemeral(respond, plainBlocks(`Resumed scheduled check ${job.id}.`));
}
