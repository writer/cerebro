import type { ScheduledJobRecord, ScheduledJobRunResult } from "../../schedules/scheduled-jobs/index.js";
import { scheduleSummary, triggerSummary } from "../../schedules/schedule-parser.js";
import { trimForSlack } from "../format.js";
import { context, escapeMrkdwn, header, listSection, section, type SlackBlock } from "./primitives.js";

export function scheduleCreatedBlocks(job: ScheduledJobRecord): SlackBlock[] {
  return [
    header("Scheduled check created"),
    section(`*${escapeMrkdwn(job.id)}*\n${escapeMrkdwn(job.description)}`),
    context([
      scheduleSummary(job.schedule),
      triggerSummary(job.trigger),
      job.channelId ? `Channel: ${job.channelId}` : "Channel: not set",
      job.nextRunAt ? `Next run: ${job.nextRunAt}` : "Next run: trigger only",
    ]),
    ...listSection("Steps", job.steps.map((step) => `${step.title}${step.dependsOn.length ? ` after ${step.dependsOn.join(", ")}` : ""}`)),
    ...listSection("Notes", job.warnings),
  ];
}

export function schedulesBlocks(jobs: ScheduledJobRecord[]): SlackBlock[] {
  if (jobs.length === 0) {
    return [header("Scheduled checks"), section("No scheduled checks are configured.")];
  }
  return [
    header("Scheduled checks"),
    ...jobs.slice(0, 10).flatMap((job) => [
      section(`*${escapeMrkdwn(job.id)}* · ${escapeMrkdwn(job.status)}\n${escapeMrkdwn(job.description)}`),
      context([
        scheduleSummary(job.schedule),
        triggerSummary(job.trigger),
        job.nextRunAt ? `Next run: ${job.nextRunAt}` : "Next run: trigger only",
        job.lastStatus ? `Last run: ${job.lastStatus}` : "Last run: none",
      ]),
    ]),
  ];
}

export function scheduleRunBlocks(result: ScheduledJobRunResult): SlackBlock[] {
  return [
    header("Scheduled check run"),
    section(`*${escapeMrkdwn(result.job.id)}* · ${escapeMrkdwn(result.status)}\n${escapeMrkdwn(trimForSlack(result.summary, 900))}`),
    ...listSection("Steps", result.stepResults.map((step) => `${step.title}: ${step.status} - ${trimForSlack(step.summary, 260)}`)),
  ];
}
