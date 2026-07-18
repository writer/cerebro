import { trimForSlack } from "../../slack/format.js";
import { nextRunAtFor } from "../schedule-parser.js";
import type { ScheduledJobContextResult, ScheduledJobRecord, ScheduledJobRunResult } from "./types.js";

export const SCHEDULE_FAILURE_BLOCK_THRESHOLD = 3;

export function nextJobState(job: ScheduledJobRecord, status: "completed" | "failed", summary: string, now: Date): ScheduledJobRecord {
  const onceDone = job.schedule?.kind === "once";
  const consecutiveFailures = status === "failed" ? (job.consecutiveFailures ?? 0) + 1 : 0;
  const blocked = status === "failed" && consecutiveFailures >= SCHEDULE_FAILURE_BLOCK_THRESHOLD;
  const nextStatus = onceDone && status === "completed"
    ? "completed"
    : blocked
      ? "blocked"
      : status === "completed" && job.status === "blocked"
        ? "active"
        : job.status;
  return {
    ...job,
    status: nextStatus,
    lastRunAt: now.toISOString(),
    lastStatus: status,
    lastSummary: trimForSlack(summary, 1000),
    nextRunAt: nextStatus === "blocked" || onceDone ? undefined : nextRunAtFor(job.schedule, now),
    updatedAt: now.toISOString(),
    consecutiveFailures,
    lastFailureAt: status === "failed" ? now.toISOString() : undefined,
    lastError: status === "failed" ? trimForSlack(summary, 500) : undefined,
    warnings: blocked
      ? unique([...job.warnings, `Paused after ${SCHEDULE_FAILURE_BLOCK_THRESHOLD} failed runs. Resume after fixing the job.`])
      : job.warnings,
  };
}

export function jobSummary(job: ScheduledJobRecord, status: "completed" | "failed", steps: ScheduledJobRunResult["stepResults"]): string {
  const completed = steps.filter((step) => step.status === "completed").length;
  const failed = steps.filter((step) => step.status === "failed").length;
  return trimForSlack(`${job.description}: ${status}. Completed ${completed} step(s); failed ${failed} step(s).`, 900);
}

export function scheduledJobMessage(
  job: ScheduledJobRecord,
  summary: string,
  steps: ScheduledJobRunResult["stepResults"],
  contextResults: ScheduledJobContextResult[],
): string {
  const lines = [
    `Scheduled check ${job.id}`,
    summary,
    contextResults.length > 0
      ? `Context: ${contextResults.map((context) => `${context.title} ${context.status}`).join("; ")}`
      : "",
    ...steps.slice(0, 6).map((step) => `- ${step.title}: ${trimForSlack(step.summary, 260)}`),
  ];
  return trimForSlack(lines.filter(Boolean).join("\n"), 3000);
}

export function shortError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return trimForSlack(message.replace(/\s+/g, " ").trim(), 300);
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}
