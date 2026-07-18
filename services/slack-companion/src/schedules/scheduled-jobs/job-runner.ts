import { logger } from "../../logger.js";
import {
  annotateSpan,
  hashTelemetryId,
  recordMetric,
  slackTelemetryAttributes,
  telemetryEvent,
  withTelemetrySpan,
} from "../../telemetry.js";
import { jobSummary, nextJobState, scheduledJobMessage } from "./output.js";
import { scheduleRecordTelemetry } from "./telemetry.js";
import type { ScheduledJobContextCollector } from "./context-collector.js";
import type { ScheduledJobStepRunner } from "./step-runner.js";
import type { ScheduledJobStore } from "./store.js";
import type {
  ScheduledJobContextResult,
  ScheduledJobRecord,
  ScheduledJobRunResult,
  ScheduledJobServiceDeps,
} from "./types.js";

export async function runScheduledJob(input: {
  deps: ScheduledJobServiceDeps;
  contextCollector: ScheduledJobContextCollector;
  stepRunner: ScheduledJobStepRunner;
  store: ScheduledJobStore;
  now: () => Date;
  slackClient?: any;
  job: ScheduledJobRecord;
  reason: string;
}): Promise<ScheduledJobRunResult> {
  const { deps, job, reason } = input;
  return withTelemetrySpan("schedule.run", {
    main: true,
    component: "scheduled-jobs",
    operation: "run",
    reason,
    ...scheduleRecordTelemetry(job),
    ...slackTelemetryAttributes({ channelId: job.channelId, userId: job.createdBy.slackUserId }),
  }, async (span) => {
    const contextResults = await input.contextCollector.collect(job);
    const stepRun = await input.stepRunner.run(job, contextResults);
    const status: ScheduledJobRunResult["status"] = stepRun.failedCount > 0 ? "failed" : "completed";
    const summary = jobSummary(job, status, stepRun.stepResults);
    await postRunResult(input.slackClient, job, summary, stepRun.stepResults, contextResults)
      .catch((error) => logger.warn("scheduled job Slack post failed", { jobId: job.id, error: String(error) }));
    const updated = nextJobState(job, status, summary, input.now());
    await input.store.put(updated);
    recordBlockedSchedule(job, updated);
    await deps.notes.record({
      kind: status === "completed" ? "maintenance" : "failure",
      title: `Scheduled check ${job.id}`,
      summary,
      details: [
        ...contextResults.map((context) => `Context ${context.title}: ${context.status} - ${context.summary}`),
        ...stepRun.stepResults.map((step) => `${step.title}: ${step.status} - ${step.summary}`),
      ].join("\n"),
      tags: ["scheduled-check", reason, status],
      channelId: job.channelId,
      outcome: status,
    }).catch((error) => logger.warn("daily note write failed", { error: String(error), kind: "scheduled-check" }));
    annotateSpan(span, {
      "schedule.run.status": status,
      "schedule.context.completed_count": contextResults.filter((context) => context.status === "completed").length,
      "schedule.context.failed_count": contextResults.filter((context) => context.status === "failed").length,
      "schedule.step.completed_count": stepRun.completedCount,
      "schedule.step.failed_count": stepRun.failedCount,
    });
    recordMetric("cerebro_slack_companion_schedule_runs_total", {
      status,
      reason,
      schedule_kind: job.schedule?.kind ?? "none",
      trigger_type: job.trigger?.type ?? "none",
    }, 1);
    return { job: updated, status, summary, contextResults, stepResults: stepRun.stepResults };
  }, {
    main: true,
    statusForResult: (result) => result.status,
    errorEventName: "schedule.run.error",
  });
}

async function postRunResult(
  slackClient: any,
  job: ScheduledJobRecord,
  summary: string,
  steps: ScheduledJobRunResult["stepResults"],
  contextResults: ScheduledJobContextResult[],
): Promise<void> {
  if (!slackClient || !job.channelId) return;
  await slackClient.chat.postMessage({
    channel: job.channelId,
    text: scheduledJobMessage(job, summary, steps, contextResults),
    unfurl_links: false,
    unfurl_media: false,
  });
}

function recordBlockedSchedule(job: ScheduledJobRecord, updated: ScheduledJobRecord): void {
  if (updated.status !== "blocked") return;
  telemetryEvent("schedule.job.blocked", {
    component: "scheduled-jobs",
    operation: "run",
    "schedule.job_id_hash": hashTelemetryId(updated.id),
    "schedule.consecutive_failures": updated.consecutiveFailures ?? 0,
  });
  recordMetric("cerebro_slack_companion_schedule_jobs_blocked_total", {
    schedule_kind: job.schedule?.kind ?? "none",
    trigger_type: job.trigger?.type ?? "none",
  }, 1);
}
