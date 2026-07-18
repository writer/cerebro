import { recordGauge } from "../../telemetry.js";
import type { ScheduledJobRecord, ScheduledJobServiceStats } from "./types.js";

export function scheduledJobStats(input: {
  enabled: boolean;
  store: "dynamodb" | "memory";
  jobs: ScheduledJobRecord[];
  now: Date;
  activeRuns: number;
  maxConcurrent: number;
  lastTickAt?: string;
  lastTickStatus?: "completed" | "failed";
  lastTickError?: string;
}): ScheduledJobServiceStats {
  const nowMs = input.now.getTime();
  const activeJobs = input.jobs.filter((job) => job.status === "active");
  const dueAges = activeJobs
    .map((job) => job.nextRunAt ? nowMs - Date.parse(job.nextRunAt) : undefined)
    .filter(isNonNegativeNumber);
  return {
    enabled: input.enabled,
    store: input.store,
    total: input.jobs.length,
    active: activeJobs.length,
    paused: input.jobs.filter((job) => job.status === "paused").length,
    completed: input.jobs.filter((job) => job.status === "completed").length,
    blocked: input.jobs.filter((job) => job.status === "blocked").length,
    dueCount: dueAges.length,
    oldestDueAgeMs: dueAges.length > 0 ? Math.max(...dueAges) : 0,
    triggerOnlyCount: activeJobs.filter((job) => job.trigger && !job.nextRunAt).length,
    activeRuns: input.activeRuns,
    maxConcurrent: input.maxConcurrent,
    lastTickAt: input.lastTickAt,
    lastTickStatus: input.lastTickStatus,
    lastTickError: input.lastTickError,
  };
}

export function recordScheduleGauges(stats: ScheduledJobServiceStats): void {
  recordGauge("cerebro_slack_companion_schedule_jobs", { status: "active" }, stats.active);
  recordGauge("cerebro_slack_companion_schedule_jobs", { status: "paused" }, stats.paused);
  recordGauge("cerebro_slack_companion_schedule_jobs", { status: "blocked" }, stats.blocked);
  recordGauge("cerebro_slack_companion_schedule_jobs", { status: "completed" }, stats.completed);
  recordGauge("cerebro_slack_companion_schedule_due_count", {}, stats.dueCount);
  recordGauge("cerebro_slack_companion_schedule_oldest_due_age_seconds", {}, stats.oldestDueAgeMs / 1000);
  recordGauge("cerebro_slack_companion_schedule_trigger_only_jobs", {}, stats.triggerOnlyCount);
  recordGauge("cerebro_slack_companion_schedule_active_runs", {}, stats.activeRuns);
  recordGauge("cerebro_slack_companion_schedule_max_concurrent", {}, stats.maxConcurrent);
  recordGauge("cerebro_slack_companion_schedule_last_tick_status", {}, stats.lastTickStatus === "failed" ? 1 : 0);
}

function isNonNegativeNumber(value: number | undefined): value is number {
  return value !== undefined && Number.isFinite(value) && value >= 0;
}
