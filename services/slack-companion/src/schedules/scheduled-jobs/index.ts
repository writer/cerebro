import type { SlackActor } from "../../auth.js";
import { logger } from "../../logger.js";
import {
  annotateMainPhase,
  annotateSpan,
  captureTelemetryError,
  hashTelemetryId,
  recordMetric,
  slackTelemetryAttributes,
  telemetryErrorKind,
  withTelemetrySpan,
} from "../../telemetry.js";
import { type ScheduledJobDraft, type ScheduledJobStatus } from "../schedule-parser.js";
import { SchedulePlannerService, type SchedulePlanner } from "../schedule-planner.js";
import { ScheduledJobContextCollector } from "./context-collector.js";
import { reviewedScheduleDraft } from "./drafts.js";
import { runScheduledJob } from "./job-runner.js";
import { shortError } from "./output.js";
import { recordScheduleGauges, scheduledJobStats } from "./stats.js";
import { ScheduledJobStore } from "./store.js";
import { scheduleRecordTelemetry } from "./telemetry.js";
import { ScheduledJobStepRunner } from "./step-runner.js";
import type {
  ScheduledJobRecord,
  ScheduledJobRunResult,
  ScheduledJobServiceDeps,
  ScheduledJobServiceOptions,
  ScheduledJobServiceStats,
} from "./types.js";
import { ScheduledJobTriggerMatcher } from "./trigger-matcher.js";

export type { ScheduledJobContextResult, ScheduledJobRecord, ScheduledJobRunResult, ScheduledJobServiceDeps, ScheduledJobServiceOptions } from "./types.js";
export type { ScheduledJobServiceStats } from "./types.js";

export class ScheduledJobService {
  private readonly store: ScheduledJobStore;
  private readonly now: () => Date;
  private readonly planner: SchedulePlanner;
  private readonly contextCollector: ScheduledJobContextCollector;
  private readonly stepRunner: ScheduledJobStepRunner;
  private readonly triggerMatcher: ScheduledJobTriggerMatcher;
  private interval?: NodeJS.Timeout;
  private slackClient?: any;
  private activeRuns = 0;
  private lastTickAt?: string;
  private lastTickStatus?: "completed" | "failed";
  private lastTickError?: string;

  constructor(
    private readonly deps: ScheduledJobServiceDeps,
    options: ScheduledJobServiceOptions = {},
  ) {
    this.now = options.now ?? (() => new Date());
    this.planner = options.planner ?? new SchedulePlannerService(deps.config);
    this.store = new ScheduledJobStore(deps.config, { dynamo: options.dynamo, now: this.now });
    this.contextCollector = new ScheduledJobContextCollector(deps);
    this.stepRunner = new ScheduledJobStepRunner(deps, this.now);
    this.triggerMatcher = new ScheduledJobTriggerMatcher(deps, this.now);
  }

  setSlackClient(client: any): void {
    this.slackClient = client;
  }

  start(client?: any): void {
    if (client) this.setSlackClient(client);
    if (!this.deps.config.schedules.enabled || this.interval) return;
    this.interval = setInterval(() => {
      void this.tick().catch((error) => logger.warn("scheduled job tick failed", { error: String(error) }));
    }, this.deps.config.schedules.pollIntervalMs);
    this.interval.unref?.();
    void this.tick().catch((error) => logger.warn("scheduled job initial tick failed", { error: String(error) }));
  }

  stop(): void {
    if (this.interval) clearInterval(this.interval);
    this.interval = undefined;
  }

  async createFromText(input: {
    text: string;
    actor: SlackActor;
    channelId?: string;
  }): Promise<ScheduledJobRecord> {
    return withTelemetrySpan("schedule.create", {
      main: true,
      component: "scheduled-jobs",
      operation: "create",
      "schedule.source_text.length": input.text.length,
      "schedule.actor_id_hash": hashTelemetryId(input.actor.actorId),
      ...slackTelemetryAttributes({ channelId: input.channelId, userId: input.actor.slackUserId }),
    }, async (span) => {
    const draft = await this.planner.plan({
      text: input.text,
      actor: input.actor,
      channelId: input.channelId,
      now: this.now(),
    });
    const record = await this.store.create(draft, input.actor);
    annotateSpan(span, scheduleRecordTelemetry(record));
    recordMetric("cerebro_slack_companion_schedules_created_total", {
      schedule_kind: record.schedule?.kind ?? "none",
      trigger_type: record.trigger?.type ?? "none",
    }, 1);
    return record;
    }, { main: true, errorEventName: "schedule.create.error" });
  }

  async createFromDraft(input: { draft: ScheduledJobDraft; actor: SlackActor }): Promise<ScheduledJobRecord> {
    return withTelemetrySpan("schedule.create_from_draft", {
      main: true,
      component: "scheduled-jobs",
      operation: "create_from_draft",
      "schedule.description.length": input.draft.description.length,
      "schedule.actor_id_hash": hashTelemetryId(input.actor.actorId),
      ...slackTelemetryAttributes({ channelId: input.draft.channelId, userId: input.actor.slackUserId }),
    }, async (span) => {
      const draft = reviewedScheduleDraft(input.draft, this.now());
      const record = await this.store.create(draft, input.actor);
      annotateSpan(span, scheduleRecordTelemetry(record));
      recordMetric("cerebro_slack_companion_schedules_created_total", {
        schedule_kind: record.schedule?.kind ?? "none",
        trigger_type: record.trigger?.type ?? "none",
      }, 1);
      return record;
    }, { main: true, errorEventName: "schedule.create_from_draft.error" });
  }

  async list(): Promise<ScheduledJobRecord[]> {
    return this.store.list();
  }

  async get(jobId: string): Promise<ScheduledJobRecord | undefined> {
    return this.store.get(jobId);
  }

  async setStatus(jobId: string, status: ScheduledJobStatus): Promise<ScheduledJobRecord> {
    const job = await this.requiredJob(jobId);
    const updated = status === "active"
      ? { ...job, status, updatedAt: this.now().toISOString(), consecutiveFailures: 0, lastFailureAt: undefined, lastError: undefined }
      : { ...job, status, updatedAt: this.now().toISOString() };
    await this.store.put(updated);
    return updated;
  }

  async runNow(jobId: string, reason = "manual"): Promise<ScheduledJobRunResult> {
    const job = await this.requiredJob(jobId);
    return this.runJob(job, reason);
  }

  async tick(): Promise<void> {
    if (!this.deps.config.schedules.enabled) return;
    const tickStartedAt = this.now().toISOString();
    try {
      await withTelemetrySpan("schedule.tick", {
      main: true,
      component: "scheduled-jobs",
      operation: "tick",
      "schedule.active_runs": this.activeRuns,
      "schedule.max_concurrent": this.deps.config.schedules.maxConcurrent,
      "schedule.store": this.deps.config.schedules.tableName ? "dynamodb" : "memory",
    }, async (span) => {
    const jobs = await this.store.list();
    annotateSpan(span, { "schedule.job.count": jobs.length });
    const baselineStats = scheduledJobStats({
      enabled: this.deps.config.schedules.enabled,
      store: this.deps.config.schedules.tableName ? "dynamodb" : "memory",
      jobs,
      now: this.now(),
      activeRuns: this.activeRuns,
      maxConcurrent: this.deps.config.schedules.maxConcurrent,
      lastTickAt: tickStartedAt,
      lastTickStatus: "completed",
    });
    const runs: Promise<void>[] = [];
    let dueCount = 0;
    for (const job of jobs) {
      if (this.activeRuns >= this.deps.config.schedules.maxConcurrent) break;
      if (job.status !== "active") continue;
      const due = await this.triggerMatcher.isDue(job).catch((error) => {
        captureTelemetryError("schedule.due_check.error", error, { component: "scheduled-jobs", operation: "is_due" });
        annotateMainPhase("schedule.due_check", "failed", { error_kind: telemetryErrorKind(error) });
        logger.warn("scheduled job due check failed", { jobId: job.id, error: String(error) });
        return false;
      });
      if (!due) continue;
      dueCount += 1;
      this.activeRuns += 1;
      runs.push(this.runJob(job, "scheduled")
        .then(() => undefined)
        .catch((error) => {
          captureTelemetryError("schedule.run.error", error, { component: "scheduled-jobs", operation: "run_job" });
          logger.warn("scheduled job run failed", { jobId: job.id, error: String(error) });
        })
        .finally(() => {
          this.activeRuns -= 1;
        }));
    }
    annotateSpan(span, {
      "schedule.due.count": dueCount,
      "schedule.run.started_count": runs.length,
    });
    recordScheduleGauges({ ...baselineStats, dueCount });
    await Promise.all(runs);
    }, { main: true, errorEventName: "schedule.tick.error" });
      this.lastTickAt = tickStartedAt;
      this.lastTickStatus = "completed";
      this.lastTickError = undefined;
    } catch (error) {
      this.lastTickAt = tickStartedAt;
      this.lastTickStatus = "failed";
      this.lastTickError = shortError(error);
      throw error;
    }
  }

  async stats(): Promise<ScheduledJobServiceStats> {
    if (!this.deps.config.schedules.enabled) {
      return this.buildStats([]);
    }
    const stats = this.buildStats(await this.store.list());
    recordScheduleGauges(stats);
    return stats;
  }

  private async runJob(job: ScheduledJobRecord, reason: string): Promise<ScheduledJobRunResult> {
    return runScheduledJob({
      deps: this.deps,
      contextCollector: this.contextCollector,
      stepRunner: this.stepRunner,
      store: this.store,
      now: this.now,
      slackClient: this.slackClient,
      job,
      reason,
    });
  }

  private buildStats(jobs: ScheduledJobRecord[]): ScheduledJobServiceStats {
    return scheduledJobStats({
      enabled: this.deps.config.schedules.enabled,
      store: this.deps.config.schedules.tableName ? "dynamodb" : "memory",
      jobs,
      now: this.now(),
      activeRuns: this.activeRuns,
      maxConcurrent: this.deps.config.schedules.maxConcurrent,
      lastTickAt: this.lastTickAt,
      lastTickStatus: this.lastTickStatus,
      lastTickError: this.lastTickError,
    });
  }

  private async requiredJob(jobId: string): Promise<ScheduledJobRecord> {
    const job = await this.store.get(jobId);
    if (!job) throw new Error(`No scheduled job matched ${jobId}.`);
    return job;
  }
}
