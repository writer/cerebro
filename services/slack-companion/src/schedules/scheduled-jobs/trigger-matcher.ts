import {
  annotateMainDependency,
  annotateSpan,
  hashTelemetryId,
  withTelemetrySpan,
} from "../../telemetry.js";
import type { ScheduleTrigger } from "../schedule-parser.js";
import { runtimeLooksUnhealthy } from "./context.js";
import type { ScheduledJobRecord, ScheduledJobServiceDeps } from "./types.js";

export class ScheduledJobTriggerMatcher {
  constructor(
    private readonly deps: ScheduledJobServiceDeps,
    private readonly now: () => Date,
  ) {}

  async isDue(job: ScheduledJobRecord): Promise<boolean> {
    const now = this.now();
    const scheduleDue = Boolean(job.nextRunAt && Date.parse(job.nextRunAt) <= now.getTime());
    const triggerDue = job.trigger ? await this.triggerMatches(job.trigger, job) : false;
    return scheduleDue || triggerDue;
  }

  private async triggerMatches(trigger: ScheduleTrigger, job: ScheduledJobRecord): Promise<boolean> {
    return withTelemetrySpan("schedule.trigger.check", {
      component: "scheduled-jobs",
      operation: "trigger_check",
      "schedule.job_id_hash": hashTelemetryId(job.id),
      "schedule.trigger.type": trigger.type,
    }, async (span) => {
      if (job.lastRunAt && this.now().getTime() - Date.parse(job.lastRunAt) < trigger.cooldownMs) {
        annotateSpan(span, { "schedule.trigger.match": false, "schedule.trigger.reason": "cooldown" });
        return false;
      }
      if (trigger.type === "runtime_health") {
        const runtimes = await this.deps.cerebro.listRuntimeHealth({ runtimeId: trigger.runtimeId, limit: 1 });
        const matched = runtimes.some((runtime) => runtimeLooksUnhealthy(runtime));
        annotateSpan(span, { "schedule.trigger.match": matched, "runtime.count": runtimes.length });
        annotateMainDependency("cerebro", "scheduled-jobs", "runtime_health", "completed", { "runtime.count": runtimes.length });
        return matched;
      }
      const counts = await Promise.all(trigger.runtimeIds.map(async (runtimeId) => {
        const findings = await this.deps.cerebro.listFindings(runtimeId, { limit: trigger.threshold + 1 });
        return findings.length;
      }));
      const findingCount = counts.reduce((sum, count) => sum + count, 0);
      const matched = findingCount > trigger.threshold;
      annotateSpan(span, {
        "schedule.trigger.match": matched,
        "finding.count": findingCount,
        "finding.threshold": trigger.threshold,
        "runtime.count": trigger.runtimeIds.length,
      });
      annotateMainDependency("cerebro", "scheduled-jobs", "list_findings", "completed", { "finding.count": findingCount });
      return matched;
    }, {
      statusForResult: (matched) => matched ? "matched" : "miss",
      errorEventName: "schedule.trigger_check.error",
    });
  }
}
