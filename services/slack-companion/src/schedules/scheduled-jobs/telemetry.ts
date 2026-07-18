import { hashTelemetryId } from "../../telemetry.js";
import type { ScheduledJobContextResult, ScheduledJobRecord } from "./types.js";

export function scheduleRecordTelemetry(job: ScheduledJobRecord): Record<string, unknown> {
  return {
    "schedule.job_id_hash": hashTelemetryId(job.id),
    "schedule.status": job.status,
    "schedule.kind": job.schedule?.kind ?? "none",
    "schedule.trigger.type": job.trigger?.type ?? "none",
    "schedule.step.count": job.steps.length,
    "schedule.context_provider.count": (job.contextProviders ?? []).length,
    "schedule.warning.count": job.warnings.length,
    "schedule.channel.present": Boolean(job.channelId),
    "schedule.next_run.present": Boolean(job.nextRunAt),
  };
}

export function contextResultTelemetry(result: ScheduledJobContextResult): Record<string, unknown> {
  return {
    "schedule.context.provider_id": result.providerId,
    "schedule.context.status": result.status,
    "schedule.context.details_present": result.details !== undefined,
  };
}
