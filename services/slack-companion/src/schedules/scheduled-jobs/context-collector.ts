import { companionSelfContext } from "../../agent/self-context.js";
import {
  annotateMainPhase,
  annotateSpan,
  withTelemetrySpan,
} from "../../telemetry.js";
import type { TelemetrySpan } from "../../telemetry/types.js";
import type { ScheduledContextProviderId } from "../schedule-parser.js";
import {
  compactFinding,
  compactRuntimeHealth,
  contextProviderTitle,
  runtimeIdForHealth,
  runtimeLooksUnhealthy,
} from "./context.js";
import { shortError } from "./output.js";
import { contextResultTelemetry } from "./telemetry.js";
import type { ScheduledJobContextResult, ScheduledJobRecord, ScheduledJobServiceDeps } from "./types.js";

export class ScheduledJobContextCollector {
  constructor(private readonly deps: ScheduledJobServiceDeps) {}

  async collect(job: ScheduledJobRecord): Promise<ScheduledJobContextResult[]> {
    const providers = job.contextProviders ?? [];
    if (providers.length === 0) return [];
    return Promise.all(providers.map((providerId) => this.collectProvider(providerId).catch((error) => ({
      providerId,
      title: contextProviderTitle(providerId),
      status: "failed" as const,
      summary: error instanceof Error ? error.message : String(error),
    }))));
  }

  private async collectProvider(providerId: ScheduledContextProviderId): Promise<ScheduledJobContextResult> {
    return withTelemetrySpan("schedule.context.provider", {
      component: "scheduled-jobs",
      operation: "context_provider",
      "schedule.context.provider_id": providerId,
    }, async (span) => {
      switch (providerId) {
        case "runtime_health_snapshot":
          return this.runtimeHealth(providerId).then((result) => {
            this.annotateProvider(providerId, result, span);
            return result;
          });
        case "open_findings_snapshot":
          return this.openFindings(providerId).then((result) => {
            this.annotateProvider(providerId, result, span);
            return result;
          });
        case "companion_self_context": {
          const result: ScheduledJobContextResult = {
            providerId,
            title: contextProviderTitle(providerId),
            status: "completed",
            summary: "Collected sanitized Slack companion runtime and configuration context.",
            details: companionSelfContext(this.deps.config, [], {
              includeTools: false,
              includeCommands: true,
              includeDebugPlan: true,
            }),
          };
          this.annotateProvider(providerId, result, span);
          return result;
        }
      }
    }, {
      statusForResult: (result) => result.status,
      errorEventName: "schedule.context_provider.error",
    });
  }

  private annotateProvider(providerId: ScheduledContextProviderId, result: ScheduledJobContextResult, span: TelemetrySpan | undefined): void {
    annotateSpan(span, contextResultTelemetry(result));
    annotateMainPhase(`schedule.context.${providerId}`, result.status, contextResultTelemetry(result));
  }

  private async runtimeHealth(providerId: ScheduledContextProviderId): Promise<ScheduledJobContextResult> {
    const runtimeIds = this.deps.config.cerebro.defaultRuntimeIds;
    const health = await this.deps.cerebro.listRuntimeHealth({
      runtimeIds: runtimeIds.length > 0 ? runtimeIds : undefined,
      limit: Math.max(runtimeIds.length, 20),
    });
    const unhealthy = health.filter((runtime) => runtimeLooksUnhealthy(runtime));
    return {
      providerId,
      title: contextProviderTitle(providerId),
      status: "completed",
      summary: `${health.length} runtime(s) returned; ${unhealthy.length} unhealthy or degraded.`,
      details: {
        default_runtime_ids: runtimeIds,
        unhealthy_runtime_ids: unhealthy.map(runtimeIdForHealth).filter(Boolean),
        runtimes: health.slice(0, 20).map(compactRuntimeHealth),
      },
    };
  }

  private async openFindings(providerId: ScheduledContextProviderId): Promise<ScheduledJobContextResult> {
    const runtimeIds = this.deps.config.cerebro.defaultRuntimeIds;
    if (runtimeIds.length === 0) {
      return {
        providerId,
        title: contextProviderTitle(providerId),
        status: "completed",
        summary: "No default runtime ids are configured for an open-finding snapshot.",
        details: { runtimes: [] },
      };
    }
    const runtimeResults = await Promise.all(runtimeIds.map(async (runtimeId) => {
      try {
        const findings = await this.deps.cerebro.listFindings(runtimeId, { limit: 5, order: "priority" });
        return {
          runtime_id: runtimeId,
          status: "completed",
          returned_count: findings.length,
          findings: findings.map(compactFinding),
        };
      } catch (error) {
        return {
          runtime_id: runtimeId,
          status: "failed",
          error: shortError(error),
          findings: [],
        };
      }
    }));
    const returned = runtimeResults.reduce((sum, runtime) => sum + runtime.findings.length, 0);
    const failures = runtimeResults.filter((runtime) => runtime.status === "failed").length;
    return {
      providerId,
      title: contextProviderTitle(providerId),
      status: failures === runtimeResults.length ? "failed" : "completed",
      summary: `${returned} open finding sample(s) returned across ${runtimeResults.length} runtime(s); ${failures} runtime lookup(s) failed.`,
      details: { runtimes: runtimeResults },
    };
  }
}
