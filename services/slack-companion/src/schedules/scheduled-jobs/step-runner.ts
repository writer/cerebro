import {
  annotateMainPhase,
  annotateSpan,
  hashTelemetryId,
  withTelemetrySpan,
} from "../../telemetry.js";
import {
  contextProviderSummary,
  scheduleSummary,
  triggerSummary,
} from "../schedule-parser.js";
import { scheduleContextPromptBlock } from "./context.js";
import type {
  ScheduledJobContextResult,
  ScheduledJobRecord,
  ScheduledJobRunResult,
  ScheduledJobServiceDeps,
} from "./types.js";

type ScheduledStepResult = ScheduledJobRunResult["stepResults"][number];

export interface ScheduledJobStepRunOutcome {
  stepResults: ScheduledStepResult[];
  completedCount: number;
  failedCount: number;
}

export class ScheduledJobStepRunner {
  constructor(
    private readonly deps: ScheduledJobServiceDeps,
    private readonly now: () => Date,
  ) {}

  async run(
    job: ScheduledJobRecord,
    contextResults: ScheduledJobContextResult[],
  ): Promise<ScheduledJobStepRunOutcome> {
    const stepResults: ScheduledStepResult[] = [];
    const completed = new Set<string>();
    const failed = new Set<string>();
    const pending = new Map(job.steps.map((step) => [step.id, step]));

    while (pending.size > 0) {
      const ready = [...pending.values()].filter((step) => step.dependsOn.every((id) => completed.has(id)));
      if (ready.length === 0) {
        for (const step of pending.values()) {
          failed.add(step.id);
          stepResults.push({
            stepId: step.id,
            title: step.title,
            status: "failed",
            summary: "Step dependency did not complete.",
          });
        }
        break;
      }
      const results = await Promise.all(ready.map((step) => this.runStep(job, step, contextResults).catch((error) => ({
        stepId: step.id,
        title: step.title,
        status: "failed" as const,
        summary: error instanceof Error ? error.message : String(error),
      }))));
      for (const result of results) {
        pending.delete(result.stepId);
        stepResults.push(result);
        if (result.status === "completed") {
          completed.add(result.stepId);
        } else {
          failed.add(result.stepId);
        }
      }
      for (const step of [...pending.values()]) {
        if (step.dependsOn.some((id) => failed.has(id))) {
          pending.delete(step.id);
          failed.add(step.id);
          stepResults.push({
            stepId: step.id,
            title: step.title,
            status: "failed",
            summary: "Step skipped because a dependency failed.",
          });
        }
      }
    }

    return {
      stepResults,
      completedCount: completed.size,
      failedCount: failed.size,
    };
  }

  private async runStep(
    job: ScheduledJobRecord,
    step: ScheduledJobRecord["steps"][number],
    contextResults: ScheduledJobContextResult[],
  ): Promise<ScheduledStepResult> {
    return withTelemetrySpan("schedule.step.run", {
      component: "scheduled-jobs",
      operation: "step_run",
      "schedule.job_id_hash": hashTelemetryId(job.id),
      "schedule.step_id_hash": hashTelemetryId(step.id),
      "schedule.step.skill_id": step.skillId,
      "schedule.step.depends_on.count": step.dependsOn.length,
      "schedule.context.count": contextResults.length,
    }, async (span) => {
      const answer = await this.deps.skills.runPrompt({
        prompt: [
          step.prompt,
          "",
          `Scheduled job id: ${job.id}.`,
          `Schedule: ${scheduleSummary(job.schedule)}.`,
          job.trigger ? `Trigger: ${triggerSummary(job.trigger)}.` : "",
          `Pre-run context providers: ${contextProviderSummary(job.contextProviders)}.`,
          scheduleContextPromptBlock(contextResults),
        ].filter(Boolean).join("\n"),
        channelId: job.channelId ?? this.deps.config.schedules.defaultChannelId ?? "scheduled-job",
        userId: job.createdBy.slackUserId,
        ts: `scheduled-${job.id}-${step.id}-${this.now().getTime()}`,
      });
      annotateSpan(span, {
        "assistant.answer.source": answer.source,
        "assistant.answer.message_count": answer.messages.length,
        "assistant.answer.evidence_count": answer.evidence.length,
        "assistant.answer.research_count": answer.research.length,
      });
      const result: ScheduledStepResult = {
        stepId: step.id,
        title: step.title,
        status: "completed",
        summary: answer.messages[0] ?? answer.answer,
      };
      return result;
    }, {
      statusForResult: (result) => result.status,
      errorEventName: "schedule.step.error",
    }).then((result) => {
      annotateMainPhase(`schedule.step.${step.id}`, result.status, {
        "schedule.step_id_hash": hashTelemetryId(step.id),
        "schedule.step.skill_id": step.skillId,
      });
      return result;
    });
  }
}
