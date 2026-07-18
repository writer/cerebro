import type { AppConfig } from "../config/index.js";
import { logger } from "../logger.js";
import { recordMetric, telemetryEvent } from "../telemetry.js";
import type { AutonomyGoalService } from "./goal-service.js";
import type { AutonomousGoalRecord } from "./goals.js";
import { shortError, unique } from "./runner-utils.js";

export const AUTONOMY_RUNNER_FAILURE_BLOCK_THRESHOLD = 3;

export async function recordRunnerAdvanceFailure(input: {
  config: AppConfig;
  goals: AutonomyGoalService;
  goal: AutonomousGoalRecord;
  error: unknown;
  now: () => Date;
}): Promise<string> {
  const summary = shortError(input.error);
  const owner = ownerLabel(input.goal);
  const attempt = consecutiveEquivalentFailures(input.goal, summary) + 1;
  recordMetric("cerebro_slack_companion_autonomy_runner_failures_total", { capability: input.goal.capabilityId }, 1);
  if (attempt >= 3) {
    const blocker = `Runner stopped after ${attempt} equivalent failures. Owner: ${owner}. Action: inspect the runner error, then resume the goal after the cause is fixed. Last error: ${summary}`;
    logger.error("autonomy goal blocked after repeated runner failures", {
      goalId: input.goal.id,
      capability: input.goal.capabilityId,
      equivalentFailureCount: attempt,
      error: summary,
    });
    telemetryEvent("autonomy.runner.blocked", {
      component: "autonomy-runner",
      operation: "tick",
      "goal.id": input.goal.id,
      "goal.capability": input.goal.capabilityId,
      "autonomy.failure.equivalent_count": attempt,
    });
    recordMetric("cerebro_slack_companion_autonomy_runner_blocked_total", { capability: input.goal.capabilityId }, 1);
    await input.goals.update(input.goal.id, {
      status: "blocked",
      nextWakeAt: null,
      blockers: unique([...input.goal.blockers, blocker]).slice(-8),
    }).catch(() => undefined);
    await input.goals.appendLog(input.goal.id, {
      kind: "blocker_found",
      summary: `Runner stopped after ${attempt} equivalent failures.`,
      details: `Owner: ${owner}\nAction: inspect the runner error, then resume the goal after the cause is fixed.\nEquivalent failure count: ${attempt}\nError: ${summary}`,
    }).catch(() => undefined);
    return `Goal blocked after ${attempt} equivalent failures: ${summary}`;
  }

  const retryDelayMs = retryDelay(input.config.autonomy.runnerPollIntervalMs, attempt);
  const retryAt = new Date(input.now().getTime() + retryDelayMs).toISOString();
  logger.warn("autonomy goal advance failed", {
    goalId: input.goal.id,
    capability: input.goal.capabilityId,
    equivalentFailureCount: attempt,
    error: summary,
    retryAt,
  });
  telemetryEvent("autonomy.runner.retry_scheduled", {
    component: "autonomy-runner",
    operation: "tick",
    "goal.id": input.goal.id,
    "goal.capability": input.goal.capabilityId,
    "autonomy.retry_at": retryAt,
    "autonomy.retry.delay_ms": retryDelayMs,
    "autonomy.failure.equivalent_count": attempt,
  });
  await input.goals.update(input.goal.id, {
    status: "active",
    nextWakeAt: retryAt,
    blockers: unique([...input.goal.blockers, `Runner retry ${attempt} of 2 scheduled. Owner: ${owner}. Action: inspect the runner error if this repeats. Last error: ${summary}`]).slice(-8),
  }).catch(() => undefined);
  await input.goals.appendLog(input.goal.id, {
    kind: "blocker_found",
    summary: "Runner could not advance the goal; retry scheduled.",
    details: `Owner: ${owner}\nAction: inspect the runner error if this repeats.\nEquivalent failure count: ${attempt}\nRetry at: ${retryAt}\nError: ${summary}`,
  }).catch(() => undefined);
  return summary;
}

function consecutiveEquivalentFailures(goal: AutonomousGoalRecord, errorSummary: string): number {
  let count = 0;
  for (const entry of [...goal.workLog].reverse()) {
    if (entry.kind !== "blocker_found" || entry.summary !== "Runner could not advance the goal; retry scheduled.") break;
    const recorded = entry.details?.split("\n").find((line) => line.startsWith("Error: "))?.slice("Error: ".length);
    if (recorded !== errorSummary) break;
    count += 1;
  }
  return count;
}

function retryDelay(pollIntervalMs: number, attempt: number): number {
  const base = Math.max(10_000, pollIntervalMs);
  return Math.min(15 * 60_000, base * (2 ** Math.max(0, attempt - 1)));
}

function ownerLabel(goal: AutonomousGoalRecord): string {
  return goal.createdBy.displayName || goal.createdBy.actorId || goal.createdBy.slackUserId || "operator";
}
