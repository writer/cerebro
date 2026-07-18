import type { RuntimeCodeGithubChecksInput, RuntimeCodeGithubPrStatusInput } from "../code/runtime-code.js";
import type { AppConfig } from "../config/index.js";
import { trimForSlack } from "../slack/format.js";
import type { AutonomyCapabilityDefinition } from "./capabilities.js";
import { githubMonitorDecision, githubMonitorTarget, githubMonitorTargetLabel, type GithubMonitorTarget } from "./github-monitor.js";
import type { AutonomyGoalService } from "./goal-service.js";
import type { AutonomyPlanStep, AutonomousGoalRecord } from "./goals.js";
import { updateStep } from "./runner-plan.js";
import { shortError, unique } from "./runner-utils.js";

export interface AutonomyGithubMonitorClient {
  githubPullRequestStatus(input: RuntimeCodeGithubPrStatusInput): Promise<Record<string, unknown>>;
  githubChecksStatus(input: RuntimeCodeGithubChecksInput): Promise<Record<string, unknown>>;
}

export interface GithubMonitorAdvanceResult {
  goalId: string;
  status: "advanced" | "claimed_elsewhere" | "skipped" | "failed";
  summary: string;
}

export async function advanceGithubMonitorStep(input: {
  goal: AutonomousGoalRecord;
  capability: AutonomyCapabilityDefinition;
  step: AutonomyPlanStep;
  startedAt: string;
  goals: AutonomyGoalService;
  code: AutonomyGithubMonitorClient;
  config: AppConfig;
  now: () => Date;
  waitForMerge?: boolean;
}): Promise<GithubMonitorAdvanceResult> {
  const { goal, capability, step, startedAt, goals, code, config, now, waitForMerge = false } = input;
  const target = githubMonitorTarget(goal);
  if (!target) {
    await goals.appendToolRun(goal.id, {
      toolId: "autonomy.github_monitor",
      toolName: "GitHub monitor",
      status: "skipped",
      reason: "No PR URL, PR number, branch, ref, or commit was attached to the goal.",
      requestSummary: `${capability.id}: ${goal.objective}`,
      responseSummary: "Add a GitHub PR URL, PR number, branch, ref, or commit to the goal so Cerebro can watch checks.",
      startedAt,
      completedAt: now().toISOString(),
    });
    const updated = await goals.update(goal.id, {
      currentPlan: updateStep(goal.currentPlan, step.id, "waiting", "Waiting for a GitHub PR or ref to monitor."),
      activeStepId: step.id,
      status: "waiting",
      nextWakeAt: null,
    });
    await goals.appendLog(updated.id, {
      kind: "decision_made",
      summary: "GitHub monitor is waiting for a PR or ref.",
      details: "Attach a PR URL, PR number, branch, ref, or commit to continue check monitoring.",
    });
    return { goalId: updated.id, status: "advanced", summary: "GitHub monitor needs a PR or ref before it can continue." };
  }

  const result = await readGithubMonitorTarget(code, target).catch((error) => ({
    ok: false,
    error: shortError(error),
  }));
  const resultOk = result.ok === true;
  const decision = resultOk ? githubMonitorDecision(result) : undefined;
  const artifactUrl = resultOk ? githubArtifactUrl(result) : undefined;
  await goals.appendToolRun(goal.id, {
    toolId: "autonomy.github_monitor",
    toolName: "GitHub monitor",
    status: resultOk ? "completed" : "failed",
    reason: `Monitor ${githubMonitorTargetLabel(target)} before the next GitOps decision.`,
    requestSummary: `${capability.id}: ${goal.objective}`,
    responseSummary: decision?.summary ?? `GitHub monitor failed: ${String(result.error ?? "unknown_error")}.`,
    error: resultOk ? undefined : String(result.error ?? "unknown_error"),
    artifactUrl,
    startedAt,
    completedAt: now().toISOString(),
  });

  if (!resultOk || !decision) {
    const failed = await goals.update(goal.id, {
      currentPlan: updateStep(goal.currentPlan, step.id, "failed", "GitHub monitor failed."),
      activeStepId: null,
      status: "blocked",
      blockers: [...goal.blockers, `GitHub monitor failed: ${String(result.error ?? "unknown_error")}.`],
      nextWakeAt: null,
    });
    await goals.appendLog(failed.id, {
      kind: "blocker_found",
      summary: "GitHub monitor failed.",
      details: trimForSlack(JSON.stringify(result, null, 2), 5000),
      artifactUrl,
    });
    return { goalId: failed.id, status: "advanced", summary: "GitHub monitor failed." };
  }

  if (decision.state === "pending" || decision.state === "unknown" || (waitForMerge && decision.state === "passed")) {
    const nextWakeAt = new Date(now().getTime() + githubMonitorIntervalMs(config)).toISOString();
    const updated = await goals.update(goal.id, {
      currentPlan: updateStep(goal.currentPlan, step.id, "pending", waitForMerge && decision.state === "passed"
        ? `${decision.summary} Waiting for merge.`
        : decision.summary),
      activeStepId: step.id,
      status: "active",
      nextWakeAt,
      artifactUrls: artifactUrl ? unique([...goal.artifactUrls, artifactUrl]) : goal.artifactUrls,
    });
    await goals.appendLog(updated.id, {
      kind: "check_result",
      summary: decision.summary,
      details: trimForSlack(JSON.stringify(result, null, 2), 5000),
      artifactUrl,
    });
    return { goalId: updated.id, status: "advanced", summary: `${decision.summary}${waitForMerge && decision.state === "passed" ? " Waiting for merge." : ""} Next check is scheduled.` };
  }

  if (decision.state === "failed") {
    const failed = await goals.update(goal.id, {
      currentPlan: updateStep(goal.currentPlan, step.id, "failed", decision.summary),
      activeStepId: null,
      status: "blocked",
      blockers: [...goal.blockers, decision.summary],
      artifactUrls: artifactUrl ? unique([...goal.artifactUrls, artifactUrl]) : goal.artifactUrls,
      nextWakeAt: null,
    });
    await goals.appendLog(failed.id, {
      kind: "check_result",
      summary: decision.summary,
      details: trimForSlack(JSON.stringify(result, null, 2), 5000),
      artifactUrl,
    });
    return { goalId: failed.id, status: "advanced", summary: decision.summary };
  }

  const completed = decision.state === "merged";
  const updatedPlan = updateStep(goal.currentPlan, step.id, "completed", decision.summary);
  const hasDownstreamWork = completed && updatedPlan.some((item) => item.status === "pending");
  const updated = await goals.update(goal.id, {
    currentPlan: updatedPlan,
    activeStepId: null,
    status: hasDownstreamWork ? "active" : completed ? "completed" : "waiting",
    completionSummary: completed && !hasDownstreamWork ? decision.summary : null,
    artifactUrls: artifactUrl ? unique([...goal.artifactUrls, artifactUrl]) : goal.artifactUrls,
    nextWakeAt: hasDownstreamWork ? now().toISOString() : null,
  });
  await goals.appendLog(updated.id, {
    kind: completed && !hasDownstreamWork ? "goal_completed" : "check_result",
    summary: completed && !hasDownstreamWork ? `Goal completed: ${decision.summary}` : decision.summary,
    details: trimForSlack(JSON.stringify(result, null, 2), 5000),
    artifactUrl,
  });
  return {
    goalId: updated.id,
    status: "advanced",
    summary: hasDownstreamWork
      ? `${decision.summary} Fresh finding verification is ready.`
      : completed ? decision.summary : `${decision.summary} Runner is waiting for review or merge direction.`,
  };
}

async function readGithubMonitorTarget(code: AutonomyGithubMonitorClient, target: GithubMonitorTarget): Promise<Record<string, unknown>> {
  if (target.kind === "pull_request") {
    if (!target.pullNumber) throw new Error("GitHub PR number is missing.");
    return code.githubPullRequestStatus({
      repo: target.repo,
      pullNumber: target.pullNumber,
      includeChecks: true,
    });
  }
  if (!target.ref) throw new Error("GitHub ref is missing.");
  return code.githubChecksStatus({
    repo: target.repo,
    ref: target.ref,
  });
}

function githubMonitorIntervalMs(config: AppConfig): number {
  return Math.max(config.autonomy.runnerPollIntervalMs, 60_000);
}

function githubArtifactUrl(result: Record<string, unknown>): string | undefined {
  const pullRequest = result.pull_request;
  if (pullRequest && typeof pullRequest === "object" && !Array.isArray(pullRequest)) {
    const url = (pullRequest as { url?: unknown }).url;
    return typeof url === "string" && url.trim() ? url.trim() : undefined;
  }
  const checkRuns = result.checks && typeof result.checks === "object" && !Array.isArray(result.checks)
    ? (result.checks as { check_runs?: unknown }).check_runs
    : undefined;
  if (!Array.isArray(checkRuns)) return undefined;
  return checkRuns
    .map((run) => run && typeof run === "object" && !Array.isArray(run) ? (run as { url?: unknown }).url : undefined)
    .find((url): url is string => typeof url === "string" && url.trim().length > 0);
}
