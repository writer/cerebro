import { hostname } from "node:os";
import { findingInvestigation, recentScaryFindings } from "../agent/tools/cerebro-tools.js";
import type { SecurityToolDeps } from "../agent/tools/types.js";
import { RuntimeCodeWorkspace } from "../code/runtime-code.js";
import type { AppConfig } from "../config/index.js";
import { logger } from "../logger.js";
import { trimForSlack } from "../slack/format.js";
import { recordMetric } from "../telemetry.js";
import { autonomyCapability, type AutonomyCapabilityDefinition } from "./capabilities.js";
import { advanceGithubMonitorStep, type AutonomyGithubMonitorClient } from "./github-monitor-runner.js";
import type { AutonomyGoalService } from "./goal-service.js";
import type { AutonomyPlanStep, AutonomousGoalRecord } from "./goals.js";
import { claimVerificationText, investigationPlanRevision, reviseInvestigationPlan, type InvestigationPlanRevision } from "./investigation-plan-revision.js";
import { parseInvestigationObjective } from "./investigation-objective.js";
import { playbookStepSummary, playbookSummary, playbookToolId } from "./playbook.js";
import { defaultAutonomyPlan } from "./plans.js";
import { blockOnExecutionContract, ensureGoalExecutionContract, executionContractDecision } from "./runner-execution-contract.js";
import { advanceApprovalOnlyStep } from "./runner-approval-step.js";
import { recordAutonomyRunnerGauges } from "./runner-metrics.js";
import { nextApprovedWaitingStep, nextReadyStep, updateStep } from "./runner-plan.js";
import { recordRunnerAdvanceFailure } from "./runner-retry.js";
import { advanceExecutableToolStep, blockUnavailableExecutableToolStep } from "./runner-tool-step.js";
import { advanceUnboundMissionStep } from "./runner-mission-step.js";
import type { AutonomyRunnerAdvanceResult, AutonomyRunnerOptions } from "./runner-types.js";
import { shortError, unique } from "./runner-utils.js";
import type { AutonomyToolDispatcher } from "./tool-dispatcher.js";

export class AutonomyRunner {
  private readonly workerId: string;
  private readonly now: () => Date;
  private readonly toolDeps?: SecurityToolDeps;
  private readonly code: AutonomyGithubMonitorClient;
  private readonly dispatcher?: AutonomyToolDispatcher;
  private interval?: NodeJS.Timeout;
  private slackClient?: any;
  constructor(
    private readonly config: AppConfig,
    private readonly goals: AutonomyGoalService,
    options: AutonomyRunnerOptions = {},
  ) {
    this.workerId = options.workerId ?? `cerebro-${process.pid}@${hostname()}`;
    this.now = options.now ?? (() => new Date());
    this.toolDeps = options.cerebro && options.memory
      ? { config, cerebro: options.cerebro, memory: options.memory }
      : undefined;
    this.code = options.code ?? new RuntimeCodeWorkspace(config);
    this.dispatcher = options.dispatcher;
  }
  setSlackClient(client: any): void {
    this.slackClient = client;
  }
  start(client?: any): void {
    if (client) this.setSlackClient(client);
    if (!this.config.autonomy.runnerEnabled || this.interval) return;
    this.interval = setInterval(() => {
      void this.tick().catch((error) => logger.warn("autonomy runner tick failed", { error: String(error) }));
    }, this.config.autonomy.runnerPollIntervalMs);
    this.interval.unref?.();
    void this.tick().catch((error) => logger.warn("autonomy runner initial tick failed", { error: String(error) }));
  }
  stop(): void {
    if (this.interval) clearInterval(this.interval);
    this.interval = undefined;
  }
  async tick(): Promise<AutonomyRunnerAdvanceResult[]> {
    if (!this.config.autonomy.runnerEnabled) return [];
    const stats = await this.goals.stats().catch(() => undefined);
    if (stats) recordAutonomyRunnerGauges(stats);
    const due = await this.goals.due(this.now());
    const selected = due.slice(0, this.config.autonomy.runnerMaxGoalsPerTick);
    recordMetric("cerebro_slack_companion_autonomy_due_goals_total", { selected: selected.length }, due.length);
    const results: AutonomyRunnerAdvanceResult[] = [];
    for (const goal of selected) {
      results.push(await this.advance(goal.id).catch(async (error) => {
        const summary = await recordRunnerAdvanceFailure({ config: this.config, goals: this.goals, goal, error, now: this.now });
        return { goalId: goal.id, status: "failed", summary };
      }));
    }
    return results;
  }

  async advance(goalId: string, expectedRevision?: number, leaseMs = this.config.autonomy.runnerLeaseMs): Promise<AutonomyRunnerAdvanceResult> {
    if (expectedRevision !== undefined && await this.goals.revision(goalId) !== expectedRevision) {
      return { goalId, status: "stale", summary: `Mission revision ${expectedRevision} is no longer current.` };
    }
    const claimed = await this.goals.claim(goalId, this.workerId, leaseMs, expectedRevision);
    if (!claimed) {
      if (expectedRevision !== undefined && await this.goals.revision(goalId) !== expectedRevision) {
        return { goalId, status: "stale", summary: `Mission revision ${expectedRevision} is no longer current.` };
      }
      return { goalId, status: "claimed_elsewhere", summary: "Goal is leased by another worker." };
    }

    try {
      const advanced = await this.advanceClaimedGoal(claimed);
      await this.postProgress(advanced.goalId, advanced.summary);
      return advanced;
    } finally {
      await this.goals.release(claimed.id, this.workerId).catch((error) => {
        logger.warn("autonomy goal lease release failed", { goalId: claimed.id, error: String(error) });
      });
    }
  }

  private async advanceClaimedGoal(goal: AutonomousGoalRecord): Promise<AutonomyRunnerAdvanceResult> {
    if (goal.status !== "active") {
      return { goalId: goal.id, status: "skipped", summary: `Goal is ${goal.status}.` };
    }

    const capability = autonomyCapability(goal.capabilityId);
    let working = goal;
    const activePlan = goal.currentPlan.length > 0 ? goal.currentPlan : defaultAutonomyPlan(goal.capabilityId);
    if (goal.currentPlan.length === 0) {
      working = await this.goals.replacePlan(goal.id, activePlan, activePlan[0]?.id);
    }

    const step = nextReadyStep(working.currentPlan) ?? nextApprovedWaitingStep(working);
    if (!step) {
      const updated = await this.goals.update(working.id, {
        status: "waiting",
        nextWakeAt: null,
      });
      await this.goals.appendLog(updated.id, {
        kind: "decision_made",
        summary: "No ready plan step is available.",
      });
      return { goalId: updated.id, status: "advanced", summary: "No ready plan step is available." };
    }

    working = await ensureGoalExecutionContract({ goal: working, capabilityId: capability.id, goals: this.goals, now: this.now, toolDeps: this.toolDeps });
    const contractDecision = executionContractDecision(working, capability.id);
    if (!contractDecision.allowed) {
      return blockOnExecutionContract({ goal: working, capability, step, decision: contractDecision, goals: this.goals });
    }

    const startedAt = this.now().toISOString();
    await this.goals.appendLog(working.id, {
      kind: "step_started",
      summary: `Started ${step.title}.`,
    });
    working = await this.goals.update(working.id, {
      activeStepId: step.id,
      currentPlan: updateStep(working.currentPlan, step.id, "active", "Started by autonomy runner."),
      status: "active",
    });

    if (step.execution) {
      const executionInput = { goal: working, capability, step, goals: this.goals, now: this.now };
      return this.dispatcher
        ? advanceExecutableToolStep({ ...executionInput, dispatcher: this.dispatcher })
        : blockUnavailableExecutableToolStep(executionInput);
    }

    if (capability.id === "self_repair" && step.id === "monitor-github-checks") {
      return advanceGithubMonitorStep({ goal: working, capability, step, startedAt, goals: this.goals, code: this.code, config: this.config, now: this.now });
    }

    if (capability.id === "remediation" && step.id === "monitor-github-merge") {
      return advanceGithubMonitorStep({
        goal: working,
        capability,
        step,
        startedAt,
        goals: this.goals,
        code: this.code,
        config: this.config,
        now: this.now,
        waitForMerge: true,
      });
    }

    if (step.mission) {
      return advanceUnboundMissionStep({ goal: working, capability, step, goals: this.goals, now: this.now });
    }

    if (capability.requiresApproval) {
      return advanceApprovalOnlyStep({ goal: working, capability, step, goals: this.goals, startedAt, now: this.now });
    }

    if (capability.id === "investigation" && this.toolDeps) {
      return this.advanceCerebroInvestigationStep(working, capability, step, startedAt);
    }

    await this.goals.appendToolRun(working.id, {
      toolId: playbookToolId(capability),
      toolName: `${capability.name} playbook`,
      status: "completed",
      reason: "Inspect registered autonomy boundary and produce the next safe execution playbook.",
      requestSummary: `${capability.id}: ${goal.objective}`,
      responseSummary: playbookSummary(capability, goal, step),
      startedAt,
      completedAt: this.now().toISOString(),
    });
    const updatedPlan = updateStep(working.currentPlan, step.id, "completed", playbookStepSummary(capability, step));
    const hasMoreReadyWork = updatedPlan.some((item) => item.status === "pending");
    const updated = await this.goals.update(working.id, {
      currentPlan: updatedPlan,
      activeStepId: null,
      status: hasMoreReadyWork ? "active" : "waiting",
      nextWakeAt: hasMoreReadyWork ? this.now().toISOString() : null,
    });
    await this.goals.appendLog(updated.id, {
      kind: "step_completed",
      summary: `Completed ${step.title}.`,
      details: `Capability: ${capability.name}; owner: ${capability.owner}; blast radius: ${capability.blastRadius}.`,
    });
    return {
      goalId: updated.id,
      status: "advanced",
      summary: hasMoreReadyWork
        ? `${capability.name} completed ${step.title}; next step is ready.`
        : `${capability.name} playbook completed. Runner is waiting for the next executable tool step.`,
    };
  }

  private async postProgress(goalId: string, summary: string): Promise<void> {
    if (!this.slackClient) return;
    const goal = await this.goals.get(goalId);
    if (!goal?.channelId) return;
    await this.slackClient.chat.postMessage({
      channel: goal.channelId,
      thread_ts: goal.threadTs,
      text: trimForSlack(`Goal ${goal.id}: ${summary}`, 2800),
      unfurl_links: false,
      unfurl_media: false,
    }).catch((error: unknown) => logger.warn("autonomy progress post failed", { goalId, error: String(error) }));
  }

  private async advanceCerebroInvestigationStep(
    goal: AutonomousGoalRecord,
    capability: AutonomyCapabilityDefinition,
    step: AutonomyPlanStep,
    startedAt: string,
  ): Promise<AutonomyRunnerAdvanceResult> {
    const outcome = await this.runCerebroInvestigation(goal, step).catch((error) => ({
      ok: false as const,
      summary: `Cerebro investigation failed: ${shortError(error)}.`,
      details: { error: shortError(error) },
    }));
    await this.goals.appendToolRun(goal.id, {
      toolId: outcome.ok ? outcome.toolId : "autonomy.cerebro_investigation",
      toolName: `${capability.name} Cerebro investigation`,
      status: outcome.ok ? "completed" : "failed",
      reason: "Execute read-only Cerebro investigation from an autonomous goal.",
      requestSummary: `${capability.id}: ${goal.objective}`,
      responseSummary: outcome.summary,
      error: outcome.ok ? undefined : outcome.summary,
      startedAt,
      completedAt: this.now().toISOString(),
    });

    if (!outcome.ok) {
      const failed = await this.goals.update(goal.id, {
        currentPlan: updateStep(goal.currentPlan, step.id, "failed", outcome.summary),
        activeStepId: null,
        status: "blocked",
        blockers: unique([...goal.blockers, `Owner: ${capability.owner}. Action: ${capability.escalationPath}. Blocker: ${outcome.summary}`]),
        nextWakeAt: null,
      });
      await this.goals.appendLog(failed.id, {
        kind: "blocker_found",
        summary: outcome.summary,
        details: trimForSlack(`Owner: ${capability.owner}\nAction: ${capability.escalationPath}\n\n${JSON.stringify(outcome.details, null, 2)}`, 5000),
      });
      return { goalId: failed.id, status: "advanced", summary: outcome.summary };
    }

    const completedPlan = updateStep(goal.currentPlan, step.id, "completed", outcome.summary);
    const updatedPlan = outcome.planRevision
      ? reviseInvestigationPlan(completedPlan, step.id, outcome.planRevision)
      : completedPlan;
    const hasMoreReadyWork = updatedPlan.some((item) => item.status === "pending");
    const updated = await this.goals.update(goal.id, {
      currentPlan: updatedPlan,
      activeStepId: null,
      status: hasMoreReadyWork ? "active" : "waiting",
      nextWakeAt: hasMoreReadyWork ? this.now().toISOString() : null,
      assumptions: unique([...goal.assumptions, ...outcome.assumptions]),
    });
    if (outcome.planRevision) {
      await this.goals.appendLog(updated.id, {
        kind: "plan_updated",
        summary: `Next investigation step: ${outcome.planRevision.title}.`,
        details: outcome.planRevision.summary,
      });
    }
    await this.goals.appendLog(updated.id, {
      kind: "check_result",
      summary: outcome.summary,
      details: trimForSlack(JSON.stringify(outcome.details, null, 2), 5000),
    });
    return {
      goalId: updated.id,
      status: "advanced",
      summary: hasMoreReadyWork ? `${outcome.summary} Next investigation step is ready.` : outcome.summary,
    };
  }

  private async runCerebroInvestigation(goal: AutonomousGoalRecord, step: AutonomyPlanStep): Promise<{
    ok: true;
    toolId: string;
    summary: string;
    details: Record<string, unknown>;
    assumptions: string[];
    planRevision?: InvestigationPlanRevision;
  }> {
    if (!this.toolDeps) throw new Error("Cerebro dependencies are not wired into the autonomy runner.");
    const parsed = parseInvestigationObjective(goal.objective, this.config.cerebro.defaultRuntimeIds);
    const memory = await this.toolDeps.memory.search(goal.objective, 4).catch((error) => ({ error: shortError(error) }));
    if (parsed.findingId && parsed.runtimeId) {
      const packet = await findingInvestigation(this.toolDeps, {
        runtimeId: parsed.runtimeId,
        findingId: parsed.findingId,
        evidenceLimit: 12,
        relatedLimit: 8,
        includeGraph: true,
      });
      const gaps = Array.isArray(packet.gaps) ? packet.gaps.length : 0;
      const evidenceCount = Array.isArray(packet.evidence) ? packet.evidence.length : 0;
      return {
        ok: true,
        toolId: "autonomy.cerebro_finding_investigation",
        summary: `Investigated ${parsed.findingId} in ${parsed.runtimeId}: ${evidenceCount} evidence row(s), ${gaps} gap(s).${claimVerificationText(packet)}`,
        details: {
          step: step.id,
          objective: goal.objective,
          parsed,
          memory_context: memory,
          packet,
        },
        assumptions: parsed.assumptions,
        planRevision: investigationPlanRevision(packet),
      };
    }

    const runtimeIds = parsed.runtimeId ? [parsed.runtimeId] : this.config.cerebro.defaultRuntimeIds;
    const [runtimeHealth, scaryFindings, graph] = await Promise.all([
      this.toolDeps.cerebro.listRuntimeHealth({ runtimeIds, limit: runtimeIds.length || 20 }).catch((error) => ({ error: shortError(error) })),
      recentScaryFindings(this.toolDeps, { runtimeIds, limit: 5 }).catch((error) => ({ error: shortError(error) })),
      this.toolDeps.cerebro.reasonGraph({ question: goal.objective }).catch((error) => ({ error: shortError(error) })),
    ]);
    return {
      ok: true,
      toolId: "autonomy.cerebro_context_investigation",
      summary: `Ran Cerebro context investigation for ${runtimeIds.length || "configured"} runtime(s); finding id ${parsed.findingId ? "detected without runtime" : "not detected"}.`,
      details: {
        step: step.id,
        objective: goal.objective,
        parsed,
        memory_context: memory,
        runtime_health: runtimeHealth,
        recent_findings: scaryFindings,
        graph_reasoning: graph,
        safe_next_actions: [
          "Use cerebro_finding_investigation once a runtime id and finding id are known.",
          "Treat this as read-only context; do not execute response actions without the approved path.",
        ],
      },
      assumptions: parsed.assumptions,
    };
  }
}
