import { createHash } from "node:crypto";
import type { AppConfig } from "../config/index.js";
import { RuntimeCodeGithubClient } from "../code/runtime-code-github-client.js";
import { redactSecurityText } from "../security/redaction.js";
import { assistantHardCorpusCaseSchema, type AssistantHardCorpusCase } from "../learning/assistant-hillclimb.js";
import { captureTelemetryError, recordMetric, telemetryEvent } from "../telemetry.js";
import { S3ImprovementArtifactStore, type ImprovementArtifactStore } from "./artifacts.js";
import { SqsImprovementJobQueue, type ImprovementJobQueue } from "./queue.js";
import {
  improvementRunId,
  initialImprovementEvent,
  newImprovementRun,
  terminalImprovementStatus,
  transitionImprovementRun,
  type ImprovementTransition,
} from "./state-machine.js";
import { DynamoImprovementRunStore, isImprovementStoreConflict, type ImprovementRunStore } from "./store.js";
import { assistanceLifetimeMs, type ImprovementHumanAssistancePublisher } from "./human-assistance.js";
import { KmsImprovementDelegationIssuer, type ImprovementDelegationIssuer } from "./delegation.js";
import {
  improvementFeedbackOutcomeSchema,
  improvementContextExposureSchema,
  improvementInteractionSchema,
  improvementOutcomeEventSchema,
  improvementSignalSchema,
  type ImprovementArtifact,
  type ImprovementCandidate,
  type ImprovementEvent,
  type ImprovementFeedbackOutcome,
  type ImprovementContextExposure,
  type ImprovementInteraction,
  type ImprovementOutcomeEvent,
  type ImprovementObserveOptions,
  type ImprovementRun,
  type ImprovementSignal,
  type ImprovementSignalRecorder,
  type ImprovementRunStatus,
} from "./types.js";

interface ImprovementControlPlaneOptions {
  store: ImprovementRunStore;
  artifacts: ImprovementArtifactStore;
  queue: ImprovementJobQueue;
  signalThreshold: number;
  cooldownHours: number;
  humanAssistance?: ImprovementHumanAssistancePublisher;
  delegations?: ImprovementDelegationIssuer;
  now?: () => Date;
}

interface CreateImprovementControlPlaneOptions {
  humanAssistance?: ImprovementHumanAssistancePublisher;
}

export class ImprovementControlPlane implements ImprovementSignalRecorder {
  private readonly now: () => Date;
  private reconcileTimer?: NodeJS.Timeout;
  private reconciliation?: Promise<void>;

  constructor(private readonly options: ImprovementControlPlaneOptions) {
    this.now = options.now ?? (() => new Date());
  }

  start(): void {
    if (this.reconcileTimer) return;
    void this.reconcilePending();
    this.reconcileTimer = setInterval(() => void this.reconcilePending(), 5_000);
    this.reconcileTimer.unref?.();
  }

  async stop(): Promise<void> {
    if (this.reconcileTimer) clearInterval(this.reconcileTimer);
    this.reconcileTimer = undefined;
    await this.reconciliation;
  }

  async recordInteraction(rawInteraction: ImprovementInteraction): Promise<ImprovementArtifact> {
    const interaction = improvementInteractionSchema.parse({
      ...rawInteraction,
      question: redactSecurityText(rawInteraction.question).slice(0, 4_000),
      answer: redactSecurityText(rawInteraction.answer).slice(0, 12_000),
      toolNames: [...new Set(rawInteraction.toolNames)].slice(0, 64),
      commitmentStates: [...new Set(rawInteraction.commitmentStates)].slice(0, 24),
    });
    return this.options.artifacts.putJson(`interaction-${interaction.interactionId}`, "interaction", interaction, new Date(interaction.occurredAt));
  }

  async recordFeedbackOutcome(rawOutcome: ImprovementFeedbackOutcome): Promise<ImprovementArtifact> {
    const outcome = improvementFeedbackOutcomeSchema.parse(rawOutcome);
    return this.options.artifacts.putJson(`interaction-${outcome.interactionId}`, "feedback", outcome, new Date(outcome.occurredAt));
  }

  async recordContextExposure(rawExposure: ImprovementContextExposure): Promise<ImprovementArtifact> {
    const exposure = improvementContextExposureSchema.parse(rawExposure);
    return this.options.artifacts.putJson(`interaction-${exposure.interactionId}`, "context_exposure", exposure, new Date(exposure.occurredAt));
  }

  async recordOutcomeEvent(rawOutcome: ImprovementOutcomeEvent): Promise<ImprovementArtifact> {
    const outcome = improvementOutcomeEventSchema.parse(rawOutcome);
    return this.options.artifacts.putJson(`interaction-${outcome.interactionId}`, "outcome", outcome, new Date(outcome.occurredAt));
  }

  async recordConversationCase(rawCase: AssistantHardCorpusCase): Promise<ImprovementArtifact> {
    const conversationCase = assistantHardCorpusCaseSchema.parse(rawCase);
    if (conversationCase.partition !== "train") {
      throw new Error("Live conversation cases may only enter the training partition.");
    }
    const now = this.now();
    return this.options.artifacts.putJson(`conversation-${now.toISOString().slice(0, 10)}-${conversationCase.id}`, "corpus", conversationCase, now);
  }

  async observe(
    rawSignal: ImprovementSignal,
    candidate: ImprovementCandidate,
    observeOptions: ImprovementObserveOptions = {},
  ): Promise<ImprovementRun | undefined> {
    const signal = sanitizeSignal(improvementSignalSchema.parse(rawSignal));
    const now = this.now();
    const runId = improvementRunId(signal.signature, now, this.options.cooldownHours);
    const artifact = await this.options.artifacts.putJson(runId, "signal", signal, now);
    let run = await this.options.store.get(runId);
    let signalAdded = false;

    if (!run) {
      const created = newImprovementRun(signal, artifact, now, this.options.cooldownHours);
      try {
        await this.options.store.create(created, initialImprovementEvent(created));
        run = created;
        signalAdded = true;
      } catch (error) {
        if (!isImprovementStoreConflict(error)) throw error;
        run = await this.options.store.get(runId);
        if (run && (run.status === "observed" || run.status === "queued")
          && !run.artifacts.some((item) => item.kind === "signal" && item.sha256 === artifact.sha256)) {
          run = await transitionWithRetry(this.options.store, run.id, { type: "signal_recorded", artifact }, "companion", this.now);
          signalAdded = true;
        }
      }
    } else if ((run.status === "observed" || run.status === "queued")
      && !run.artifacts.some((item) => item.kind === "signal" && item.sha256 === artifact.sha256)) {
      run = await transitionWithRetry(this.options.store, run.id, { type: "signal_recorded", artifact }, "companion", this.now);
      signalAdded = true;
    }

    if (!run || terminalImprovementStatus(run.status) || (run.status !== "observed" && run.status !== "queued")) return run;
    if (run.signalCount < this.options.signalThreshold) return run;

    const recipient = assistanceRecipient(observeOptions, now);
    if (run.status === "observed" || signalAdded || (!run.assistance && recipient)) {
      const inputSignalShas = run.artifacts
        .filter((item) => item.kind === "signal")
        .slice(-6)
        .map((item) => item.sha256);
      run = await transitionWithRetry(this.options.store, run.id, {
        type: "author_requested",
        inputSignalShas,
        repo: candidate.repo,
        baseRef: candidate.baseRef ?? "main",
        assistance: recipient,
      }, "companion", this.now);
    }
    if (!run.authorGeneration || !run.authorInputSignalShas) {
      throw new Error(`Improvement run ${run.id} is queued without a persisted author generation.`);
    }
    telemetryEvent("improvement.run.queued", {
      component: "improvement-control-plane",
      operation: "queue_candidate",
      "improvement.run_id_hash": shortHash(run.id),
      "improvement.issue_kind": run.issueKind,
      "improvement.skill_id": run.skillId,
      "improvement.signal_count": run.signalCount,
      "improvement.author_generation": run.authorGeneration,
    });
    recordMetric("cerebro_slack_companion_improvement_runs_total", { status: "queued", source: run.source }, 1);
    await this.reconcileRun(run.id);
    return (await this.options.store.get(run.id)) ?? run;
  }

  async recordHumanAssistanceOutcome(input: {
    runId: string;
    channelId: string;
    intendedUserId: string;
    outcome: string;
  }): Promise<ImprovementRun | undefined> {
    if (!/^improvement-[a-f0-9]{24}$/.test(input.runId)) return undefined;
    let run = await this.options.store.get(input.runId);
    if (!run?.assistance) return undefined;
    if (run.assistance.channelId !== input.channelId || run.assistance.intendedUserId !== input.intendedUserId) return undefined;
    if (new Date(run.assistance.expiresAt).getTime() <= this.now().getTime()) return undefined;
    const outcome = boundedHumanOutcome(input.outcome);
    if (!outcome) return undefined;
    const expectedQuestion = `Required regression outcome: ${outcome}`;
    if (run.assistance.outcomeArtifact) {
      await assertSameHumanOutcome(this.options.artifacts, run.assistance.outcomeArtifact, expectedQuestion);
      await this.reconcileRun(run.id);
      return (await this.options.store.get(run.id)) ?? run;
    }
    if (terminalStatus(run.status)) return undefined;

    const now = this.now();
    const signal = improvementSignalSchema.parse({
      signature: run.signature,
      source: "operator",
      issueKind: run.issueKind,
      skillId: run.skillId,
      occurredAt: now.toISOString(),
      question: expectedQuestion,
      reason: "human-regression-outcome",
      toolNames: [],
      evidenceCount: 0,
      actionCount: 0,
      commitmentStates: [],
    });
    const artifact = await this.options.artifacts.putJson(`${run.id}-human-outcome`, "signal", signal, now) as ImprovementArtifact & { kind: "signal" };

    for (let attempt = 0; attempt < 3; attempt += 1) {
      run = await this.options.store.get(input.runId);
      if (!run?.assistance) return undefined;
      if (run.assistance.outcomeArtifact) {
        await assertSameHumanOutcome(this.options.artifacts, run.assistance.outcomeArtifact, expectedQuestion);
        break;
      }
      if (terminalStatus(run.status)) return undefined;
      const inputSignalShas = [...run.artifacts, artifact]
        .filter((item) => item.kind === "signal")
        .slice(-6)
        .map((item) => item.sha256);
      const result = transitionImprovementRun(run, {
        type: "refinement_requested",
        artifact,
        inputSignalShas,
        repo: run.pullRequest?.repo ?? run.authorRequest?.repo,
        baseRef: run.authorRequest?.baseRef ?? "main",
      }, { now: this.now(), actor: "companion" });
      try {
        await this.options.store.commit(run.version, result.run, result.event);
        run = result.run;
        break;
      } catch (error) {
        if (!isImprovementStoreConflict(error)) throw error;
        if (attempt === 2) throw error;
      }
    }
    if (!run?.assistance?.outcomeArtifact) return undefined;
    await this.reconcileRun(run.id);
    return (await this.options.store.get(run.id)) ?? run;
  }

  async reconcilePending(): Promise<void> {
    if (this.reconciliation) return this.reconciliation;
    this.reconciliation = this.reconcilePendingOnce().finally(() => {
      this.reconciliation = undefined;
    });
    return this.reconciliation;
  }

  private async reconcilePendingOnce(): Promise<void> {
    const statuses: ImprovementRunStatus[] = ["queued", "candidate_ready", "evaluating", "shadowing", "canary", "awaiting_promotion"];
    for (const status of statuses) {
      const runs = await this.options.store.listByStatus(status, 100);
      for (const run of runs) {
        try {
          await this.reconcileRun(run.id);
        } catch (error) {
          captureTelemetryError("improvement.assistance.reconcile_failed", error, {
            component: "improvement-control-plane",
            operation: "reconcile_assistance",
            "improvement.run_id_hash": shortHash(run.id),
          });
        }
      }
    }
  }

  private async reconcileRun(runId: string): Promise<void> {
    let run = await this.options.store.get(runId);
    if (!run) return;
    const request = run.authorRequest;
    const activeLease = run.authorLease && Date.parse(run.authorLease.expiresAt) > this.now().getTime();
    if (run.status === "queued" && request
      && run.authorGeneration === request.generation
      && run.authorDispatch?.generation !== request.generation
      && !activeLease) {
      const delegation = this.options.delegations
        ? await this.options.delegations.issue({ run, request, jobKind: "author_candidate" })
        : undefined;
      await this.options.queue.send({
        schemaVersion: 1,
        kind: "author_candidate",
        runId: run.id,
        generation: request.generation,
        inputSignalShas: request.inputSignalShas,
        repo: request.repo,
        baseRef: request.baseRef,
        delegation,
      }, 5);
      try {
        await transitionWithRetry(this.options.store, run.id, {
          type: "author_dispatched",
          generation: request.generation,
        }, "companion", this.now);
      } catch (error) {
        const current = await this.options.store.get(run.id);
        if (!current || current.authorGeneration === request.generation) throw error;
      }
    }
    run = (await this.options.store.get(runId)) ?? run;
    if (run.assistance?.deliveryStatus === "pending" && this.options.humanAssistance) {
      const delivery = await this.options.humanAssistance.publish(run);
      if (delivery) {
        await transitionWithRetry(this.options.store, run.id, {
          type: "assistance_enqueued",
          deliveryId: delivery.id,
        }, "companion", this.now);
      }
    }
  }
}

export function createImprovementControlPlane(
  config: AppConfig,
  options: CreateImprovementControlPlaneOptions = {},
): ImprovementControlPlane | undefined {
  if (!config.improvement.enabled) return undefined;
  if (!config.improvement.tableName || !config.improvement.artifactBucket || !config.improvement.queueUrl
    || !config.improvement.delegationKeyId) {
    telemetryEvent("improvement.control_plane.blocked", {
      component: "improvement-control-plane",
      operation: "configure",
      "improvement.table_configured": Boolean(config.improvement.tableName),
      "improvement.bucket_configured": Boolean(config.improvement.artifactBucket),
      "improvement.queue_configured": Boolean(config.improvement.queueUrl),
      "improvement.delegation_key_configured": Boolean(config.improvement.delegationKeyId),
    });
    throw new Error("Recursive improvement is enabled but its table, artifact bucket, queue, or delegation key is missing.");
  }
  const candidateSource = new RuntimeCodeGithubClient({ code: config.code });
  return new ImprovementControlPlane({
    store: new DynamoImprovementRunStore(config.improvement.tableName),
    artifacts: new S3ImprovementArtifactStore(config.improvement.artifactBucket),
    queue: new SqsImprovementJobQueue(config.improvement.queueUrl),
    signalThreshold: config.improvement.signalThreshold,
    cooldownHours: config.selfRepair.cooldownHours,
    humanAssistance: options.humanAssistance,
    delegations: new KmsImprovementDelegationIssuer({
      keyId: config.improvement.delegationKeyId,
      defaultRepo: config.code.defaultRepo,
      rolloutMode: config.improvement.delegationRolloutMode,
      canaryBasisPoints: config.improvement.delegationCanaryBasisPoints,
      ttlSeconds: config.improvement.delegationTtlSeconds,
      policyVersion: config.improvement.delegationPolicyVersion,
      toolsetVersion: config.improvement.delegationToolsetVersion,
      budgets: {
        maxFiles: Math.min(config.code.maxFiles, 6),
        maxFileBytes: Math.min(config.code.maxFileBytes, 120_000),
        maxTotalBytes: 200_000,
        maxSourceCalls: config.improvement.delegationMaxSourceCalls,
        maxRuntimeMs: config.improvement.delegationMaxRuntimeMs,
      },
    }, candidateSource),
  });
}

export async function transitionWithRetry(
  store: ImprovementRunStore,
  runId: string,
  transition: ImprovementTransition,
  actor: ImprovementEvent["actor"],
  now: () => Date,
): Promise<ImprovementRun> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const current = await store.get(runId);
    if (!current) throw new Error(`Improvement run ${runId} was not found.`);
    const result = transitionImprovementRun(current, transition, { now: now(), actor });
    try {
      await store.commit(current.version, result.run, result.event);
      return result.run;
    } catch (error) {
      lastError = error;
      if (!isImprovementStoreConflict(error)) throw error;
    }
  }
  captureTelemetryError("improvement.run.conflict", lastError, {
    component: "improvement-control-plane",
    operation: transition.type,
    "improvement.run_id_hash": shortHash(runId),
  });
  throw lastError instanceof Error ? lastError : new Error("Improvement run changed during transition.");
}

function sanitizeSignal(signal: ImprovementSignal): ImprovementSignal {
  return {
    ...signal,
    question: signal.question ? redactSecurityText(signal.question).slice(0, 4_000) : undefined,
    answer: signal.answer ? redactSecurityText(signal.answer).slice(0, 12_000) : undefined,
    toolNames: [...new Set(signal.toolNames)].slice(0, 64),
    commitmentStates: [...new Set(signal.commitmentStates)].slice(0, 24),
  };
}

function assistanceRecipient(options: ImprovementObserveOptions, now: Date): {
  channelId: string;
  intendedUserId: string;
  expiresAt: string;
} | undefined {
  const channelId = options.humanAssistance?.channelId.trim().toUpperCase() ?? "";
  const intendedUserId = options.humanAssistance?.intendedUserId.trim().toUpperCase() ?? "";
  if (!/^[CDG][A-Z0-9]+$/.test(channelId) || !/^[UW][A-Z0-9]+$/.test(intendedUserId)) return undefined;
  return {
    channelId,
    intendedUserId,
    expiresAt: new Date(now.getTime() + assistanceLifetimeMs).toISOString(),
  };
}

function boundedHumanOutcome(value: string): string {
  return redactSecurityText(value)
    .replace(/<@[UW][A-Z0-9]+>/gi, "[person]")
    .replace(/\b[CDGUW][A-Z0-9]{7,}\b/gi, "[workspace-id]")
    .replace(/\b\d{10}\.\d{6}\b/g, "[message-time]")
    .replace(/https?:\/\/\S+/gi, "[link]")
    .replace(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi, "[email]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 600);
}

function terminalStatus(status: ImprovementRunStatus): boolean {
  return status === "promoted" || status === "rolled_back" || status === "blocked";
}

async function assertSameHumanOutcome(
  artifacts: ImprovementArtifactStore,
  artifact: ImprovementArtifact,
  expectedQuestion: string,
): Promise<void> {
  const existing = improvementSignalSchema.parse(await artifacts.getJson(artifact));
  if (existing.question !== expectedQuestion) {
    throw new Error("This improvement run already has a different human regression outcome.");
  }
}

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}
