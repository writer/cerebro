import { createHash, randomUUID } from "node:crypto";
import { DeleteMessageCommand, ReceiveMessageCommand, SQSClient } from "@aws-sdk/client-sqs";
import { KMSClient, VerifyCommand } from "@aws-sdk/client-kms";
import { z } from "zod";
import { RuntimeCodeGithubClient, runtimePullRequestBody } from "../code/runtime-code-github-client.js";
import type { RuntimeCodePrInput } from "../code/runtime-code-types.js";
import { normalizeRelativePath } from "../code/runtime-code-utils.js";
import type { ImprovementWorkerConfig } from "../config/improvement-worker.js";
import { buildTrafficReplayReport, parseTrafficReplayCase, type TrafficReplayCase } from "../learning/traffic-replay.js";
import { logger } from "../logger.js";
import { redactSecurityText } from "../security/redaction.js";
import { captureTelemetryError, recordMetric, telemetryEvent } from "../telemetry.js";
import { stableJson, S3ImprovementArtifactStore, type ImprovementArtifactStore } from "./artifacts.js";
import {
  CandidateAuthorPolicyError,
  ModelImprovementCandidateAuthor,
  type ImprovementCandidateAuthor,
  type ImprovementCandidateAuthorResult,
  type ImprovementCandidateSource,
} from "./candidate-author.js";
import { transitionWithRetry } from "./control-plane.js";
import { assertDelegationFresh, delegationExecutionDecision } from "./delegation.js";
import { SqsImprovementJobQueue, type ImprovementJobQueue } from "./queue.js";
import { transitionImprovementRun } from "./state-machine.js";
import { DynamoImprovementRunStore, isImprovementStoreConflict, type ImprovementRunStore } from "./store.js";
import {
  candidatePullRequestJobSchema,
  improvementJobSchema,
  improvementSignalSchema,
  promotionPayloadSchema,
  type ImprovementCiCheck,
  type ImprovementCiReceipt,
  type ImprovementCandidateReceipt,
  type ImprovementDelegationManifest,
  type ImprovementJob,
  type ImprovementOutcome,
  type ImprovementRun,
  type ImprovementRunStatus,
  type ImprovementSignal,
} from "./types.js";

interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

interface CandidatePullRequestCreator extends ImprovementCandidateSource {
  createPullRequest(input: RuntimeCodePrInput): Promise<Record<string, unknown>>;
  candidatePullRequestState?(input: { repo: string; branch: string; paths: string[] }): Promise<Record<string, unknown>>;
  completeCandidatePullRequest?(input: { pullRequest: RuntimeCodePrInput; expectedCandidateHeadSha: string }): Promise<Record<string, unknown>>;
  pullRequestStatus(input: { repo: string; pullNumber: number; includeChecks?: boolean }): Promise<Record<string, unknown>>;
}

const AUTHOR_LEASE_GRACE_MS = 60_000;
// Recovery can inspect 12 files sequentially plus branch, commit, PR, base, and
// final-head state. Each GitHub call is bounded to 15 seconds in the runtime client.
const AUTHOR_GITHUB_WRITE_BUDGET_MS = 22 * 15_000;

const pullRequestResultSchema = z.object({
  ok: z.literal(true),
  repo: z.string().min(3),
  branch: z.string().min(1),
  pull_request: z.object({
    number: z.number().int().positive(),
    url: z.string().url(),
    head_sha: z.string().regex(/^[a-f0-9]{40}$/),
  }),
});

const pullRequestStatusSchema = z.object({
  ok: z.literal(true),
  repo: z.string().min(3),
  pull_request: z.object({
    number: z.number().int().positive(),
    head_sha: z.string().regex(/^[a-f0-9]{40}$/),
    state: z.string().min(1).max(80),
    draft: z.boolean(),
    merged: z.boolean(),
    head_ref: z.string().min(1).max(240),
    head_repo: z.string().min(3).max(200),
    base_ref: z.string().min(1).max(240).optional(),
    base_sha: z.string().regex(/^[a-f0-9]{40}$/).optional(),
  }),
  checks: z.object({
    check_runs: z.array(z.object({
      name: z.string().min(1).max(200),
      status: z.string().min(1).max(80),
      conclusion: z.string().min(1).max(80).nullable(),
    })).default([]),
    statuses: z.array(z.object({
      context: z.string().min(1).max(200),
      state: z.string().min(1).max(80),
    })).default([]),
  }).default({ check_runs: [], statuses: [] }),
});

const candidateWriteIntentPayloadSchema = z.object({
  schemaVersion: z.literal(1),
  generation: z.number().int().positive(),
  pullRequest: candidatePullRequestJobSchema,
  author: z.object({
    sourceRef: z.string().min(1).max(500),
    sourceCallCount: z.number().int().positive(),
    sourceReceipts: z.array(z.object({
      path: z.string().min(1).max(500),
      sha: z.string().min(1).max(160),
      bytes: z.number().int().nonnegative(),
    })).max(100),
  }).optional(),
}).strict();

const candidatePullRequestStateSchema = z.object({
  ok: z.literal(true),
  repo: z.string().min(3).max(200),
  branch: z.string().min(1).max(240),
  branch_exists: z.boolean(),
  head_sha: z.string().regex(/^[a-f0-9]{40}$/).optional(),
  head_parent_shas: z.array(z.string().regex(/^[a-f0-9]{40}$/)).max(10),
  head_changed_paths: z.array(z.string().min(1).max(500)).max(100),
  head_changes: z.array(z.object({
    path: z.string().min(1).max(500),
    status: z.string().min(1).max(80),
    previous_path: z.string().min(1).max(500).optional(),
  })).max(100),
  head_changed_paths_truncated: z.boolean(),
  pull_requests: z.array(z.object({
    number: z.number().int().positive(),
    url: z.string().url(),
    title: z.string().min(1).max(240),
    body: z.string().max(20_000),
    state: z.string().min(1).max(80),
    draft: z.boolean(),
    merged: z.boolean(),
    head_ref: z.string().min(1).max(240),
    head_sha: z.string().regex(/^[a-f0-9]{40}$/),
    head_repo: z.string().min(3).max(200),
    base_ref: z.string().min(1).max(240),
    base_sha: z.string().regex(/^[a-f0-9]{40}$/),
  })).max(100),
  pull_requests_truncated: z.boolean(),
  files: z.array(z.record(z.string(), z.unknown())).max(12),
});

const recoveredCandidateFileSchema = z.object({
  ok: z.literal(true),
  path: z.string().min(1).max(500),
  content: z.string().max(120_000),
});

const corpusSchema = z.union([
  z.array(z.unknown()),
  z.object({ cases: z.array(z.unknown()) }),
]);

type AuthorGenerationJob = Extract<ImprovementJob, { kind: "author_candidate" | "open_candidate_pr" }>;

interface VerifiedAuthorDelegation {
  manifest: ImprovementDelegationManifest;
  decision: "execute" | "shadow";
}

interface AuthorClaim {
  run: ImprovementRun;
  generation: number;
  inputSignalShas: string[];
  token: string;
}

type CandidateWriteIntentPayload = z.infer<typeof candidateWriteIntentPayloadSchema>;

export class ImprovementWorker {
  private readonly store: ImprovementRunStore;
  private readonly artifacts: ImprovementArtifactStore;
  private readonly queueClient: CommandSender;
  private readonly kms: CommandSender;
  private readonly pullRequests?: CandidatePullRequestCreator;
  private readonly jobs: ImprovementJobQueue;
  private readonly candidateAuthor?: ImprovementCandidateAuthor;
  private readonly now: () => Date;
  private stopped = false;

  constructor(private readonly config: ImprovementWorkerConfig, options: {
    store?: ImprovementRunStore;
    artifacts?: ImprovementArtifactStore;
    queueClient?: CommandSender;
    kms?: CommandSender;
    pullRequests?: CandidatePullRequestCreator;
    jobs?: ImprovementJobQueue;
    candidateAuthor?: ImprovementCandidateAuthor;
    now?: () => Date;
  } = {}) {
    this.store = options.store ?? new DynamoImprovementRunStore(config.tableName);
    this.artifacts = options.artifacts ?? new S3ImprovementArtifactStore(config.artifactBucket);
    this.queueClient = options.queueClient ?? new SQSClient({});
    this.kms = options.kms ?? new KMSClient({});
    this.pullRequests = options.pullRequests
      ?? (config.lane === "verifier" ? undefined : new RuntimeCodeGithubClient({ code: config.code }));
    this.jobs = options.jobs ?? new SqsImprovementJobQueue(config.queueUrl);
    this.candidateAuthor = options.candidateAuthor
      ?? (this.pullRequests ? new ModelImprovementCandidateAuthor(config, { source: this.pullRequests }) : undefined);
    this.now = options.now ?? (() => new Date());
  }

  async start(): Promise<void> {
    this.stopped = false;
    telemetryEvent("improvement.worker.started", {
      component: "improvement-worker",
      operation: "start",
      "improvement.worker_lane": this.config.lane,
    });
    while (!this.stopped) {
      await this.pollOnce().catch(async (error) => {
        captureTelemetryError("improvement.worker.poll_failed", error, { component: "improvement-worker", operation: "poll" });
        logger.error("improvement worker poll failed", { event: "improvement.worker.poll_failed", error: shortError(error) });
        await wait(this.config.pollIntervalMs);
      });
    }
  }

  stop(): void {
    this.stopped = true;
  }

  async handle(job: ImprovementJob): Promise<void> {
    if (!laneAllows(this.config.lane, job.kind)) {
      throw new Error(`Improvement ${this.config.lane} workcell cannot execute ${job.kind}.`);
    }
    switch (job.kind) {
      case "author_candidate":
        await this.authorCandidate(job);
        return;
      case "open_candidate_pr":
        await this.openCandidate(job);
        return;
      case "evaluate_candidate":
        await this.evaluateCandidate(job);
        return;
      case "record_shadow":
        await this.recordOutcome(job.runId, requireCandidateVersion(job.candidateVersion, "Shadow outcome job"), job.outcome, "shadow");
        return;
      case "record_canary":
        await this.recordOutcome(job.runId, requireCandidateVersion(job.candidateVersion, "Canary outcome job"), job.outcome, "canary");
        return;
      case "promotion_decision":
        await this.applyPromotionDecision(job);
        return;
      case "sweep_stale_runs":
        await this.sweepStaleRuns();
        return;
    }
  }

  private async authorCandidate(job: Extract<ImprovementJob, { kind: "author_candidate" }>): Promise<void> {
    const delegation = await this.verifyAuthorDelegation(job);
    const claim = await this.claimAuthorGeneration(job);
    if (!claim) return;

    try {
      if (delegation?.decision === "shadow") {
        telemetryEvent("improvement.delegation.shadowed", {
          component: "improvement-worker",
          operation: "enforce_delegation_rollout",
          "improvement.delegation_mode": delegation.manifest.rollout.mode,
          "improvement.delegation_cohort": delegation.manifest.rollout.cohortBucket,
          "improvement.author_generation": claim.generation,
        });
        await this.blockCandidate(claim, `delegation_${delegation.manifest.rollout.mode}_no_execution`);
        return;
      }
      const existingIntent = claim.run.candidateWriteIntent?.generation === claim.generation;
      let payload: CandidateWriteIntentPayload;
      if (existingIntent) {
        payload = await this.loadCandidateWriteIntent(claim);
      } else {
        const signalArtifacts = claim.inputSignalShas.map((sha) => claim.run.artifacts
          .find((artifact) => artifact.kind === "signal" && artifact.sha256 === sha));
        if (signalArtifacts.some((artifact) => artifact === undefined)) {
          await this.blockCandidate(claim, "candidate_author_missing_signal_artifact");
          throw new CandidateAuthorPolicyError("Candidate author input does not match the persisted signal artifacts.");
        }
        const signals: ImprovementSignal[] = [];
        for (const artifact of signalArtifacts) {
          signals.push(improvementSignalSchema.parse(await this.artifacts.getJson(artifact!)));
        }
        const refinementBoundary = claim.run.refinementBaseVersion
          ? await this.requireRefinementPullRequestBoundary(claim.run, claim.run.refinementBaseVersion)
          : undefined;
        const authorStartedAt = this.now().getTime();
        const authored = await this.authorCandidateAgent().author({
          run: claim.run,
          signals,
          repo: job.repo ?? this.config.code.defaultRepo,
          baseRef: refinementBoundary?.baseRef ?? job.baseRef,
          ...(delegation
            ? { sourceRef: delegation.manifest.sourceSha }
            : claim.run.refinementBaseVersion ? { sourceRef: claim.run.refinementBaseVersion } : {}),
          ...(delegation ? {
            maxSourceCalls: delegation.manifest.budgets.maxSourceCalls,
            maxRuntimeMs: delegation.manifest.budgets.maxRuntimeMs,
          } : {}),
        });
        if (delegation) {
          assertDelegationFresh(delegation.manifest, this.now());
          assertAuthoredWithinDelegation(delegation.manifest, authored, this.now().getTime() - authorStartedAt);
        }
        const currentBeforeWrite = await this.currentAuthorClaimRun(claim);
        if (!currentBeforeWrite) return;
        if (authored.pullRequest.draft !== true) throw new CandidateAuthorPolicyError("Candidate author may only open draft pull requests.");
        const pullRequest = refinementBoundary
          ? {
              ...authored.pullRequest,
              repo: claim.run.pullRequest!.repo,
              branch: claim.run.pullRequest!.branch,
              base: refinementBoundary.baseRef,
              expectedBaseSha: refinementBoundary.baseSha,
              expectedHeadSha: refinementBoundary.headSha,
              draft: true as const,
              draftBoundReuse: true,
            }
          : bindCandidateWrite(authored.pullRequest, authored.resolvedRef, currentBeforeWrite.candidateBranchWrite);
        payload = await this.persistCandidateWriteIntent(claim, pullRequest, {
          sourceRef: `${job.repo ?? this.config.code.defaultRepo}@${authored.resolvedRef}`,
          sourceCallCount: authored.sourceCallCount,
          sourceReceipts: authored.sourceReceipts,
        });
      }
      if (delegation) {
        assertDelegationFresh(delegation.manifest, this.now());
        assertPullRequestWithinDelegation(delegation.manifest, payload.pullRequest);
      }
      const rawResult = await this.executeCandidateWrite(claim, payload, existingIntent);
      if (!rawResult) return;
      await this.recordAuthorBranchWrite(claim, rawResult, payload.pullRequest.base ?? job.baseRef);
      if (claim.run.refinementBaseVersion) {
        const result = pullRequestResultSchema.safeParse(rawResult);
        if (result.success) await this.requireRefinementPullRequestBoundary(claim.run, result.data.pull_request.head_sha);
      }
      if (!await this.authorClaimIsCurrent(claim)) return;
      await this.recordCandidate(claim, rawResult, payload.author, false);
    } catch (error) {
      if (error instanceof CandidateAuthorPolicyError) {
        await this.blockCandidate(claim, `candidate_author_rejected:${safeCandidateError(error)}`);
      }
      throw error;
    } finally {
      await this.releaseAuthorClaim(claim);
    }
  }

  private async pollOnce(): Promise<void> {
    const response = await this.queueClient.send(new ReceiveMessageCommand({
      QueueUrl: this.config.queueUrl,
      MaxNumberOfMessages: 1,
      WaitTimeSeconds: 20,
      VisibilityTimeout: this.config.lane === "verifier"
        ? 120
        : Math.min(1_200, Math.max(120,
            Math.ceil((this.config.author.timeoutMs + AUTHOR_GITHUB_WRITE_BUDGET_MS + AUTHOR_LEASE_GRACE_MS) / 1_000))),
      MessageSystemAttributeNames: ["ApproximateReceiveCount"],
    })) as { Messages?: Array<{ Body?: string; ReceiptHandle?: string; MessageId?: string }> };
    const message = response.Messages?.[0];
    if (!message?.Body || !message.ReceiptHandle) return;
    const job = improvementJobSchema.parse(JSON.parse(message.Body) as unknown);
    await this.handle(job);
    await this.queueClient.send(new DeleteMessageCommand({ QueueUrl: this.config.queueUrl, ReceiptHandle: message.ReceiptHandle }));
    recordMetric("cerebro_slack_companion_improvement_jobs_total", { kind: job.kind, outcome: "completed" }, 1);
    logger.info("improvement worker job completed", {
      event: "improvement.worker.job_completed",
      jobKind: job.kind,
      messageId: message.MessageId,
    });
  }

  private async openCandidate(job: Extract<ImprovementJob, { kind: "open_candidate_pr" }>): Promise<void> {
    const delegation = await this.verifyAuthorDelegation(job);
    const claim = await this.claimAuthorGeneration(job);
    if (!claim) return;
    try {
      if (delegation?.decision === "shadow") {
        await this.blockCandidate(claim, `delegation_${delegation.manifest.rollout.mode}_no_execution`);
        return;
      }
      if (!job.pullRequest.draftBoundReuse || !job.pullRequest.expectedBaseSha) {
        throw new CandidateAuthorPolicyError("Candidate pull request jobs require an immutable base SHA and draft-bound reuse.");
      }
      const existingIntent = claim.run.candidateWriteIntent?.generation === claim.generation;
      const payload = existingIntent
        ? await this.loadCandidateWriteIntent(claim)
        : await this.persistCandidateWriteIntent(claim, bindCandidateWrite(
            job.pullRequest,
            job.pullRequest.expectedBaseSha,
            claim.run.candidateBranchWrite,
          ));
      if (delegation) {
        assertDelegationFresh(delegation.manifest, this.now());
        assertPullRequestWithinDelegation(delegation.manifest, payload.pullRequest);
      }
      const rawResult = await this.executeCandidateWrite(claim, payload, existingIntent);
      if (!rawResult) return;
      await this.recordAuthorBranchWrite(claim, rawResult, payload.pullRequest.base ?? "main");
      if (!await this.authorClaimIsCurrent(claim)) return;
      await this.recordCandidate(claim, rawResult);
    } catch (error) {
      if (error instanceof CandidateAuthorPolicyError) {
        await this.blockCandidate(claim, `candidate_author_rejected:${safeCandidateError(error)}`);
      }
      throw error;
    } finally {
      await this.releaseAuthorClaim(claim);
    }
  }

  private async persistCandidateWriteIntent(
    claim: AuthorClaim,
    rawPullRequest: RuntimeCodePrInput,
    author?: CandidateWriteIntentPayload["author"],
  ): Promise<CandidateWriteIntentPayload> {
    const current = await this.currentAuthorClaimRun(claim);
    if (!current) throw new Error("Candidate author claim changed before its write intent was persisted.");
    if (current.candidateWriteIntent?.generation === claim.generation) return this.loadCandidateWriteIntent(claim);
    const normalizedPullRequest = {
      ...rawPullRequest,
      files: rawPullRequest.files.map((file) => ({ ...file, path: normalizeRelativePath(file.path) })),
    };
    const parsed = candidatePullRequestJobSchema.safeParse(normalizedPullRequest);
    if (!parsed.success) throw new CandidateAuthorPolicyError("Candidate write intent did not satisfy the bounded pull request contract.");
    const pullRequest = parsed.data;
    if (!pullRequest.repo || !pullRequest.base || !pullRequest.branch
      || !pullRequest.expectedBaseSha || !pullRequest.expectedHeadSha
      || pullRequest.draft !== true || pullRequest.draftBoundReuse !== true) {
      throw new CandidateAuthorPolicyError("Candidate write intent requires an exact repository, base, branch, base SHA, head SHA, and draft-bound reuse.");
    }
    if (new Set(pullRequest.files.map((file) => file.path)).size !== pullRequest.files.length) {
      throw new CandidateAuthorPolicyError("Candidate write intent contains duplicate normalized file paths.");
    }
    const payload = candidateWriteIntentPayloadSchema.parse({
      schemaVersion: 1,
      generation: claim.generation,
      pullRequest,
      ...(author ? { author } : {}),
    });
    const artifact = await this.artifacts.putJson(claim.run.id, "candidate_intent", payload, this.now());
    const payloadSha256 = stableSha256(payload);
    if (artifact.sha256 !== payloadSha256) throw new Error("Candidate write intent artifact did not preserve the exact payload digest.");
    await transitionWithRetry(this.store, claim.run.id, {
      type: "author_write_intended",
      generation: claim.generation,
      token: claim.token,
      repo: pullRequest.repo,
      baseRef: pullRequest.base,
      branch: pullRequest.branch,
      expectedBaseSha: pullRequest.expectedBaseSha,
      expectedHeadSha: pullRequest.expectedHeadSha,
      payloadSha256,
      artifact,
    }, "worker", this.now);
    return payload;
  }

  private async loadCandidateWriteIntent(claim: AuthorClaim): Promise<CandidateWriteIntentPayload> {
    const current = await this.currentAuthorClaimRun(claim);
    const intent = current?.candidateWriteIntent;
    if (!current || !intent || intent.generation !== claim.generation) {
      throw new CandidateAuthorPolicyError("Candidate author retry is missing its generation-bound write intent.");
    }
    const parsed = candidateWriteIntentPayloadSchema.safeParse(await this.artifacts.getJson(intent.artifact));
    if (!parsed.success || stableSha256(parsed.data) !== intent.payloadSha256
      || intent.artifact.sha256 !== intent.payloadSha256) {
      throw new CandidateAuthorPolicyError("Candidate author retry could not verify its immutable write intent payload.");
    }
    const pullRequest = parsed.data.pullRequest;
    if (parsed.data.generation !== claim.generation
      || pullRequest.repo !== intent.repo
      || pullRequest.base !== intent.baseRef
      || pullRequest.branch !== intent.branch
      || pullRequest.expectedBaseSha !== intent.expectedBaseSha
      || pullRequest.expectedHeadSha !== intent.expectedHeadSha
      || pullRequest.draft !== true
      || pullRequest.draftBoundReuse !== true) {
      throw new CandidateAuthorPolicyError("Candidate author retry payload does not match its durable write intent receipt.");
    }
    return parsed.data;
  }

  private async executeCandidateWrite(
    claim: AuthorClaim,
    payload: CandidateWriteIntentPayload,
    reconcileFirst: boolean,
  ): Promise<Record<string, unknown> | undefined> {
    if (!await this.currentAuthorClaimRun(claim)) return undefined;
    if (reconcileFirst) {
      const recovered = await this.reconcileCandidateWrite(claim, payload);
      if (recovered === undefined) return undefined;
      if (recovered) return recovered;
      if (!await this.currentAuthorClaimRun(claim)) return undefined;
    }
    return this.authorPullRequests().createPullRequest(payload.pullRequest);
  }

  private async reconcileCandidateWrite(
    claim: AuthorClaim,
    payload: CandidateWriteIntentPayload,
  ): Promise<Record<string, unknown> | null | undefined> {
    const pullRequest = payload.pullRequest;
    if (!pullRequest.repo || !pullRequest.branch || !pullRequest.base
      || !pullRequest.expectedBaseSha || !pullRequest.expectedHeadSha) {
      throw new CandidateAuthorPolicyError("Candidate write recovery is missing an exact GitHub boundary.");
    }
    const pullRequests = this.authorPullRequests();
    if (!pullRequests.candidatePullRequestState) {
      throw new Error("Candidate write recovery inspection is not configured.");
    }
    const rawState = await pullRequests.candidatePullRequestState({
      repo: pullRequest.repo,
      branch: pullRequest.branch,
      paths: pullRequest.files.map((file) => file.path),
    });
    if (rawState.ok !== true) {
      const reason = typeof rawState.error === "string" ? rawState.error : "candidate_state_failed";
      throw new Error(`Candidate write recovery inspection failed: ${reason}`);
    }
    const parsedState = candidatePullRequestStateSchema.safeParse(rawState);
    if (!parsedState.success) {
      throw new CandidateAuthorPolicyError("Candidate write recovery returned incomplete branch or pull request evidence.");
    }
    const state = parsedState.data;
    if (!state.branch_exists && state.pull_requests.length === 0) return null;
    if (!state.branch_exists || !state.head_sha
      || state.repo.toLowerCase() !== pullRequest.repo.toLowerCase()
      || state.branch !== pullRequest.branch) {
      throw new CandidateAuthorPolicyError("Candidate write recovery found a moved or mismatched GitHub branch.");
    }
    if (state.pull_requests_truncated || state.pull_requests.length > 1) {
      throw new CandidateAuthorPolicyError("Candidate write recovery found ambiguous pull request history for the intended branch.");
    }
    if (state.pull_requests.length === 0 && state.head_sha === pullRequest.expectedHeadSha) {
      if (!await this.currentAuthorClaimRun(claim)) return undefined;
      return this.resumeCandidateWrite(payload, state.head_sha);
    }
    if (state.head_parent_shas.length !== 1 || state.head_parent_shas[0] !== pullRequest.expectedHeadSha
      || state.head_changed_paths_truncated
      || !sameStringSet(state.head_changed_paths, pullRequest.files.map((file) => file.path))
      || state.head_changes.length !== pullRequest.files.length
      || state.head_changes.some((change) => !["added", "modified"].includes(change.status) || change.previous_path)) {
      throw new CandidateAuthorPolicyError("Candidate write recovery found a moved or content-ambiguous candidate head.");
    }
    const actualFiles = state.files.map((file) => recoveredCandidateFileSchema.safeParse(file));
    if (actualFiles.some((file) => !file.success)) {
      throw new CandidateAuthorPolicyError("Candidate write recovery could not verify every intended file at the candidate head.");
    }
    const contentByPath = new Map(actualFiles.map((file) => [file.data!.path, file.data!.content]));
    if (contentByPath.size !== pullRequest.files.length
      || pullRequest.files.some((file) => contentByPath.get(file.path) !== file.content)) {
      throw new CandidateAuthorPolicyError("Candidate write recovery found candidate file content outside the immutable intent.");
    }
    if (state.pull_requests.length === 0) {
      if (!await this.currentAuthorClaimRun(claim)) return undefined;
      return this.resumeCandidateWrite(payload, state.head_sha);
    }
    const recovered = state.pull_requests[0]!;
    if (recovered.state !== "open" || recovered.draft !== true || recovered.merged
      || recovered.title !== pullRequest.title || recovered.body !== runtimePullRequestBody(pullRequest)
      || recovered.head_repo.toLowerCase() !== pullRequest.repo.toLowerCase()
      || recovered.head_ref !== pullRequest.branch
      || recovered.head_sha !== state.head_sha
      || recovered.base_ref !== pullRequest.base
      || recovered.base_sha !== pullRequest.expectedBaseSha) {
      throw new CandidateAuthorPolicyError("Candidate write recovery found a moved, closed, non-draft, or mismatched GitHub candidate.");
    }
    telemetryEvent("improvement.author.write_recovered", {
      component: "improvement-worker",
      operation: "reconcile_candidate_write",
      "improvement.run_id_hash": shortHash(claim.run.id),
      "improvement.author_generation": claim.generation,
      "improvement.pull_request_number": recovered.number,
    });
    return {
      ok: true,
      repo: state.repo,
      branch: state.branch,
      pull_request: {
        number: recovered.number,
        url: recovered.url,
        head_sha: state.head_sha,
      },
      recovered_write: true,
    };
  }

  private async resumeCandidateWrite(
    payload: CandidateWriteIntentPayload,
    expectedCandidateHeadSha: string,
  ): Promise<Record<string, unknown>> {
    const pullRequests = this.authorPullRequests();
    if (!pullRequests.completeCandidatePullRequest) {
      throw new Error("Candidate write completion is not configured.");
    }
    const result = await pullRequests.completeCandidatePullRequest({
      pullRequest: payload.pullRequest,
      expectedCandidateHeadSha,
    });
    if (result.ok !== true) {
      const reason = typeof result.error === "string" ? result.error : "candidate_write_completion_failed";
      throw new CandidateAuthorPolicyError(`Candidate write completion failed closed: ${reason}.`);
    }
    return result;
  }

  private async recordCandidate(
    claim: AuthorClaim,
    rawResult: Record<string, unknown>,
    author?: {
      sourceRef: string;
      sourceCallCount: number;
      sourceReceipts: Array<{ path: string; sha: string; bytes: number }>;
    },
    blockOnPullRequestFailure = true,
  ): Promise<void> {
    const result = pullRequestResultSchema.safeParse(rawResult);
    if (!result.success) {
      const reason = rawResult.ok === false && typeof rawResult.error === "string" ? rawResult.error : "candidate_pr_failed";
      if (blockOnPullRequestFailure) await this.blockCandidate(claim, reason);
      throw new Error(`Candidate PR failed: ${reason}`);
    }
    if (claim.run.pullRequest && (claim.run.pullRequest.repo !== result.data.repo
      || claim.run.pullRequest.number !== result.data.pull_request.number
      || claim.run.pullRequest.branch !== result.data.branch)) {
      throw new CandidateAuthorPolicyError("Refinement must update the existing draft pull request.");
    }
    const current = await this.requireRun(claim.run.id);
    if (current.pullRequest && (current.pullRequest.repo !== result.data.repo
      || current.pullRequest.number !== result.data.pull_request.number
      || current.pullRequest.branch !== result.data.branch)) {
      throw new CandidateAuthorPolicyError("Candidate result no longer matches the run's draft pull request.");
    }
    const artifact = await this.artifacts.putJson(claim.run.id, "candidate", {
      repo: result.data.repo,
      branch: result.data.branch,
      pullRequest: result.data.pull_request,
      authorGeneration: claim.generation,
      inputSignalShas: claim.inputSignalShas,
      ...(author ? {
        sourceRef: author.sourceRef,
        sourceCallCount: author.sourceCallCount,
        sourceReceipts: author.sourceReceipts,
      } : {}),
    });
    await transitionWithRetry(this.store, claim.run.id, {
      type: "candidate_ready",
      authorGeneration: claim.generation,
      authorLeaseToken: claim.token,
      candidateVersion: result.data.pull_request.head_sha,
      pullRequest: {
        repo: result.data.repo,
        number: result.data.pull_request.number,
        url: result.data.pull_request.url,
        branch: result.data.branch,
      },
      artifact,
    }, "worker", this.now);
  }

  private async requireRefinementPullRequestBoundary(
    run: ImprovementRun,
    expectedHead: string,
  ): Promise<{ baseRef: string; baseSha: string; headSha: string }> {
    if (!run.pullRequest) throw new CandidateAuthorPolicyError("Refinement requires the run's existing draft pull request.");
    const rawStatus = await this.authorPullRequests().pullRequestStatus({
      repo: run.pullRequest.repo,
      pullNumber: run.pullRequest.number,
      includeChecks: false,
    });
    const status = pullRequestStatusSchema.safeParse(rawStatus);
    if (!status.success
      || status.data.repo !== run.pullRequest.repo
      || status.data.pull_request.number !== run.pullRequest.number
      || status.data.pull_request.state.toLowerCase() !== "open"
      || !status.data.pull_request.draft
      || status.data.pull_request.merged
      || status.data.pull_request.head_ref !== run.pullRequest.branch
      || status.data.pull_request.head_repo !== run.pullRequest.repo
      || status.data.pull_request.head_sha !== expectedHead
      || !status.data.pull_request.base_ref
      || !status.data.pull_request.base_sha) {
      throw new CandidateAuthorPolicyError("Refinement requires the same open draft pull request at its exact stored head and base.");
    }
    return {
      baseRef: status.data.pull_request.base_ref,
      baseSha: status.data.pull_request.base_sha,
      headSha: status.data.pull_request.head_sha,
    };
  }

  private async claimAuthorGeneration(job: AuthorGenerationJob): Promise<AuthorClaim | undefined> {
    const generation = requireAuthorGeneration(job.generation);
    const inputSignalShas = requireAuthorInputSignalShas(job.inputSignalShas);
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const current = await this.requireRun(job.runId);
      if (current.status === "candidate_ready" || laterThanCandidate(current.status)) {
        this.recordStaleJob(job.kind, "candidate_already_advanced");
        return undefined;
      }
      if (current.status !== "queued") throw new Error(`Improvement run ${current.id} is ${current.status}; candidate work requires queued.`);
      if (current.authorGeneration !== generation || !sameStrings(current.authorInputSignalShas, inputSignalShas)
        || !authorJobMatchesRequest(job, current)) {
        this.recordStaleJob(job.kind, "author_generation_superseded");
        return undefined;
      }
      const now = this.now();
      if (current.authorLease && Date.parse(current.authorLease.expiresAt) > now.getTime()) {
        const delaySeconds = Math.max(1, Math.min(900, Math.ceil((Date.parse(current.authorLease.expiresAt) - now.getTime()) / 1_000)));
        await this.jobs.send(job, delaySeconds);
        telemetryEvent("improvement.author.lease_wait", {
          component: "improvement-worker",
          operation: "claim_author_generation",
          "improvement.author_generation": generation,
          "improvement.retry_delay_seconds": delaySeconds,
        });
        return undefined;
      }
      const token = randomUUID();
      const expiresAt = new Date(now.getTime()
        + this.config.author.timeoutMs + AUTHOR_GITHUB_WRITE_BUDGET_MS + AUTHOR_LEASE_GRACE_MS).toISOString();
      const result = transitionImprovementRun(current, { type: "author_claimed", generation, token, expiresAt }, { now, actor: "worker" });
      try {
        await this.store.commit(current.version, result.run, result.event);
        return { run: result.run, generation, inputSignalShas, token };
      } catch (error) {
        if (!isImprovementStoreConflict(error)) throw error;
      }
    }
    throw new Error(`Improvement run ${job.runId} changed while claiming author generation ${generation}.`);
  }

  private async authorClaimIsCurrent(claim: AuthorClaim): Promise<boolean> {
    return Boolean(await this.currentAuthorClaimRun(claim));
  }

  private async currentAuthorClaimRun(claim: AuthorClaim): Promise<ImprovementRun | undefined> {
    const current = await this.requireRun(claim.run.id);
    return current.status === "queued"
      && current.authorGeneration === claim.generation
      && sameStrings(current.authorInputSignalShas, claim.inputSignalShas)
      && current.authorLease?.generation === claim.generation
      && current.authorLease.token === claim.token
      && Date.parse(current.authorLease.expiresAt) > this.now().getTime()
      ? current
      : undefined;
  }

  private async recordAuthorBranchWrite(claim: AuthorClaim, rawResult: Record<string, unknown>, baseRef: string): Promise<void> {
    const result = pullRequestResultSchema.safeParse(rawResult);
    if (!result.success) return;
    await transitionWithRetry(this.store, claim.run.id, {
      type: "author_write_recorded",
      generation: claim.generation,
      token: claim.token,
      repo: result.data.repo,
      baseRef,
      branch: result.data.branch,
      pullRequestNumber: result.data.pull_request.number,
      pullRequestUrl: result.data.pull_request.url,
      headSha: result.data.pull_request.head_sha,
    }, "worker", this.now);
  }

  private async releaseAuthorClaim(claim: AuthorClaim): Promise<void> {
    const current = await this.requireRun(claim.run.id);
    if (current.status !== "queued" || current.authorLease?.generation !== claim.generation || current.authorLease.token !== claim.token) return;
    const released = await transitionWithRetry(this.store, claim.run.id, {
      type: "author_released",
      generation: claim.generation,
      token: claim.token,
    }, "worker", this.now).catch((error) => {
      if (!isImprovementStoreConflict(error)) throw error;
      return undefined;
    });
    if (this.config.lane === "all" && released?.authorGeneration && released.authorGeneration > claim.generation
      && released.authorRequest?.generation === released.authorGeneration) {
      await this.jobs.send({
        schemaVersion: 1,
        kind: "author_candidate",
        runId: released.id,
        generation: released.authorRequest.generation,
        inputSignalShas: released.authorRequest.inputSignalShas,
        repo: released.authorRequest.repo,
        baseRef: released.authorRequest.baseRef,
      });
    }
  }

  private async blockCandidate(claim: AuthorClaim, reason: string): Promise<void> {
    if (!await this.authorClaimIsCurrent(claim)) return;
    await transitionWithRetry(this.store, claim.run.id, {
      type: "blocked",
      reason: reason.slice(0, 500),
      authorGeneration: claim.generation,
      authorLeaseToken: claim.token,
    }, "worker", this.now);
  }

  private async reconcilePendingAuthorRequest(run: ImprovementRun): Promise<void> {
    const request = run.authorRequest;
    if (!request || run.authorGeneration !== request.generation
      || !sameStrings(run.authorInputSignalShas, request.inputSignalShas)) {
      await transitionWithRetry(this.store, run.id, {
        type: "blocked",
        reason: "Queued improvement run is missing its durable author request.",
      }, "worker", this.now);
      telemetryEvent("improvement.author.legacy_run_blocked", {
        component: "improvement-worker",
        operation: "reconcile_author_dispatch",
      });
      return;
    }
    if (run.authorDispatch?.generation === request.generation) return;
    if (run.authorLease && Date.parse(run.authorLease.expiresAt) > this.now().getTime()) return;
    await this.jobs.send({
      schemaVersion: 1,
      kind: "author_candidate",
      runId: run.id,
      generation: request.generation,
      inputSignalShas: request.inputSignalShas,
      repo: request.repo,
      baseRef: request.baseRef,
    }, 5);
    try {
      await transitionWithRetry(this.store, run.id, {
        type: "author_dispatched",
        generation: request.generation,
      }, "worker", this.now);
    } catch (error) {
      const current = await this.requireRun(run.id);
      if (current.authorGeneration === request.generation) throw error;
    }
    telemetryEvent("improvement.author.dispatch_reconciled", {
      component: "improvement-worker",
      operation: "reconcile_author_dispatch",
      "improvement.author_generation": request.generation,
    });
  }

  private recordStaleJob(kind: ImprovementJob["kind"], reason: string): void {
    telemetryEvent("improvement.worker.stale_job", {
      component: "improvement-worker",
      operation: "discard_stale_job",
      "improvement.job_kind": kind,
      "improvement.stale_reason": reason,
    });
  }

  private async evaluateCandidate(job: Extract<ImprovementJob, { kind: "evaluate_candidate" }>): Promise<void> {
    let run = await this.requireRun(job.runId);
    if (run.candidateVersion !== job.candidateVersion) {
      this.recordStaleJob(job.kind, "candidate_version_superseded");
      return;
    }
    if (run.status === "shadowing" || laterThanShadow(run.status)) return;
    await this.verifyCandidateReceipt(job.candidateReceipt, job.receiptSignature, this.requireEvidenceKeyId());
    const boundaryBlocker = candidateReceiptBoundaryBlocker(run, job.candidateReceipt);
    if (boundaryBlocker) {
      await transitionWithRetry(this.store, run.id, { type: "blocked", reason: boundaryBlocker }, "evaluator", this.now);
      return;
    }
    if (job.candidateReceipt.headSha !== job.candidateVersion
      || !sameStrings(job.candidateReceipt.requiredChecks, job.requiredChecks)) {
      await transitionWithRetry(this.store, run.id, {
        type: "blocked",
        reason: "Signed candidate evidence does not match the queued candidate version and required checks.",
      }, "evaluator", this.now);
      return;
    }
    if (run.status === "candidate_ready") {
      if (!run.pullRequest || !run.candidateVersion) throw new Error("Candidate evaluation requires a draft pull request and commit SHA.");
      const assessment = assessCandidateReceipt(job.candidateReceipt, job.requiredChecks);
      if (assessment.state === "pending") {
        throw new Error(`Signed candidate evidence has pending checks: ${assessment.pending.join(", ")}.`);
      }
      const verifiedAt = job.candidateReceipt.observedAt;
      const artifact = await this.artifacts.putJson(run.id, "ci", {
        schemaVersion: 1,
        source: "github_protected_workflow",
        repo: run.pullRequest.repo,
        pullRequestNumber: run.pullRequest.number,
        headSha: run.candidateVersion,
        requiredChecks: job.requiredChecks,
        checks: assessment.checks,
        successful: assessment.state === "passed",
        verifiedAt,
      });
      if (artifact.kind !== "ci") throw new Error("CI artifact store returned the wrong receipt kind.");
      const receipt: ImprovementCiReceipt = {
        repo: run.pullRequest.repo,
        pullRequestNumber: run.pullRequest.number,
        headSha: run.candidateVersion,
        requiredChecks: job.requiredChecks,
        checks: assessment.checks,
        successful: assessment.state === "passed",
        verifiedAt,
        artifact: { ...artifact, kind: "ci" },
      };
      if (!receipt.successful) {
        await transitionWithRetry(this.store, run.id, {
          type: "ci_failed",
          receipt,
          reason: `Required GitHub checks failed for ${run.candidateVersion}: ${assessment.failed.join(", ")}.`,
        }, "evaluator", this.now);
        return;
      }
      run = await transitionWithRetry(this.store, run.id, {
        type: "evaluation_started",
        evaluatorVersion: job.evaluatorVersion,
        ciReceipt: receipt,
      }, "evaluator", this.now);
    } else if (run.status === "evaluating") {
      if (run.evaluatorVersion !== job.evaluatorVersion || !run.ciReceipt?.successful
        || run.ciReceipt.headSha !== job.candidateVersion) {
        throw new Error("Active evaluation does not match the queued candidate and CI receipt.");
      }
    } else {
      throw new Error(`Improvement run ${run.id} is ${run.status}; evaluation requires candidate_ready or evaluating.`);
    }

    const corpus = corpusSchema.parse(await this.artifacts.getJson(job.corpusArtifact));
    const rawCases = Array.isArray(corpus) ? corpus : corpus.cases;
    const cases: TrafficReplayCase[] = rawCases.map(parseTrafficReplayCase);
    const report = buildTrafficReplayReport(cases);
    const artifact = await this.artifacts.putJson(run.id, "evaluation", report);
    if (artifact.kind !== "evaluation") throw new Error("Evaluation artifact store returned the wrong receipt kind.");
    const evaluationArtifact = { ...artifact, kind: "evaluation" as const };
    await transitionWithRetry(this.store, run.id, {
      type: "evaluation_recorded",
      evaluation: {
        corpusPartition: "held_out",
        candidateVersion: job.candidateVersion,
        evaluatorVersion: job.evaluatorVersion,
        releaseReady: report.releaseReady,
        caseCount: report.caseCount,
        passRate: report.passRate,
        averageScore: report.averageScore,
        correctionClosureRate: report.correctionClosureRate,
        regressionRate: report.regressionRate,
        blockers: report.blockers,
        artifact: evaluationArtifact,
      },
    }, "evaluator", this.now);
  }

  private async recordOutcome(
    runId: string,
    candidateVersion: string,
    outcome: ImprovementOutcome,
    stage: ImprovementOutcome["stage"],
  ): Promise<void> {
    if (outcome.stage !== stage) throw new Error(`Outcome stage ${outcome.stage} does not match ${stage}.`);
    const current = await this.requireRun(runId);
    if (current.candidateVersion !== candidateVersion) {
      this.recordStaleJob(stage === "shadow" ? "record_shadow" : "record_canary", "candidate_version_superseded");
      return;
    }
    if (stage === "shadow" && ["canary", "awaiting_promotion", "promoted", "rolled_back", "blocked"].includes(current.status)) return;
    if (stage === "canary" && ["awaiting_promotion", "promoted", "rolled_back", "blocked"].includes(current.status)) return;
    await transitionWithRetry(this.store, runId, {
      type: stage === "shadow" ? "shadow_recorded" : "canary_recorded",
      candidateVersion,
      outcome,
    }, "evaluator", this.now);
  }

  private async applyPromotionDecision(job: Extract<ImprovementJob, { kind: "promotion_decision" }>): Promise<void> {
    const payload = promotionPayloadSchema.parse(job.payload);
    const candidateVersion = requireCandidateVersion(payload.candidateVersion, "Promotion decision payload");
    const current = await this.requireRun(payload.runId);
    if (current.candidateVersion !== candidateVersion) {
      this.recordStaleJob(job.kind, "candidate_version_superseded");
      return;
    }
    const verified = await this.kms.send(new VerifyCommand({
      KeyId: this.requirePromotionKeyId(),
      Message: Buffer.from(stableJson(payload), "utf8"),
      MessageType: "RAW",
      Signature: Buffer.from(job.signature, "base64"),
      SigningAlgorithm: "ECDSA_SHA_256",
    })) as { SignatureValid?: boolean };
    if (!verified.SignatureValid) throw new Error("Promotion decision signature is invalid.");
    if (payload.decision === "promote" && current.status === "promoted") return;
    if (payload.decision === "rollback" && current.status === "rolled_back") return;
    if (payload.decision === "promote") await this.verifyCandidateCommit(current, payload.candidateReceipt);
    const approval = {
      reviewedBy: payload.reviewedBy,
      reviewedAt: payload.reviewedAt,
      sourceRef: payload.sourceRef,
      reason: payload.reason,
      signingKeyId: this.requirePromotionKeyId(),
      signature: job.signature,
    };
    await transitionWithRetry(this.store, payload.runId, payload.decision === "promote"
      ? { type: "promoted", candidateVersion, approval }
      : { type: "rolled_back", candidateVersion, reason: payload.reason, approval }, "promotion_controller", this.now);
  }

  private async verifyCandidateCommit(run: ImprovementRun, receipt: ImprovementCandidateReceipt): Promise<void> {
    if (!run.pullRequest || !run.candidateVersion || !run.ciReceipt?.successful) {
      throw new Error("Promotion requires a candidate pull request, commit SHA, and successful CI receipt.");
    }
    assertCandidateReceiptFresh(receipt, this.now());
    const blocker = candidateReceiptBoundaryBlocker(run, receipt);
    if (blocker || receipt.headSha !== run.candidateVersion || run.ciReceipt.headSha !== run.candidateVersion
      || !sameStrings(receipt.requiredChecks, run.ciReceipt.requiredChecks)) {
      throw new Error("Candidate pull request changed after held-out evaluation.");
    }
    if (assessCandidateReceipt(receipt, run.ciReceipt.requiredChecks).state !== "passed") {
      throw new Error("Promotion requires every receipt-bound GitHub check to remain successful.");
    }
  }

  private async sweepStaleRuns(): Promise<void> {
    const cutoff = this.now().getTime() - this.config.staleRunHours * 3_600_000;
    const statuses: ImprovementRunStatus[] = this.config.lane === "all"
      ? ["queued", "candidate_ready", "evaluating", "shadowing", "canary", "awaiting_promotion"]
      : ["candidate_ready", "evaluating", "shadowing", "canary", "awaiting_promotion"];
    for (const status of statuses) {
      const runs = await this.store.listByStatus(status, 100);
      for (const listed of runs) {
        if (listed.status === "queued") await this.reconcilePendingAuthorRequest(listed);
        const run = await this.requireRun(listed.id);
        if (run.status !== status) continue;
        if (Date.parse(run.updatedAt) >= cutoff) continue;
        await transitionWithRetry(this.store, run.id, {
          type: "blocked",
          reason: `No state change for ${this.config.staleRunHours} hours while ${status}.`,
        }, "worker", this.now).catch((error) => {
          logger.warn("improvement stale run changed during sweep", {
            event: "improvement.worker.sweep_conflict",
            runId: run.id,
            status,
            error: shortError(error),
          });
        });
      }
    }
  }

  private async verifyCandidateReceipt(
    receipt: ImprovementCandidateReceipt,
    signature: string,
    keyId: string,
  ): Promise<void> {
    assertCandidateReceiptFresh(receipt, this.now());
    const verified = await this.kms.send(new VerifyCommand({
      KeyId: keyId,
      Message: Buffer.from(stableJson(receipt), "utf8"),
      MessageType: "RAW",
      Signature: Buffer.from(signature, "base64"),
      SigningAlgorithm: "ECDSA_SHA_256",
    })) as { SignatureValid?: boolean };
    if (!verified.SignatureValid) throw new Error("Candidate evidence signature is invalid.");
  }

  private async verifyAuthorDelegation(job: AuthorGenerationJob): Promise<VerifiedAuthorDelegation | undefined> {
    if (!job.delegation) {
      if (this.config.lane === "all") return undefined;
      throw new CandidateAuthorPolicyError("Author workcells require a signed delegation manifest.");
    }
    if (!this.config.delegationKeyId) {
      throw new CandidateAuthorPolicyError("The delegation verification key is not configured for this workcell.");
    }
    const { manifest, signature } = job.delegation;
    const verified = await this.kms.send(new VerifyCommand({
      KeyId: this.config.delegationKeyId,
      Message: Buffer.from(stableJson(manifest), "utf8"),
      MessageType: "RAW",
      Signature: Buffer.from(signature, "base64"),
      SigningAlgorithm: "ECDSA_SHA_256",
    })) as { SignatureValid?: boolean };
    if (!verified.SignatureValid) throw new CandidateAuthorPolicyError("Delegation signature is invalid.");
    assertDelegationFresh(manifest, this.now());
    const generation = requireAuthorGeneration(job.generation);
    const inputSignalShas = requireAuthorInputSignalShas(job.inputSignalShas);
    const repo = job.kind === "author_candidate"
      ? job.repo ?? this.config.code.defaultRepo
      : job.pullRequest.repo ?? this.config.code.defaultRepo;
    const baseRef = job.kind === "author_candidate" ? job.baseRef : job.pullRequest.base ?? "main";
    if (manifest.runId !== job.runId || manifest.generation !== generation || manifest.jobKind !== job.kind
      || !sameStrings(manifest.inputSignalShas, inputSignalShas)
      || manifest.repo !== repo || manifest.baseRef !== baseRef) {
      throw new CandidateAuthorPolicyError("Delegation does not match the queued author job boundary.");
    }
    if (manifest.policyVersion !== this.config.delegationPolicyVersion
      || manifest.toolsetVersion !== this.config.delegationToolsetVersion) {
      throw new CandidateAuthorPolicyError("Delegation policy or toolset version is not active in this workcell.");
    }
    if (manifest.budgets.maxFiles > Math.min(this.config.code.maxFiles, 6)
      || manifest.budgets.maxFileBytes > Math.min(this.config.code.maxFileBytes, 120_000)
      || manifest.budgets.maxTotalBytes > 200_000
      || manifest.budgets.maxSourceCalls > this.config.author.maxSourceCalls
      || manifest.budgets.maxRuntimeMs > this.config.author.timeoutMs) {
      throw new CandidateAuthorPolicyError("Delegation exceeds this workcell's execution budget.");
    }
    telemetryEvent("improvement.delegation.verified", {
      component: "improvement-worker",
      operation: "verify_author_delegation",
      "improvement.delegation_mode": manifest.rollout.mode,
      "improvement.delegation_cohort": manifest.rollout.cohortBucket,
      "improvement.author_generation": manifest.generation,
    });
    return { manifest, decision: delegationExecutionDecision(manifest) };
  }

  private authorPullRequests(): CandidatePullRequestCreator {
    if (!this.pullRequests) throw new Error("The verifier workcell has no GitHub author credential.");
    return this.pullRequests;
  }

  private authorCandidateAgent(): ImprovementCandidateAuthor {
    if (!this.candidateAuthor) throw new Error("The verifier workcell has no candidate author model.");
    return this.candidateAuthor;
  }

  private requirePromotionKeyId(): string {
    if (!this.config.promotionKeyId) throw new Error("The promotion verification key is not configured for this workcell.");
    return this.config.promotionKeyId;
  }

  private requireEvidenceKeyId(): string {
    if (!this.config.evidenceKeyId) throw new Error("The candidate evidence verification key is not configured for this workcell.");
    return this.config.evidenceKeyId;
  }

  private async requireRun(runId: string): Promise<ImprovementRun> {
    const run = await this.store.get(runId);
    if (!run) throw new Error(`Improvement run ${runId} was not found.`);
    return run;
  }
}

function laterThanCandidate(status: ImprovementRunStatus): boolean {
  return ["evaluating", "shadowing", "canary", "awaiting_promotion", "promoted", "rolled_back", "blocked"].includes(status);
}

function laterThanShadow(status: ImprovementRunStatus): boolean {
  return ["canary", "awaiting_promotion", "promoted", "rolled_back", "blocked"].includes(status);
}

function assessCandidateReceipt(
  receipt: ImprovementCandidateReceipt,
  requiredChecks: string[],
): { state: "passed" | "pending" | "failed"; checks: ImprovementCiCheck[]; pending: string[]; failed: string[] } {
  const checks: ImprovementCiCheck[] = [];
  const pending: string[] = [];
  const failed: string[] = [];
  for (const name of requiredChecks) {
    const check = receipt.checks.find((item) => item.name === name);
    if (check) {
      checks.push(check);
      if ((check.source === "check_run" && check.status !== "completed")
        || (check.source === "commit_status" && check.status === "pending")) pending.push(name);
      else if (check.conclusion !== "success") failed.push(`${name}=${check.conclusion}`);
      continue;
    }
    pending.push(`${name}=missing`);
  }
  return {
    state: pending.length > 0 ? "pending" : failed.length > 0 ? "failed" : "passed",
    checks,
    pending,
    failed,
  };
}

function candidateReceiptBoundaryBlocker(
  run: ImprovementRun,
  receipt: ImprovementCandidateReceipt,
): string | undefined {
  if (!run.pullRequest || receipt.repo !== run.pullRequest.repo || receipt.pullRequestNumber !== run.pullRequest.number
    || receipt.pullRequestUrl !== run.pullRequest.url) {
    return "Signed candidate evidence does not match the stored pull request.";
  }
  if (receipt.state !== "open" || !receipt.draft || receipt.merged) {
    return "Candidate pull request is no longer an open, unmerged draft.";
  }
  if (receipt.headRepo !== run.pullRequest.repo) {
    return "Candidate pull request head repository changed.";
  }
  if (receipt.headRef !== run.pullRequest.branch) {
    return "Candidate pull request branch changed.";
  }
  if (receipt.headSha !== run.candidateVersion) return "Candidate pull request head changed.";
  const intent = run.candidateWriteIntent;
  if (intent && (receipt.baseRef !== intent.baseRef || receipt.baseSha !== intent.expectedBaseSha)) {
    return "Candidate pull request base changed.";
  }
  return undefined;
}

function laneAllows(lane: ImprovementWorkerConfig["lane"], kind: ImprovementJob["kind"]): boolean {
  if (lane === "all") return true;
  if (lane === "author") return kind === "author_candidate" || kind === "open_candidate_pr";
  return kind === "evaluate_candidate" || kind === "record_shadow" || kind === "record_canary"
    || kind === "promotion_decision" || kind === "sweep_stale_runs";
}

function assertCandidateReceiptFresh(receipt: ImprovementCandidateReceipt, now: Date): void {
  const observedAt = Date.parse(receipt.observedAt);
  const ageMs = now.getTime() - observedAt;
  if (!Number.isFinite(observedAt) || ageMs < -300_000 || ageMs > 3_600_000) {
    throw new Error("Signed candidate evidence is outside the one-hour verification window.");
  }
}

function assertAuthoredWithinDelegation(
  manifest: ImprovementDelegationManifest,
  authored: ImprovementCandidateAuthorResult,
  runtimeMs: number,
): void {
  if (authored.resolvedRef !== manifest.sourceSha) {
    throw new CandidateAuthorPolicyError("Candidate author resolved a source commit outside its delegation.");
  }
  if (authored.sourceCallCount > manifest.budgets.maxSourceCalls || runtimeMs > manifest.budgets.maxRuntimeMs) {
    throw new CandidateAuthorPolicyError("Candidate author exceeded its delegated source-call or runtime budget.");
  }
  const totalBytes = authored.pullRequest.files.reduce((total, file) => total + Buffer.byteLength(file.content, "utf8"), 0);
  if (authored.pullRequest.repo !== manifest.repo || (authored.pullRequest.base ?? "main") !== manifest.baseRef
    || authored.pullRequest.draft !== true || authored.pullRequest.files.length > manifest.budgets.maxFiles
    || totalBytes > manifest.budgets.maxTotalBytes
    || authored.pullRequest.files.some((file) => Buffer.byteLength(file.content, "utf8") > manifest.budgets.maxFileBytes)) {
    throw new CandidateAuthorPolicyError("Candidate author exceeded its delegated repository, base, draft, or file budget.");
  }
}

function assertPullRequestWithinDelegation(manifest: ImprovementDelegationManifest, pullRequest: RuntimeCodePrInput): void {
  const repo = pullRequest.repo;
  const baseRef = pullRequest.base ?? "main";
  const totalBytes = pullRequest.files.reduce((total, file) => total + Buffer.byteLength(file.content, "utf8"), 0);
  if (repo !== manifest.repo || baseRef !== manifest.baseRef || pullRequest.expectedBaseSha !== manifest.baseSha
    || pullRequest.draft !== true || pullRequest.files.length > manifest.budgets.maxFiles
    || totalBytes > manifest.budgets.maxTotalBytes
    || pullRequest.files.some((file) => Buffer.byteLength(file.content, "utf8") > manifest.budgets.maxFileBytes)) {
    throw new CandidateAuthorPolicyError("Candidate pull request exceeds its delegated repository, base, draft, or file budget.");
  }
}

function shortError(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).replace(/\s+/g, " ").slice(0, 300);
}

function safeCandidateError(error: unknown): string {
  return redactSecurityText(shortError(error)).replace(/\s+/g, " ").slice(0, 300);
}

function requireAuthorGeneration(value: number | undefined): number {
  if (!value) throw new Error("Candidate author job is missing its persisted author generation.");
  return value;
}

function requireAuthorInputSignalShas(value: string[] | undefined): string[] {
  if (!value || value.length === 0) throw new Error("Candidate author job is missing its exact input signal SHA set.");
  return value;
}

function requireCandidateVersion(value: string | undefined, label: string): string {
  if (!value) throw new Error(`${label} is missing its exact candidate version.`);
  return value;
}

function sameStrings(left: string[] | undefined, right: string[]): boolean {
  return Boolean(left && left.length === right.length && left.every((value, index) => value === right[index]));
}

function authorJobMatchesRequest(job: AuthorGenerationJob, run: ImprovementRun): boolean {
  const request = run.authorRequest;
  if (!request || request.generation !== job.generation || !sameStrings(request.inputSignalShas, job.inputSignalShas ?? [])) return false;
  if (job.kind === "author_candidate") return request.repo === job.repo && request.baseRef === job.baseRef;
  return request.repo === job.pullRequest.repo && request.baseRef === (job.pullRequest.base ?? "main");
}

function bindCandidateWrite(
  input: RuntimeCodePrInput,
  resolvedBaseSha: string,
  prior: ImprovementRun["candidateBranchWrite"],
): RuntimeCodePrInput {
  const expectedHeadSha = prior
    && prior.repo === input.repo
    && prior.baseRef === (input.base ?? "main")
    && prior.branch === input.branch
    ? prior.headSha
    : resolvedBaseSha;
  return {
    ...input,
    expectedBaseSha: resolvedBaseSha,
    expectedHeadSha,
    draft: true,
    draftBoundReuse: true,
  };
}

function stableSha256(value: unknown): string {
  return createHash("sha256").update(stableJson(value)).digest("hex");
}

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function sameStringSet(left: string[], right: string[]): boolean {
  if (left.length !== right.length) return false;
  const sortedRight = [...right].sort();
  return [...left].sort().every((value, index) => value === sortedRight[index]);
}

async function wait(ms: number): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, Math.max(250, Math.min(ms, 60_000)));
  });
}
