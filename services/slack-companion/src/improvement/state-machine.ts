import { createHash, randomBytes } from "node:crypto";
import type {
  ImprovementApproval,
  ImprovementArtifact,
  ImprovementCiReceipt,
  ImprovementEvaluation,
  ImprovementEvent,
  ImprovementHumanAssistance,
  ImprovementOutcome,
  ImprovementPullRequest,
  ImprovementRun,
  ImprovementRunStatus,
  ImprovementSignal,
} from "./types.js";

export type ImprovementTransition =
  | { type: "signal_recorded"; artifact: ImprovementArtifact }
  | { type: "queued" }
  | { type: "author_requested"; inputSignalShas: string[]; repo?: string; baseRef: string; assistance?: Pick<ImprovementHumanAssistance, "channelId" | "intendedUserId" | "expiresAt"> }
  | { type: "assistance_enqueued"; deliveryId: string }
  | { type: "refinement_requested"; artifact: ImprovementArtifact & { kind: "signal" }; inputSignalShas: string[]; repo?: string; baseRef: string }
  | { type: "author_dispatched"; generation: number }
  | { type: "author_claimed"; generation: number; token: string; expiresAt: string }
  | { type: "author_write_intended"; generation: number; token: string; repo: string; baseRef: string; branch: string; expectedBaseSha: string; expectedHeadSha: string; payloadSha256: string; artifact: ImprovementArtifact }
  | { type: "author_write_recorded"; generation: number; token: string; repo: string; baseRef: string; branch: string; pullRequestNumber: number; pullRequestUrl: string; headSha: string }
  | { type: "author_released"; generation: number; token: string }
  | { type: "candidate_ready"; candidateVersion: string; pullRequest: ImprovementPullRequest; artifact?: ImprovementArtifact; authorGeneration?: number; authorLeaseToken?: string }
  | { type: "candidate_revised"; candidateVersion: string; artifact: ImprovementArtifact }
  | { type: "evaluation_started"; evaluatorVersion: string; ciReceipt: ImprovementCiReceipt }
  | { type: "ci_failed"; receipt: ImprovementCiReceipt; reason: string }
  | { type: "evaluation_recorded"; evaluation: ImprovementEvaluation }
  | { type: "shadow_recorded"; candidateVersion: string; outcome: ImprovementOutcome }
  | { type: "canary_recorded"; candidateVersion: string; outcome: ImprovementOutcome }
  | { type: "promoted"; candidateVersion: string; approval: ImprovementApproval }
  | { type: "rolled_back"; reason: string; candidateVersion?: string; approval?: ImprovementApproval; artifact?: ImprovementArtifact }
  | { type: "blocked"; reason: string; authorGeneration?: number; authorLeaseToken?: string };

export interface ImprovementTransitionResult {
  run: ImprovementRun;
  event: ImprovementEvent;
}

export function newImprovementRun(signal: ImprovementSignal, artifact: ImprovementArtifact, now: Date, cooldownHours: number): ImprovementRun {
  const timestamp = now.toISOString();
  return {
    id: improvementRunId(signal.signature, now, cooldownHours),
    candidateKey: randomBytes(6).toString("hex"),
    signature: signal.signature,
    source: signal.source,
    issueKind: signal.issueKind,
    skillId: signal.skillId,
    status: "observed",
    signalCount: 1,
    artifacts: [artifact],
    blockers: [],
    version: 1,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

export function transitionImprovementRun(
  current: ImprovementRun,
  transition: ImprovementTransition,
  input: { now: Date; actor: ImprovementEvent["actor"] },
): ImprovementTransitionResult {
  const next = structuredClone(current);
  const fromStatus = current.status;
  const at = input.now.toISOString();
  let toStatus = fromStatus;
  let detail: ImprovementEvent["detail"] = {};

  switch (transition.type) {
    case "signal_recorded":
      requireStatus(current, ["observed", "queued"]);
      next.signalCount += 1;
      appendArtifact(next, transition.artifact);
      detail = { signal_count: next.signalCount };
      break;
    case "queued":
      requireStatus(current, ["observed"]);
      toStatus = "queued";
      next.queuedAt = at;
      break;
    case "assistance_enqueued":
      requireStatus(current, ["queued", "candidate_ready", "evaluating", "shadowing", "canary", "awaiting_promotion"]);
      if (!current.assistance) throw new Error("Human assistance delivery requires a persisted recipient.");
      if (current.assistance.deliveryStatus !== "answered") {
        next.assistance = {
          ...current.assistance,
          deliveryStatus: "enqueued",
          deliveryId: bounded(transition.deliveryId, 240),
        };
      }
      detail = { delivery_status: next.assistance?.deliveryStatus ?? "answered" };
      break;
    case "refinement_requested":
      requireStatus(current, ["queued", "candidate_ready", "evaluating", "shadowing", "canary", "awaiting_promotion"]);
      if (!current.assistance) throw new Error("Human assistance outcome requires a persisted recipient.");
      if (transition.artifact.kind !== "signal") throw new Error("Human assistance outcome must be stored as a signal artifact.");
      toStatus = "queued";
      appendArtifact(next, transition.artifact);
      next.assistance = {
        ...current.assistance,
        deliveryStatus: "answered",
        outcomeArtifact: transition.artifact,
        refinementStatus: "pending",
      };
      next.refinementBaseVersion = current.candidateVersion;
      const inputSignalShas = uniqueSignalShas(next, transition.inputSignalShas);
      next.authorGeneration = (current.authorGeneration ?? 0) + 1;
      next.authorInputSignalShas = inputSignalShas;
      next.authorRequest = {
        generation: next.authorGeneration,
        inputSignalShas,
        repo: transition.repo,
        baseRef: transition.baseRef,
        requestedAt: at,
      };
      delete next.authorDispatch;
      delete next.candidateVersion;
      delete next.evaluatorVersion;
      delete next.ciReceipt;
      delete next.evaluation;
      delete next.shadowOutcome;
      delete next.canaryOutcome;
      delete next.approval;
      next.blockers = [];
      detail = { refinement_status: "pending", author_generation: next.authorGeneration, input_signal_count: inputSignalShas.length };
      break;
    case "author_requested": {
      requireStatus(current, ["observed", "queued"]);
      const requestedSignalShas = uniqueSignalShas(current, transition.inputSignalShas);
      const latestSignalShas = current.artifacts
        .filter((artifact) => artifact.kind === "signal")
        .slice(-6)
        .map((artifact) => artifact.sha256);
      const inputSignalShas = sameStrings(requestedSignalShas, latestSignalShas)
        ? requestedSignalShas
        : latestSignalShas;
      const sameGeneration = current.status === "queued"
        && sameStrings(current.authorInputSignalShas, inputSignalShas)
        && Boolean(current.authorRequest
          && current.authorRequest.repo === transition.repo
          && current.authorRequest.baseRef === transition.baseRef);
      next.authorGeneration = sameGeneration && current.authorGeneration ? current.authorGeneration : (current.authorGeneration ?? 0) + 1;
      next.authorInputSignalShas = inputSignalShas;
      if (!sameGeneration) {
        next.authorRequest = {
          generation: next.authorGeneration,
          inputSignalShas,
          repo: transition.repo,
          baseRef: transition.baseRef,
          requestedAt: at,
        };
        delete next.authorDispatch;
      }
      toStatus = "queued";
      next.queuedAt ??= at;
      if (!current.assistance && transition.assistance) {
        next.assistance = { ...transition.assistance, deliveryStatus: "pending" };
      }
      detail = { author_generation: next.authorGeneration, input_signal_count: inputSignalShas.length, generation_changed: !sameGeneration };
      break;
    }
    case "author_dispatched":
      requireStatus(current, ["queued"]);
      assertAuthorGeneration(current, transition.generation);
      if (!current.authorRequest || current.authorRequest.generation !== transition.generation) {
        throw new Error("Improvement run does not have the matching durable author request.");
      }
      next.authorDispatch = { generation: transition.generation, enqueuedAt: at };
      detail = { author_generation: transition.generation };
      break;
    case "author_claimed":
      requireStatus(current, ["queued"]);
      assertAuthorGeneration(current, transition.generation);
      if (current.authorLease && Date.parse(current.authorLease.expiresAt) > input.now.getTime()) {
        throw new Error(`Improvement author generation ${current.authorLease.generation} already has an active lease.`);
      }
      if (Date.parse(transition.expiresAt) <= input.now.getTime()) throw new Error("Improvement author lease must expire in the future.");
      next.authorLease = {
        generation: transition.generation,
        token: transition.token,
        acquiredAt: at,
        expiresAt: transition.expiresAt,
      };
      detail = { author_generation: transition.generation, lease_expires_at: transition.expiresAt };
      break;
    case "author_write_intended": {
      requireStatus(current, ["queued"]);
      assertAuthorGeneration(current, transition.generation);
      assertActiveAuthorLease(current, transition.generation, transition.token, input.now);
      if (!current.authorRequest || (current.authorRequest.repo && current.authorRequest.repo !== transition.repo)
        || current.authorRequest.baseRef !== transition.baseRef) {
        throw new Error("Candidate write intent does not match the active repository target.");
      }
      if (transition.artifact.kind !== "candidate_intent" || transition.artifact.sha256 !== transition.payloadSha256) {
        throw new Error("Candidate write intent requires its exact immutable payload artifact.");
      }
      const intended = {
        generation: transition.generation,
        repo: transition.repo,
        baseRef: transition.baseRef,
        branch: transition.branch,
        expectedBaseSha: transition.expectedBaseSha,
        expectedHeadSha: transition.expectedHeadSha,
        payloadSha256: transition.payloadSha256,
        artifact: { ...transition.artifact, kind: "candidate_intent" as const },
        recordedAt: at,
      };
      if (current.candidateWriteIntent?.generation === transition.generation
        && !sameCandidateWriteIntent(current.candidateWriteIntent, intended)) {
        throw new Error("Candidate write intent is immutable within an author generation.");
      }
      if (current.candidateWriteIntent && current.candidateWriteIntent.generation > transition.generation) {
        throw new Error("Candidate write intent is older than the active stored intent.");
      }
      next.candidateWriteIntent = current.candidateWriteIntent?.generation === transition.generation
        ? current.candidateWriteIntent
        : intended;
      appendArtifact(next, transition.artifact);
      detail = { author_generation: transition.generation, payload_sha256: transition.payloadSha256 };
      break;
    }
    case "author_write_recorded":
      requireStatus(current, ["queued"]);
      assertMatchingAuthorLease(current, transition.generation, transition.token);
      if (!current.authorRequest || (current.authorRequest.repo && current.authorRequest.repo !== transition.repo)
        || current.authorRequest.baseRef !== transition.baseRef) {
        throw new Error("Candidate branch write does not match the active repository target.");
      }
      if (!current.candidateWriteIntent || current.candidateWriteIntent.generation !== transition.generation
        || current.candidateWriteIntent.repo !== transition.repo
        || current.candidateWriteIntent.baseRef !== transition.baseRef
        || current.candidateWriteIntent.branch !== transition.branch) {
        throw new Error("Candidate branch write does not match the durable write intent.");
      }
      if (current.candidateWriteIntent.expectedHeadSha === transition.headSha) {
        throw new Error("Candidate branch write did not advance the intended head.");
      }
      if (current.candidateBranchWrite && current.candidateBranchWrite.generation > transition.generation) {
        throw new Error("Candidate branch write is older than the stored branch head receipt.");
      }
      next.candidateBranchWrite = {
        generation: transition.generation,
        repo: transition.repo,
        baseRef: transition.baseRef,
        branch: transition.branch,
        pullRequestNumber: transition.pullRequestNumber,
        pullRequestUrl: transition.pullRequestUrl,
        headSha: transition.headSha,
        recordedAt: at,
      };
      detail = { author_generation: transition.generation, candidate_version: transition.headSha, pull_number: transition.pullRequestNumber };
      break;
    case "author_released":
      requireStatus(current, ["queued"]);
      assertMatchingAuthorLease(current, transition.generation, transition.token);
      delete next.authorLease;
      detail = { author_generation: transition.generation };
      break;
    case "candidate_ready":
      requireStatus(current, ["queued"]);
      if (current.pullRequest && (current.pullRequest.repo !== transition.pullRequest.repo
        || current.pullRequest.number !== transition.pullRequest.number
        || current.pullRequest.branch !== transition.pullRequest.branch)) {
        throw new Error("Refinement must update the existing draft pull request.");
      }
      if (current.authorGeneration !== undefined) {
        if (transition.authorGeneration === undefined || !transition.authorLeaseToken) {
          throw new Error("Candidate readiness requires the active author generation and lease token.");
        }
        assertActiveAuthorLease(current, transition.authorGeneration, transition.authorLeaseToken, input.now);
        if (!current.candidateWriteIntent || current.candidateWriteIntent.generation !== transition.authorGeneration) {
          throw new Error("Candidate readiness requires the matching durable write intent.");
        }
        if (!current.candidateBranchWrite || current.candidateBranchWrite.generation !== transition.authorGeneration
          || current.candidateBranchWrite.repo !== transition.pullRequest.repo
          || current.candidateBranchWrite.branch !== transition.pullRequest.branch
          || current.candidateBranchWrite.pullRequestNumber !== transition.pullRequest.number
          || current.candidateBranchWrite.headSha !== transition.candidateVersion) {
          throw new Error("Candidate readiness requires the matching branch write receipt.");
        }
        next.candidateGeneration = transition.authorGeneration;
      } else if (transition.authorGeneration !== undefined || transition.authorLeaseToken) {
        throw new Error("Legacy candidate runs cannot accept a generation claim.");
      }
      toStatus = "candidate_ready";
      next.candidateVersion = bounded(transition.candidateVersion, 200);
      delete next.refinementBaseVersion;
      next.pullRequest = transition.pullRequest;
      delete next.authorLease;
      if (transition.artifact) appendArtifact(next, transition.artifact);
      if (current.assistance?.outcomeArtifact
        && current.authorInputSignalShas?.includes(current.assistance.outcomeArtifact.sha256)) {
        next.assistance = {
          ...current.assistance,
          refinementStatus: "completed",
        };
      }
      detail = {
        candidate_version: next.candidateVersion,
        pull_number: transition.pullRequest.number,
        ...(next.candidateGeneration ? { author_generation: next.candidateGeneration } : {}),
      };
      break;
    case "candidate_revised":
      requireStatus(current, ["candidate_ready"]);
      if (!current.pullRequest) throw new Error("Candidate revision requires an existing draft pull request.");
      next.candidateVersion = bounded(transition.candidateVersion, 200);
      delete next.ciReceipt;
      delete next.evaluatorVersion;
      delete next.evaluation;
      appendArtifact(next, transition.artifact);
      detail = { candidate_version: next.candidateVersion, pull_number: current.pullRequest.number };
      break;
    case "evaluation_started":
      requireStatus(current, ["candidate_ready"]);
      assertDistinctVersions(current.candidateVersion, transition.evaluatorVersion);
      assertCiReceipt(current, transition.ciReceipt, true);
      toStatus = "evaluating";
      next.evaluatorVersion = bounded(transition.evaluatorVersion, 200);
      next.ciReceipt = transition.ciReceipt;
      appendArtifact(next, transition.ciReceipt.artifact);
      detail = { evaluator_version: next.evaluatorVersion, candidate_version: transition.ciReceipt.headSha };
      break;
    case "ci_failed":
      requireStatus(current, ["candidate_ready"]);
      assertCiReceipt(current, transition.receipt, false);
      toStatus = "blocked";
      next.ciReceipt = transition.receipt;
      next.blockers = [bounded(transition.reason, 500)];
      appendArtifact(next, transition.receipt.artifact);
      detail = { candidate_version: transition.receipt.headSha, reason: next.blockers[0] ?? "required_ci_failed" };
      break;
    case "evaluation_recorded":
      requireStatus(current, ["evaluating"]);
      assertEvaluation(current, transition.evaluation);
      next.evaluation = transition.evaluation;
      appendArtifact(next, transition.evaluation.artifact);
      toStatus = transition.evaluation.releaseReady ? "shadowing" : "blocked";
      next.blockers = transition.evaluation.releaseReady ? [] : transition.evaluation.blockers;
      detail = { candidate_version: transition.evaluation.candidateVersion, release_ready: transition.evaluation.releaseReady, case_count: transition.evaluation.caseCount };
      break;
    case "shadow_recorded":
      requireStatus(current, ["shadowing"]);
      assertCandidateVersion(current, transition.candidateVersion, "Shadow outcome");
      requireOutcomeStage(transition.outcome, "shadow");
      next.shadowOutcome = transition.outcome;
      appendArtifact(next, transition.outcome.artifact);
      toStatus = transition.outcome.success ? "canary" : "rolled_back";
      detail = { candidate_version: transition.candidateVersion, success: transition.outcome.success, sample_size: transition.outcome.sampleSize };
      break;
    case "canary_recorded":
      requireStatus(current, ["canary"]);
      assertCandidateVersion(current, transition.candidateVersion, "Canary outcome");
      requireOutcomeStage(transition.outcome, "canary");
      next.canaryOutcome = transition.outcome;
      appendArtifact(next, transition.outcome.artifact);
      toStatus = transition.outcome.success ? "awaiting_promotion" : "rolled_back";
      detail = { candidate_version: transition.candidateVersion, success: transition.outcome.success, sample_size: transition.outcome.sampleSize };
      break;
    case "promoted":
      requireStatus(current, ["awaiting_promotion"]);
      assertCandidateVersion(current, transition.candidateVersion, "Promotion decision");
      if (!current.ciReceipt?.successful || current.ciReceipt.headSha !== current.candidateVersion
        || !current.evaluation?.releaseReady || !current.shadowOutcome?.success || !current.canaryOutcome?.success) {
        throw new Error("Promotion requires bound passing CI, held-out evaluation, shadow outcome, and canary outcome.");
      }
      assertDistinctVersions(current.candidateVersion, current.evaluatorVersion);
      toStatus = "promoted";
      next.approval = transition.approval;
      detail = { candidate_version: transition.candidateVersion, reviewed_by: transition.approval.reviewedBy, source_ref: transition.approval.sourceRef };
      break;
    case "rolled_back":
      requireStatus(current, ["queued", "candidate_ready", "evaluating", "shadowing", "canary", "awaiting_promotion"]);
      if (transition.candidateVersion !== undefined) assertCandidateVersion(current, transition.candidateVersion, "Rollback decision");
      toStatus = "rolled_back";
      next.blockers = [bounded(transition.reason, 500)];
      next.approval = transition.approval;
      if (transition.artifact) appendArtifact(next, transition.artifact);
      detail = { ...(transition.candidateVersion ? { candidate_version: transition.candidateVersion } : {}), reason: next.blockers[0] ?? "rollback" };
      break;
    case "blocked":
      requireStatus(current, ["observed", "queued", "candidate_ready", "evaluating", "shadowing", "canary", "awaiting_promotion"]);
      if (transition.authorGeneration !== undefined || transition.authorLeaseToken !== undefined) {
        if (transition.authorGeneration === undefined || !transition.authorLeaseToken) {
          throw new Error("Authoring block requires both the generation and lease token.");
        }
        assertActiveAuthorLease(current, transition.authorGeneration, transition.authorLeaseToken, input.now);
      }
      toStatus = "blocked";
      delete next.authorLease;
      next.blockers = [bounded(transition.reason, 500)];
      detail = { reason: next.blockers[0] ?? "blocked" };
      break;
  }

  next.status = toStatus;
  next.version = current.version + 1;
  next.updatedAt = at;
  const event: ImprovementEvent = {
    id: `${at}#${String(next.version).padStart(8, "0")}#${transition.type}`,
    runId: next.id,
    type: transition.type,
    fromStatus,
    toStatus,
    at,
    actor: input.actor,
    detail,
  };
  return { run: next, event };
}

function sameCandidateWriteIntent(
  left: ImprovementRun["candidateWriteIntent"],
  right: NonNullable<ImprovementRun["candidateWriteIntent"]>,
): boolean {
  return Boolean(left
    && left.generation === right.generation
    && left.repo === right.repo
    && left.baseRef === right.baseRef
    && left.branch === right.branch
    && left.expectedBaseSha === right.expectedBaseSha
    && left.expectedHeadSha === right.expectedHeadSha
    && left.payloadSha256 === right.payloadSha256
    && left.artifact.uri === right.artifact.uri
    && left.artifact.sha256 === right.artifact.sha256);
}

export function initialImprovementEvent(run: ImprovementRun): ImprovementEvent {
  return {
    id: `${run.createdAt}#00000001#observed`,
    runId: run.id,
    type: "observed",
    toStatus: "observed",
    at: run.createdAt,
    actor: "companion",
    detail: { signal_count: run.signalCount },
  };
}

export function improvementRunId(signature: string, now: Date, cooldownHours: number): string {
  const windowMs = Math.max(1, cooldownHours) * 3_600_000;
  const window = Math.floor(now.getTime() / windowMs);
  const digest = createHash("sha256").update(`${signature}|${window}`).digest("hex").slice(0, 24);
  return `improvement-${digest}`;
}

export function terminalImprovementStatus(status: ImprovementRunStatus): boolean {
  return status === "promoted" || status === "rolled_back" || status === "blocked";
}

function requireStatus(run: ImprovementRun, allowed: ImprovementRunStatus[]): void {
  if (!allowed.includes(run.status)) {
    throw new Error(`Improvement run ${run.id} cannot transition from ${run.status}.`);
  }
}

function assertDistinctVersions(candidateVersion: string | undefined, evaluatorVersion: string | undefined): void {
  if (!candidateVersion || !evaluatorVersion) throw new Error("Candidate and evaluator versions are required.");
  if (candidateVersion === evaluatorVersion) throw new Error("Candidate and evaluator versions must be different.");
}

function assertAuthorGeneration(run: ImprovementRun, generation: number): void {
  if (!run.authorGeneration || !run.authorInputSignalShas) throw new Error("Improvement run does not have a persisted author generation.");
  if (run.authorGeneration !== generation) throw new Error(`Author generation ${generation} is stale; current generation is ${run.authorGeneration}.`);
}

function assertAuthorLease(run: ImprovementRun, generation: number, token: string): void {
  assertAuthorGeneration(run, generation);
  assertMatchingAuthorLease(run, generation, token);
}

function assertMatchingAuthorLease(run: ImprovementRun, generation: number, token: string): void {
  if (!run.authorLease || run.authorLease.generation !== generation || run.authorLease.token !== token) {
    throw new Error("Improvement author lease does not match the active generation claim.");
  }
}

function assertActiveAuthorLease(run: ImprovementRun, generation: number, token: string, now: Date): void {
  assertAuthorLease(run, generation, token);
  if (Date.parse(run.authorLease!.expiresAt) <= now.getTime()) throw new Error("Improvement author lease expired before the write completed.");
}

function assertCandidateVersion(run: ImprovementRun, candidateVersion: string, label: string): void {
  if (!run.candidateVersion || run.candidateVersion !== candidateVersion) {
    throw new Error(`${label} candidate version does not match the active candidate.`);
  }
}

function uniqueSignalShas(run: ImprovementRun, values: string[]): string[] {
  const shas = [...new Set(values)];
  if (shas.length === 0 || shas.length > 6 || shas.length !== values.length) {
    throw new Error("Author generation requires one to six unique signal artifact SHA values.");
  }
  const available = new Set(run.artifacts.filter((artifact) => artifact.kind === "signal").map((artifact) => artifact.sha256));
  if (shas.some((sha) => !/^[a-f0-9]{64}$/.test(sha) || !available.has(sha))) {
    throw new Error("Author generation input does not match the run's signal artifacts.");
  }
  return shas;
}

function sameStrings(left: string[] | undefined, right: string[]): boolean {
  return Boolean(left && left.length === right.length && left.every((value, index) => value === right[index]));
}

function assertEvaluation(run: ImprovementRun, evaluation: ImprovementEvaluation): void {
  assertDistinctVersions(evaluation.candidateVersion, evaluation.evaluatorVersion);
  if (run.candidateVersion !== evaluation.candidateVersion) throw new Error("Evaluation candidate version does not match the run.");
  if (run.evaluatorVersion !== evaluation.evaluatorVersion) throw new Error("Evaluation version does not match the active evaluator.");
  if (!run.ciReceipt?.successful || run.ciReceipt.headSha !== evaluation.candidateVersion) {
    throw new Error("Evaluation requires a successful GitHub CI receipt bound to the candidate version.");
  }
  if (evaluation.corpusPartition !== "held_out") throw new Error("Promotion evaluation must use the held-out corpus.");
  if (evaluation.artifact.kind !== "evaluation") throw new Error("Evaluation receipt must reference an evaluation artifact.");
}

function assertCiReceipt(run: ImprovementRun, receipt: ImprovementCiReceipt, successful: boolean): void {
  if (!run.pullRequest || !run.candidateVersion) throw new Error("GitHub CI verification requires a candidate pull request and commit SHA.");
  if (receipt.repo !== run.pullRequest.repo || receipt.pullRequestNumber !== run.pullRequest.number) {
    throw new Error("GitHub CI receipt does not match the candidate pull request.");
  }
  if (receipt.headSha !== run.candidateVersion) throw new Error("GitHub CI receipt does not match the candidate version.");
  if (receipt.successful !== successful) throw new Error(`GitHub CI receipt must be ${successful ? "successful" : "failed"}.`);
  if (receipt.artifact.kind !== "ci") throw new Error("GitHub CI receipt must reference a CI artifact.");
}

function requireOutcomeStage(outcome: ImprovementOutcome, stage: ImprovementOutcome["stage"]): void {
  if (outcome.stage !== stage) throw new Error(`Expected ${stage} outcome, received ${outcome.stage}.`);
  if (outcome.artifact.kind !== stage) throw new Error(`${stage} receipt must reference a ${stage} artifact.`);
  if (!outcome.success && !outcome.rollbackReason) throw new Error(`Failed ${stage} outcomes require a rollback reason.`);
}

function appendArtifact(run: ImprovementRun, artifact: ImprovementArtifact): void {
  if (!run.artifacts.some((item) => item.uri === artifact.uri && item.sha256 === artifact.sha256)) run.artifacts.push(artifact);
}

function bounded(value: string, max: number): string {
  return value.trim().replace(/\s+/g, " ").slice(0, max);
}
