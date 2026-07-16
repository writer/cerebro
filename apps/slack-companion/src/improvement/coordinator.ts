import { createHash } from "node:crypto";
import type { ExecutionCoordinator } from "../execution/coordinator.js";
import { ExecutionInvariantError } from "../execution/coordinator.js";
import type {
  ExternalEffectDraft,
  ExternalEffectInspection,
  ExternalEffectPort,
  ExternalEffectResult,
  ExternalEffectVerification,
  RecoverableExternalEffectInspection,
} from "../execution/effect-reconciliation.js";
import { ExternalEffectReconciler } from "../execution/effect-reconciliation.js";
import type {
  EffectIntentValue,
  ExternalEffectIntentV1,
  WorkLeaseV1,
} from "../execution/model.js";
import type { DurableExecutionPort } from "../execution/ports.js";
import { stableIdentity } from "../delivery/coordinator.js";
import {
  IMPROVEMENT_EVIDENCE_KINDS,
  type ImprovementAuthoringIntent,
  type ImprovementAuthoringOutcome,
  type ImprovementAuthoringRequest,
  type ImprovementCandidateInput,
  type ImprovementCandidateV1,
  type ImprovementEvidenceSnapshot,
  type ImprovementFreshEvidenceInput,
} from "./contracts.js";
import type {
  DurableImprovementCandidatePort,
  ImprovementAuthorPort,
  ImprovementClockPort,
  ImprovementEvidencePort,
  ImprovementVerificationPort,
} from "./ports.js";

export class ImprovementConflictError extends Error {}
export class ImprovementInputError extends Error {}

export interface ImprovementCoordinatorOptions {
  author: ImprovementAuthorPort;
  candidates: DurableImprovementCandidatePort;
  clock: ImprovementClockPort;
  evidence: ImprovementEvidencePort;
  execution: ExecutionCoordinator;
  execution_store: Pick<
    DurableExecutionPort,
    "getEffectIntent" | "persistEffectIntent"
  >;
  verification: ImprovementVerificationPort;
}

export class ImprovementCoordinator {
  private readonly author: ImprovementAuthorPort;
  private readonly candidates: DurableImprovementCandidatePort;
  private readonly clock: ImprovementClockPort;
  private readonly effects: ExternalEffectReconciler;
  private readonly evidence: ImprovementEvidencePort;
  private readonly execution: ExecutionCoordinator;

  constructor(options: ImprovementCoordinatorOptions) {
    this.author = options.author;
    this.candidates = options.candidates;
    this.clock = options.clock;
    this.evidence = options.evidence;
    this.execution = options.execution;
    this.effects = new ExternalEffectReconciler({
      clock: options.clock,
      execution: options.execution,
      external: new ImprovementEffectBridge(
        options.author,
        options.evidence,
        options.verification,
      ),
      store: options.execution_store,
    });
  }

  async register(
    input: ImprovementCandidateInput,
  ): Promise<{ candidate: ImprovementCandidateV1; created: boolean }> {
    validateCandidateInput(input);
    const now = this.clock.now().toISOString();
    const candidateId = stableIdentity("improvement", [
      input.candidate_key_digest,
    ]);
    const candidate: ImprovementCandidateV1 = {
      author_generation: 0,
      base_digest: input.base_digest,
      branch_ref: input.branch_ref,
      candidate_id: candidateId,
      candidate_key_digest: input.candidate_key_digest,
      created_at: now,
      draft_ref: input.draft_ref,
      head_digest: input.head_digest,
      revision: 1,
      schema_version: "improvement-candidate/v1",
      status: "open",
      updated_at: now,
    };
    return this.candidates.putIfAbsent({
      candidate,
      payload_fingerprint: digest(JSON.stringify([
        input.base_digest,
        input.branch_ref,
        input.candidate_key_digest,
        input.draft_ref,
        input.head_digest,
      ])),
    });
  }

  async authorCandidate(
    request: ImprovementAuthoringRequest,
  ): Promise<ImprovementAuthoringOutcome> {
    validateAuthoringRequest(request);
    if (request.session.run.state !== "running") {
      throw new ImprovementInputError("Improvement authoring requires a running execution session.");
    }
    const current = await this.requireCandidate(request.candidate_id);
    assertExpectedCandidate(current, request);
    const draft = await this.author.inspectDraft(request.expected_draft_ref);
    assertExactOpenDraft(draft, request, current.status === "authoring");

    const reservation = await this.candidates.reserveAuthor({
      candidate_id: request.candidate_id,
      expected_author_generation: request.expected_author_generation,
      expected_base_digest: request.expected_base_digest,
      expected_branch_ref: request.expected_branch_ref,
      expected_draft_ref: request.expected_draft_ref,
      expected_head_digest: request.expected_head_digest,
      expected_revision: request.expected_revision,
      lease: request.session.lease,
      reserved_at: this.clock.now().toISOString(),
    });
    const reserved = reservation.candidate;
    const candidateVersion = stableIdentity("candidate-version", [
      reserved.candidate_id,
      String(reserved.author_generation),
      request.expected_head_digest,
    ]);
    const intent = improvementIntent(reserved, candidateVersion);
    const intentDigest = digest(JSON.stringify(intent));

    await ensurePreparedCheckpoint(this.execution, request, {
      checkpoint_id: stableIdentity("checkpoint", [candidateVersion, "prepared"]),
      completed_step_ids: ["candidate_reserved", "prior_head_verified"],
      effect_receipt_ids: [],
      payload_digest: intentDigest,
      payload_ref: `improvement-intent://${candidateVersion}`,
      resume_cursor: "authoring",
      sequence: request.checkpoint_sequence,
    });

    const effectDraft: ExternalEffectDraft = {
      approval_ref: request.approval_ref,
      approval_required: true,
      candidate_version: candidateVersion,
      effect_id: stableIdentity("effect", [candidateVersion]),
      idempotency_key: stableIdentity("improvement-effect", [candidateVersion]),
      request: intent,
      rollback_plan_ref: request.rollback_plan_ref,
      step_id: "author_exact_open_draft",
      target_ref: reserved.draft_ref,
    };
    const effectResult = await this.effects.execute(
      request.session,
      {
        candidate_version: candidateVersion,
        fencing_token: request.session.lease.fencing_token,
        generation: request.session.lease.generation,
        idempotency_key: effectDraft.idempotency_key,
        lease_token: request.session.lease.lease_token,
        run_id: request.session.run.run_id,
      },
      effectDraft,
    );
    if (effectResult.status === "stale") {
      throw new ImprovementConflictError(`Improvement effect is stale: ${effectResult.reason}`);
    }
    const effect = effectResult.effect;
    if (
      effect.state !== "succeeded" ||
      effect.result_ref === undefined ||
      effect.result_digest === undefined ||
      effect.verification_receipt_ref === undefined
    ) {
      throw new ImprovementConflictError("Improvement authoring was not independently verified.");
    }
    const result = await this.author.readResult(effect.result_ref);
    assertExactAuthorResult(result, intent, effect.result_digest);
    const invalidation = await this.requireInvalidation(
      reserved.candidate_id,
      reserved.author_generation,
    );

    await ensureFinalCheckpoint(this.execution, request, {
      checkpoint_id: stableIdentity("checkpoint", [candidateVersion, "authored"]),
      completed_step_ids: [
        "candidate_reserved",
        "prior_head_verified",
        "evidence_invalidated",
        "draft_authored",
        "authoring_verified",
      ],
      effect_receipt_ids: [effect.effect_id],
      payload_digest: effect.result_digest,
      payload_ref: effect.result_ref,
      resume_cursor: "awaiting_fresh_evidence",
      sequence: request.checkpoint_sequence + 1,
    });
    const completed = await this.candidates.completeAuthoring({
      author_generation: reserved.author_generation,
      author_result_digest: effect.result_digest,
      author_result_ref: effect.result_ref,
      candidate_id: reserved.candidate_id,
      effect_receipt_ref: `effect-receipt://${effect.effect_id}`,
      evidence_invalidation_digest: invalidation.bundle_digest,
      evidence_invalidation_ref: invalidation.bundle_ref,
      expected_prior_head_digest: request.expected_head_digest,
      expected_revision: reserved.revision,
      lease: request.session.lease,
      new_head_digest: result.new_head_digest,
      updated_at: this.clock.now().toISOString(),
      verification_receipt_ref: effect.verification_receipt_ref,
    });
    return { candidate: completed, effect, result };
  }

  async recordFreshEvidence(
    input: ImprovementFreshEvidenceInput,
  ): Promise<ImprovementCandidateV1> {
    validateFreshEvidence(input);
    const candidate = await this.requireCandidate(input.candidate_id);
    if (
      (candidate.status !== "awaiting_evidence" && candidate.status !== "ready") ||
      candidate.revision !== input.expected_revision ||
      candidate.author_generation !== input.author_generation ||
      candidate.head_digest !== input.head_digest
    ) {
      throw new ImprovementConflictError("Fresh evidence does not match the candidate head.");
    }
    const snapshot = await this.evidence.recordFresh(input);
    if (!isExactEvidenceSnapshot(snapshot, candidate, {
      head_digest: candidate.head_digest,
      state: "fresh",
    })) {
      return candidate;
    }
    return this.candidates.markEvidenceReady({
      author_generation: candidate.author_generation,
      candidate_id: candidate.candidate_id,
      expected_revision: candidate.revision,
      fresh_evidence_digest: snapshot.bundle_digest,
      fresh_evidence_ref: snapshot.bundle_ref,
      head_digest: candidate.head_digest,
      updated_at: this.clock.now().toISOString(),
    });
  }

  private async requireCandidate(candidateId: string): Promise<ImprovementCandidateV1> {
    const candidate = await this.candidates.read(candidateId);
    if (candidate === undefined) {
      throw new ImprovementInputError("The improvement candidate does not exist.");
    }
    return candidate;
  }

  private async requireInvalidation(
    candidateId: string,
    authorGeneration: number,
  ): Promise<ImprovementEvidenceSnapshot> {
    const snapshot = await this.evidence.read(candidateId, authorGeneration);
    if (
      snapshot === undefined ||
      !isExactEvidenceSnapshot(
        snapshot,
        { author_generation: authorGeneration, candidate_id: candidateId },
        { state: "invalidated" },
      )
    ) {
      throw new ImprovementConflictError("Required evidence was not invalidated before authoring.");
    }
    return snapshot;
  }
}

class ImprovementEffectBridge implements ExternalEffectPort {
  constructor(
    private readonly author: ImprovementAuthorPort,
    private readonly evidence: ImprovementEvidencePort,
    private readonly verification: ImprovementVerificationPort,
  ) {}

  async apply(
    external: ExternalEffectIntentV1,
    lease: WorkLeaseV1,
  ): Promise<ExternalEffectResult> {
    const intent = decodeIntent(external.request);
    await this.invalidate(intent, lease);
    const result = await this.author.apply(intent, lease);
    return externalResult(intent, result);
  }

  async inspect(
    external: ExternalEffectIntentV1,
    lease: WorkLeaseV1,
  ): Promise<ExternalEffectInspection> {
    const intent = decodeIntent(external.request);
    const inspection = await this.author.inspect(intent, lease);
    switch (inspection.state) {
      case "absent":
        return inspection;
      case "applied":
        return { result: externalResult(intent, inspection.result), state: "applied" };
      case "prepared":
      case "materialized":
        return {
          candidate_version: inspection.candidate_version,
          resume_token: inspection.resume_token,
          state: inspection.state,
        };
      case "ambiguous":
      case "boundary_mismatch":
      case "target_moved":
        return inspection;
    }
  }

  async resume(
    external: ExternalEffectIntentV1,
    inspection: RecoverableExternalEffectInspection,
    lease: WorkLeaseV1,
  ): Promise<ExternalEffectResult> {
    const intent = decodeIntent(external.request);
    await this.invalidate(intent, lease);
    const result = await this.author.resume(intent, inspection.resume_token, lease);
    return externalResult(intent, result);
  }

  async verify(
    external: ExternalEffectIntentV1,
    result: ExternalEffectResult,
    lease: WorkLeaseV1,
  ): Promise<ExternalEffectVerification> {
    const intent = decodeIntent(external.request);
    const authorResult = await this.author.readResult(result.result_ref);
    if (authorResult === undefined) {
      throw new ImprovementConflictError("The durable author result is missing.");
    }
    const verification = await this.verification.verify(intent, authorResult, lease);
    const evidence = await this.evidence.read(
      intent.candidate_id,
      intent.author_generation,
    );
    const invalidated =
      evidence !== undefined &&
      isExactEvidenceSnapshot(
        evidence,
        {
          author_generation: intent.author_generation,
          candidate_id: intent.candidate_id,
        },
        { state: "invalidated" },
      );
    return {
      candidate_version: intent.candidate_version,
      receipt_ref: verification.receipt_ref,
      state: verification.state === "verified" && invalidated ? "verified" : "failed",
    };
  }

  private async invalidate(intent: ImprovementAuthoringIntent, lease: WorkLeaseV1) {
    const receipt = await this.evidence.invalidate(
      {
        author_generation: intent.author_generation,
        candidate_id: intent.candidate_id,
        candidate_version: intent.candidate_version,
        kinds: intent.required_evidence,
        prior_head_digest: intent.prior_head_digest,
      },
      lease,
    );
    const snapshot = await this.evidence.read(
      intent.candidate_id,
      intent.author_generation,
    );
    if (
      snapshot === undefined ||
      !isExactEvidenceSnapshot(
        snapshot,
        {
          author_generation: intent.author_generation,
          candidate_id: intent.candidate_id,
        },
        { state: "invalidated" },
      )
    ) {
      throw new ImprovementConflictError("Required evidence invalidation is not exact.");
    }
    return receipt;
  }
}

function improvementIntent(
  candidate: ImprovementCandidateV1,
  candidateVersion: string,
): ImprovementAuthoringIntent {
  if (candidate.authoring_prior_head_digest === undefined) {
    throw new ImprovementConflictError("The reserved candidate has no prior head.");
  }
  return {
    author_generation: candidate.author_generation,
    base_digest: candidate.base_digest,
    branch_ref: candidate.branch_ref,
    candidate_id: candidate.candidate_id,
    candidate_version: candidateVersion,
    draft_ref: candidate.draft_ref,
    prior_head_digest: candidate.authoring_prior_head_digest,
    required_evidence: IMPROVEMENT_EVIDENCE_KINDS,
  };
}

function decodeIntent(value: EffectIntentValue): ImprovementAuthoringIntent {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new ExecutionInvariantError("Improvement effect intent is invalid.");
  }
  const record = value as Record<string, EffectIntentValue>;
  const requiredEvidence = record.required_evidence;
  const intent = {
    author_generation: record.author_generation,
    base_digest: record.base_digest,
    branch_ref: record.branch_ref,
    candidate_id: record.candidate_id,
    candidate_version: record.candidate_version,
    draft_ref: record.draft_ref,
    prior_head_digest: record.prior_head_digest,
    required_evidence: requiredEvidence,
  };
  if (
    !Number.isSafeInteger(intent.author_generation) ||
    typeof intent.base_digest !== "string" ||
    typeof intent.branch_ref !== "string" ||
    typeof intent.candidate_id !== "string" ||
    typeof intent.candidate_version !== "string" ||
    typeof intent.draft_ref !== "string" ||
    typeof intent.prior_head_digest !== "string" ||
    !Array.isArray(requiredEvidence) ||
    requiredEvidence.some((kind) =>
      typeof kind !== "string" ||
      !IMPROVEMENT_EVIDENCE_KINDS.includes(kind as never)
    )
  ) {
    throw new ExecutionInvariantError("Improvement effect intent fields are invalid.");
  }
  return intent as ImprovementAuthoringIntent;
}

function externalResult(
  intent: ImprovementAuthoringIntent,
  result: {
    candidate_version: string;
    result_digest: string;
    result_ref: string;
  },
): ExternalEffectResult {
  if (result.candidate_version !== intent.candidate_version) {
    throw new ImprovementConflictError("Author result changed candidate version.");
  }
  return {
    candidate_version: result.candidate_version,
    result_digest: result.result_digest,
    result_ref: result.result_ref,
  };
}

function assertExpectedCandidate(
  candidate: ImprovementCandidateV1,
  request: ImprovementAuthoringRequest,
): void {
  const firstReservation =
    candidate.status === "open" &&
    candidate.revision === request.expected_revision &&
    candidate.author_generation === request.expected_author_generation;
  const exactRetry =
    candidate.status === "authoring" &&
    candidate.authoring_prior_head_digest === request.expected_head_digest &&
    candidate.author_generation === request.expected_author_generation + 1;
  if (!firstReservation && !exactRetry) {
    throw new ImprovementConflictError("Candidate revision or author generation changed.");
  }
  if (
    candidate.base_digest !== request.expected_base_digest ||
    candidate.branch_ref !== request.expected_branch_ref ||
    candidate.draft_ref !== request.expected_draft_ref ||
    candidate.head_digest !== request.expected_head_digest
  ) {
    throw new ImprovementConflictError("Candidate base, head, branch, or draft changed.");
  }
}

function assertExactOpenDraft(
  draft: Awaited<ReturnType<ImprovementAuthorPort["inspectDraft"]>>,
  request: ImprovementAuthoringRequest,
  recovering: boolean,
): void {
  if (
    draft === undefined ||
    draft.state !== "open" ||
    draft.base_digest !== request.expected_base_digest ||
    draft.branch_ref !== request.expected_branch_ref ||
    draft.draft_ref !== request.expected_draft_ref ||
    (!recovering && draft.head_digest !== request.expected_head_digest)
  ) {
    throw new ImprovementConflictError("The exact existing draft head is not open.");
  }
}

async function ensurePreparedCheckpoint(
  execution: ExecutionCoordinator,
  request: ImprovementAuthoringRequest,
  draft: Parameters<ExecutionCoordinator["checkpoint"]>[1],
): Promise<void> {
  const latest = request.session.checkpoint;
  if (latest === undefined) {
    await execution.checkpoint(request.session, draft);
    return;
  }
  const exactPrepared =
    latest.sequence === draft.sequence &&
    latest.checkpoint_id === draft.checkpoint_id &&
    latest.payload_digest === draft.payload_digest &&
    latest.payload_ref === draft.payload_ref &&
    latest.resume_cursor === draft.resume_cursor;
  const alreadyAuthored =
    latest.sequence === draft.sequence + 1 &&
    latest.resume_cursor === "awaiting_fresh_evidence";
  if (!exactPrepared && !alreadyAuthored) {
    throw new ImprovementConflictError("Execution checkpoint does not match authoring intent.");
  }
}

async function ensureFinalCheckpoint(
  execution: ExecutionCoordinator,
  request: ImprovementAuthoringRequest,
  draft: Parameters<ExecutionCoordinator["checkpoint"]>[1],
): Promise<void> {
  const latest = request.session.checkpoint;
  const exactFinal =
    latest !== undefined &&
    latest.sequence === draft.sequence &&
    latest.checkpoint_id === draft.checkpoint_id &&
    latest.payload_digest === draft.payload_digest &&
    latest.payload_ref === draft.payload_ref &&
    latest.resume_cursor === draft.resume_cursor &&
    latest.effect_receipt_ids.length === 1 &&
    latest.effect_receipt_ids[0] === draft.effect_receipt_ids[0];
  if (!exactFinal) {
    await execution.checkpoint(request.session, draft);
  }
}

function assertExactAuthorResult(
  result: Awaited<ReturnType<ImprovementAuthorPort["readResult"]>>,
  intent: ImprovementAuthoringIntent,
  resultDigest: string,
): asserts result is NonNullable<typeof result> {
  if (
    result === undefined ||
    result.candidate_version !== intent.candidate_version ||
    result.base_digest !== intent.base_digest ||
    result.branch_ref !== intent.branch_ref ||
    result.draft_ref !== intent.draft_ref ||
    result.prior_head_digest !== intent.prior_head_digest ||
    result.result_digest !== resultDigest ||
    result.new_head_digest === intent.prior_head_digest
  ) {
    throw new ImprovementConflictError("Author result does not match the exact draft intent.");
  }
}

function validateCandidateInput(input: ImprovementCandidateInput): void {
  assertDigest(input.candidate_key_digest, "candidate key");
  assertDigest(input.base_digest, "base");
  assertDigest(input.head_digest, "head");
  assertOpaqueRef(input.branch_ref, "branch");
  assertOpaqueRef(input.draft_ref, "draft");
}

function validateAuthoringRequest(request: ImprovementAuthoringRequest): void {
  if (!Number.isSafeInteger(request.expected_revision) || request.expected_revision < 1) {
    throw new ImprovementInputError("Expected revision must be positive.");
  }
  if (
    !Number.isSafeInteger(request.expected_author_generation) ||
    request.expected_author_generation < 0 ||
    !Number.isSafeInteger(request.checkpoint_sequence) ||
    request.checkpoint_sequence < 1
  ) {
    throw new ImprovementInputError("Author generation and checkpoint sequence are invalid.");
  }
  assertDigest(request.expected_base_digest, "base");
  assertDigest(request.expected_head_digest, "head");
  assertOpaqueRef(request.expected_branch_ref, "branch");
  assertOpaqueRef(request.expected_draft_ref, "draft");
  assertSafeRef(request.approval_ref, "approval");
  assertSafeRef(request.rollback_plan_ref, "rollback");
}

function validateFreshEvidence(input: ImprovementFreshEvidenceInput): void {
  if (!IMPROVEMENT_EVIDENCE_KINDS.includes(input.kind)) {
    throw new ImprovementInputError("Evidence kind is not supported.");
  }
  if (
    !/^improvement-[a-f0-9]{32}$/.test(input.candidate_id) ||
    !Number.isSafeInteger(input.author_generation) ||
    input.author_generation < 1 ||
    !Number.isSafeInteger(input.expected_revision) ||
    input.expected_revision < 1
  ) {
    throw new ImprovementInputError("Evidence candidate revision is invalid.");
  }
  assertDigest(input.head_digest, "evidence head");
  assertDigest(input.evidence_digest, "evidence");
  assertSafeRef(input.evidence_ref, "evidence");
}

function isExactEvidenceSnapshot(
  snapshot: ImprovementEvidenceSnapshot,
  candidate: Pick<ImprovementCandidateV1, "author_generation" | "candidate_id">,
  expected: { state: "invalidated" } | { head_digest: string; state: "fresh" },
): boolean {
  if (
    snapshot.candidate_id !== candidate.candidate_id ||
    snapshot.author_generation !== candidate.author_generation ||
    snapshot.states.length !== IMPROVEMENT_EVIDENCE_KINDS.length
  ) return false;

  const kinds = new Set<string>();
  for (const state of snapshot.states) {
    if (
      state.candidate_id !== candidate.candidate_id ||
      state.author_generation !== candidate.author_generation ||
      !IMPROVEMENT_EVIDENCE_KINDS.includes(state.kind) ||
      kinds.has(state.kind) ||
      state.state !== expected.state
    ) return false;
    if (
      expected.state === "fresh" &&
      (state.head_digest !== expected.head_digest ||
        state.evidence_digest === undefined ||
        state.evidence_ref === undefined)
    ) return false;
    kinds.add(state.kind);
  }
  return kinds.size === IMPROVEMENT_EVIDENCE_KINDS.length;
}

function assertDigest(value: string, field: string): void {
  if (!/^sha256:[a-f0-9]{64}$/.test(value)) {
    throw new ImprovementInputError(`${field} must be a sha256 digest.`);
  }
}

function assertOpaqueRef(value: string, kind: "branch" | "draft"): void {
  if (!new RegExp(`^${kind}://[a-z0-9][a-z0-9._-]{0,127}$`).test(value)) {
    throw new ImprovementInputError(`${kind} must be an opaque reference.`);
  }
}

function assertSafeRef(value: string, field: string): void {
  if (!/^[a-z][a-z0-9+.-]*:\/\/[a-z0-9][a-z0-9._-]{0,127}$/.test(value)) {
    throw new ImprovementInputError(`${field} must be an opaque reference.`);
  }
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
