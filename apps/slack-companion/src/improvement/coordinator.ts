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
  decideAssistantTurnPromotion,
  type AssistantTurnEvaluationV1,
  type AssistantTurnPromotionDecisionV1,
} from "../assistant-turn/evaluation.js";
import {
  IMPROVEMENT_EVIDENCE_KINDS,
  IMPROVEMENT_INDEPENDENT_EVIDENCE_KINDS,
  type ImprovementAuthoringIntent,
  type ImprovementAuthoringOutcome,
  type ImprovementAuthoringRequest,
  type ImprovementCandidateInput,
  type ImprovementCandidateV1,
  type ImprovementEvidenceRecord,
  type ImprovementEvidencePutReceiptV1,
  type ImprovementEvidenceSnapshot,
  type ImprovementFreshEvidenceInput,
  type ImprovementOutcomeEvaluationSetV1,
  type ImprovementOutcomeEvidenceInput,
  type ImprovementOutcomeEvidenceOutcome,
} from "./contracts.js";
import {
  ImprovementEvaluationSetReceiptError,
  validateImprovementOutcomeEvaluationSet,
} from "./evaluation-set-receipt.js";
import type {
  DurableImprovementCandidatePort,
  ImprovementAuthorPort,
  ImprovementClockPort,
  ImprovementEvidencePort,
  ImprovementOutcomeEvaluatorPort,
  ImprovementVerificationPort,
} from "./ports.js";

export class ImprovementConflictError extends Error {}
export class ImprovementInputError extends Error {}

type ResolvedImprovementOutcomeEvidence = Omit<
  ImprovementOutcomeEvidenceInput,
  "baseline_evaluation_receipt" | "candidate_evaluation_receipt"
> & {
  baseline: ImprovementOutcomeEvaluationSetV1;
  candidate: ImprovementOutcomeEvaluationSetV1;
};

export interface ImprovementCoordinatorOptions {
  author: ImprovementAuthorPort;
  candidates: DurableImprovementCandidatePort;
  clock: ImprovementClockPort;
  evidence: ImprovementEvidencePort;
  evaluator: ImprovementOutcomeEvaluatorPort;
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
  private readonly evaluator: ImprovementOutcomeEvaluatorPort;
  private readonly execution: ExecutionCoordinator;

  constructor(options: ImprovementCoordinatorOptions) {
    this.author = options.author;
    this.candidates = options.candidates;
    this.clock = options.clock;
    this.evidence = options.evidence;
    this.evaluator = options.evaluator;
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
    if (!(IMPROVEMENT_INDEPENDENT_EVIDENCE_KINDS as readonly string[]).includes(input.kind)) {
      throw new ImprovementInputError(
        "Outcome evidence must pass the assistant-turn promotion gate.",
      );
    }
    const candidate = await this.requireCandidate(input.candidate_id);
    assertEvidenceCandidate(candidate, input);
    return this.recordEvidence(candidate, input);
  }

  async recordOutcomeEvidence(
    input: ImprovementOutcomeEvidenceInput,
  ): Promise<ImprovementOutcomeEvidenceOutcome> {
    validateOutcomeEvidence(input);
    const candidate = await this.requireCandidate(input.candidate_id);
    assertEvidenceCandidate(candidate, input);
    const resolved = await this.resolveOutcomeEvidence(input);
    if (
      candidate.authoring_prior_head_digest === undefined ||
      resolved.baseline.receipt.evaluated_head_digest !==
        candidate.authoring_prior_head_digest ||
      resolved.candidate.receipt.evaluated_head_digest !== candidate.head_digest
    ) {
      throw new ImprovementConflictError(
        "Outcome evidence does not match the baseline and candidate heads.",
      );
    }
    const decision = decideAssistantTurnPromotion(
      resolved.baseline.evaluations,
      resolved.candidate.evaluations,
    );
    if (!decision.promotion_ready) return { candidate, decision };

    const evidence = outcomeEvidenceRecords(resolved, decision);
    let current = candidate;
    for (const record of evidence) {
      const recorded = await this.recordEvidence(current, record);
      if (recorded === current) {
        const snapshot = await this.evidence.read(
          current.candidate_id,
          current.author_generation,
        );
        if (!isBoundEvidenceSnapshot(snapshot, current)) {
          return { candidate: current, decision };
        }
      }
      current = recorded;
    }
    return { candidate: current, decision };
  }

  private async recordEvidence(
    candidate: ImprovementCandidateV1,
    input: ImprovementEvidenceRecord,
  ): Promise<ImprovementCandidateV1> {
    const payloadFingerprint = evidencePayloadFingerprint(input);
    const receipt = await this.evidence.putFreshIfAbsent({
      payload_fingerprint: payloadFingerprint,
      record: input,
    });
    validateEvidencePutReceipt(receipt, input, payloadFingerprint);
    if (receipt.status === "conflict") {
      throw new ImprovementConflictError(
        "Fresh evidence conflicts with the immutable stored receipt.",
      );
    }
    const snapshot = receipt.snapshot;
    const exactSnapshot = isBoundEvidenceSnapshot(snapshot, candidate) &&
      snapshotContainsEvidence(snapshot, input);
    if (!exactSnapshot) {
      if (candidate.status === "ready") {
        throw new ImprovementConflictError(
          "Ready evidence replay did not return the exact stored snapshot.",
        );
      }
      return candidate;
    }
    if (!snapshot.states.every((state) => state.state === "fresh")) return candidate;
    if (candidate.status === "ready") {
      if (
        candidate.fresh_evidence_digest !== snapshot.bundle_digest ||
        candidate.fresh_evidence_ref !== snapshot.bundle_ref
      ) {
        throw new ImprovementConflictError(
          "Ready evidence completion conflicts with the stored snapshot.",
        );
      }
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

  private async resolveOutcomeEvidence(
    input: ImprovementOutcomeEvidenceInput,
  ): Promise<ResolvedImprovementOutcomeEvidence> {
    const [baseline, candidate] = await Promise.all([
      this.evaluator.resolve(input.baseline_evaluation_receipt),
      this.evaluator.resolve(input.candidate_evaluation_receipt),
    ]);
    if (baseline === undefined || candidate === undefined) {
      throw new ImprovementConflictError(
        "The trusted evaluator receipt is unavailable.",
      );
    }
    try {
      validateImprovementOutcomeEvaluationSet(baseline);
      validateImprovementOutcomeEvaluationSet(candidate);
    } catch (error) {
      if (error instanceof ImprovementEvaluationSetReceiptError) {
        throw new ImprovementInputError(error.message);
      }
      throw error;
    }
    if (
      baseline.receipt.receipt_digest !==
        input.baseline_evaluation_receipt.receipt_digest ||
      candidate.receipt.receipt_digest !==
        input.candidate_evaluation_receipt.receipt_digest
    ) {
      throw new ImprovementConflictError(
        "The trusted evaluator receipt digest does not match the requested receipt.",
      );
    }
    return { ...input, baseline, candidate };
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

function validateFreshEvidence(input: ImprovementEvidenceRecord): void {
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

function validateOutcomeEvidence(input: ImprovementOutcomeEvidenceInput): void {
  assertExactPlainRecord(input, [
    "author_generation",
    "baseline_evaluation_receipt",
    "candidate_evaluation_receipt",
    "candidate_id",
    "expected_revision",
    "head_digest",
    "held_out_evidence_ref",
    "promotion_evidence_ref",
    "shadow_evidence_ref",
  ], "outcome evidence input");
  if (
    !/^improvement-[a-f0-9]{32}$/.test(input.candidate_id) ||
    !Number.isSafeInteger(input.author_generation) ||
    input.author_generation < 1 ||
    !Number.isSafeInteger(input.expected_revision) ||
    input.expected_revision < 1
  ) {
    throw new ImprovementInputError("Outcome evidence candidate revision is invalid.");
  }
  assertDigest(input.head_digest, "outcome head");
  for (const [label, reference] of [
    ["baseline", input.baseline_evaluation_receipt],
    ["candidate", input.candidate_evaluation_receipt],
  ] as const) {
    assertExactPlainRecord(
      reference,
      ["receipt_digest", "receipt_ref"],
      `${label} evaluator receipt reference`,
    );
    assertDigest(reference.receipt_digest, `${label} evaluator receipt`);
    assertSafeRef(reference.receipt_ref, `${label} evaluator receipt`);
  }
  if (
    input.baseline_evaluation_receipt.receipt_ref ===
      input.candidate_evaluation_receipt.receipt_ref
  ) {
    throw new ImprovementInputError(
      "Baseline and candidate evaluator receipts must be distinct.",
    );
  }
  assertSafeRef(input.held_out_evidence_ref, "held-out evidence");
  assertSafeRef(input.shadow_evidence_ref, "shadow evidence");
  assertSafeRef(input.promotion_evidence_ref, "promotion evidence");
}

function assertEvidenceCandidate(
  candidate: ImprovementCandidateV1,
  input: Pick<
    ImprovementEvidenceRecord,
    "author_generation" | "candidate_id" | "expected_revision" | "head_digest"
  >,
): void {
  const exactAwaitingRevision = candidate.status === "awaiting_evidence" &&
    candidate.revision === input.expected_revision;
  const exactReadyReplay = candidate.status === "ready" &&
    (candidate.revision === input.expected_revision ||
      candidate.revision === input.expected_revision + 1) &&
    candidate.fresh_evidence_digest !== undefined &&
    candidate.fresh_evidence_ref !== undefined;
  if (
    (!exactAwaitingRevision && !exactReadyReplay) ||
    candidate.candidate_id !== input.candidate_id ||
    candidate.author_generation !== input.author_generation ||
    candidate.head_digest !== input.head_digest
  ) {
    throw new ImprovementConflictError("Fresh evidence does not match the candidate head.");
  }
}

function outcomeEvidenceRecords(
  input: ResolvedImprovementOutcomeEvidence,
  decision: AssistantTurnPromotionDecisionV1,
): ImprovementEvidenceRecord[] {
  const heldOut = outcomePartition(input, "held_out");
  const shadow = outcomePartition(input, "shadow");
  const common = {
    author_generation: input.author_generation,
    candidate_id: input.candidate_id,
    expected_revision: input.expected_revision,
    head_digest: input.head_digest,
  };
  return [
    {
      ...common,
      evidence_digest: canonicalDigest(heldOut),
      evidence_ref: input.held_out_evidence_ref,
      kind: "eval",
    },
    {
      ...common,
      evidence_digest: canonicalDigest(shadow),
      evidence_ref: input.shadow_evidence_ref,
      kind: "shadow",
    },
    {
      ...common,
      evidence_digest: canonicalDigest({
        candidate_evaluation_receipt_digest: input.candidate.receipt.receipt_digest,
        candidate_head_digest: input.candidate.receipt.evaluated_head_digest,
        decision,
        baseline_evaluation_receipt_digest: input.baseline.receipt.receipt_digest,
        baseline_head_digest: input.baseline.receipt.evaluated_head_digest,
      }),
      evidence_ref: input.promotion_evidence_ref,
      kind: "promotion",
    },
  ];
}

function outcomePartition(
  input: ResolvedImprovementOutcomeEvidence,
  partition: "held_out" | "shadow",
): {
  baseline: AssistantTurnEvaluationV1[];
  baseline_evaluation_receipt_digest: string;
  baseline_head_digest: string;
  candidate: AssistantTurnEvaluationV1[];
  candidate_evaluation_receipt_digest: string;
  candidate_head_digest: string;
  partition: "held_out" | "shadow";
  schema_version: "improvement-outcome-evidence/v1";
} {
  return {
    baseline: canonicalEvaluations(input.baseline.evaluations, partition),
    baseline_evaluation_receipt_digest: input.baseline.receipt.receipt_digest,
    baseline_head_digest: input.baseline.receipt.evaluated_head_digest,
    candidate: canonicalEvaluations(input.candidate.evaluations, partition),
    candidate_evaluation_receipt_digest: input.candidate.receipt.receipt_digest,
    candidate_head_digest: input.candidate.receipt.evaluated_head_digest,
    partition,
    schema_version: "improvement-outcome-evidence/v1",
  };
}

function canonicalEvaluations(
  evaluations: readonly AssistantTurnEvaluationV1[],
  partition: "held_out" | "shadow",
): AssistantTurnEvaluationV1[] {
  return evaluations
    .filter((evaluation) => evaluation.partition === partition)
    .slice()
    .sort((left, right) => (
      left.case_ref < right.case_ref ? -1 : left.case_ref > right.case_ref ? 1 : 0
    ));
}

function isBoundEvidenceSnapshot(
  snapshot: ImprovementEvidenceSnapshot | undefined,
  candidate: Pick<
    ImprovementCandidateV1,
    "author_generation" | "candidate_id" | "head_digest"
  >,
): snapshot is ImprovementEvidenceSnapshot {
  if (
    snapshot === undefined ||
    !isExactDataRecord(snapshot, [
      "author_generation",
      "bundle_digest",
      "bundle_ref",
      "candidate_id",
      "states",
    ]) ||
    !isDenseDataArray(snapshot.states) ||
    snapshot.candidate_id !== candidate.candidate_id ||
    snapshot.author_generation !== candidate.author_generation ||
    !/^sha256:[a-f0-9]{64}$/.test(snapshot.bundle_digest) ||
    !/^[a-z][a-z0-9+.-]*:\/\/[a-z0-9][a-z0-9._-]{0,127}$/.test(snapshot.bundle_ref) ||
    snapshot.states.length !== IMPROVEMENT_EVIDENCE_KINDS.length
  ) return false;

  const kinds = new Set<string>();
  for (const state of snapshot.states) {
    if (state === null || typeof state !== "object") return false;
    const stateDescriptor = Object.getOwnPropertyDescriptor(state, "state");
    if (stateDescriptor === undefined || !("value" in stateDescriptor)) return false;
    const stateValue = stateDescriptor.value;
    const expectedKeys = stateValue === "fresh"
      ? [
          "author_generation",
          "candidate_id",
          "evidence_digest",
          "evidence_ref",
          "head_digest",
          "kind",
          "schema_version",
          "state",
          "updated_at",
        ]
      : stateValue === "invalidated" ? [
          "author_generation",
          "candidate_id",
          "kind",
          "schema_version",
          "state",
          "updated_at",
        ] : undefined;
    if (
      expectedKeys === undefined ||
      !isExactDataRecord(state, expectedKeys) ||
      state.candidate_id !== candidate.candidate_id ||
      state.author_generation !== candidate.author_generation ||
      state.schema_version !== "improvement-evidence-state/v1" ||
      !isCanonicalTimestamp(state.updated_at) ||
      !IMPROVEMENT_EVIDENCE_KINDS.includes(state.kind) ||
      (state.state !== "fresh" && state.state !== "invalidated") ||
      kinds.has(state.kind)
    ) return false;
    if (
      state.state === "fresh" &&
      (state.head_digest !== candidate.head_digest ||
        state.evidence_digest === undefined ||
        !/^sha256:[a-f0-9]{64}$/.test(state.evidence_digest) ||
        state.evidence_ref === undefined ||
        !/^[a-z][a-z0-9+.-]*:\/\/[a-z0-9][a-z0-9._-]{0,127}$/.test(
          state.evidence_ref,
        ))
    ) return false;
    if (
      state.state === "invalidated" &&
      (state.head_digest !== undefined ||
        state.evidence_digest !== undefined ||
        state.evidence_ref !== undefined)
    ) return false;
    kinds.add(state.kind);
  }
  return kinds.size === IMPROVEMENT_EVIDENCE_KINDS.length;
}

function snapshotContainsEvidence(
  snapshot: ImprovementEvidenceSnapshot,
  input: ImprovementEvidenceRecord,
): boolean {
  const state = snapshot.states.find((value) => value.kind === input.kind);
  return state?.state === "fresh"
    && state.head_digest === input.head_digest
    && state.evidence_digest === input.evidence_digest
    && state.evidence_ref === input.evidence_ref;
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

function evidencePayloadFingerprint(input: Pick<
  ImprovementEvidenceRecord,
  | "author_generation"
  | "candidate_id"
  | "evidence_digest"
  | "evidence_ref"
  | "head_digest"
  | "kind"
>): string {
  return digest(JSON.stringify([
    "improvement-evidence-payload/v1",
    input.candidate_id,
    input.author_generation,
    input.kind,
    input.head_digest,
    input.evidence_digest,
    input.evidence_ref,
  ]));
}

function validateEvidencePutReceipt(
  receipt: ImprovementEvidencePutReceiptV1,
  input: ImprovementEvidenceRecord,
  payloadFingerprint: string,
): void {
  assertExactPlainRecord(receipt, [
    "author_generation",
    "candidate_id",
    "kind",
    "receipt_digest",
    "receipt_ref",
    "requested_payload_fingerprint",
    "schema_version",
    "snapshot",
    "status",
    "stored_payload_fingerprint",
  ], "evidence put receipt");
  if (
    receipt.schema_version !== "improvement-evidence-put-receipt/v1" ||
    receipt.candidate_id !== input.candidate_id ||
    receipt.author_generation !== input.author_generation ||
    receipt.kind !== input.kind ||
    receipt.requested_payload_fingerprint !== payloadFingerprint ||
    !/^sha256:[a-f0-9]{64}$/.test(receipt.stored_payload_fingerprint) ||
    (receipt.status !== "created" &&
      receipt.status !== "replayed" &&
      receipt.status !== "conflict")
  ) {
    throw new ImprovementConflictError("The evidence put receipt identity is invalid.");
  }
  assertDigest(receipt.receipt_digest, "evidence put receipt");
  assertSafeRef(receipt.receipt_ref, "evidence put receipt");
  if (receipt.status === "conflict") {
    const storedState = findFreshEvidenceState(receipt.snapshot, input.kind);
    if (
      receipt.stored_payload_fingerprint === payloadFingerprint ||
      storedState?.state !== "fresh" ||
      storedState.head_digest === undefined ||
      storedState.evidence_digest === undefined ||
      storedState.evidence_ref === undefined ||
      !isBoundEvidenceSnapshot(receipt.snapshot, {
        author_generation: input.author_generation,
        candidate_id: input.candidate_id,
        head_digest: storedState.head_digest,
      }) ||
      evidencePayloadFingerprint({
        author_generation: storedState.author_generation,
        candidate_id: storedState.candidate_id,
        evidence_digest: storedState.evidence_digest,
        evidence_ref: storedState.evidence_ref,
        head_digest: storedState.head_digest,
        kind: storedState.kind,
      }) !== receipt.stored_payload_fingerprint
    ) {
      throw new ImprovementConflictError(
        "The evidence conflict receipt does not prove the immutable stored payload.",
      );
    }
    return;
  }
  if (
    receipt.stored_payload_fingerprint !== payloadFingerprint ||
    !isBoundEvidenceSnapshot(receipt.snapshot, input) ||
    !snapshotContainsEvidence(receipt.snapshot, input)
  ) {
    throw new ImprovementConflictError(
      "The evidence put receipt does not prove the exact stored payload.",
    );
  }
}

function findFreshEvidenceState(
  snapshot: ImprovementEvidenceSnapshot,
  kind: ImprovementEvidenceRecord["kind"],
): ImprovementEvidenceSnapshot["states"][number] | undefined {
  if (
    !isExactDataRecord(snapshot, [
      "author_generation",
      "bundle_digest",
      "bundle_ref",
      "candidate_id",
      "states",
    ]) ||
    !isDenseDataArray(snapshot.states)
  ) return undefined;
  for (const state of snapshot.states) {
    if (state === null || typeof state !== "object") return undefined;
    const kindDescriptor = Object.getOwnPropertyDescriptor(state, "kind");
    const stateDescriptor = Object.getOwnPropertyDescriptor(state, "state");
    if (
      kindDescriptor === undefined || !("value" in kindDescriptor) ||
      stateDescriptor === undefined || !("value" in stateDescriptor)
    ) return undefined;
    if (kindDescriptor.value === kind && stateDescriptor.value === "fresh") return state;
  }
  return undefined;
}

function assertExactPlainRecord(
  value: unknown,
  expectedKeys: readonly string[],
  label: string,
): asserts value is Record<string, unknown> {
  if (!isExactDataRecord(value, expectedKeys)) {
    throw new ImprovementInputError(
      `The ${label} must contain exactly the supported plain-data fields.`,
    );
  }
}

function isExactDataRecord(
  value: unknown,
  expectedKeys: readonly string[],
): value is Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) return false;
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))
  ) return false;
  return (keys as string[]).every((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined && "value" in descriptor && descriptor.enumerable &&
      descriptor.value !== undefined;
  });
}

function isDenseDataArray(value: unknown): value is readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1) return false;
  return keys.every((key) => {
    if (key === "length") return true;
    if (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key)) return false;
    const index = Number(key);
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return index < value.length && descriptor !== undefined &&
      "value" in descriptor && descriptor.enumerable;
  });
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function canonicalDigest(value: unknown): string {
  return digest(canonicalStringify(value));
}

function canonicalStringify(value: unknown): string {
  if (Array.isArray(value)) {
    const items: string[] = [];
    for (let index = 0; index < value.length; index += 1) {
      items.push(canonicalStringify(value[index]));
    }
    return `[${items.join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => (
      `${JSON.stringify(key)}:${canonicalStringify((value as Record<string, unknown>)[key])}`
    )).join(",")}}`;
  }
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new ImprovementInputError("Outcome evidence contains a non-canonical value.");
  }
  return serialized;
}
