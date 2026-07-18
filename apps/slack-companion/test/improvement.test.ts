import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, test } from "node:test";
import type { RunReceiptV1, WorkLeaseV1 } from "@writer/cerebro-sdk";
import { ExecutionCoordinator } from "../src/execution/coordinator.js";
import type { ExecutionSession } from "../src/execution/model.js";
import { ReferenceMemoryExecutionStore } from "../src/execution/reference-store.js";
import { stableIdentity } from "../src/delivery/coordinator.js";
import type {
  AssistantTurnEvaluationBlockerV1,
  AssistantTurnEvaluationV1,
} from "../src/assistant-turn/evaluation.js";
import {
  ImprovementConflictError,
  ImprovementCoordinator,
  ImprovementInputError,
} from "../src/improvement/coordinator.js";
import type {
  ImprovementAuthorCompletion,
  ImprovementAuthorInspection,
  ImprovementAuthorReservation,
  ImprovementAuthorReservationResult,
  ImprovementAuthorResult,
  ImprovementAuthorVerification,
  ImprovementAuthoringIntent,
  ImprovementAuthoringRequest,
  ImprovementCandidateCommit,
  ImprovementCandidateCommitResult,
  ImprovementCandidateInput,
  ImprovementCandidateV1,
  ImprovementDraftSnapshot,
  ImprovementEvidenceCompletion,
  ImprovementEvidenceInvalidationRequest,
  ImprovementEvidenceRecord,
  ImprovementEvidenceSnapshot,
  ImprovementEvidenceStateV1,
  ImprovementFreshEvidenceInput,
  ImprovementOutcomeEvidenceInput,
} from "../src/improvement/contracts.js";
import { IMPROVEMENT_EVIDENCE_KINDS } from "../src/improvement/contracts.js";
import type {
  DurableImprovementCandidatePort,
  ImprovementAuthorPort,
  ImprovementEvidencePort,
  ImprovementVerificationPort,
} from "../src/improvement/ports.js";

const start = "2026-07-16T12:00:00.000Z";

describe("ImprovementCoordinator", () => {
  test("registers one opaque candidate and rejects changed intent", async () => {
    const fixture = makeFixture();
    const first = await fixture.coordinator.register(candidateInput());
    const duplicate = await fixture.coordinator.register(candidateInput());

    assert.equal(first.created, true);
    assert.equal(duplicate.created, false);
    assert.equal(first.candidate.candidate_id, duplicate.candidate.candidate_id);
    assert.match(first.candidate.candidate_id, /^improvement-[a-f0-9]{32}$/);
    assert.equal(JSON.stringify(first.candidate).includes("conversation"), false);

    await assert.rejects(
      fixture.coordinator.register(
        candidateInput({ head_digest: sha("changed-head") }),
      ),
      ImprovementConflictError,
    );
    await assert.rejects(
      fixture.coordinator.register(
        candidateInput({ draft_ref: "draft://not/opaque" }),
      ),
      ImprovementInputError,
    );
  });

  test("authors only the exact open draft after evidence invalidation", async () => {
    const fixture = makeFixture();
    const candidate = (await fixture.coordinator.register(candidateInput())).candidate;
    const session = await fixture.session(1);

    await assert.rejects(
      fixture.coordinator.authorCandidate(
        authorRequest(candidate, session, {
          expected_head_digest: sha("wrong-prior-head"),
        }),
      ),
      ImprovementConflictError,
    );
    assert.equal(fixture.author.applyCalls, 0);

    const outcome = await fixture.coordinator.authorCandidate(
      authorRequest(candidate, session),
    );
    assert.equal(outcome.candidate.status, "awaiting_evidence");
    assert.equal(outcome.candidate.author_generation, 1);
    assert.equal(outcome.effect.state, "succeeded");
    assert.equal(fixture.author.applyCalls, 1);
    assert.equal(fixture.evidence.observedIntentFirst, true);
    assert.deepEqual(fixture.author.events.slice(0, 2), [
      "evidence_invalidated",
      "author_applied",
    ]);
    assert.equal(outcome.result.draft_ref, candidate.draft_ref);
    assert.equal(outcome.result.branch_ref, candidate.branch_ref);
    assert.equal(outcome.result.base_digest, candidate.base_digest);
    assert.equal(outcome.result.prior_head_digest, candidate.head_digest);
    assert.notEqual(outcome.result.new_head_digest, candidate.head_digest);
  });

  test("rejects duplicate or missing invalidation kinds before authoring", async () => {
    for (const corruption of ["duplicate", "missing"] as const) {
      const fixture = makeFixture();
      const candidate = (await fixture.coordinator.register(candidateInput())).candidate;
      const session = await fixture.session(1);
      fixture.evidence.corruptNextInvalidation(corruption);

      await assert.rejects(
        fixture.coordinator.authorCandidate(authorRequest(candidate, session)),
        ImprovementConflictError,
      );
      assert.equal(fixture.author.applyCalls, 0, corruption);
    }
  });

  test("recovers an outcome-unknown author effect by inspection without reauthoring", async () => {
    const fixture = makeFixture();
    const candidate = (await fixture.coordinator.register(candidateInput())).candidate;
    const firstSession = await fixture.session(1);
    fixture.author.crashAfterApply = true;

    await assert.rejects(
      fixture.coordinator.authorCandidate(authorRequest(candidate, firstSession)),
      /simulated crash after authoring/,
    );
    assert.equal(fixture.author.applyCalls, 1);
    assert.equal((await fixture.candidates.read(candidate.candidate_id))?.status, "authoring");

    fixture.clock.advance(61_000);
    const recovered = await fixture.execution.reconcileExpired();
    assert.equal(recovered.length, 1);
    const resumed = await fixture.session(2);
    fixture.author.crashAfterApply = false;
    const outcome = await fixture.coordinator.authorCandidate(
      authorRequest(candidate, resumed),
    );

    assert.equal(outcome.effect.generation, 2);
    assert.equal(outcome.candidate.active_execution_generation, 2);
    assert.equal(outcome.candidate.status, "awaiting_evidence");
    assert.equal(fixture.author.applyCalls, 1);
    assert.equal(fixture.author.inspectCalls, 1);
    assert.equal(fixture.evidence.uniqueInvalidationCount, 1);

  });

  test("reconciles verified authoring after candidate completion storage fails", async () => {
    const fixture = makeFixture();
    const candidate = (await fixture.coordinator.register(candidateInput())).candidate;
    const firstSession = await fixture.session(1);
    fixture.candidates.failNextCompletion = true;

    await assert.rejects(
      fixture.coordinator.authorCandidate(authorRequest(candidate, firstSession)),
      /injected candidate completion failure/,
    );
    assert.equal(fixture.author.applyCalls, 1);
    assert.equal((await fixture.candidates.read(candidate.candidate_id))?.status, "authoring");

    await fixture.execution.release(firstSession);
    const resumed = await fixture.session(2);
    const outcome = await fixture.coordinator.authorCandidate(
      authorRequest(candidate, resumed),
    );
    assert.equal(outcome.candidate.status, "awaiting_evidence");
    assert.equal(outcome.effect.generation, 1);
    assert.equal(fixture.author.applyCalls, 1);
    assert.equal(fixture.author.inspectCalls, 0);
  });

  test("increments author generation and fences an older execution lease", async () => {
    const fixture = makeFixture();
    const candidate = (await fixture.coordinator.register(candidateInput())).candidate;
    const reserved = await fixture.candidates.reserveAuthor(
      reservation(candidate, leaseProof(2, 2)),
    );
    assert.equal(reserved.candidate.author_generation, 1);
    assert.equal(reserved.candidate.active_execution_generation, 2);

    await assert.rejects(
      async () => fixture.candidates.reserveAuthor(
        reservation(candidate, leaseProof(1, 1)),
      ),
      /stale/,
    );
  });

  test("requires gated outcomes before every exact-head evidence class can become fresh", async () => {
    const fixture = makeFixture();
    const candidate = (await fixture.coordinator.register(candidateInput())).candidate;
    const session = await fixture.session(1);
    const authored = await fixture.coordinator.authorCandidate(
      authorRequest(candidate, session),
    );

    await assert.rejects(
      fixture.coordinator.recordFreshEvidence(
        freshEvidence(authored.candidate, "ci", {
          head_digest: sha("wrong-evidence-head"),
        }),
      ),
      ImprovementConflictError,
    );

    for (const kind of ["eval", "shadow", "promotion"] as const) {
      const bypass = {
        ...freshEvidence(authored.candidate, "ci"),
        kind,
      } as unknown as ImprovementFreshEvidenceInput;
      await assert.rejects(
        fixture.coordinator.recordFreshEvidence(bypass),
        /must pass the assistant-turn promotion gate/,
      );
    }

    let current = await fixture.coordinator.recordFreshEvidence(
      freshEvidence(authored.candidate, "ci"),
    );
    current = await fixture.coordinator.recordFreshEvidence(
      freshEvidence(current, "canary"),
    );
    assert.equal(current.status, "awaiting_evidence");

    const outcome = await fixture.coordinator.recordOutcomeEvidence(
      outcomeEvidence(current),
    );
    current = outcome.candidate;
    assert.equal(outcome.decision.promotion_ready, true);
    assert.equal(current.status, "ready");
    assert.equal(current.fresh_evidence_ref, fixture.evidence.bundleRef);
    assert.equal(
      (await fixture.evidence.read(current.candidate_id, current.author_generation))
        ?.states.every((state) => state.state === "fresh"),
      true,
    );
  });

  test("does not record outcome evidence when the candidate fails the promotion gate", async () => {
    const fixture = makeFixture();
    const candidate = (await fixture.coordinator.register(candidateInput())).candidate;
    const session = await fixture.session(1);
    const authored = await fixture.coordinator.authorCandidate(
      authorRequest(candidate, session),
    );

    const outcome = await fixture.coordinator.recordOutcomeEvidence(
      outcomeEvidence(authored.candidate, {
        candidate_score: 0.71,
        candidate_blockers: ["outcome_unknown"],
      }),
    );

    assert.equal(outcome.decision.promotion_ready, false);
    assert.equal(outcome.candidate.status, "awaiting_evidence");
    const states = (await fixture.evidence.read(
      outcome.candidate.candidate_id,
      outcome.candidate.author_generation,
    ))?.states;
    assert.equal(states?.every((state) => state.state === "invalidated"), true);
  });

  test("binds outcome evidence to the exact baseline and candidate heads", async () => {
    const fixture = makeFixture();
    const candidate = (await fixture.coordinator.register(candidateInput())).candidate;
    const session = await fixture.session(1);
    const authored = await fixture.coordinator.authorCandidate(
      authorRequest(candidate, session),
    );

    await assert.rejects(
      fixture.coordinator.recordOutcomeEvidence(
        outcomeEvidence(authored.candidate, {
          baseline_head_digest: sha("wrong-baseline-head"),
        }),
      ),
      /does not match the baseline and candidate heads/,
    );
    await assert.rejects(
      fixture.coordinator.recordOutcomeEvidence(
        outcomeEvidence(authored.candidate, {
          candidate_head_digest: sha("wrong-candidate-head"),
        }),
      ),
      /does not match the baseline and candidate heads/,
    );

    const oversized = outcomeEvidence(authored.candidate);
    oversized.candidate = {
      ...oversized.candidate,
      evaluations: Array.from(
        { length: 513 },
        (_, index) => oversized.candidate.evaluations[
          index % oversized.candidate.evaluations.length
        ]!,
      ),
    };
    await assert.rejects(
      fixture.coordinator.recordOutcomeEvidence(oversized),
      /evaluations are required and bounded/,
    );
  });

  test("recovers idempotently when outcome evidence persists before a response failure", async () => {
    const fixture = makeFixture();
    const candidate = (await fixture.coordinator.register(candidateInput())).candidate;
    const session = await fixture.session(1);
    let current = (await fixture.coordinator.authorCandidate(
      authorRequest(candidate, session),
    )).candidate;
    current = await fixture.coordinator.recordFreshEvidence(freshEvidence(current, "ci"));
    current = await fixture.coordinator.recordFreshEvidence(freshEvidence(current, "canary"));
    fixture.evidence.failNextFreshResponse();

    await assert.rejects(
      fixture.coordinator.recordOutcomeEvidence(outcomeEvidence(current)),
      /injected fresh evidence response failure/,
    );

    const recovered = await fixture.coordinator.recordOutcomeEvidence(
      outcomeEvidence(current),
    );
    assert.equal(recovered.candidate.status, "ready");
    assert.equal(recovered.decision.promotion_ready, true);
  });

  test("rejects fresh evidence snapshots with changed identity or receipt content", async () => {
    for (const corruption of ["candidate", "generation", "evidence"] as const) {
      const fixture = makeFixture();
      const candidate = (await fixture.coordinator.register(candidateInput())).candidate;
      const session = await fixture.session(1);
      let current = (await fixture.coordinator.authorCandidate(
        authorRequest(candidate, session),
      )).candidate;
      const outcomes = await fixture.coordinator.recordOutcomeEvidence(
        outcomeEvidence(current),
      );
      current = outcomes.candidate;
      current = await fixture.coordinator.recordFreshEvidence(
        freshEvidence(current, "ci"),
      );

      fixture.evidence.corruptNextFreshSnapshot(corruption);
      const rejected = await fixture.coordinator.recordFreshEvidence(
        freshEvidence(current, "canary"),
      );
      assert.equal(rejected.status, "awaiting_evidence", corruption);
      assert.equal(rejected.fresh_evidence_ref, undefined, corruption);
    }
  });
});

function makeFixture() {
  const clock = new MutableClock();
  const executionStore = new ReferenceMemoryExecutionStore();
  executionStore.seedRun(runReceipt());
  const execution = new ExecutionCoordinator({
    clock,
    lease_duration_ms: 60_000,
    store: executionStore,
  });
  const candidates = new MemoryCandidateStore();
  const evidence = new MemoryEvidencePort(clock, executionStore);
  const author = new MemoryAuthorPort(evidence);
  const verification = new MemoryVerificationPort(author, clock);
  const coordinator = new ImprovementCoordinator({
    author,
    candidates,
    clock,
    evidence,
    execution,
    execution_store: executionStore,
    verification,
  });

  async function session(generation: number): Promise<ExecutionSession> {
    const started = await execution.start({
      generation,
      lease_token: `execution-lease-${generation}`,
      owner_id: `author-worker-${generation}`,
      run_id: "run-improvement-1",
      service_state: "ready",
    });
    if (started.status === "not_runnable") assert.fail("expected author execution session");
    return started.session;
  }

  return {
    author,
    candidates,
    clock,
    coordinator,
    evidence,
    execution,
    executionStore,
    session,
    verification,
  };
}

class MemoryCandidateStore implements DurableImprovementCandidatePort {
  failNextCompletion = false;
  private readonly fingerprints = new Map<string, string>();
  private readonly records = new Map<string, ImprovementCandidateV1>();

  putIfAbsent(commit: ImprovementCandidateCommit): Promise<ImprovementCandidateCommitResult> {
    const id = commit.candidate.candidate_id;
    const prior = this.records.get(id);
    if (prior !== undefined) {
      if (this.fingerprints.get(id) !== commit.payload_fingerprint) {
        return Promise.reject(new ImprovementConflictError("Candidate intent changed."));
      }
      return Promise.resolve({ candidate: clone(prior), created: false });
    }
    this.records.set(id, clone(commit.candidate));
    this.fingerprints.set(id, commit.payload_fingerprint);
    return Promise.resolve({ candidate: clone(commit.candidate), created: true });
  }

  read(candidateId: string) {
    const candidate = this.records.get(candidateId);
    return Promise.resolve(candidate === undefined ? undefined : clone(candidate));
  }

  reserveAuthor(
    reservation: ImprovementAuthorReservation,
  ): Promise<ImprovementAuthorReservationResult> {
    const candidate = this.require(reservation.candidate_id);
    this.assertExactIdentity(candidate, reservation);
    if (candidate.status === "open") {
      if (
        candidate.revision !== reservation.expected_revision ||
        candidate.author_generation !== reservation.expected_author_generation ||
        candidate.head_digest !== reservation.expected_head_digest
      ) throw new ImprovementConflictError("Candidate revision changed.");
      const next: ImprovementCandidateV1 = {
        ...candidate,
        active_execution_generation: reservation.lease.generation,
        active_fencing_token: reservation.lease.fencing_token,
        author_generation: candidate.author_generation + 1,
        authoring_prior_head_digest: candidate.head_digest,
        revision: candidate.revision + 1,
        status: "authoring",
        updated_at: reservation.reserved_at,
      };
      this.records.set(next.candidate_id, clone(next));
      return Promise.resolve({ candidate: clone(next), created: true });
    }
    if (
      candidate.status !== "authoring" ||
      candidate.author_generation !== reservation.expected_author_generation + 1 ||
      candidate.authoring_prior_head_digest !== reservation.expected_head_digest
    ) throw new ImprovementConflictError("Candidate author attempt changed.");

    const currentProof = [
      candidate.active_execution_generation ?? 0,
      candidate.active_fencing_token ?? 0,
    ] as const;
    const nextProof = [reservation.lease.generation, reservation.lease.fencing_token] as const;
    if (
      nextProof[0] < currentProof[0] ||
      (nextProof[0] === currentProof[0] && nextProof[1] < currentProof[1])
    ) throw new ImprovementConflictError("Author lease proof is stale.");
    if (nextProof[0] === currentProof[0] && nextProof[1] === currentProof[1]) {
      return Promise.resolve({ candidate: clone(candidate), created: false });
    }
    const takenOver = {
      ...candidate,
      active_execution_generation: nextProof[0],
      active_fencing_token: nextProof[1],
      revision: candidate.revision + 1,
      updated_at: reservation.reserved_at,
    };
    this.records.set(candidate.candidate_id, clone(takenOver));
    return Promise.resolve({ candidate: clone(takenOver), created: false });
  }

  completeAuthoring(completion: ImprovementAuthorCompletion) {
    if (this.failNextCompletion) {
      this.failNextCompletion = false;
      return Promise.reject(new Error("injected candidate completion failure"));
    }
    const candidate = this.require(completion.candidate_id);
    if (candidate.status === "awaiting_evidence") {
      if (
        candidate.author_generation === completion.author_generation &&
        candidate.head_digest === completion.new_head_digest &&
        candidate.author_result_digest === completion.author_result_digest &&
        candidate.author_result_ref === completion.author_result_ref
      ) return Promise.resolve(clone(candidate));
      return Promise.reject(new ImprovementConflictError("Author completion changed."));
    }
    if (
      candidate.status !== "authoring" ||
      candidate.revision !== completion.expected_revision ||
      candidate.author_generation !== completion.author_generation ||
      candidate.authoring_prior_head_digest !== completion.expected_prior_head_digest ||
      candidate.active_execution_generation !== completion.lease.generation ||
      candidate.active_fencing_token !== completion.lease.fencing_token
    ) return Promise.reject(new ImprovementConflictError("Author completion is stale."));
    const next: ImprovementCandidateV1 = {
      ...candidate,
      author_result_digest: completion.author_result_digest,
      author_result_ref: completion.author_result_ref,
      effect_receipt_ref: completion.effect_receipt_ref,
      evidence_invalidation_digest: completion.evidence_invalidation_digest,
      evidence_invalidation_ref: completion.evidence_invalidation_ref,
      head_digest: completion.new_head_digest,
      revision: candidate.revision + 1,
      status: "awaiting_evidence",
      updated_at: completion.updated_at,
      verification_receipt_ref: completion.verification_receipt_ref,
    };
    this.records.set(candidate.candidate_id, clone(next));
    return Promise.resolve(clone(next));
  }

  markEvidenceReady(completion: ImprovementEvidenceCompletion) {
    const candidate = this.require(completion.candidate_id);
    if (candidate.status === "ready") return Promise.resolve(clone(candidate));
    if (
      candidate.status !== "awaiting_evidence" ||
      candidate.revision !== completion.expected_revision ||
      candidate.author_generation !== completion.author_generation ||
      candidate.head_digest !== completion.head_digest
    ) return Promise.reject(new ImprovementConflictError("Evidence completion is stale."));
    const next: ImprovementCandidateV1 = {
      ...candidate,
      fresh_evidence_digest: completion.fresh_evidence_digest,
      fresh_evidence_ref: completion.fresh_evidence_ref,
      revision: candidate.revision + 1,
      status: "ready",
      updated_at: completion.updated_at,
    };
    this.records.set(candidate.candidate_id, clone(next));
    return Promise.resolve(clone(next));
  }

  private require(id: string): ImprovementCandidateV1 {
    const candidate = this.records.get(id);
    if (candidate === undefined) throw new ImprovementConflictError("Candidate missing.");
    return clone(candidate);
  }

  private assertExactIdentity(
    candidate: ImprovementCandidateV1,
    reservation: ImprovementAuthorReservation,
  ): void {
    if (
      candidate.base_digest !== reservation.expected_base_digest ||
      candidate.branch_ref !== reservation.expected_branch_ref ||
      candidate.draft_ref !== reservation.expected_draft_ref
    ) throw new ImprovementConflictError("Candidate target changed.");
  }
}

class MemoryEvidencePort implements ImprovementEvidencePort {
  readonly bundleRef = "evidence-bundle://opaque-improvement";
  observedIntentFirst = false;
  private nextFreshCorruption?: "candidate" | "generation" | "evidence";
  private nextFreshResponseFailure = false;
  private nextInvalidationCorruption?: "duplicate" | "missing";
  private readonly records = new Map<string, ImprovementEvidenceSnapshot>();

  constructor(
    private readonly clock: MutableClock,
    private readonly executionStore: ReferenceMemoryExecutionStore,
  ) {}

  get uniqueInvalidationCount(): number {
    return this.records.size;
  }

  corruptNextFreshSnapshot(corruption: "candidate" | "generation" | "evidence"): void {
    this.nextFreshCorruption = corruption;
  }

  failNextFreshResponse(): void {
    this.nextFreshResponseFailure = true;
  }

  corruptNextInvalidation(corruption: "duplicate" | "missing"): void {
    this.nextInvalidationCorruption = corruption;
  }

  async invalidate(
    request: ImprovementEvidenceInvalidationRequest,
    lease: WorkLeaseV1,
  ) {
    const effectIntent = await this.executionStore.getEffectIntent(
      lease.run_id,
      stableIdentity("improvement-effect", [request.candidate_version]),
    );
    this.observedIntentFirst =
      effectIntent !== undefined &&
      typeof effectIntent.request === "object" &&
      effectIntent.request !== null &&
      !Array.isArray(effectIntent.request) &&
      effectIntent.request.prior_head_digest === request.prior_head_digest &&
      Array.isArray(effectIntent.request.required_evidence);
    const key = evidenceKey(request.candidate_id, request.author_generation);
    const prior = this.records.get(key);
    if (prior !== undefined) {
      return {
        author_generation: request.author_generation,
        candidate_id: request.candidate_id,
        invalidation_digest: prior.bundle_digest,
        invalidation_ref: prior.bundle_ref,
      };
    }
    let states: ImprovementEvidenceStateV1[] = request.kinds.map((kind) => ({
      author_generation: request.author_generation,
      candidate_id: request.candidate_id,
      kind,
      schema_version: "improvement-evidence-state/v1",
      state: "invalidated",
      updated_at: this.clock.now().toISOString(),
    }));
    if (this.nextInvalidationCorruption === "duplicate") {
      states = [...states.slice(0, -1), clone(states[0]!)];
    } else if (this.nextInvalidationCorruption === "missing") {
      states = states.slice(0, -1);
    }
    this.nextInvalidationCorruption = undefined;
    const snapshot = this.snapshot(request.candidate_id, request.author_generation, states);
    this.records.set(key, snapshot);
    return {
      author_generation: request.author_generation,
      candidate_id: request.candidate_id,
      invalidation_digest: snapshot.bundle_digest,
      invalidation_ref: snapshot.bundle_ref,
    };
  }

  read(candidateId: string, authorGeneration: number) {
    const snapshot = this.records.get(evidenceKey(candidateId, authorGeneration));
    return Promise.resolve(snapshot === undefined ? undefined : clone(snapshot));
  }

  recordFresh(input: ImprovementEvidenceRecord) {
    const key = evidenceKey(input.candidate_id, input.author_generation);
    const snapshot = this.records.get(key);
    if (snapshot === undefined) return Promise.reject(new ImprovementConflictError("Evidence was not invalidated."));
    const states = snapshot.states.map((state) => {
      if (state.kind !== input.kind) return state;
      if (state.state === "fresh") {
        if (
          state.head_digest !== input.head_digest ||
          state.evidence_digest !== input.evidence_digest ||
          state.evidence_ref !== input.evidence_ref
        ) throw new ImprovementConflictError("Fresh evidence changed.");
        return state;
      }
      return {
        ...state,
        evidence_digest: input.evidence_digest,
        evidence_ref: input.evidence_ref,
        head_digest: input.head_digest,
        state: "fresh" as const,
        updated_at: this.clock.now().toISOString(),
      };
    });
    const next = this.snapshot(input.candidate_id, input.author_generation, states);
    this.records.set(key, next);
    if (this.nextFreshResponseFailure) {
      this.nextFreshResponseFailure = false;
      return Promise.reject(new Error("injected fresh evidence response failure"));
    }
    if (this.nextFreshCorruption === undefined) {
      return Promise.resolve(clone(next));
    }
    const corrupted = clone(next);
    if (this.nextFreshCorruption === "candidate") {
      corrupted.candidate_id = `improvement-${"f".repeat(32)}`;
      corrupted.states = corrupted.states.map((state) => ({
        ...state,
        candidate_id: corrupted.candidate_id,
      }));
    } else if (this.nextFreshCorruption === "generation") {
      corrupted.author_generation += 1;
      corrupted.states = corrupted.states.map((state) => ({
        ...state,
        author_generation: corrupted.author_generation,
      }));
    } else {
      corrupted.states = corrupted.states.map((state) => state.kind === input.kind
        ? { ...state, evidence_digest: sha("corrupt-evidence") }
        : state);
    }
    this.nextFreshCorruption = undefined;
    return Promise.resolve(corrupted);
  }

  private snapshot(
    candidateId: string,
    authorGeneration: number,
    states: ImprovementEvidenceStateV1[],
  ): ImprovementEvidenceSnapshot {
    return {
      author_generation: authorGeneration,
      bundle_digest: sha(JSON.stringify(states)),
      bundle_ref: this.bundleRef,
      candidate_id: candidateId,
      states: clone(states),
    };
  }
}

class MemoryAuthorPort implements ImprovementAuthorPort {
  applyCalls = 0;
  crashAfterApply = false;
  readonly events: string[] = [];
  inspectCalls = 0;
  private readonly results = new Map<string, ImprovementAuthorResult>();
  private snapshot: ImprovementDraftSnapshot = {
    base_digest: sha("base"),
    branch_ref: "branch://opaque-improvement",
    draft_ref: "draft://opaque-improvement",
    head_digest: sha("head-1"),
    state: "open",
  };

  constructor(
    private readonly evidence: MemoryEvidencePort,
  ) {}

  currentSnapshot(): ImprovementDraftSnapshot {
    return clone(this.snapshot);
  }

  inspectDraft(draftRef: string) {
    if (draftRef !== this.snapshot.draft_ref) return Promise.resolve(undefined);
    return Promise.resolve(clone(this.snapshot));
  }

  async apply(intent: ImprovementAuthoringIntent, _lease: WorkLeaseV1) {
    this.applyCalls += 1;
    const evidence = await this.evidence.read(intent.candidate_id, intent.author_generation);
    if (
      evidence === undefined ||
      evidence.states.some((state) => state.state !== "invalidated")
    ) throw new Error("evidence was not invalidated before authoring");
    this.events.push("evidence_invalidated");
    assertExactAuthorTarget(this.snapshot, intent);
    const result = authorResult(intent);
    this.results.set(result.result_ref, clone(result));
    this.snapshot = { ...this.snapshot, head_digest: result.new_head_digest };
    this.events.push("author_applied");
    if (this.crashAfterApply) throw new Error("simulated crash after authoring");
    return result;
  }

  inspect(intent: ImprovementAuthoringIntent, _lease: WorkLeaseV1): Promise<ImprovementAuthorInspection> {
    this.inspectCalls += 1;
    const result = [...this.results.values()].find(
      (candidate) => candidate.candidate_version === intent.candidate_version,
    );
    return Promise.resolve(
      result === undefined
        ? { state: "absent" }
        : { result: clone(result), state: "applied" },
    );
  }

  resume(intent: ImprovementAuthoringIntent, _resumeToken: string, lease: WorkLeaseV1) {
    return this.apply(intent, lease);
  }

  readResult(resultRef: string) {
    const result = this.results.get(resultRef);
    return Promise.resolve(result === undefined ? undefined : clone(result));
  }
}

class MemoryVerificationPort implements ImprovementVerificationPort {
  constructor(
    private readonly author: MemoryAuthorPort,
    private readonly clock: MutableClock,
  ) {}

  verify(
    intent: ImprovementAuthoringIntent,
    result: ImprovementAuthorResult,
    _lease: WorkLeaseV1,
  ): Promise<ImprovementAuthorVerification> {
    const snapshot = this.author.currentSnapshot();
    const verified =
      result.candidate_version === intent.candidate_version &&
      snapshot.state === "open" &&
      snapshot.draft_ref === intent.draft_ref &&
      snapshot.branch_ref === intent.branch_ref &&
      snapshot.base_digest === intent.base_digest &&
      snapshot.head_digest === result.new_head_digest;
    return Promise.resolve({
      candidate_version: intent.candidate_version,
      receipt_ref: `verification://${intent.candidate_id}-${this.clock.now().getTime()}`,
      state: verified ? "verified" : "failed",
    });
  }
}

function assertExactAuthorTarget(
  snapshot: ImprovementDraftSnapshot,
  intent: ImprovementAuthoringIntent,
): void {
  if (
    snapshot.state !== "open" ||
    snapshot.draft_ref !== intent.draft_ref ||
    snapshot.branch_ref !== intent.branch_ref ||
    snapshot.base_digest !== intent.base_digest ||
    snapshot.head_digest !== intent.prior_head_digest
  ) throw new ImprovementConflictError("Author target moved.");
}

class MutableClock {
  private milliseconds = Date.parse(start);

  advance(durationMs: number): void {
    this.milliseconds += durationMs;
  }

  now(): Date {
    return new Date(this.milliseconds);
  }
}

function candidateInput(
  overrides: Partial<ImprovementCandidateInput> = {},
): ImprovementCandidateInput {
  return {
    base_digest: sha("base"),
    branch_ref: "branch://opaque-improvement",
    candidate_key_digest: sha("candidate-key"),
    draft_ref: "draft://opaque-improvement",
    head_digest: sha("head-1"),
    ...overrides,
  };
}

function authorRequest(
  candidate: ImprovementCandidateV1,
  session: ExecutionSession,
  overrides: Partial<ImprovementAuthoringRequest> = {},
): ImprovementAuthoringRequest {
  return {
    approval_ref: "approval://opaque-improvement",
    candidate_id: candidate.candidate_id,
    checkpoint_sequence: 1,
    expected_author_generation: candidate.author_generation,
    expected_base_digest: candidate.base_digest,
    expected_branch_ref: candidate.branch_ref,
    expected_draft_ref: candidate.draft_ref,
    expected_head_digest: candidate.head_digest,
    expected_revision: candidate.revision,
    rollback_plan_ref: "rollback://opaque-improvement",
    session,
    ...overrides,
  };
}

function reservation(
  candidate: ImprovementCandidateV1,
  lease: WorkLeaseV1,
): ImprovementAuthorReservation {
  return {
    candidate_id: candidate.candidate_id,
    expected_author_generation: candidate.author_generation,
    expected_base_digest: candidate.base_digest,
    expected_branch_ref: candidate.branch_ref,
    expected_draft_ref: candidate.draft_ref,
    expected_head_digest: candidate.head_digest,
    expected_revision: candidate.revision,
    lease,
    reserved_at: start,
  };
}

function leaseProof(generation: number, fencingToken: number): WorkLeaseV1 {
  return {
    fencing_token: fencingToken,
    generation,
    heartbeat_at: start,
    lease_expires_at: "2026-07-16T12:01:00.000Z",
    lease_token: `lease-${generation}-${fencingToken}`,
    owner_id: `author-${generation}`,
    run_id: "run-improvement-1",
    schema_version: "work-lease/v1",
  };
}

function freshEvidence(
  candidate: ImprovementCandidateV1,
  kind: ImprovementFreshEvidenceInput["kind"],
  overrides: Partial<ImprovementFreshEvidenceInput> = {},
): ImprovementFreshEvidenceInput {
  return {
    author_generation: candidate.author_generation,
    candidate_id: candidate.candidate_id,
    evidence_digest: sha(`evidence-${kind}`),
    evidence_ref: `evidence://${kind}-opaque`,
    expected_revision: candidate.revision,
    head_digest: candidate.head_digest,
    kind,
    ...overrides,
  };
}

function outcomeEvidence(
  candidate: ImprovementCandidateV1,
  overrides: {
    baseline_head_digest?: string;
    candidate_blockers?: AssistantTurnEvaluationBlockerV1[];
    candidate_head_digest?: string;
    candidate_score?: number;
  } = {},
): ImprovementOutcomeEvidenceInput {
  const baselineHead = overrides.baseline_head_digest
    ?? candidate.authoring_prior_head_digest
    ?? assert.fail("authored candidate must preserve its prior head");
  return {
    author_generation: candidate.author_generation,
    baseline: {
      evaluated_head_digest: baselineHead,
      evaluations: promotionEvaluations(
        "policy://baseline",
        0.72,
        ["outcome_unknown"],
      ),
    },
    candidate: {
      evaluated_head_digest: overrides.candidate_head_digest ?? candidate.head_digest,
      evaluations: promotionEvaluations(
        "policy://candidate",
        overrides.candidate_score ?? 0.94,
        overrides.candidate_blockers ?? [],
      ),
    },
    candidate_id: candidate.candidate_id,
    expected_revision: candidate.revision,
    head_digest: candidate.head_digest,
    held_out_evidence_ref: "evidence://held-out-outcomes",
    promotion_evidence_ref: "evidence://outcome-promotion",
    shadow_evidence_ref: "evidence://shadow-outcomes",
  };
}

function promotionEvaluations(
  policyRef: string,
  score: number,
  blockers: AssistantTurnEvaluationBlockerV1[],
): AssistantTurnEvaluationV1[] {
  return (["held_out", "shadow"] as const).flatMap((partition) => (
    Array.from({ length: 8 }, (_, index) => ({
      blockers: [...blockers],
      case_digest: sha(`case-${partition}-${index}`),
      case_ref: `case://${partition}-${index}`,
      dimensions: {
        coverage_honesty: score,
        delivery_completeness: score,
        evidence_use: score,
        execution_efficiency: score,
        grounding: score,
        human_burden: score,
        intervention_fit: score,
        latency_budget: score,
        outcome_closure: score,
      },
      evaluator_ref: "evaluation://sealed-outcomes",
      observation_digest: sha(`observation-${partition}-${index}`),
      observation_ref: `observation://${partition}-${index}`,
      partition,
      passed: blockers.length === 0 && score >= 0.8,
      policy_ref: policyRef,
      schema_version: "assistant-turn-evaluation/v1" as const,
      score,
    }))
  ));
}

function authorResult(intent: ImprovementAuthoringIntent): ImprovementAuthorResult {
  const resultRef = `author-result://${intent.candidate_id}-${intent.author_generation}`;
  return {
    base_digest: intent.base_digest,
    branch_ref: intent.branch_ref,
    candidate_version: intent.candidate_version,
    draft_ref: intent.draft_ref,
    new_head_digest: sha(`${intent.candidate_version}:new-head`),
    prior_head_digest: intent.prior_head_digest,
    result_digest: sha(resultRef),
    result_ref: resultRef,
  };
}

function runReceipt(): RunReceiptV1 {
  return {
    admitted_at: start,
    binding_id: "binding-opaque",
    idempotency_key: "event:opaque-improvement",
    input_digest: sha("improvement-input"),
    receipt_id: "receipt-opaque-improvement",
    received_at: start,
    required_capabilities: [],
    retention_policy_ref: "retention://default",
    revision: 1,
    run_id: "run-improvement-1",
    run_kind: "reconciliation",
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: "subject://opaque-improvement",
    tenant_id: "opaque-tenant",
    updated_at: start,
  };
}

function evidenceKey(candidateId: string, authorGeneration: number): string {
  return `${candidateId}:${authorGeneration}`;
}

function sha(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}
