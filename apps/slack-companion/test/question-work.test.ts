import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { RunReceiptV1, WorkLeaseV1 } from "../src/execution/model.js";
import type {
  QuestionWorkAdmissionInput,
  QuestionWorkPreflightV1,
} from "../src/question-work/contracts.js";
import {
  QuestionWorkConflictError,
  QuestionWorkCoordinator,
  QuestionWorkInputError,
  QuestionWorkStaleLeaseError,
  questionWorkIdentity,
} from "../src/question-work/coordinator.js";
import { ReferenceMemoryQuestionWorkStore } from "../src/question-work/reference-store.js";

const NOW = "2026-07-16T12:00:00.000Z";

describe("QuestionWorkCoordinator", () => {
  test("permits acknowledgement only after atomic durable admission", async () => {
    const fixture = makeFixture();
    const workId = questionWorkIdentity(admission());
    fixture.store.failNextAdmit();

    await assert.rejects(
      fixture.coordinator.admit(admission(), readyPreflight()),
      /durable admission failure/,
    );
    assert.equal(await fixture.store.read(workId), undefined);
    assert.equal(fixture.store.readTask(workId), undefined);

    const accepted = await fixture.coordinator.admit(admission(), readyPreflight());
    assert.deepEqual(accepted, {
      acknowledgement_permitted: true,
      continuation_permitted: true,
      duplicate: false,
      state: "queued",
      work_id: workId,
    });
    assert.equal(fixture.store.readTask(workId)?.work_revision, 1);
    assert.equal(fixture.store.readPreflight(workId)?.receipt_ref, "preflight://receipt-1");
    assert.equal((await fixture.store.read(workId))?.thread_ref, "slack-thread://opaque/thread-1");

    const duplicate = await fixture.coordinator.admit(admission(), readyPreflight());
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.work_id, workId);
    await assert.rejects(
      fixture.coordinator.admit(
        { ...admission(), request_ref: "request://changed" },
        readyPreflight(),
      ),
      QuestionWorkConflictError,
    );
  });

  test("keeps missing-input work durable and resumes only after a ready preflight", async () => {
    const fixture = makeFixture();
    const accepted = await fixture.coordinator.admit(
      admission(),
      readyPreflight({
        receipt_digest: "sha256:waiting-preflight",
        receipt_ref: "preflight://waiting",
        required_input_refs: ["input-request://scope"],
        state: "waiting",
      }),
    );
    assert.equal(accepted.state, "waiting");
    assert.equal(accepted.continuation_permitted, false);
    assert.equal(fixture.store.readTask(accepted.work_id), undefined);

    const runnable = await fixture.coordinator.makeRunnable(
      accepted.work_id,
      1,
      readyPreflight({
        receipt_digest: "sha256:ready-preflight",
        receipt_ref: "preflight://ready",
      }),
    );
    assert.equal(runnable.work.state, "queued");
    assert.equal(runnable.task.work_revision, 2);
    assert.equal(runnable.created, true);

    const duplicate = await fixture.coordinator.makeRunnable(
      accepted.work_id,
      1,
      readyPreflight({
        receipt_digest: "sha256:ready-preflight",
        receipt_ref: "preflight://ready",
      }),
    );
    assert.equal(duplicate.created, false);
    assert.deepEqual(duplicate.task, runnable.task);
    await assert.rejects(
      fixture.coordinator.makeRunnable(
        accepted.work_id,
        1,
        readyPreflight({
          max_attempts: 4,
          receipt_digest: "sha256:expanded-preflight",
          receipt_ref: "preflight://expanded",
        }),
      ),
      /cannot expand the admitted work bounds/,
    );
  });

  test("rejects unbounded or rejected preflight work before persistence", async () => {
    const rejected = makeFixture();
    await assert.rejects(
      rejected.coordinator.admit(
        admission(),
        readyPreflight({ state: "rejected" }),
      ),
      QuestionWorkInputError,
    );
    assert.equal(await rejected.store.read(questionWorkIdentity(admission())), undefined);

    const unbounded = makeFixture();
    await assert.rejects(
      unbounded.coordinator.admit(
        admission(),
        readyPreflight({
          required_capability_refs: Array.from(
            { length: 33 },
            (_, index) => `capability://${index}`,
          ),
        }),
      ),
      /bounded and distinct/,
    );
  });

  test("rejects empty admission fields before persistence", async () => {
    const fixture = makeFixture();
    await assert.rejects(
      fixture.coordinator.admit(
        admission({ request_ref: " " }),
        readyPreflight(),
      ),
      /request_ref cannot be empty/,
    );
    assert.equal(
      await fixture.store.read(questionWorkIdentity(admission())),
      undefined,
    );
  });

  test("persists monotonic progress and resumes retry work under a newer fence", async () => {
    const fixture = makeFixture();
    const accepted = await fixture.coordinator.admit(admission(), readyPreflight());
    const task = fixture.store.readTask(accepted.work_id);
    assert(task);
    const firstLease = lease(1, 1, "worker-a", "lease-a");
    const started = await fixture.coordinator.claim(task, firstLease);
    assert(started);
    assert.equal(started.status, "started");
    assert.equal(started.work.revision, 2);

    const duplicateClaim = await fixture.coordinator.claim(task, firstLease);
    assert.equal(duplicateClaim?.created, false);

    const progressInput = {
      completed_step_ids: ["preflight", "evidence-read"],
      expected_revision: 2,
      lease: firstLease,
      progress_digest: "sha256:progress-1",
      progress_ref: "question-progress://work-1/1",
      resume_cursor: "cursor://after-evidence-read",
      sequence: 1,
      work_id: accepted.work_id,
    };
    const progress = await fixture.coordinator.appendProgress(progressInput);
    assert.equal(progress.created, true);
    assert.equal(progress.work.revision, 3);
    assert.equal((await fixture.coordinator.appendProgress(progressInput)).created, false);

    const retryInput = {
      available_at: "2026-07-16T12:01:00.000Z",
      expected_revision: 3,
      failure_receipt_digest: "sha256:retryable-read",
      failure_receipt_ref: "failure://retryable-read",
      lease: firstLease,
      reason_code: "source_temporarily_unavailable",
      work_id: accepted.work_id,
    };
    const retry = await fixture.coordinator.scheduleRetry(retryInput);
    assert.equal(retry.work.state, "retryable");
    assert.equal(retry.task.work_revision, 4);
    assert.equal((await fixture.coordinator.scheduleRetry(retryInput)).created, false);
    await assert.rejects(
      async () =>
        fixture.coordinator.scheduleRetry({
          ...retryInput,
          lease: lease(1, 1, "worker-other", "lease-other"),
        }),
      QuestionWorkStaleLeaseError,
    );

    fixture.clock.set("2026-07-16T12:02:00.000Z");
    const secondLease = lease(2, 2, "worker-b", "lease-b", "2026-07-16T12:10:00.000Z");
    const resumed = await fixture.coordinator.claim(retry.task, secondLease);
    assert(resumed);
    assert.equal(resumed.status, "resumed");
    assert.equal(resumed.latest_progress?.resume_cursor, "cursor://after-evidence-read");
    assert.equal(resumed.work.revision, 5);

    await assert.rejects(
      async () =>
        fixture.coordinator.appendProgress({
          ...progressInput,
          expected_revision: 5,
          sequence: 2,
        }),
      QuestionWorkStaleLeaseError,
    );

    const incomplete = await fixture.coordinator.recordOutcome({
      expected_revision: 5,
      lease: secondLease,
      outcome: "incomplete",
      reason_code: "required_evidence_unavailable",
      receipt_digest: "sha256:incomplete-receipt",
      receipt_ref: "question-outcome://incomplete",
      work_id: accepted.work_id,
    });
    assert.equal(incomplete.work.state, "incomplete");
    assert.equal(incomplete.outcome.result_ref, undefined);
    assert.equal(fixture.store.readProgress(accepted.work_id).length, 1);
    assert.equal(fixture.store.readRetry(accepted.work_id)?.reason_code, "source_temporarily_unavailable");
  });

  test("persists bounded answers and keeps unsuccessful outcomes explicit", async () => {
    const completeFixture = await startFixture("question");
    const completed = await completeFixture.fixture.coordinator.recordOutcome({
      expected_revision: completeFixture.started.work.revision,
      lease: completeFixture.activeLease,
      outcome: "completed",
      reason_code: "answer_persisted",
      receipt_digest: "sha256:answer-receipt",
      receipt_ref: "question-outcome://complete",
      result_bytes: 512,
      result_digest: "sha256:answer",
      result_kind: "answer",
      result_ref: "answer://durable/1",
      work_id: completeFixture.accepted.work_id,
    });
    assert.equal(completed.work.state, "completed");
    assert.equal(completeFixture.fixture.store.readOutcome(completed.work.work_id)?.result_ref, "answer://durable/1");

    const boundedFixture = await startFixture("question", { max_result_bytes: 256 });
    await assert.rejects(
      boundedFixture.fixture.coordinator.recordOutcome({
        expected_revision: boundedFixture.started.work.revision,
        lease: boundedFixture.activeLease,
        outcome: "completed",
        reason_code: "answer_persisted",
        receipt_digest: "sha256:oversized-receipt",
        receipt_ref: "question-outcome://oversized",
        result_bytes: 257,
        result_digest: "sha256:oversized-answer",
        result_kind: "answer",
        result_ref: "answer://durable/oversized",
        work_id: boundedFixture.accepted.work_id,
      }),
      /exceeds its admitted bound/,
    );

    const failedFixture = await startFixture("attestation");
    const failed = await failedFixture.fixture.coordinator.recordOutcome({
      expected_revision: failedFixture.started.work.revision,
      lease: failedFixture.activeLease,
      outcome: "failed",
      reason_code: "preflight_evidence_invalid",
      receipt_digest: "sha256:failed-receipt",
      receipt_ref: "question-outcome://failed",
      work_id: failedFixture.accepted.work_id,
    });
    assert.equal(failed.work.state, "failed");
    assert.equal(failed.outcome.result_kind, undefined);
  });
});

async function startFixture(
  kind: "attestation" | "question",
  preflightOverrides: Partial<QuestionWorkPreflightV1> = {},
) {
  const input = admission({ work_kind: kind, idempotency_key: `event-${kind}` });
  const fixture = makeFixture(input);
  const accepted = await fixture.coordinator.admit(input, readyPreflight(preflightOverrides));
  const task = fixture.store.readTask(accepted.work_id);
  assert(task);
  const activeLease = lease(1, 1, "worker-a", "lease-a");
  const started = await fixture.coordinator.claim(task, activeLease);
  assert(started);
  return { accepted, activeLease, fixture, started };
}

function makeFixture(input = admission()) {
  const clock = new MutableClock(NOW);
  const store = new ReferenceMemoryQuestionWorkStore();
  store.seedRun(runReceipt(input));
  return {
    clock,
    coordinator: new QuestionWorkCoordinator({ clock, runs: store, store }),
    store,
  };
}

function admission(
  overrides: Partial<QuestionWorkAdmissionInput> = {},
): QuestionWorkAdmissionInput {
  return {
    binding_id: "binding-1",
    idempotency_key: "event-1",
    installation_id: "installation-1",
    request_digest: "sha256:request-1",
    request_ref: "slack-request://opaque/request-1",
    request_run_id: "run-1",
    subject_ref: "subject://thread-1",
    tenant_id: "tenant-1",
    thread_ref: "slack-thread://opaque/thread-1",
    work_kind: "question",
    ...overrides,
  };
}

function readyPreflight(
  overrides: Partial<QuestionWorkPreflightV1> = {},
): QuestionWorkPreflightV1 {
  return {
    max_attempts: 3,
    max_result_bytes: 4_096,
    max_steps: 8,
    receipt_digest: "sha256:preflight-1",
    receipt_ref: "preflight://receipt-1",
    request_digest: "sha256:request-1",
    required_capability_refs: [],
    required_input_refs: [],
    schema_version: "question-work-preflight/v1",
    state: "ready",
    ...overrides,
  };
}

function runReceipt(input: QuestionWorkAdmissionInput): RunReceiptV1 {
  return {
    admitted_at: "2026-07-16T11:59:00.000Z",
    binding_id: input.binding_id,
    idempotency_key: `run-${input.idempotency_key}`,
    input_digest: input.request_digest,
    receipt_id: "receipt-run-1",
    received_at: "2026-07-16T11:58:59.000Z",
    required_capabilities: [],
    retention_policy_ref: "retention://default",
    revision: 1,
    run_id: input.request_run_id,
    run_kind: "interactive",
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: input.subject_ref,
    tenant_id: input.tenant_id,
    updated_at: "2026-07-16T11:59:00.000Z",
  };
}

function lease(
  generation: number,
  fencingToken: number,
  ownerId: string,
  leaseId: string,
  expiresAt = "2026-07-16T12:05:00.000Z",
): WorkLeaseV1 {
  return {
    fencing_token: fencingToken,
    generation,
    heartbeat_at: "2026-07-16T12:00:00.000Z",
    lease_expires_at: expiresAt,
    lease_token: leaseId,
    owner_id: ownerId,
    run_id: "run-1",
    schema_version: "work-lease/v1",
  };
}

class MutableClock {
  constructor(private value: string) {}

  now(): Date {
    return new Date(this.value);
  }

  set(value: string): void {
    this.value = value;
  }
}
