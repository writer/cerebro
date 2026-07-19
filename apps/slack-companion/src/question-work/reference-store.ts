import type { RunReceiptV1, WorkLeaseV1 } from "../execution/model.js";
import {
  QuestionWorkConflictError,
  QuestionWorkStaleLeaseError,
} from "./coordinator.js";
import type {
  QuestionWorkAdmissionCommit,
  QuestionWorkAdmissionCommitResult,
  QuestionWorkClaim,
  QuestionWorkClaimResult,
  QuestionWorkOutcomeInput,
  QuestionWorkOutcomeReceiptV1,
  QuestionWorkOutcomeResult,
  QuestionWorkPreflightV1,
  QuestionWorkProgressInput,
  QuestionWorkProgressResult,
  QuestionWorkProgressV1,
  QuestionWorkRetryInput,
  QuestionWorkRetryReceiptV1,
  QuestionWorkRetryResult,
  QuestionWorkRunnableCommit,
  QuestionWorkRunnableResult,
  QuestionWorkTaskV1,
  QuestionWorkV1,
} from "./contracts.js";
import type {
  DurableQuestionWorkPort,
  QuestionWorkRunReceiptPort,
} from "./ports.js";

/** Conformance fixture only. Production adapters must use durable storage. */
export class ReferenceMemoryQuestionWorkStore
  implements DurableQuestionWorkPort, QuestionWorkRunReceiptPort
{
  private readonly fingerprints = new Map<string, string>();
  private readonly highestLeases = new Map<string, WorkLeaseV1>();
  private readonly outcomes = new Map<string, QuestionWorkOutcomeReceiptV1>();
  private readonly preflights = new Map<string, QuestionWorkPreflightV1>();
  private readonly progress = new Map<string, QuestionWorkProgressV1[]>();
  private readonly retries = new Map<string, QuestionWorkRetryReceiptV1>();
  private readonly runs = new Map<string, RunReceiptV1>();
  private readonly tasks = new Map<string, QuestionWorkTaskV1>();
  private readonly work = new Map<string, QuestionWorkV1>();
  private failNextAdmission = false;

  seedRun(run: RunReceiptV1): void {
    this.runs.set(run.run_id, structuredClone(run));
  }

  readRun(runId: string): RunReceiptV1 | undefined {
    return clone(this.runs.get(runId));
  }

  failNextAdmit(): void {
    this.failNextAdmission = true;
  }

  admitAndQueue(
    commit: QuestionWorkAdmissionCommit,
  ): Promise<QuestionWorkAdmissionCommitResult> {
    if (this.failNextAdmission) {
      this.failNextAdmission = false;
      return Promise.reject(new Error("injected durable admission failure"));
    }
    const current = this.work.get(commit.work.work_id);
    if (current !== undefined) {
      if (this.fingerprints.get(current.work_id) !== commit.payload_fingerprint) {
        throw new QuestionWorkConflictError("Question-work idempotency intent changed.");
      }
      return Promise.resolve({
        created: false,
        preflight: cloneRequired(this.preflights.get(current.work_id)),
        task: clone(this.tasks.get(current.work_id)),
        work: structuredClone(current),
      });
    }

    // These mutations model one transaction: snapshot, preflight, and outbox.
    this.work.set(commit.work.work_id, structuredClone(commit.work));
    this.fingerprints.set(commit.work.work_id, commit.payload_fingerprint);
    this.preflights.set(commit.work.work_id, structuredClone(commit.preflight));
    if (commit.task !== undefined) {
      this.tasks.set(commit.work.work_id, structuredClone(commit.task));
    }
    return Promise.resolve({
      created: true,
      preflight: structuredClone(commit.preflight),
      task: clone(commit.task),
      work: structuredClone(commit.work),
    });
  }

  makeRunnable(
    commit: QuestionWorkRunnableCommit,
  ): Promise<QuestionWorkRunnableResult> {
    const current = this.requireWork(commit.work_id);
    const priorPreflight = this.preflights.get(commit.work_id);
    if (
      current.state === "queued" &&
      current.revision === commit.expected_revision + 1 &&
      samePreflight(priorPreflight, commit.preflight) &&
      sameTask(this.tasks.get(commit.work_id), commit.task)
    ) {
      return Promise.resolve({
        created: false,
        task: structuredClone(commit.task),
        work: structuredClone(current),
      });
    }
    if (current.state !== "waiting" || current.revision !== commit.expected_revision) {
      throw new QuestionWorkConflictError("Question-work preflight revision changed.");
    }
    const updated: QuestionWorkV1 = {
      ...current,
      max_attempts: commit.preflight.max_attempts,
      max_result_bytes: commit.preflight.max_result_bytes,
      max_steps: commit.preflight.max_steps,
      preflight_receipt_ref: commit.preflight.receipt_ref,
      revision: current.revision + 1,
      state: "queued",
      updated_at: commit.updated_at,
    };
    if (commit.task.work_revision !== updated.revision) {
      throw new QuestionWorkConflictError("Question-work task does not match the runnable revision.");
    }

    // These mutations model one transaction: ready preflight, snapshot, outbox.
    this.preflights.set(commit.work_id, structuredClone(commit.preflight));
    this.tasks.set(commit.work_id, structuredClone(commit.task));
    this.work.set(commit.work_id, updated);
    return Promise.resolve({
      created: true,
      task: structuredClone(commit.task),
      work: structuredClone(updated),
    });
  }

  claim(input: QuestionWorkClaim): Promise<QuestionWorkClaimResult | undefined> {
    const current = this.requireWork(input.task.work_id);
    const records = this.progress.get(current.work_id) ?? [];
    if (
      current.state === "running" &&
      current.active_lease !== undefined &&
      sameLease(current.active_lease, input.lease) &&
      current.active_task_idempotency_key === input.task.idempotency_key &&
      current.active_task_revision === input.task.work_revision
    ) {
      return Promise.resolve({
        created: false,
        latest_progress: clone(records.at(-1)),
        status: records.length === 0 ? "started" : "resumed",
        work: structuredClone(current),
      });
    }
    if (
      (current.state !== "queued" && current.state !== "retryable") ||
      current.revision !== input.task.work_revision ||
      input.lease.run_id !== current.request_run_id ||
      input.task.request_run_id !== current.request_run_id ||
      input.task.thread_ref !== current.thread_ref ||
      Date.parse(input.task.available_at) > Date.parse(input.claimed_at) ||
      current.attempts >= current.max_attempts
    ) {
      return Promise.resolve(undefined);
    }
    this.assertNewLease(current.work_id, input.lease);
    const claimed: QuestionWorkV1 = {
      ...current,
      active_lease: structuredClone(input.lease),
      active_task_idempotency_key: input.task.idempotency_key,
      active_task_revision: input.task.work_revision,
      attempts: current.attempts + 1,
      revision: current.revision + 1,
      state: "running",
      updated_at: input.claimed_at,
    };
    this.highestLeases.set(current.work_id, structuredClone(input.lease));
    this.tasks.delete(current.work_id);
    this.work.set(current.work_id, claimed);
    return Promise.resolve({
      created: true,
      latest_progress: clone(records.at(-1)),
      status: records.length === 0 ? "started" : "resumed",
      work: structuredClone(claimed),
    });
  }

  appendProgress(
    input: QuestionWorkProgressInput,
    recordedAt: string,
  ): Promise<QuestionWorkProgressResult> {
    const current = this.requireWork(input.work_id);
    const records = this.progress.get(input.work_id) ?? [];
    const prior = records.at(-1);
    if (
      prior?.sequence === input.sequence &&
      current.revision === input.expected_revision + 1 &&
      sameProgress(prior, input)
    ) {
      return Promise.resolve({
        created: false,
        progress: structuredClone(prior),
        work: structuredClone(current),
      });
    }
    this.assertOwnedRunning(current, input.lease, recordedAt);
    if (
      current.revision !== input.expected_revision ||
      input.sequence <= current.latest_progress_sequence ||
      input.sequence > current.max_steps
    ) {
      throw new QuestionWorkConflictError("Question-work progress is stale or outside its admitted bound.");
    }
    const progress: QuestionWorkProgressV1 = {
      completed_step_ids: [...input.completed_step_ids],
      fencing_token: input.lease.fencing_token,
      generation: input.lease.generation,
      lease_token: input.lease.lease_token,
      owner_id: input.lease.owner_id,
      progress_digest: input.progress_digest,
      progress_ref: input.progress_ref,
      recorded_at: recordedAt,
      resume_cursor: input.resume_cursor,
      schema_version: "question-work-progress/v1",
      sequence: input.sequence,
      work_id: input.work_id,
    };
    const updated: QuestionWorkV1 = {
      ...current,
      latest_progress_sequence: input.sequence,
      revision: current.revision + 1,
      updated_at: recordedAt,
    };
    records.push(progress);
    this.progress.set(input.work_id, records);
    this.work.set(input.work_id, updated);
    return Promise.resolve({ created: true, progress: structuredClone(progress), work: structuredClone(updated) });
  }

  scheduleRetry(
    input: QuestionWorkRetryInput,
    recordedAt: string,
  ): Promise<QuestionWorkRetryResult> {
    const current = this.requireWork(input.work_id);
    const prior = this.retries.get(input.work_id);
    const priorTask = this.tasks.get(input.work_id);
    if (
      current.state === "retryable" &&
      current.revision === input.expected_revision + 1 &&
      prior !== undefined &&
      sameRetry(prior, input) &&
      priorTask !== undefined
    ) {
      return Promise.resolve({
        created: false,
        receipt: structuredClone(prior),
        task: structuredClone(priorTask),
        work: structuredClone(current),
      });
    }
    this.assertOwnedRunning(current, input.lease, recordedAt);
    if (current.revision !== input.expected_revision || current.attempts >= current.max_attempts) {
      throw new QuestionWorkConflictError("Question-work retry is stale or its attempt bound is exhausted.");
    }
    const updated: QuestionWorkV1 = {
      ...current,
      active_lease: undefined,
      active_task_idempotency_key: undefined,
      active_task_revision: undefined,
      revision: current.revision + 1,
      state: "retryable",
      updated_at: recordedAt,
    };
    const task: QuestionWorkTaskV1 = {
      available_at: input.available_at,
      idempotency_key: retryTaskIdentity(input.work_id, updated.revision),
      request_run_id: updated.request_run_id,
      schema_version: "question-work-task/v1",
      thread_ref: updated.thread_ref,
      work_id: input.work_id,
      work_revision: updated.revision,
    };
    const receipt: QuestionWorkRetryReceiptV1 = {
      available_at: input.available_at,
      failure_receipt_digest: input.failure_receipt_digest,
      failure_receipt_ref: input.failure_receipt_ref,
      fencing_token: input.lease.fencing_token,
      generation: input.lease.generation,
      lease_token: input.lease.lease_token,
      owner_id: input.lease.owner_id,
      reason_code: input.reason_code,
      recorded_at: recordedAt,
      schema_version: "question-work-retry-receipt/v1",
      work_id: input.work_id,
    };
    this.retries.set(input.work_id, receipt);
    this.tasks.set(input.work_id, task);
    this.work.set(input.work_id, updated);
    return Promise.resolve({
      created: true,
      receipt: structuredClone(receipt),
      task: structuredClone(task),
      work: structuredClone(updated),
    });
  }

  recordOutcome(
    input: QuestionWorkOutcomeInput,
    recordedAt: string,
  ): Promise<QuestionWorkOutcomeResult> {
    const current = this.requireWork(input.work_id);
    const prior = this.outcomes.get(input.work_id);
    if (
      isTerminal(current.state) &&
      current.revision === input.expected_revision + 1 &&
      prior !== undefined &&
      sameOutcome(prior, input)
    ) {
      return Promise.resolve({
        created: false,
        outcome: structuredClone(prior),
        work: structuredClone(current),
      });
    }
    this.assertOwnedRunning(current, input.lease, recordedAt);
    if (current.revision !== input.expected_revision) {
      throw new QuestionWorkConflictError("Question-work outcome revision changed.");
    }
    const outcome: QuestionWorkOutcomeReceiptV1 = {
      fencing_token: input.lease.fencing_token,
      generation: input.lease.generation,
      lease_token: input.lease.lease_token,
      owner_id: input.lease.owner_id,
      outcome: input.outcome,
      reason_code: input.reason_code,
      receipt_digest: input.receipt_digest,
      receipt_ref: input.receipt_ref,
      recorded_at: recordedAt,
      result_bytes: input.result_bytes,
      result_digest: input.result_digest,
      result_kind: input.result_kind,
      result_ref: input.result_ref,
      schema_version: "question-work-outcome-receipt/v1",
      work_id: input.work_id,
    };
    const updated: QuestionWorkV1 = {
      ...current,
      active_lease: undefined,
      active_task_idempotency_key: undefined,
      active_task_revision: undefined,
      revision: current.revision + 1,
      state: input.outcome,
      updated_at: recordedAt,
    };
    this.outcomes.set(input.work_id, outcome);
    this.work.set(input.work_id, updated);
    return Promise.resolve({ created: true, outcome: structuredClone(outcome), work: structuredClone(updated) });
  }

  read(workId: string): Promise<QuestionWorkV1 | undefined> {
    return Promise.resolve(clone(this.work.get(workId)));
  }

  readOutcome(workId: string): QuestionWorkOutcomeReceiptV1 | undefined {
    return clone(this.outcomes.get(workId));
  }

  readPreflight(workId: string): QuestionWorkPreflightV1 | undefined {
    return clone(this.preflights.get(workId));
  }

  readProgress(workId: string): QuestionWorkProgressV1[] {
    return structuredClone(this.progress.get(workId) ?? []);
  }

  readRetry(workId: string): QuestionWorkRetryReceiptV1 | undefined {
    return clone(this.retries.get(workId));
  }

  readTask(workId: string): QuestionWorkTaskV1 | undefined {
    return clone(this.tasks.get(workId));
  }

  private assertNewLease(workId: string, lease: WorkLeaseV1): void {
    const highest = this.highestLeases.get(workId);
    if (highest === undefined) return;
    if (
      lease.generation < highest.generation ||
      (lease.generation === highest.generation && lease.fencing_token <= highest.fencing_token)
    ) {
      throw new QuestionWorkStaleLeaseError("Question work rejected an outdated lease fence.");
    }
  }

  private assertOwnedRunning(work: QuestionWorkV1, lease: WorkLeaseV1, observedAt: string): void {
    if (
      work.state !== "running" ||
      work.active_lease === undefined ||
      !sameLease(work.active_lease, lease) ||
      lease.run_id !== work.request_run_id ||
      Date.parse(lease.lease_expires_at) <= Date.parse(observedAt)
    ) {
      throw new QuestionWorkStaleLeaseError("Question work rejected a stale lease mutation.");
    }
  }

  private requireWork(workId: string): QuestionWorkV1 {
    const work = this.work.get(workId);
    if (work === undefined) {
      throw new QuestionWorkConflictError("Question work does not exist.");
    }
    return work;
  }
}

function retryTaskIdentity(workId: string, revision: number): string {
  return `question-retry-${workId}-${revision}`;
}

function sameTask(left: QuestionWorkTaskV1 | undefined, right: QuestionWorkTaskV1): boolean {
  return left !== undefined && JSON.stringify(left) === JSON.stringify(right);
}

function samePreflight(
  left: QuestionWorkPreflightV1 | undefined,
  right: QuestionWorkPreflightV1,
): boolean {
  return left !== undefined && JSON.stringify(left) === JSON.stringify(right);
}

function sameLease(left: WorkLeaseV1, right: WorkLeaseV1): boolean {
  return (
    left.fencing_token === right.fencing_token &&
    left.generation === right.generation &&
    left.heartbeat_at === right.heartbeat_at &&
    left.lease_expires_at === right.lease_expires_at &&
    left.lease_token === right.lease_token &&
    left.owner_id === right.owner_id &&
    left.run_id === right.run_id
  );
}

function sameProgress(prior: QuestionWorkProgressV1, input: QuestionWorkProgressInput): boolean {
  return (
    JSON.stringify(prior.completed_step_ids) === JSON.stringify(input.completed_step_ids) &&
    prior.fencing_token === input.lease.fencing_token &&
    prior.generation === input.lease.generation &&
    prior.lease_token === input.lease.lease_token &&
    prior.owner_id === input.lease.owner_id &&
    prior.progress_digest === input.progress_digest &&
    prior.progress_ref === input.progress_ref &&
    prior.resume_cursor === input.resume_cursor
  );
}

function sameRetry(prior: QuestionWorkRetryReceiptV1, input: QuestionWorkRetryInput): boolean {
  return (
    prior.available_at === input.available_at &&
    prior.failure_receipt_digest === input.failure_receipt_digest &&
    prior.failure_receipt_ref === input.failure_receipt_ref &&
    prior.fencing_token === input.lease.fencing_token &&
    prior.generation === input.lease.generation &&
    prior.lease_token === input.lease.lease_token &&
    prior.owner_id === input.lease.owner_id &&
    prior.reason_code === input.reason_code
  );
}

function sameOutcome(prior: QuestionWorkOutcomeReceiptV1, input: QuestionWorkOutcomeInput): boolean {
  return (
    prior.fencing_token === input.lease.fencing_token &&
    prior.generation === input.lease.generation &&
    prior.lease_token === input.lease.lease_token &&
    prior.owner_id === input.lease.owner_id &&
    prior.outcome === input.outcome &&
    prior.reason_code === input.reason_code &&
    prior.receipt_digest === input.receipt_digest &&
    prior.receipt_ref === input.receipt_ref &&
    prior.result_bytes === input.result_bytes &&
    prior.result_digest === input.result_digest &&
    prior.result_kind === input.result_kind &&
    prior.result_ref === input.result_ref
  );
}

function isTerminal(state: QuestionWorkV1["state"]): boolean {
  return state === "completed" || state === "incomplete" || state === "failed";
}

function clone<T>(value: T | undefined): T | undefined {
  return value === undefined ? undefined : structuredClone(value);
}

function cloneRequired<T>(value: T | undefined): T {
  if (value === undefined) throw new QuestionWorkConflictError("Question-work durable state is incomplete.");
  return structuredClone(value);
}
