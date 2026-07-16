import { createHash } from "node:crypto";
import type { RunReceiptV1, WorkLeaseV1 } from "../execution/model.js";
import {
  QUESTION_WORK_LIMITS,
  type QuestionWorkAcknowledgement,
  type QuestionWorkAdmissionInput,
  type QuestionWorkClaimResult,
  type QuestionWorkOutcomeInput,
  type QuestionWorkOutcomeResult,
  type QuestionWorkPreflightV1,
  type QuestionWorkProgressInput,
  type QuestionWorkProgressResult,
  type QuestionWorkRetryInput,
  type QuestionWorkRetryResult,
  type QuestionWorkRunnableResult,
  type QuestionWorkTaskV1,
  type QuestionWorkV1,
} from "./contracts.js";
import type {
  DurableQuestionWorkPort,
  QuestionWorkClockPort,
  QuestionWorkRunReceiptPort,
} from "./ports.js";

export class QuestionWorkConflictError extends Error {}
export class QuestionWorkInputError extends Error {}
export class QuestionWorkStaleLeaseError extends Error {}

export interface QuestionWorkCoordinatorOptions {
  clock: QuestionWorkClockPort;
  runs: QuestionWorkRunReceiptPort;
  store: DurableQuestionWorkPort;
}

export class QuestionWorkCoordinator {
  private readonly clock: QuestionWorkClockPort;
  private readonly runs: QuestionWorkRunReceiptPort;
  private readonly store: DurableQuestionWorkPort;

  constructor(options: QuestionWorkCoordinatorOptions) {
    this.clock = options.clock;
    this.runs = options.runs;
    this.store = options.store;
  }

  async admit(
    input: QuestionWorkAdmissionInput,
    preflight: QuestionWorkPreflightV1,
  ): Promise<QuestionWorkAcknowledgement> {
    validateAdmissionInput(input);
    validatePreflight(preflight, input.request_digest, true);
    const run = await this.runs.readRun(input.request_run_id);
    validateRequestRun(run, input);

    const now = this.clock.now().toISOString();
    const workId = questionWorkIdentity(input);
    const state = preflight.state === "ready" ? "queued" : "waiting";
    const work: QuestionWorkV1 = {
      attempts: 0,
      binding_id: input.binding_id,
      created_at: now,
      idempotency_key: input.idempotency_key,
      installation_id: input.installation_id,
      latest_progress_sequence: 0,
      max_attempts: preflight.max_attempts,
      max_result_bytes: preflight.max_result_bytes,
      max_steps: preflight.max_steps,
      preflight_receipt_ref: preflight.receipt_ref,
      request_digest: input.request_digest,
      request_ref: input.request_ref,
      request_run_id: input.request_run_id,
      revision: 1,
      schema_version: "question-work/v1",
      state,
      subject_ref: input.subject_ref,
      tenant_id: input.tenant_id,
      thread_ref: input.thread_ref,
      updated_at: now,
      work_id: workId,
      work_kind: input.work_kind,
    };
    const task = state === "queued" ? taskFor(work, now) : undefined;
    const result = await this.store.admitAndQueue({
      payload_fingerprint: admissionFingerprint(input, preflight),
      preflight,
      task,
      work,
    });
    return {
      acknowledgement_permitted: true,
      continuation_permitted: result.task !== undefined,
      duplicate: !result.created,
      state: result.work.state,
      work_id: result.work.work_id,
    };
  }

  async makeRunnable(
    workId: string,
    expectedRevision: number,
    preflight: QuestionWorkPreflightV1,
  ): Promise<QuestionWorkRunnableResult> {
    requireRef(workId, "work_id");
    requireRevision(expectedRevision);
    const current = await this.requireWork(workId);
    if (
      current.state !== "waiting" &&
      !(current.state === "queued" && current.revision === expectedRevision + 1)
    ) {
      throw new QuestionWorkConflictError("Only waiting question work can become runnable.");
    }
    validatePreflight(preflight, current.request_digest, false);
    if (preflight.state !== "ready") {
      throw new QuestionWorkInputError("Runnable question work requires a ready preflight receipt.");
    }
    if (
      preflight.max_attempts > current.max_attempts ||
      preflight.max_result_bytes > current.max_result_bytes ||
      preflight.max_steps > current.max_steps
    ) {
      throw new QuestionWorkInputError("A continuation preflight cannot expand the admitted work bounds.");
    }
    const now = this.clock.now().toISOString();
    return this.store.makeRunnable({
      expected_revision: expectedRevision,
      preflight,
      task: taskFor({ ...current, revision: expectedRevision + 1 }, now),
      updated_at: now,
      work_id: workId,
    });
  }

  claim(task: QuestionWorkTaskV1, lease: WorkLeaseV1): Promise<QuestionWorkClaimResult | undefined> {
    validateTask(task);
    this.validateLease(lease, task.request_run_id);
    const claimedAt = this.clock.now().toISOString();
    return this.store.claim({
      claimed_at: claimedAt,
      lease,
      task,
    });
  }

  appendProgress(input: QuestionWorkProgressInput): Promise<QuestionWorkProgressResult> {
    validateProgress(input);
    this.validateLease(input.lease);
    return this.store.appendProgress(input, this.clock.now().toISOString());
  }

  scheduleRetry(input: QuestionWorkRetryInput): Promise<QuestionWorkRetryResult> {
    const now = this.clock.now();
    validateRetry(input, now);
    this.validateLease(input.lease);
    return this.store.scheduleRetry(input, now.toISOString());
  }

  async recordOutcome(input: QuestionWorkOutcomeInput): Promise<QuestionWorkOutcomeResult> {
    this.validateLease(input.lease);
    const work = await this.requireWork(input.work_id);
    validateOutcome(input, work);
    return this.store.recordOutcome(input, this.clock.now().toISOString());
  }

  private async requireWork(workId: string): Promise<QuestionWorkV1> {
    const work = await this.store.read(workId);
    if (work === undefined) {
      throw new QuestionWorkInputError("Question work does not exist.");
    }
    return work;
  }

  private validateLease(lease: WorkLeaseV1, runId?: string): void {
    validateLeaseShape(lease);
    if (runId !== undefined && lease.run_id !== runId) {
      throw new QuestionWorkStaleLeaseError("The work lease belongs to another run.");
    }
    if (Date.parse(lease.lease_expires_at) <= this.clock.now().getTime()) {
      throw new QuestionWorkStaleLeaseError("The work lease has expired.");
    }
  }
}

export function questionWorkIdentity(input: QuestionWorkAdmissionInput): string {
  return `question-work-${digest(JSON.stringify([
    input.tenant_id,
    input.installation_id,
    input.binding_id,
    input.thread_ref,
    input.idempotency_key,
  ])).slice(0, 32)}`;
}

function taskFor(work: QuestionWorkV1, availableAt: string): QuestionWorkTaskV1 {
  return {
    available_at: availableAt,
    idempotency_key: digest(JSON.stringify([work.work_id, work.revision])),
    request_run_id: work.request_run_id,
    schema_version: "question-work-task/v1",
    thread_ref: work.thread_ref,
    work_id: work.work_id,
    work_revision: work.revision,
  };
}

function validateAdmissionInput(input: QuestionWorkAdmissionInput): void {
  for (const [label, value] of Object.entries(input)) {
    if (typeof value !== "string" || value.trim() === "") {
      throw new QuestionWorkInputError(`${label} cannot be empty.`);
    }
    if (value.length > 2_048) {
      throw new QuestionWorkInputError(`${label} exceeds the portable reference limit.`);
    }
  }
  if (input.work_kind !== "question" && input.work_kind !== "attestation") {
    throw new QuestionWorkInputError("The question-work kind is unsupported.");
  }
}

function validatePreflight(
  preflight: QuestionWorkPreflightV1,
  requestDigest: string,
  allowWaiting: boolean,
): void {
  if (preflight.schema_version !== "question-work-preflight/v1") {
    throw new QuestionWorkInputError("The question-work preflight version is unsupported.");
  }
  if (preflight.request_digest !== requestDigest) {
    throw new QuestionWorkInputError("The preflight receipt does not match the question input.");
  }
  requireRef(preflight.receipt_ref, "preflight receipt_ref");
  requireRef(preflight.receipt_digest, "preflight receipt_digest");
  requireBoundedInteger(preflight.max_attempts, 1, QUESTION_WORK_LIMITS.max_attempts, "max_attempts");
  requireBoundedInteger(preflight.max_steps, 1, QUESTION_WORK_LIMITS.max_steps, "max_steps");
  requireBoundedInteger(
    preflight.max_result_bytes,
    1,
    QUESTION_WORK_LIMITS.max_result_bytes,
    "max_result_bytes",
  );
  validateBoundedDistinctRefs(preflight.required_capability_refs, "required capability");
  validateBoundedDistinctRefs(preflight.required_input_refs, "required input");
  if (preflight.state !== "ready" && preflight.state !== "waiting" && preflight.state !== "rejected") {
    throw new QuestionWorkInputError("The question-work preflight state is unsupported.");
  }
  if (preflight.state === "rejected") {
    throw new QuestionWorkInputError("Rejected preflight work cannot be acknowledged as admitted.");
  }
  if (!allowWaiting && preflight.state !== "ready") {
    throw new QuestionWorkInputError("The continuation preflight is not ready.");
  }
  if (preflight.state === "ready" && preflight.required_input_refs.length !== 0) {
    throw new QuestionWorkInputError("A ready preflight cannot retain missing inputs.");
  }
  if (preflight.state === "waiting" && preflight.required_input_refs.length === 0) {
    throw new QuestionWorkInputError("A waiting preflight must name a missing input reference.");
  }
}

function validateRequestRun(
  run: RunReceiptV1 | undefined,
  input: QuestionWorkAdmissionInput,
): asserts run is RunReceiptV1 {
  if (run === undefined) {
    throw new QuestionWorkInputError("A durable admitted run is required before question-work acknowledgement.");
  }
  if (
    run.run_id !== input.request_run_id ||
    run.binding_id !== input.binding_id ||
    run.subject_ref !== input.subject_ref ||
    run.tenant_id !== input.tenant_id ||
    run.input_digest !== input.request_digest
  ) {
    throw new QuestionWorkInputError("The admitted run does not match the question work.");
  }
  if (
    run.state !== "queued" &&
    run.state !== "leased" &&
    run.state !== "running" &&
    run.state !== "waiting" &&
    run.state !== "paused"
  ) {
    throw new QuestionWorkInputError("The admitted run cannot accept new question work.");
  }
}

function validateTask(task: QuestionWorkTaskV1): void {
  if (task.schema_version !== "question-work-task/v1") {
    throw new QuestionWorkInputError("The question-work task version is unsupported.");
  }
  for (const [value, label] of [
    [task.available_at, "available_at"],
    [task.idempotency_key, "idempotency_key"],
    [task.request_run_id, "request_run_id"],
    [task.thread_ref, "thread_ref"],
    [task.work_id, "work_id"],
  ] as const) {
    requireRef(value, label);
  }
  requireRevision(task.work_revision);
  if (!Number.isFinite(Date.parse(task.available_at))) {
    throw new QuestionWorkInputError("Task availability must be a timestamp.");
  }
}

function validateProgress(input: QuestionWorkProgressInput): void {
  requireRef(input.work_id, "work_id");
  requireRevision(input.expected_revision);
  requireBoundedInteger(input.sequence, 1, QUESTION_WORK_LIMITS.max_steps, "progress sequence");
  requireRef(input.progress_ref, "progress_ref");
  requireRef(input.progress_digest, "progress_digest");
  requireRef(input.resume_cursor, "resume_cursor");
  if (
    input.completed_step_ids.length > QUESTION_WORK_LIMITS.max_steps ||
    new Set(input.completed_step_ids).size !== input.completed_step_ids.length
  ) {
    throw new QuestionWorkInputError("Completed question-work steps must be bounded and distinct.");
  }
  input.completed_step_ids.forEach((step) => requireRef(step, "completed step"));
}

function validateRetry(input: QuestionWorkRetryInput, now: Date): void {
  requireRef(input.work_id, "work_id");
  requireRevision(input.expected_revision);
  requireRef(input.failure_receipt_ref, "failure_receipt_ref");
  requireRef(input.failure_receipt_digest, "failure_receipt_digest");
  requireRef(input.reason_code, "reason_code");
  if (!Number.isFinite(Date.parse(input.available_at)) || Date.parse(input.available_at) <= now.getTime()) {
    throw new QuestionWorkInputError("Retry availability must be a future timestamp.");
  }
}

function validateOutcome(input: QuestionWorkOutcomeInput, work: QuestionWorkV1): void {
  requireRef(input.work_id, "work_id");
  requireRevision(input.expected_revision);
  requireRef(input.reason_code, "reason_code");
  requireRef(input.receipt_ref, "receipt_ref");
  requireRef(input.receipt_digest, "receipt_digest");
  if (input.outcome !== "completed" && input.outcome !== "incomplete" && input.outcome !== "failed") {
    throw new QuestionWorkInputError("The question-work outcome is unsupported.");
  }
  const resultFields = [
    input.result_ref,
    input.result_digest,
    input.result_kind,
    input.result_bytes,
  ];
  const supplied = resultFields.filter((value) => value !== undefined).length;
  if (supplied !== 0 && supplied !== resultFields.length) {
    throw new QuestionWorkInputError("A persisted result requires its reference, digest, kind, and byte count.");
  }
  if (input.outcome === "completed" && supplied === 0) {
    throw new QuestionWorkInputError("Completed question work requires a persisted result receipt.");
  }
  if (supplied === resultFields.length) {
    requireRef(input.result_ref!, "result_ref");
    requireRef(input.result_digest!, "result_digest");
    requireBoundedInteger(input.result_bytes!, 1, QUESTION_WORK_LIMITS.max_result_bytes, "result_bytes");
    if (input.result_bytes! > work.max_result_bytes) {
      throw new QuestionWorkInputError("The question-work result exceeds its admitted bound.");
    }
    const expectedKind = work.work_kind === "question" ? "answer" : "attestation";
    if (input.result_kind !== expectedKind) {
      throw new QuestionWorkInputError("The persisted result kind does not match the admitted work.");
    }
  }
}

function validateLeaseShape(lease: WorkLeaseV1): void {
  if (lease.schema_version !== "work-lease/v1") {
    throw new QuestionWorkStaleLeaseError("The work lease version is unsupported.");
  }
  for (const value of [
    lease.heartbeat_at,
    lease.lease_expires_at,
    lease.lease_token,
    lease.owner_id,
    lease.run_id,
  ]) {
    requireRef(value, "lease field");
  }
  requireBoundedInteger(lease.generation, 1, Number.MAX_SAFE_INTEGER, "lease generation");
  requireBoundedInteger(lease.fencing_token, 1, Number.MAX_SAFE_INTEGER, "lease fence");
  if (!Number.isFinite(Date.parse(lease.heartbeat_at)) || !Number.isFinite(Date.parse(lease.lease_expires_at))) {
    throw new QuestionWorkStaleLeaseError("The work lease timestamps are invalid.");
  }
}

function validateBoundedDistinctRefs(refs: string[], label: string): void {
  if (refs.length > QUESTION_WORK_LIMITS.max_preflight_refs || new Set(refs).size !== refs.length) {
    throw new QuestionWorkInputError(`${label} references must be bounded and distinct.`);
  }
  refs.forEach((ref) => requireRef(ref, `${label} reference`));
}

function requireRef(value: string, label: string): void {
  if (value.trim() === "" || value.length > 2_048) {
    throw new QuestionWorkInputError(`${label} must be a bounded opaque reference.`);
  }
}

function requireRevision(value: number): void {
  requireBoundedInteger(value, 1, Number.MAX_SAFE_INTEGER, "revision");
}

function requireBoundedInteger(value: number, min: number, max: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new QuestionWorkInputError(`${label} is outside the supported bound.`);
  }
}

function admissionFingerprint(
  input: QuestionWorkAdmissionInput,
  preflight: QuestionWorkPreflightV1,
): string {
  return digest(JSON.stringify([
    input.binding_id,
    input.idempotency_key,
    input.installation_id,
    input.request_digest,
    input.request_ref,
    input.request_run_id,
    input.subject_ref,
    input.tenant_id,
    input.thread_ref,
    input.work_kind,
    preflight.max_attempts,
    preflight.max_result_bytes,
    preflight.max_steps,
    preflight.receipt_digest,
    preflight.receipt_ref,
    preflight.state,
    preflight.required_capability_refs,
    preflight.required_input_refs,
  ]));
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
