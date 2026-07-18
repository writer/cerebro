import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type { ScheduleMisfirePolicy } from "@writer/cerebro-sdk";
import {
  acquireScheduledOccurrence,
  createScheduledOccurrence,
  updateScheduledOccurrence,
} from "../operations/schedules.js";
import type {
  ScheduledLeaseClaim,
  ScheduledLeaseRequest,
} from "../operations/schedules.js";
import type {
  AnswerWatchAuthorityV1,
  AnswerWatchAuthorizationV1,
  AnswerWatchMaterialStateV1,
  AnswerWatchObservationV1,
  AnswerWatchObservationReceiptLookupV1,
  AnswerWatchObservationReceiptV1,
  AnswerWatchOccurrenceClaimV1,
  AnswerWatchOccurrenceV1,
  AnswerWatchStateV1,
  AnswerWatchTargetBindingV1,
  AnswerWatchTargetCandidateV1,
  AnswerWatchUpdateV1,
  AnswerWatchV1,
  ApplyAnswerWatchObservationResultV1,
  CreateAnswerWatchObservationInputV1,
  SlackAnswerWatchStatusV1,
  StartAnswerWatchInputV1,
  StartAnswerWatchResultV1,
  StopAnswerWatchRequestV1,
  StopAnswerWatchReceiptLookupV1,
  StopAnswerWatchReceiptV1,
  StopAnswerWatchResultV1,
} from "./contracts.js";
import { ANSWER_WATCH_LIMITS } from "./contracts.js";

const UNSAFE_TEXT_CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000d\u000e-\u001f\u007f]/;

const WATCH_STATES: readonly AnswerWatchStateV1[] = [
  "queued",
  "active",
  "degraded",
  "completed",
  "closed",
  "failed",
  "cancelled",
  "retired",
];
const OBSERVATION_STATUSES: readonly AnswerWatchObservationV1["status"][] = [
  "pending",
  "satisfied",
  "closed",
  "unavailable",
  "failed",
];
const MATERIAL_TERMINAL_STATES: readonly AnswerWatchMaterialStateV1["terminal_state"][] = [
  "open",
  "satisfied",
  "closed_without_satisfaction",
  "failed",
];

const WATCH_TRANSITIONS: Readonly<Record<AnswerWatchStateV1, readonly AnswerWatchStateV1[]>> = {
  active: ["degraded", "completed", "closed", "failed", "cancelled"],
  cancelled: ["retired"],
  closed: ["retired"],
  completed: ["retired"],
  degraded: ["active", "completed", "closed", "failed", "cancelled"],
  failed: ["retired"],
  queued: ["active", "degraded", "completed", "closed", "failed", "cancelled"],
  retired: [],
};

export class AnswerWatchInvariantError extends Error {}

export function bindAnswerWatchTarget(input: {
  answer_ref: string;
  candidates: readonly AnswerWatchTargetCandidateV1[];
  evidence_ref: string;
  resolved_at: string;
}): AnswerWatchTargetBindingV1 {
  requireRef(input.answer_ref, "answer_ref");
  requireRef(input.evidence_ref, "evidence_ref");
  const resolvedAt = normalizeTimestamp(input.resolved_at, "resolved_at");
  if (input.candidates.length !== 1) {
    throw new AnswerWatchInvariantError(
      "A delivered answer must resolve to exactly one watch target.",
    );
  }
  const target = input.candidates[0]!;
  if (target.authority !== "read") {
    throw new AnswerWatchInvariantError("Answer watches require read-only authority.");
  }
  requireRef(target.target_kind, "target_kind");
  requireRef(target.target_ref, "target_ref");
  requireRef(target.target_version, "target_version");
  const bindingDigest = stableDigest([
    input.answer_ref,
    input.evidence_ref,
    target.authority,
    target.target_kind,
    target.target_ref,
    target.target_version,
  ]);
  return {
    answer_ref: input.answer_ref,
    authority: "read",
    binding_digest: `sha256:${bindingDigest}`,
    binding_ref: `answer-watch-binding:${bindingDigest.slice(0, 32)}`,
    evidence_ref: input.evidence_ref,
    resolved_at: resolvedAt,
    schema_version: "answer-watch-target-binding/v1",
    target_kind: target.target_kind,
    target_ref: target.target_ref,
    target_version: target.target_version,
  };
}

export function authorizeAnswerWatch(
  actorRef: string,
  authority: AnswerWatchAuthorityV1,
  binding: AnswerWatchTargetBindingV1,
): AnswerWatchAuthorizationV1 {
  requireRef(actorRef, "actor_ref");
  validateAuthority(authority);
  validateBinding(binding);
  if (authority.answer_ref !== binding.answer_ref) {
    return deniedAuthorization("answer_binding_mismatch");
  }
  if (actorRef === authority.requester_ref) {
    return { allowed: true, role: "requester", schema_version: "answer-watch-authorization/v1" };
  }
  if (authority.operator_refs.includes(actorRef)) {
    return { allowed: true, role: "operator", schema_version: "answer-watch-authorization/v1" };
  }
  return deniedAuthorization("actor_not_authorized");
}

export function startAnswerWatch(input: StartAnswerWatchInputV1): StartAnswerWatchResultV1 {
  requireRef(input.conversation_ref, "conversation_ref");
  requireRequestKey(input.request_key);
  requireRef(input.schedule_ref, "schedule_ref");
  const createdAt = normalizeTimestamp(input.created_at, "created_at");
  const authorization = authorizeAnswerWatch(input.actor_ref, input.authority, input.binding);
  if (!authorization.allowed) {
    return {
      authorization,
      disposition: "denied",
      schema_version: "start-answer-watch-result/v1",
    };
  }

  const watchId = answerWatchIdentity(input.binding.answer_ref, input.request_key);
  if (input.prior_watch !== undefined) {
    validateWatch(input.prior_watch);
    if (
      input.prior_watch.watch_id !== watchId ||
      input.prior_watch.answer_ref !== input.binding.answer_ref ||
      input.prior_watch.request_key !== input.request_key ||
      input.prior_watch.binding_ref !== input.binding.binding_ref ||
      input.prior_watch.binding_digest !== input.binding.binding_digest ||
      input.prior_watch.target_ref !== input.binding.target_ref ||
      input.prior_watch.target_version !== input.binding.target_version ||
      input.prior_watch.conversation_ref !== input.conversation_ref ||
      input.prior_watch.schedule_ref !== input.schedule_ref
    ) {
      throw new AnswerWatchInvariantError(
        "Answer watch idempotency key has a different server-side binding.",
      );
    }
    return {
      authorization,
      created: false,
      disposition: "started",
      schema_version: "start-answer-watch-result/v1",
      watch: structuredClone(input.prior_watch),
    };
  }

  return {
    authorization,
    created: true,
    disposition: "started",
    schema_version: "start-answer-watch-result/v1",
    watch: {
      answer_ref: input.binding.answer_ref,
      authority: "read",
      binding_digest: input.binding.binding_digest,
      binding_ref: input.binding.binding_ref,
      conversation_ref: input.conversation_ref,
      created_at: createdAt,
      request_key: input.request_key,
      revision: 1,
      schedule_ref: input.schedule_ref,
      schema_version: "answer-watch/v1",
      state: "queued",
      state_sequence: 0,
      target_kind: input.binding.target_kind,
      target_ref: input.binding.target_ref,
      target_version: input.binding.target_version,
      updated_at: createdAt,
      watch_id: watchId,
    },
  };
}

export function answerWatchIdentity(answerRef: string, requestKey: string): string {
  requireRef(answerRef, "answer_ref");
  requireRequestKey(requestKey);
  return `answer-watch:${stableDigest([answerRef, requestKey]).slice(0, 32)}`;
}

export function answerWatchMaterialDigest(
  state: AnswerWatchMaterialStateV1,
): string {
  validateMaterialState(state);
  return `sha256:${stableDigest([
    String(state.checks.passed),
    String(state.checks.pending),
    String(state.checks.failed),
    String(state.draft),
    state.merge_state,
    state.head_ref,
    state.terminal_state,
  ])}`;
}

export function answerWatchObservationReceiptIdentity(
  watchId: string,
  observationId: string,
): string {
  requireRef(watchId, "watch_id");
  requireRef(observationId, "observation_id");
  return `answer-watch-observation-receipt:${stableDigest([watchId, observationId])}`;
}

/**
 * Constructs the only accepted observation identity. The digest binds a
 * retryable observation id to the exact occurrence and material payload.
 */
export function createAnswerWatchObservation(
  input: CreateAnswerWatchObservationInputV1,
): AnswerWatchObservationV1 {
  const observedAt = normalizeTimestamp(input.observed_at, "observed_at");
  const materialDigest = answerWatchMaterialDigest(input.material_state);
  const observation = {
    material_digest: materialDigest,
    material_state: structuredClone(input.material_state),
    observation_id: input.observation_id,
    observed_at: observedAt,
    occurrence_id: input.occurrence_id,
    reason_code: input.reason_code,
    schema_version: "answer-watch-observation/v1" as const,
    status: input.status,
    summary: input.summary,
    target_ref: input.target_ref,
    target_version: input.target_version,
    watch_id: input.watch_id,
  };
  const result: AnswerWatchObservationV1 = {
    ...observation,
    observation_digest: observationDigest(observation),
  };
  validateObservation(result);
  return result;
}

export function createAnswerWatchOccurrence(input: {
  created_at: string;
  due_at: string;
  generation: number;
  misfire_policy: ScheduleMisfirePolicy;
  schedule_revision: number;
  watch: AnswerWatchV1;
}): AnswerWatchOccurrenceV1 {
  validateWatch(input.watch);
  assertWatchNotTerminal(input.watch.state);
  return {
    occurrence: createScheduledOccurrence({
      due_at: input.due_at,
      generation: input.generation,
      misfire_policy: input.misfire_policy,
      schedule_id: input.watch.schedule_ref,
      schedule_revision: input.schedule_revision,
    }, input.created_at),
    schema_version: "answer-watch-occurrence/v1",
    watch_id: input.watch.watch_id,
  };
}

export function beginAnswerWatchOccurrence(
  current: AnswerWatchOccurrenceV1,
  request: ScheduledLeaseRequest,
): AnswerWatchOccurrenceClaimV1 {
  validateOccurrence(current);
  const claim: ScheduledLeaseClaim = {
    fencing_token: request.fencing_token,
    generation: request.generation,
    lease_token: request.lease_token,
    owner_id: request.owner_id,
  };
  if (current.occurrence.state === "running") {
    const resumed = updateScheduledOccurrence(current.occurrence, claim, "running", request.now);
    if (resumed !== undefined) {
      return {
        acquired: true,
        claim,
        created: false,
        occurrence: { ...current, occurrence: resumed },
      };
    }
  }
  const acquired = acquireScheduledOccurrence(current.occurrence, request);
  if (!acquired.acquired) return acquired;
  const running = updateScheduledOccurrence(acquired.occurrence, claim, "running", request.now);
  if (running === undefined) {
    throw new AnswerWatchInvariantError("Acquired watch occurrence lost its active lease.");
  }
  return {
    acquired: true,
    claim,
    created: true,
    occurrence: { ...current, occurrence: running },
  };
}

export function applyAnswerWatchObservation(input: {
  claim: ScheduledLeaseClaim;
  occurrence: AnswerWatchOccurrenceV1;
  observation: AnswerWatchObservationV1;
  receipt_lookup: AnswerWatchObservationReceiptLookupV1;
  watch: AnswerWatchV1;
}): ApplyAnswerWatchObservationResultV1 {
  validateWatch(input.watch);
  validateOccurrence(input.occurrence);
  validateObservation(input.observation);
  validateObservationReceiptLookup(input.receipt_lookup);
  if (
    input.occurrence.watch_id !== input.watch.watch_id ||
    input.observation.watch_id !== input.watch.watch_id ||
    input.observation.occurrence_id !== input.occurrence.occurrence.occurrence_id ||
    input.observation.target_ref !== input.watch.target_ref
  ) {
    throw new AnswerWatchInvariantError("Observation, occurrence, and watch identities must match.");
  }

  const receiptId = answerWatchObservationReceiptIdentity(
    input.watch.watch_id,
    input.observation.observation_id,
  );
  if (input.receipt_lookup.found) {
    const receipt = input.receipt_lookup.receipt;
    if (
      receipt.receipt_id !== receiptId ||
      receipt.watch_id !== input.watch.watch_id ||
      receipt.observation_id !== input.observation.observation_id ||
      receipt.observation_digest !== input.observation.observation_digest
    ) {
      throw new AnswerWatchInvariantError(
        "Observation receipt lookup returned different content.",
      );
    }
    validateObservationReceiptAgainstObservation(receipt, input.observation);
    return {
      occurrence: structuredClone(receipt.occurrence),
      receipt: structuredClone(receipt),
      replayed: true,
      schema_version: "apply-answer-watch-observation-result/v1",
      update: structuredClone(receipt.update),
      watch: structuredClone(input.watch),
    };
  }
  if (input.receipt_lookup.receipt_id !== receiptId) {
    throw new AnswerWatchInvariantError("Observation receipt lookup identity does not match.");
  }
  if (input.watch.last_observation_id === input.observation.observation_id) {
    throw new AnswerWatchInvariantError(
      "Durable observation receipt lookup missed an already recorded observation.",
    );
  }

  assertWatchNotTerminal(input.watch.state);
  const observedAt = requireMonotonicTimestamp(
    requireMonotonicTimestamp(
      input.observation.observed_at,
      input.watch.updated_at,
      "observed_at",
    ),
    input.occurrence.occurrence.updated_at,
    "observed_at",
  );
  const nextState = observationState(input.observation.status);
  requireWatchTransitionIfChanged(input.watch.state, nextState);
  const stateChanged = input.watch.state !== nextState;
  const materialChange = input.watch.last_material_digest !== input.observation.material_digest;
  const terminal = isTerminal(nextState);
  const publish = stateChanged || materialChange || terminal;
  const stateSequence = input.watch.state_sequence + (stateChanged ? 1 : 0);
  const sequence = input.watch.revision + 1;
  const update: AnswerWatchUpdateV1 = {
    event_id: `${input.watch.watch_id}:update:${input.watch.revision + 1}`,
    from_state: input.watch.state,
    idempotency_key: `${input.watch.watch_id}:observation:${input.observation.observation_id}`,
    material_change: materialChange,
    observation_ref: input.observation.observation_id,
    occurred_at: observedAt,
    publish,
    reason_code: input.observation.reason_code,
    schema_version: "answer-watch-update/v1",
    sequence,
    summary: input.observation.summary,
    terminal,
    to_state: nextState,
    watch_id: input.watch.watch_id,
  };
  const finished = updateScheduledOccurrence(
    input.occurrence.occurrence,
    input.claim,
    input.observation.status === "failed" ? "failed" : "completed",
    observedAt,
  );
  if (finished === undefined) {
    throw new AnswerWatchInvariantError(
      "A watch observation requires the active generation and fencing claim.",
    );
  }
  const occurrence: AnswerWatchOccurrenceV1 = {
    ...input.occurrence,
    observation_ref: input.observation.observation_id,
    occurrence: finished,
  };
  const watch: AnswerWatchV1 = {
    ...input.watch,
    last_material_digest: input.observation.material_digest,
    last_observation_digest: input.observation.observation_digest,
    last_observation_id: input.observation.observation_id,
    last_target_version: input.observation.target_version,
    last_update: update,
    revision: input.watch.revision + 1,
    state: nextState,
    state_sequence: stateSequence,
    updated_at: observedAt,
  };
  const receipt: AnswerWatchObservationReceiptV1 = {
    observation_digest: input.observation.observation_digest,
    observation_id: input.observation.observation_id,
    occurrence: structuredClone(occurrence),
    receipt_id: receiptId,
    schema_version: "answer-watch-observation-receipt/v1",
    update: structuredClone(update),
    watch_id: input.watch.watch_id,
  };
  validateObservationReceiptAgainstObservation(receipt, input.observation);
  return {
    occurrence,
    receipt,
    replayed: false,
    schema_version: "apply-answer-watch-observation-result/v1",
    update,
    watch,
  };
}

export function stopAnswerWatch(
  current: AnswerWatchV1,
  request: StopAnswerWatchRequestV1,
  receiptLookup: StopAnswerWatchReceiptLookupV1,
): StopAnswerWatchResultV1 {
  validateWatch(current);
  validateStopRequest(request);
  validateStopReceiptLookup(receiptLookup);
  if (request.watch_id !== current.watch_id) {
    throw new AnswerWatchInvariantError("Stop request must belong to the watch.");
  }
  const receiptId = answerWatchStopReceiptIdentity(current.watch_id, request.request_key);
  const requestDigest = stopRequestDigest(request);
  if (receiptLookup.found) {
    const receipt = receiptLookup.receipt;
    if (receipt.receipt_id !== receiptId || receipt.request_digest !== requestDigest) {
      throw new AnswerWatchInvariantError(
        "Stop receipt lookup returned different content for the request key.",
      );
    }
    validateStopReceiptAgainstRequest(receipt, request);
    return {
      receipt: structuredClone(receipt),
      replayed: true,
      schema_version: "stop-answer-watch-result/v1",
      update: structuredClone(receipt.update),
      watch: structuredClone(current),
    };
  }
  if (receiptLookup.receipt_id !== receiptId) {
    throw new AnswerWatchInvariantError("Stop receipt lookup identity does not match.");
  }
  if (current.last_update?.idempotency_key === receiptId) {
    throw new AnswerWatchInvariantError(
      "Durable stop receipt lookup missed an already recorded transition.",
    );
  }
  if (current.state === request.to_state) {
    throw new AnswerWatchInvariantError(
      `Watch is already ${request.to_state}; use the original stop request key to replay.`,
    );
  }
  requireWatchTransitionIfChanged(current.state, request.to_state);
  const normalizedOccurredAt = requireMonotonicTimestamp(
    request.occurred_at,
    current.updated_at,
    "occurred_at",
  );
  const stateSequence = current.state_sequence + 1;
  const sequence = current.revision + 1;
  const update: AnswerWatchUpdateV1 = {
    event_id: `${current.watch_id}:update:${current.revision + 1}`,
    from_state: current.state,
    idempotency_key: receiptId,
    material_change: true,
    observation_ref: `watch://${current.watch_id}/transition/${sequence}`,
    occurred_at: normalizedOccurredAt,
    publish: true,
    reason_code: request.reason_code,
    schema_version: "answer-watch-update/v1",
    sequence,
    summary: request.to_state === "cancelled" ? "Watch cancelled." : "Watch retired.",
    terminal: true,
    to_state: request.to_state,
    watch_id: current.watch_id,
  };
  const receipt: StopAnswerWatchReceiptV1 = {
    receipt_id: receiptId,
    request_digest: requestDigest,
    schema_version: "stop-answer-watch-receipt/v1",
    update: structuredClone(update),
    watch_id: current.watch_id,
  };
  validateStopReceiptAgainstRequest(receipt, request);
  return {
    receipt,
    replayed: false,
    schema_version: "stop-answer-watch-result/v1",
    update,
    watch: {
      ...current,
      last_update: update,
      revision: current.revision + 1,
      state: request.to_state,
      state_sequence: stateSequence,
      updated_at: normalizedOccurredAt,
    },
  };
}

function validateStopRequest(request: StopAnswerWatchRequestV1): void {
  if (request.schema_version !== "stop-answer-watch-request/v1") {
    throw new AnswerWatchInvariantError("Unsupported answer watch stop request version.");
  }
  requireCanonicalTimestamp(request.occurred_at, "occurred_at");
  requireRef(request.reason_code, "reason_code");
  requireRequestKey(request.request_key);
  requireRef(request.watch_id, "watch_id");
  requireEnum(request.to_state, ["cancelled", "retired"], "to_state");
}

export function answerWatchStopReceiptIdentity(watchId: string, requestKey: string): string {
  requireRef(watchId, "watch_id");
  requireRequestKey(requestKey);
  return `answer-watch-stop:${stableDigest([watchId, requestKey])}`;
}

function stopRequestDigest(request: StopAnswerWatchRequestV1): string {
  return `sha256:${stableDigest([
    request.watch_id,
    request.request_key,
    request.to_state,
    request.occurred_at,
    request.reason_code,
  ])}`;
}

function validateObservationReceiptLookup(
  lookup: AnswerWatchObservationReceiptLookupV1,
): void {
  if (lookup.schema_version !== "answer-watch-observation-receipt-lookup/v1") {
    throw new AnswerWatchInvariantError(
      "Unsupported answer watch observation receipt lookup version.",
    );
  }
  if (typeof lookup.found !== "boolean") {
    throw new AnswerWatchInvariantError("Observation receipt lookup found must be boolean.");
  }
  if (lookup.found) validateObservationReceipt(lookup.receipt);
  else requireRef(lookup.receipt_id, "receipt_id");
}

function validateObservationReceipt(receipt: AnswerWatchObservationReceiptV1): void {
  if (receipt.schema_version !== "answer-watch-observation-receipt/v1") {
    throw new AnswerWatchInvariantError(
      "Unsupported answer watch observation receipt version.",
    );
  }
  for (const [label, value] of Object.entries({
    observation_digest: receipt.observation_digest,
    observation_id: receipt.observation_id,
    receipt_id: receipt.receipt_id,
    watch_id: receipt.watch_id,
  })) requireRef(value, label);
  validateOccurrence(receipt.occurrence);
  validateUpdate(receipt.update);
  if (
    receipt.receipt_id !== answerWatchObservationReceiptIdentity(
      receipt.watch_id,
      receipt.observation_id,
    ) ||
    receipt.occurrence.watch_id !== receipt.watch_id ||
    receipt.occurrence.observation_ref !== receipt.observation_id ||
    receipt.update.watch_id !== receipt.watch_id ||
    receipt.update.observation_ref !== receipt.observation_id ||
    receipt.update.idempotency_key !==
      `${receipt.watch_id}:observation:${receipt.observation_id}` ||
    receipt.update.occurred_at !== receipt.occurrence.occurrence.updated_at
  ) {
    throw new AnswerWatchInvariantError(
      "Observation receipt fields do not describe one recorded update.",
    );
  }
}

function validateObservationReceiptAgainstObservation(
  receipt: AnswerWatchObservationReceiptV1,
  observation: AnswerWatchObservationV1,
): void {
  validateObservationReceipt(receipt);
  const expectedState = observationState(observation.status);
  const expectedOccurrenceState = observation.status === "failed" ? "failed" : "completed";
  if (
    receipt.observation_digest !== observation.observation_digest ||
    receipt.observation_id !== observation.observation_id ||
    receipt.watch_id !== observation.watch_id ||
    receipt.occurrence.occurrence.occurrence_id !== observation.occurrence_id ||
    receipt.occurrence.occurrence.state !== expectedOccurrenceState ||
    receipt.update.occurred_at !== observation.observed_at ||
    receipt.update.reason_code !== observation.reason_code ||
    receipt.update.summary !== observation.summary ||
    receipt.update.terminal !== isTerminal(expectedState) ||
    receipt.update.to_state !== expectedState
  ) {
    throw new AnswerWatchInvariantError(
      "Observation receipt does not match the canonical observation.",
    );
  }
}

function validateStopReceiptLookup(lookup: StopAnswerWatchReceiptLookupV1): void {
  if (lookup.schema_version !== "stop-answer-watch-receipt-lookup/v1") {
    throw new AnswerWatchInvariantError("Unsupported answer watch stop receipt lookup version.");
  }
  if (typeof lookup.found !== "boolean") {
    throw new AnswerWatchInvariantError("Stop receipt lookup found must be boolean.");
  }
  if (lookup.found) validateStopReceipt(lookup.receipt);
  else requireRef(lookup.receipt_id, "receipt_id");
}

function validateStopReceipt(receipt: StopAnswerWatchReceiptV1): void {
  if (receipt.schema_version !== "stop-answer-watch-receipt/v1") {
    throw new AnswerWatchInvariantError("Unsupported answer watch stop receipt version.");
  }
  for (const [label, value] of Object.entries({
    receipt_id: receipt.receipt_id,
    request_digest: receipt.request_digest,
    watch_id: receipt.watch_id,
  })) requireRef(value, label);
  validateUpdate(receipt.update);
  if (
    receipt.update.idempotency_key !== receipt.receipt_id ||
    receipt.update.watch_id !== receipt.watch_id
  ) {
    throw new AnswerWatchInvariantError(
      "Stop receipt fields do not describe one recorded update.",
    );
  }
}

function validateStopReceiptAgainstRequest(
  receipt: StopAnswerWatchReceiptV1,
  request: StopAnswerWatchRequestV1,
): void {
  validateStopReceipt(receipt);
  if (
    receipt.receipt_id !== answerWatchStopReceiptIdentity(
      request.watch_id,
      request.request_key,
    ) ||
    receipt.request_digest !== stopRequestDigest(request) ||
    receipt.watch_id !== request.watch_id ||
    receipt.update.occurred_at !== request.occurred_at ||
    receipt.update.reason_code !== request.reason_code ||
    receipt.update.to_state !== request.to_state ||
    receipt.update.terminal !== true
  ) {
    throw new AnswerWatchInvariantError(
      "Stop receipt does not match the canonical stop request.",
    );
  }
}

export function projectSlackAnswerWatchStatus(watch: AnswerWatchV1): SlackAnswerWatchStatusV1 {
  validateWatch(watch);
  const summary = watch.last_update?.summary;
  const projection = (() => {
    switch (watch.state) {
      case "queued": return { state: "queued" as const, terminal: false, text: "Watch queued. Updates will appear in this thread." };
      case "active": return { state: "watching" as const, terminal: false, text: summary ?? "Watch active. Waiting for a material change." };
      case "degraded": return { state: "degraded" as const, terminal: false, text: summary ?? "Watch degraded. The next scheduled check will retry." };
      case "completed": return { state: "completed" as const, terminal: true, text: summary ?? "Watch completed." };
      case "closed": return { state: "closed" as const, terminal: true, text: summary ?? "Watch target closed before the condition was satisfied." };
      case "failed": return { state: "failed" as const, terminal: true, text: summary ?? "Watch failed." };
      case "cancelled":
      case "retired": return { state: "stopped" as const, terminal: true, text: summary ?? "Watch stopped." };
    }
  })();
  return {
    schema_version: "slack-answer-watch-status/v1",
    should_publish: watch.state === "queued" || watch.last_update?.publish === true,
    ...projection,
    watch_id: watch.watch_id,
  };
}

function observationState(status: AnswerWatchObservationV1["status"]): AnswerWatchStateV1 {
  switch (status) {
    case "pending": return "active";
    case "satisfied": return "completed";
    case "closed": return "closed";
    case "unavailable": return "degraded";
    case "failed": return "failed";
  }
}

function isTerminal(state: AnswerWatchStateV1): boolean {
  return state === "completed" || state === "closed" || state === "failed" ||
    state === "cancelled" || state === "retired";
}

function assertWatchNotTerminal(state: AnswerWatchStateV1): void {
  if (isTerminal(state)) throw new AnswerWatchInvariantError(`Watch state ${state} is terminal.`);
}

function validateBinding(binding: AnswerWatchTargetBindingV1): void {
  if (binding.schema_version !== "answer-watch-target-binding/v1") {
    throw new AnswerWatchInvariantError("Unsupported answer watch target binding version.");
  }
  if (binding.authority !== "read") {
    throw new AnswerWatchInvariantError("Answer watches require read-only authority.");
  }
  for (const [label, value] of Object.entries({
    answer_ref: binding.answer_ref,
    binding_digest: binding.binding_digest,
    binding_ref: binding.binding_ref,
    evidence_ref: binding.evidence_ref,
    target_kind: binding.target_kind,
    target_ref: binding.target_ref,
    target_version: binding.target_version,
  })) requireRef(value, label);
  requireCanonicalTimestamp(binding.resolved_at, "resolved_at");
  const expectedDigest = stableDigest([
    binding.answer_ref,
    binding.evidence_ref,
    binding.authority,
    binding.target_kind,
    binding.target_ref,
    binding.target_version,
  ]);
  if (
    binding.binding_digest !== `sha256:${expectedDigest}` ||
    binding.binding_ref !== `answer-watch-binding:${expectedDigest.slice(0, 32)}`
  ) {
    throw new AnswerWatchInvariantError(
      "Answer watch binding identity does not match its server-side evidence.",
    );
  }
}

function validateAuthority(authority: AnswerWatchAuthorityV1): void {
  if (authority.schema_version !== "answer-watch-authority/v1") {
    throw new AnswerWatchInvariantError("Unsupported answer watch authority version.");
  }
  requireRef(authority.answer_ref, "answer_ref");
  requireRef(authority.requester_ref, "requester_ref");
  uniqueRefs(authority.operator_refs, "operator_refs");
}

function validateWatch(watch: AnswerWatchV1): void {
  if (watch.schema_version !== "answer-watch/v1") {
    throw new AnswerWatchInvariantError("Unsupported answer watch version.");
  }
  for (const [label, value] of Object.entries({
    answer_ref: watch.answer_ref,
    binding_digest: watch.binding_digest,
    binding_ref: watch.binding_ref,
    conversation_ref: watch.conversation_ref,
    schedule_ref: watch.schedule_ref,
    target_kind: watch.target_kind,
    target_ref: watch.target_ref,
    target_version: watch.target_version,
    watch_id: watch.watch_id,
  })) requireRef(value, label);
  requireRequestKey(watch.request_key);
  if (watch.authority !== "read") {
    throw new AnswerWatchInvariantError("Answer watches require read-only authority.");
  }
  requireEnum(watch.state, WATCH_STATES, "state");
  requirePositiveInteger(watch.revision, "revision");
  requireNonNegativeInteger(watch.state_sequence, "state_sequence");
  if (watch.state_sequence > watch.revision - 1) {
    throw new AnswerWatchInvariantError("Watch state sequence cannot exceed its update count.");
  }
  const createdAt = requireCanonicalTimestamp(watch.created_at, "created_at");
  const updatedAt = requireCanonicalTimestamp(watch.updated_at, "updated_at");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw new AnswerWatchInvariantError("Watch time cannot move backward.");
  }
  if ((watch.last_observation_id === undefined) !== (watch.last_observation_digest === undefined)) {
    throw new AnswerWatchInvariantError("Watch observation id and digest must be recorded together.");
  }
  for (const [label, value] of Object.entries({
    last_material_digest: watch.last_material_digest,
    last_observation_digest: watch.last_observation_digest,
    last_observation_id: watch.last_observation_id,
    last_target_version: watch.last_target_version,
  })) {
    if (value !== undefined) requireRef(value, label);
  }
  if (watch.last_update !== undefined) {
    validateUpdate(watch.last_update);
    if (
      watch.last_update.watch_id !== watch.watch_id ||
      watch.last_update.sequence !== watch.revision ||
      watch.last_update.event_id !== `${watch.watch_id}:update:${watch.revision}` ||
      watch.last_update.to_state !== watch.state ||
      watch.last_update.occurred_at !== watch.updated_at
    ) {
      throw new AnswerWatchInvariantError(
        "Watch revision, state, identity, and time must match its last update.",
      );
    }
  }
  if ((watch.revision === 1) !== (watch.last_update === undefined)) {
    throw new AnswerWatchInvariantError(
      "Initial watches have no update; later revisions require the last update.",
    );
  }
  if (
    watch.revision === 1 &&
    (
      watch.state !== "queued" ||
      watch.state_sequence !== 0 ||
      watch.last_material_digest !== undefined ||
      watch.last_observation_digest !== undefined ||
      watch.last_observation_id !== undefined ||
      watch.last_target_version !== undefined
    )
  ) {
    throw new AnswerWatchInvariantError(
      "Initial watch state must be queued without observation state.",
    );
  }
}

function validateOccurrence(occurrence: AnswerWatchOccurrenceV1): void {
  if (occurrence.schema_version !== "answer-watch-occurrence/v1") {
    throw new AnswerWatchInvariantError("Unsupported answer watch occurrence version.");
  }
  requireRef(occurrence.watch_id, "watch_id");
  if (occurrence.occurrence.schema_version !== "scheduled-occurrence/v1") {
    throw new AnswerWatchInvariantError("Watch occurrence must use the canonical scheduled occurrence.");
  }
  for (const [label, value] of Object.entries({
    idempotency_key: occurrence.occurrence.idempotency_key,
    lease_token: occurrence.occurrence.lease_token,
    occurrence_id: occurrence.occurrence.occurrence_id,
    owner_id: occurrence.occurrence.owner_id,
    run_id: occurrence.occurrence.run_id,
    schedule_id: occurrence.occurrence.schedule_id,
  })) {
    if (value !== undefined) requireRef(value, label);
  }
  if (occurrence.observation_ref !== undefined) {
    requireRef(occurrence.observation_ref, "observation_ref");
  }
  requirePositiveInteger(occurrence.occurrence.generation, "generation");
  requirePositiveInteger(occurrence.occurrence.schedule_revision, "schedule_revision");
  requireCanonicalTimestamp(occurrence.occurrence.created_at, "created_at");
  requireCanonicalTimestamp(occurrence.occurrence.due_at, "due_at");
  if (occurrence.occurrence.heartbeat_at !== undefined) {
    requireCanonicalTimestamp(occurrence.occurrence.heartbeat_at, "heartbeat_at");
  }
  if (occurrence.occurrence.lease_expires_at !== undefined) {
    requireCanonicalTimestamp(occurrence.occurrence.lease_expires_at, "lease_expires_at");
  }
  requireCanonicalTimestamp(occurrence.occurrence.updated_at, "updated_at");
}

function validateObservation(observation: AnswerWatchObservationV1): void {
  if (observation.schema_version !== "answer-watch-observation/v1") {
    throw new AnswerWatchInvariantError("Unsupported answer watch observation version.");
  }
  for (const [label, value] of Object.entries({
    material_digest: observation.material_digest,
    observation_digest: observation.observation_digest,
    observation_id: observation.observation_id,
    occurrence_id: observation.occurrence_id,
    reason_code: observation.reason_code,
    target_ref: observation.target_ref,
    target_version: observation.target_version,
    watch_id: observation.watch_id,
  })) requireRef(value, label);
  requireEnum(observation.status, OBSERVATION_STATUSES, "status");
  requireSummary(observation.summary);
  requireCanonicalTimestamp(observation.observed_at, "observed_at");
  const canonicalDigest = answerWatchMaterialDigest(observation.material_state);
  if (observation.material_digest !== canonicalDigest) {
    throw new AnswerWatchInvariantError(
      "Observation material digest does not match its structured state.",
    );
  }
  if (observation.observation_digest !== observationDigest(observation)) {
    throw new AnswerWatchInvariantError(
      "Observation digest does not match its canonical payload.",
    );
  }
  const expectedTerminalState = (() => {
    switch (observation.status) {
      case "pending":
      case "unavailable": return "open";
      case "satisfied": return "satisfied";
      case "closed": return "closed_without_satisfaction";
      case "failed": return "failed";
    }
  })();
  if (observation.material_state.terminal_state !== expectedTerminalState) {
    throw new AnswerWatchInvariantError(
      "Observation status and terminal material state must match.",
    );
  }
}

function validateUpdate(update: AnswerWatchUpdateV1): void {
  if (update.schema_version !== "answer-watch-update/v1") {
    throw new AnswerWatchInvariantError("Unsupported answer watch update version.");
  }
  for (const [label, value] of Object.entries({
    event_id: update.event_id,
    idempotency_key: update.idempotency_key,
    observation_ref: update.observation_ref,
    reason_code: update.reason_code,
    watch_id: update.watch_id,
  })) requireRef(value, label);
  requireEnum(update.from_state, WATCH_STATES, "from_state");
  requireEnum(update.to_state, WATCH_STATES, "to_state");
  requireBoolean(update.material_change, "material_change");
  requireBoolean(update.publish, "publish");
  requireBoolean(update.terminal, "terminal");
  requirePositiveInteger(update.sequence, "sequence");
  requireSummary(update.summary);
  requireCanonicalTimestamp(update.occurred_at, "occurred_at");
  requireWatchTransitionIfChanged(update.from_state, update.to_state);
  if (update.terminal !== isTerminal(update.to_state)) {
    throw new AnswerWatchInvariantError(
      "Update terminal flag must match its destination state.",
    );
  }
}

function validateMaterialState(state: AnswerWatchMaterialStateV1): void {
  if (state.schema_version !== "answer-watch-material-state/v1") {
    throw new AnswerWatchInvariantError("Unsupported answer watch material state version.");
  }
  requireNonNegativeInteger(state.checks.passed, "checks.passed");
  requireNonNegativeInteger(state.checks.pending, "checks.pending");
  requireNonNegativeInteger(state.checks.failed, "checks.failed");
  requireBoolean(state.draft, "draft");
  requireRef(state.head_ref, "head_ref");
  requireRef(state.merge_state, "merge_state");
  requireEnum(state.terminal_state, MATERIAL_TERMINAL_STATES, "terminal_state");
}

function requireWatchTransitionIfChanged(from: AnswerWatchStateV1, to: AnswerWatchStateV1): void {
  if (from === to) return;
  if (!WATCH_TRANSITIONS[from].includes(to)) {
    throw new AnswerWatchInvariantError(`Invalid answer watch transition: ${from} -> ${to}`);
  }
}

function deniedAuthorization(
  reasonCode: Extract<AnswerWatchAuthorizationV1, { allowed: false }>["reason_code"],
): Extract<AnswerWatchAuthorizationV1, { allowed: false }> {
  return { allowed: false, reason_code: reasonCode, schema_version: "answer-watch-authorization/v1" };
}

function stableDigest(parts: readonly string[]): string {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(String(part.length)).update(":").update(part);
  return hash.digest("hex");
}

function observationDigest(observation: Pick<
  AnswerWatchObservationV1,
  | "material_digest"
  | "observation_id"
  | "observed_at"
  | "occurrence_id"
  | "reason_code"
  | "status"
  | "summary"
  | "target_ref"
  | "target_version"
  | "watch_id"
>): string {
  return `sha256:${stableDigest([
    observation.observation_id,
    observation.watch_id,
    observation.occurrence_id,
    observation.target_ref,
    observation.target_version,
    observation.observed_at,
    observation.status,
    observation.reason_code,
    observation.summary,
    observation.material_digest,
  ])}`;
}

function uniqueRefs(values: readonly string[], label: string): void {
  if (values.length > ANSWER_WATCH_LIMITS.operator_refs) {
    throw new AnswerWatchInvariantError(
      `${label} must contain at most ${ANSWER_WATCH_LIMITS.operator_refs} references.`,
    );
  }
  const unique = new Set<string>();
  for (const value of values) {
    requireRef(value, label);
    if (unique.has(value)) throw new AnswerWatchInvariantError(`${label} must be unique.`);
    unique.add(value);
  }
}

function requireMonotonicTimestamp(value: string, previous: string, label: string): string {
  const normalized = requireCanonicalTimestamp(value, label);
  if (Date.parse(normalized) < Date.parse(previous)) {
    throw new AnswerWatchInvariantError(`${label} cannot move backward.`);
  }
  return normalized;
}

function normalizeTimestamp(value: string, label: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new AnswerWatchInvariantError(`${label} must be an ISO timestamp.`);
  return new Date(timestamp).toISOString();
}

function requireCanonicalTimestamp(value: string, label: string): string {
  const normalized = normalizeTimestamp(value, label);
  if (value !== normalized) {
    throw new AnswerWatchInvariantError(
      `${label} must be a canonical UTC timestamp with millisecond precision.`,
    );
  }
  return normalized;
}

function requirePositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new AnswerWatchInvariantError(`${label} must be a positive integer.`);
  }
}

function requireNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new AnswerWatchInvariantError(`${label} must be a non-negative integer.`);
  }
}

function requireBoolean(value: boolean, label: string): void {
  if (typeof value !== "boolean") {
    throw new AnswerWatchInvariantError(`${label} must be boolean.`);
  }
}

function requireEnum<T extends string>(
  value: T,
  allowed: readonly T[],
  label: string,
): void {
  if (!allowed.includes(value)) {
    throw new AnswerWatchInvariantError(`${label} has an unsupported value.`);
  }
}

function requireRef(value: string, label: string): void {
  requireBoundedText(value, label, ANSWER_WATCH_LIMITS.ref_utf8_bytes);
  if (/\s/.test(value)) {
    throw new AnswerWatchInvariantError(`${label} must be an opaque reference without whitespace.`);
  }
}

function requireRequestKey(value: string): void {
  requireBoundedText(value, "request_key", ANSWER_WATCH_LIMITS.request_key_utf8_bytes);
  if (/\s/.test(value)) {
    throw new AnswerWatchInvariantError(
      "request_key must be an opaque key without whitespace.",
    );
  }
}

function requireSummary(value: string): void {
  requireBoundedText(value, "summary", ANSWER_WATCH_LIMITS.summary_utf8_bytes);
}

function requireBoundedText(value: string, label: string, maxUtf8Bytes: number): void {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new AnswerWatchInvariantError(`${label} must not be empty.`);
  }
  if (UNSAFE_TEXT_CONTROL_CHARACTERS.test(value)) {
    throw new AnswerWatchInvariantError(`${label} contains an unsafe control character.`);
  }
  if (Buffer.byteLength(value, "utf8") > maxUtf8Bytes) {
    throw new AnswerWatchInvariantError(
      `${label} must be at most ${maxUtf8Bytes} UTF-8 bytes.`,
    );
  }
}
