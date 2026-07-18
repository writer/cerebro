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
  AnswerWatchOccurrenceClaimV1,
  AnswerWatchOccurrenceV1,
  AnswerWatchStateV1,
  AnswerWatchTargetBindingV1,
  AnswerWatchTargetCandidateV1,
  AnswerWatchUpdateV1,
  AnswerWatchV1,
  ApplyAnswerWatchObservationResultV1,
  SlackAnswerWatchStatusV1,
  StartAnswerWatchInputV1,
  StartAnswerWatchResultV1,
} from "./contracts.js";

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
  const resolvedAt = requireTimestamp(input.resolved_at, "resolved_at");
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
  requireText(input.request_key, "request_key");
  requireRef(input.schedule_ref, "schedule_ref");
  const createdAt = requireTimestamp(input.created_at, "created_at");
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
  requireText(requestKey, "request_key");
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
  watch: AnswerWatchV1;
}): ApplyAnswerWatchObservationResultV1 {
  validateWatch(input.watch);
  validateOccurrence(input.occurrence);
  validateObservation(input.observation);
  if (
    input.occurrence.watch_id !== input.watch.watch_id ||
    input.observation.watch_id !== input.watch.watch_id ||
    input.observation.occurrence_id !== input.occurrence.occurrence.occurrence_id ||
    input.observation.target_ref !== input.watch.target_ref
  ) {
    throw new AnswerWatchInvariantError("Observation, occurrence, and watch identities must match.");
  }

  if (input.watch.last_observation_id === input.observation.observation_id) {
    if (
      input.watch.last_observation_digest !== input.observation.observation_digest ||
      input.watch.last_update === undefined
    ) {
      throw new AnswerWatchInvariantError("Observation idempotency key has different content.");
    }
    return {
      occurrence: structuredClone(input.occurrence),
      replayed: true,
      schema_version: "apply-answer-watch-observation-result/v1",
      update: structuredClone(input.watch.last_update),
      watch: structuredClone(input.watch),
    };
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
  return {
    occurrence,
    replayed: false,
    schema_version: "apply-answer-watch-observation-result/v1",
    update,
    watch,
  };
}

export function stopAnswerWatch(
  current: AnswerWatchV1,
  toState: "cancelled" | "retired",
  occurredAt: string,
  reasonCode: string,
): { update: AnswerWatchUpdateV1; watch: AnswerWatchV1 } {
  validateWatch(current);
  requireText(reasonCode, "reason_code");
  requireWatchTransitionIfChanged(current.state, toState);
  const normalizedOccurredAt = requireMonotonicTimestamp(occurredAt, current.updated_at, "occurred_at");
  const stateSequence = current.state_sequence + 1;
  const sequence = current.revision + 1;
  const update: AnswerWatchUpdateV1 = {
    event_id: `${current.watch_id}:update:${current.revision + 1}`,
    from_state: current.state,
    idempotency_key: `${current.watch_id}:transition:${stateSequence}:${toState}`,
    material_change: true,
    observation_ref: `watch://${current.watch_id}/transition/${sequence}`,
    occurred_at: normalizedOccurredAt,
    publish: true,
    reason_code: reasonCode,
    schema_version: "answer-watch-update/v1",
    sequence,
    summary: toState === "cancelled" ? "Watch cancelled." : "Watch retired.",
    terminal: true,
    to_state: toState,
    watch_id: current.watch_id,
  };
  return {
    update,
    watch: {
      ...current,
      last_update: update,
      revision: current.revision + 1,
      state: toState,
      state_sequence: stateSequence,
      updated_at: normalizedOccurredAt,
    },
  };
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
  requireTimestamp(binding.resolved_at, "resolved_at");
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
    request_key: watch.request_key,
    schedule_ref: watch.schedule_ref,
    target_kind: watch.target_kind,
    target_ref: watch.target_ref,
    target_version: watch.target_version,
    watch_id: watch.watch_id,
  })) requireRef(value, label);
  if (watch.authority !== "read") {
    throw new AnswerWatchInvariantError("Answer watches require read-only authority.");
  }
  requirePositiveInteger(watch.revision, "revision");
  requireNonNegativeInteger(watch.state_sequence, "state_sequence");
  const createdAt = requireTimestamp(watch.created_at, "created_at");
  const updatedAt = requireTimestamp(watch.updated_at, "updated_at");
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    throw new AnswerWatchInvariantError("Watch time cannot move backward.");
  }
  if ((watch.last_observation_id === undefined) !== (watch.last_observation_digest === undefined)) {
    throw new AnswerWatchInvariantError("Watch observation id and digest must be recorded together.");
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
  requireRef(occurrence.occurrence.occurrence_id, "occurrence_id");
  requirePositiveInteger(occurrence.occurrence.generation, "generation");
  requirePositiveInteger(occurrence.occurrence.schedule_revision, "schedule_revision");
  requireTimestamp(occurrence.occurrence.due_at, "due_at");
  requireTimestamp(occurrence.occurrence.updated_at, "updated_at");
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
  requireText(observation.summary, "summary");
  requireTimestamp(observation.observed_at, "observed_at");
  const canonicalDigest = answerWatchMaterialDigest(observation.material_state);
  if (observation.material_digest !== canonicalDigest) {
    throw new AnswerWatchInvariantError(
      "Observation material digest does not match its structured state.",
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

function validateMaterialState(state: AnswerWatchMaterialStateV1): void {
  if (state.schema_version !== "answer-watch-material-state/v1") {
    throw new AnswerWatchInvariantError("Unsupported answer watch material state version.");
  }
  requireNonNegativeInteger(state.checks.passed, "checks.passed");
  requireNonNegativeInteger(state.checks.pending, "checks.pending");
  requireNonNegativeInteger(state.checks.failed, "checks.failed");
  requireRef(state.head_ref, "head_ref");
  requireRef(state.merge_state, "merge_state");
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

function uniqueRefs(values: readonly string[], label: string): void {
  const unique = new Set<string>();
  for (const value of values) {
    requireRef(value, label);
    if (unique.has(value)) throw new AnswerWatchInvariantError(`${label} must be unique.`);
    unique.add(value);
  }
}

function requireMonotonicTimestamp(value: string, previous: string, label: string): string {
  const normalized = requireTimestamp(value, label);
  if (Date.parse(normalized) < Date.parse(previous)) {
    throw new AnswerWatchInvariantError(`${label} cannot move backward.`);
  }
  return normalized;
}

function requireTimestamp(value: string, label: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new AnswerWatchInvariantError(`${label} must be an ISO timestamp.`);
  return new Date(timestamp).toISOString();
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

function requireRef(value: string, label: string): void {
  requireText(value, label);
  if (/\s/.test(value)) {
    throw new AnswerWatchInvariantError(`${label} must be an opaque reference without whitespace.`);
  }
}

function requireText(value: string, label: string): void {
  if (value.trim().length === 0) throw new AnswerWatchInvariantError(`${label} must not be empty.`);
}
