export const TOOL_CATALOG_ENTRY_SCHEMA_VERSION = "tool-catalog-entry/v1" as const;
export const TOOL_AUTHORITY_DECISION_SCHEMA_VERSION =
  "tool-authority-decision/v1" as const;
export const TOOL_INVOCATION_RESULT_SCHEMA_VERSION =
  "tool-invocation-result/v1" as const;
export const TOOL_INVOCATION_RECEIPT_SCHEMA_VERSION =
  "tool-invocation-receipt/v1" as const;

export type ToolEffectClass = "read" | "write" | "external_effect";
export type ToolAuthorityClass = "observe" | "propose" | "actuate";
export type ToolReplayPolicy =
  | "safe"
  | "receipt_required"
  | "reconcile_before_retry";

export interface ToolCatalogEntryV1 {
  readonly schema_version: typeof TOOL_CATALOG_ENTRY_SCHEMA_VERSION;
  readonly tool_id: string;
  readonly tool_version: string;
  readonly title: string;
  readonly summary: string;
  readonly input_schema_ref: string;
  readonly result_schema_ref: string;
  readonly effect_class: ToolEffectClass;
  readonly authority_class: ToolAuthorityClass;
  readonly replay_policy: ToolReplayPolicy;
  readonly required_capabilities: readonly string[];
}

export type ToolAuthorityOutcome =
  | "allowed"
  | "denied"
  | "approval_required";

/**
 * An append-only decision bound to one exact invocation request.
 *
 * `authority_ref` is an opaque durable record identifier. It is never a
 * credential, endpoint, provider response, or process-local object handle.
 */
export interface ToolAuthorityDecisionV1 {
  readonly schema_version: typeof TOOL_AUTHORITY_DECISION_SCHEMA_VERSION;
  readonly decision_id: string;
  readonly invocation_id: string;
  readonly run_id: string;
  readonly step_id: string;
  readonly subject_ref: string;
  readonly tool_id: string;
  readonly tool_version: string;
  readonly request_digest: string;
  readonly outcome: ToolAuthorityOutcome;
  readonly authority_ref: string;
  readonly reason_code: string;
  readonly decided_at: string;
  readonly expires_at?: string;
}

export interface ToolInvocationSucceededResultV1 {
  readonly schema_version: typeof TOOL_INVOCATION_RESULT_SCHEMA_VERSION;
  readonly invocation_id: string;
  readonly outcome: "succeeded";
  readonly summary: string;
  readonly output_ref: string;
  readonly output_digest: string;
  readonly recorded_at: string;
}

export interface ToolInvocationFailedResultV1 {
  readonly schema_version: typeof TOOL_INVOCATION_RESULT_SCHEMA_VERSION;
  readonly invocation_id: string;
  readonly outcome: "failed";
  readonly summary: string;
  readonly error_code: string;
  readonly retryable: boolean;
  readonly recorded_at: string;
}

export interface ToolInvocationUnknownResultV1 {
  readonly schema_version: typeof TOOL_INVOCATION_RESULT_SCHEMA_VERSION;
  readonly invocation_id: string;
  readonly outcome: "unknown";
  readonly summary: string;
  readonly uncertainty_code: string;
  readonly recorded_at: string;
}

/** A bounded result that cannot carry an arbitrary integration payload. */
export type ToolInvocationResultV1 =
  | ToolInvocationSucceededResultV1
  | ToolInvocationFailedResultV1
  | ToolInvocationUnknownResultV1;

export type ToolInvocationState =
  | "authorized"
  | "executing"
  | "succeeded"
  | "failed"
  | "unknown";

/**
 * A fenced current receipt for one tool invocation.
 *
 * Integration adapters may execute the invocation, but they must persist this
 * portable receipt shape and reconcile `unknown` before attempting a retry.
 */
export interface ToolInvocationReceiptV1 {
  readonly schema_version: typeof TOOL_INVOCATION_RECEIPT_SCHEMA_VERSION;
  readonly receipt_id: string;
  readonly invocation_id: string;
  readonly idempotency_key: string;
  readonly run_id: string;
  readonly step_id: string;
  readonly tool_id: string;
  readonly tool_version: string;
  readonly request_digest: string;
  readonly authority_decision_id: string;
  readonly generation: number;
  readonly fencing_token: number;
  readonly lease_token: string;
  readonly sequence: number;
  readonly state: ToolInvocationState;
  readonly authorized_at: string;
  readonly started_at?: string;
  readonly completed_at?: string;
  readonly recorded_at: string;
  readonly result?: ToolInvocationResultV1;
}

export class ToolContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ToolContractError";
  }
}

const TOOL_ID_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const TOOL_VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const CAPABILITY_PATTERN = /^[a-z][a-z0-9]*(?::[a-z][a-z0-9_-]*)+$/;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const REASON_CODE_PATTERN = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;

export function assertToolCatalogEntry(
  entry: ToolCatalogEntryV1,
): void {
  assertKnownKeys(
    entry,
    [
      "schema_version",
      "tool_id",
      "tool_version",
      "title",
      "summary",
      "input_schema_ref",
      "result_schema_ref",
      "effect_class",
      "authority_class",
      "replay_policy",
      "required_capabilities",
    ],
    "tool catalog entry",
  );
  if (entry.schema_version !== TOOL_CATALOG_ENTRY_SCHEMA_VERSION) {
    throw new ToolContractError("tool catalog schema version is unsupported");
  }
  assertToolCoordinate(entry.tool_id, entry.tool_version);
  assertBoundedText(entry.title, "tool title", 1, 120);
  assertBoundedText(entry.summary, "tool summary", 1, 280);
  assertOpaqueRef(entry.input_schema_ref, "input schema ref");
  assertOpaqueRef(entry.result_schema_ref, "result schema ref");
  if (!(["read", "write", "external_effect"] as const).includes(entry.effect_class)) {
    throw new ToolContractError("tool effect class is unsupported");
  }
  if (!(["observe", "propose", "actuate"] as const).includes(entry.authority_class)) {
    throw new ToolContractError("tool authority class is unsupported");
  }
  if (
    !(["safe", "receipt_required", "reconcile_before_retry"] as const).includes(
      entry.replay_policy,
    )
  ) {
    throw new ToolContractError("tool replay policy is unsupported");
  }
  if (entry.required_capabilities.length === 0) {
    throw new ToolContractError("tool requires at least one capability");
  }
  const capabilities = new Set<string>();
  for (const capability of entry.required_capabilities) {
    if (!CAPABILITY_PATTERN.test(capability)) {
      throw new ToolContractError("tool capability is malformed");
    }
    if (capabilities.has(capability)) {
      throw new ToolContractError("tool capability is duplicated");
    }
    capabilities.add(capability);
  }
  if (
    entry.effect_class === "external_effect" &&
    entry.replay_policy !== "reconcile_before_retry"
  ) {
    throw new ToolContractError(
      "external effects must reconcile before retry",
    );
  }
  if (
    entry.authority_class === "actuate" &&
    entry.effect_class === "read"
  ) {
    throw new ToolContractError("read tools cannot use actuate authority");
  }
}

export function assertToolAuthorityDecision(
  decision: ToolAuthorityDecisionV1,
): void {
  assertKnownKeys(
    decision,
    [
      "schema_version",
      "decision_id",
      "invocation_id",
      "run_id",
      "step_id",
      "subject_ref",
      "tool_id",
      "tool_version",
      "request_digest",
      "outcome",
      "authority_ref",
      "reason_code",
      "decided_at",
      "expires_at",
    ],
    "tool authority decision",
  );
  if (decision.schema_version !== TOOL_AUTHORITY_DECISION_SCHEMA_VERSION) {
    throw new ToolContractError("tool authority schema version is unsupported");
  }
  assertOpaqueRef(decision.decision_id, "decision id");
  assertOpaqueRef(decision.invocation_id, "invocation id");
  assertOpaqueRef(decision.run_id, "run id");
  assertOpaqueRef(decision.step_id, "step id");
  assertOpaqueRef(decision.subject_ref, "subject ref");
  assertToolCoordinate(decision.tool_id, decision.tool_version);
  assertDigest(decision.request_digest, "request digest");
  if (!(["allowed", "denied", "approval_required"] as const).includes(decision.outcome)) {
    throw new ToolContractError("tool authority outcome is unsupported");
  }
  assertOpaqueRef(decision.authority_ref, "authority ref");
  if (!REASON_CODE_PATTERN.test(decision.reason_code)) {
    throw new ToolContractError("authority reason code is malformed");
  }
  const decidedAt = assertTimestamp(decision.decided_at, "decided at");
  if (decision.expires_at !== undefined) {
    const expiresAt = assertTimestamp(decision.expires_at, "expires at");
    if (expiresAt <= decidedAt) {
      throw new ToolContractError("authority expiry must follow its decision");
    }
  }
}

export function assertToolInvocationResult(
  result: ToolInvocationResultV1,
): void {
  const outcomeKeys =
    result.outcome === "succeeded"
      ? ["output_ref", "output_digest"]
      : result.outcome === "failed"
        ? ["error_code", "retryable"]
        : ["uncertainty_code"];
  assertKnownKeys(
    result,
    [
      "schema_version",
      "invocation_id",
      "outcome",
      "summary",
      "recorded_at",
      ...outcomeKeys,
    ],
    "tool invocation result",
  );
  if (result.schema_version !== TOOL_INVOCATION_RESULT_SCHEMA_VERSION) {
    throw new ToolContractError("tool result schema version is unsupported");
  }
  assertOpaqueRef(result.invocation_id, "result invocation id");
  if (!(["succeeded", "failed", "unknown"] as const).includes(result.outcome)) {
    throw new ToolContractError("tool result outcome is unsupported");
  }
  assertBoundedText(result.summary, "result summary", 1, 280);
  assertTimestamp(result.recorded_at, "result recorded at");

  if (result.outcome === "succeeded") {
    assertOpaqueRef(result.output_ref, "output ref");
    assertDigest(result.output_digest, "output digest");
    return;
  }
  if (result.outcome === "failed") {
    if (!REASON_CODE_PATTERN.test(result.error_code)) {
      throw new ToolContractError("tool result error code is malformed");
    }
    return;
  }
  if (!REASON_CODE_PATTERN.test(result.uncertainty_code)) {
    throw new ToolContractError("tool result uncertainty code is malformed");
  }
}

export function assertToolInvocationReceipt(
  receipt: ToolInvocationReceiptV1,
): void {
  assertKnownKeys(
    receipt,
    [
      "schema_version",
      "receipt_id",
      "invocation_id",
      "idempotency_key",
      "run_id",
      "step_id",
      "tool_id",
      "tool_version",
      "request_digest",
      "authority_decision_id",
      "generation",
      "fencing_token",
      "lease_token",
      "sequence",
      "state",
      "authorized_at",
      "started_at",
      "completed_at",
      "recorded_at",
      "result",
    ],
    "tool invocation receipt",
  );
  if (receipt.schema_version !== TOOL_INVOCATION_RECEIPT_SCHEMA_VERSION) {
    throw new ToolContractError("tool receipt schema version is unsupported");
  }
  assertOpaqueRef(receipt.receipt_id, "receipt id");
  assertOpaqueRef(receipt.invocation_id, "invocation id");
  assertOpaqueRef(receipt.idempotency_key, "idempotency key");
  assertOpaqueRef(receipt.run_id, "run id");
  assertOpaqueRef(receipt.step_id, "step id");
  assertToolCoordinate(receipt.tool_id, receipt.tool_version);
  assertDigest(receipt.request_digest, "request digest");
  assertOpaqueRef(receipt.authority_decision_id, "authority decision id");
  assertPositiveInteger(receipt.generation, "generation");
  assertNonNegativeInteger(receipt.fencing_token, "fencing token");
  assertOpaqueRef(receipt.lease_token, "lease token");
  assertNonNegativeInteger(receipt.sequence, "sequence");
  if (
    !(["authorized", "executing", "succeeded", "failed", "unknown"] as const).includes(
      receipt.state,
    )
  ) {
    throw new ToolContractError("tool receipt state is unsupported");
  }

  const authorizedAt = assertTimestamp(receipt.authorized_at, "authorized at");
  const recordedAt = assertTimestamp(receipt.recorded_at, "recorded at");
  if (recordedAt < authorizedAt) {
    throw new ToolContractError("receipt cannot precede authorization");
  }

  const startedAt = optionalTimestamp(receipt.started_at, "started at");
  const completedAt = optionalTimestamp(receipt.completed_at, "completed at");
  if (startedAt !== undefined && startedAt < authorizedAt) {
    throw new ToolContractError("tool start cannot precede authorization");
  }
  if (completedAt !== undefined && startedAt === undefined) {
    throw new ToolContractError("completed tool receipt requires a start time");
  }
  if (
    completedAt !== undefined &&
    startedAt !== undefined &&
    completedAt < startedAt
  ) {
    throw new ToolContractError("tool completion cannot precede its start");
  }

  if (receipt.state === "authorized") {
    if (startedAt !== undefined || completedAt !== undefined || receipt.result) {
      throw new ToolContractError(
        "authorized receipt cannot contain execution outcome",
      );
    }
    return;
  }
  if (receipt.state === "executing") {
    if (startedAt === undefined || completedAt !== undefined || receipt.result) {
      throw new ToolContractError(
        "executing receipt requires only a start time",
      );
    }
    return;
  }
  if (startedAt === undefined || receipt.result === undefined) {
    throw new ToolContractError("terminal receipt requires a start and result");
  }
  assertToolInvocationResult(receipt.result);
  if (receipt.result.invocation_id !== receipt.invocation_id) {
    throw new ToolContractError("tool result invocation does not match receipt");
  }
  if (receipt.result.outcome !== receipt.state) {
    throw new ToolContractError("tool result outcome does not match receipt");
  }
  if (receipt.result.recorded_at !== receipt.recorded_at) {
    throw new ToolContractError("tool result and receipt must be recorded together");
  }
  if (receipt.state === "unknown") {
    if (completedAt !== undefined) {
      throw new ToolContractError("unknown tool outcome cannot be completed");
    }
    return;
  }
  if (completedAt === undefined || completedAt !== recordedAt) {
    throw new ToolContractError(
      "completed tool result and receipt must be recorded together",
    );
  }
}

export function assertToolInvocationAuthority(
  decision: ToolAuthorityDecisionV1,
  receipt: ToolInvocationReceiptV1,
): void {
  assertToolAuthorityDecision(decision);
  assertToolInvocationReceipt(receipt);
  if (decision.outcome !== "allowed") {
    throw new ToolContractError("tool invocation requires allowed authority");
  }
  if (
    decision.decision_id !== receipt.authority_decision_id ||
    decision.invocation_id !== receipt.invocation_id ||
    decision.run_id !== receipt.run_id ||
    decision.step_id !== receipt.step_id ||
    decision.tool_id !== receipt.tool_id ||
    decision.tool_version !== receipt.tool_version ||
    decision.request_digest !== receipt.request_digest
  ) {
    throw new ToolContractError("tool authority does not match invocation receipt");
  }
  const authorizedAt = Date.parse(receipt.authorized_at);
  const decidedAt = Date.parse(decision.decided_at);
  if (authorizedAt < decidedAt) {
    throw new ToolContractError("tool receipt cannot predate its authority decision");
  }
  if (
    decision.expires_at !== undefined &&
    authorizedAt >= Date.parse(decision.expires_at)
  ) {
    throw new ToolContractError("tool authority expired before invocation");
  }
}

function assertToolCoordinate(toolId: string, toolVersion: string): void {
  if (!TOOL_ID_PATTERN.test(toolId)) {
    throw new ToolContractError("tool id is malformed");
  }
  if (!TOOL_VERSION_PATTERN.test(toolVersion)) {
    throw new ToolContractError("tool version is malformed");
  }
}

function assertKnownKeys(
  value: object,
  allowedKeys: readonly string[],
  label: string,
): void {
  const allowed = new Set(allowedKeys);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new ToolContractError(`${label} contains an unsupported field`);
  }
}

function assertOpaqueRef(value: string, label: string): void {
  assertBoundedText(value, label, 1, 256);
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(value) ||
    value.includes("://")
  ) {
    throw new ToolContractError(`${label} must be an opaque identifier`);
  }
}

function assertDigest(value: string, label: string): void {
  if (!SHA256_PATTERN.test(value)) {
    throw new ToolContractError(`${label} must be a sha256 digest`);
  }
}

function assertBoundedText(
  value: string,
  label: string,
  minimum: number,
  maximum: number,
): void {
  const length = value.trim().length;
  if (
    length < minimum ||
    length > maximum ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new ToolContractError(`${label} length is invalid`);
  }
}

function assertTimestamp(value: string, label: string): number {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new ToolContractError(`${label} must be an ISO timestamp`);
  }
  if (new Date(timestamp).toISOString() !== value) {
    throw new ToolContractError(`${label} must be canonical UTC`);
  }
  return timestamp;
}

function optionalTimestamp(
  value: string | undefined,
  label: string,
): number | undefined {
  return value === undefined ? undefined : assertTimestamp(value, label);
}

function assertPositiveInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new ToolContractError(`${label} must be a positive integer`);
  }
}

function assertNonNegativeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ToolContractError(`${label} must be a non-negative integer`);
  }
}
