import { createHash } from "node:crypto";
import type { ToolCatalogEntryV1 } from "../tools/contracts.js";
import {
  assertToolAuthorityDecision,
} from "../tools/contracts.js";
import {
  COMPUTER_SANDBOX_ACTION_KINDS,
  COMPUTER_SANDBOX_ACTION_RESULT_SCHEMA_VERSION,
  COMPUTER_SANDBOX_ACTION_SCHEMA_VERSION,
  COMPUTER_SANDBOX_PROVIDER_SCHEMA_VERSION,
  COMPUTER_SANDBOX_SESSION_REQUEST_SCHEMA_VERSION,
  COMPUTER_SANDBOX_SESSION_SCHEMA_VERSION,
  MAX_COMPUTER_SANDBOX_ACTIONS,
  MAX_COMPUTER_SANDBOX_ALLOWED_ORIGINS,
  MAX_COMPUTER_SANDBOX_CAPABILITIES,
  MAX_COMPUTER_SANDBOX_PROVIDERS,
  ComputerSandboxContractError,
  type ComputerSandboxActionKind,
  type ComputerSandboxActionPolicy,
  type ComputerSandboxActionResultV1,
  type ComputerSandboxActionV1,
  type ComputerSandboxCapability,
  type ComputerSandboxProviderCandidate,
  type ComputerSandboxProviderRanking,
  type ComputerSandboxProviderV1,
  type ComputerSandboxSessionRequestV1,
  type ComputerSandboxSessionV1,
} from "./contracts.js";

const PROVIDER_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const OPAQUE_REF = /^[a-z][a-z0-9+.-]*:\/\/\S+$/;
const REASON_CODE = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const ORIGIN = /^https:\/\/[a-zA-Z0-9.-]+(?::\d{1,5})?$/;
const SESSION_ID = /^computer-session:\/\/sha256\/[a-f0-9]{64}$/;

const CAPABILITIES = new Set<ComputerSandboxCapability>([
  "browser",
  "desktop",
  "downloads",
  "files",
  "uploads",
]);
const ACTIONS = new Set<ComputerSandboxActionKind>(
  COMPUTER_SANDBOX_ACTION_KINDS,
);

const ACTION_POLICIES: Readonly<
  Record<ComputerSandboxActionKind, ComputerSandboxActionPolicy>
> = Object.freeze({
  activate: actionPolicy(
    "computer.actuate",
    "external_effect",
    "actuate",
    "reconcile_before_retry",
  ),
  close: actionPolicy(
    "computer.session.close",
    "external_effect",
    "actuate",
    "reconcile_before_retry",
  ),
  download: actionPolicy(
    "computer.download",
    "read",
    "observe",
    "receipt_required",
  ),
  focus: actionPolicy(
    "computer.interact",
    "write",
    "propose",
    "receipt_required",
  ),
  navigate: actionPolicy("computer.navigate", "read", "observe", "safe"),
  observe: actionPolicy("computer.observe", "read", "observe", "safe"),
  scroll: actionPolicy(
    "computer.interact",
    "write",
    "propose",
    "receipt_required",
  ),
  submit: actionPolicy(
    "computer.actuate",
    "external_effect",
    "actuate",
    "reconcile_before_retry",
  ),
  type: actionPolicy(
    "computer.type",
    "external_effect",
    "actuate",
    "reconcile_before_retry",
  ),
  upload: actionPolicy(
    "computer.upload",
    "external_effect",
    "actuate",
    "reconcile_before_retry",
  ),
});

export function computerSandboxToolCatalogEntries():
readonly ToolCatalogEntryV1[] {
  return Object.freeze([
    tool(
      "computer.session.create",
      "Create computer session",
      "Create one isolated, expiring computer session.",
      "external_effect",
      "actuate",
      "reconcile_before_retry",
      ["computer:session"],
    ),
    tool(
      "computer.observe",
      "Observe computer",
      "Read one bounded screenshot or accessibility observation by reference.",
      "read",
      "observe",
      "safe",
      ["computer:observe"],
    ),
    tool(
      "computer.navigate",
      "Navigate computer",
      "Navigate within the session's allowed origins.",
      "read",
      "observe",
      "safe",
      ["computer:navigate"],
    ),
    tool(
      "computer.interact",
      "Adjust computer view",
      "Focus or scroll within the current computer view.",
      "write",
      "propose",
      "receipt_required",
      ["computer:interact"],
    ),
    tool(
      "computer.download",
      "Download computer file",
      "Download a bounded file through the host file boundary.",
      "read",
      "observe",
      "receipt_required",
      ["computer:files"],
    ),
    tool(
      "computer.type",
      "Enter computer input",
      "Enter exact text as an external effect with reconciliation before retry.",
      "external_effect",
      "actuate",
      "reconcile_before_retry",
      ["computer:input"],
    ),
    tool(
      "computer.upload",
      "Upload computer file",
      "Upload a bounded file as an external effect with reconciliation before retry.",
      "external_effect",
      "actuate",
      "reconcile_before_retry",
      ["computer:files"],
    ),
    tool(
      "computer.actuate",
      "Commit computer action",
      "Activate or submit an external effect after exact authority approval.",
      "external_effect",
      "actuate",
      "reconcile_before_retry",
      ["computer:actuate"],
    ),
    tool(
      "computer.session.close",
      "Close computer session",
      "Close an isolated computer session and reconcile an uncertain outcome.",
      "external_effect",
      "actuate",
      "reconcile_before_retry",
      ["computer:session"],
    ),
  ]);
}

export function computerSandboxActionPolicy(
  kind: ComputerSandboxActionKind,
): ComputerSandboxActionPolicy {
  const policy = ACTION_POLICIES[kind];
  if (policy === undefined) {
    throw new ComputerSandboxContractError("computer action kind is unsupported");
  }
  return policy;
}

export function validateComputerSandboxProvider(
  provider: ComputerSandboxProviderV1,
): void {
  assertKnownKeys(provider, [
    "capabilities",
    "max_session_seconds",
    "observed_at",
    "provider_id",
    "provider_version",
    "schema_version",
    "state",
    "supported_actions",
    "valid_until",
  ], "computer sandbox provider");
  if (provider.schema_version !== COMPUTER_SANDBOX_PROVIDER_SCHEMA_VERSION) {
    throw new ComputerSandboxContractError(
      "computer sandbox provider schema version is unsupported",
    );
  }
  if (!PROVIDER_ID.test(provider.provider_id)) {
    throw new ComputerSandboxContractError("provider_id is malformed");
  }
  if (!SEMVER.test(provider.provider_version)) {
    throw new ComputerSandboxContractError("provider_version is malformed");
  }
  if (!["ready", "degraded", "offline"].includes(provider.state)) {
    throw new ComputerSandboxContractError("provider state is unsupported");
  }
  requireDistinctSet(
    provider.capabilities,
    CAPABILITIES,
    MAX_COMPUTER_SANDBOX_CAPABILITIES,
    "provider capability",
  );
  requireDistinctSet(
    provider.supported_actions,
    ACTIONS,
    MAX_COMPUTER_SANDBOX_ACTIONS,
    "provider action",
  );
  if (
    !Number.isSafeInteger(provider.max_session_seconds) ||
    provider.max_session_seconds < 60 ||
    provider.max_session_seconds > 86_400
  ) {
    throw new ComputerSandboxContractError(
      "provider max session seconds is outside its bound",
    );
  }
  const observedAt = requireTime(provider.observed_at, "provider observed_at");
  const validUntil = requireTime(provider.valid_until, "provider valid_until");
  if (validUntil <= observedAt) {
    throw new ComputerSandboxContractError(
      "provider validity must follow observation",
    );
  }
}

export function validateComputerSandboxSessionRequest(
  request: ComputerSandboxSessionRequestV1,
  observedAt: string = request.requested_at,
): void {
  validateComputerSandboxSessionRequestShape(request);
  const observed = requireTime(observedAt, "session request observed_at");
  assertToolAuthorityDecision(request.authority);
  if (
    request.authority.invocation_id !== request.request_id ||
    request.authority.run_id !== request.run_id ||
    request.authority.step_id !== request.step_id ||
    request.authority.subject_ref !== request.subject_ref ||
    request.authority.tool_id !== "computer.session.create" ||
    request.authority.tool_version !== "1.0.0" ||
    request.authority.request_digest !== sessionRequestDigestValue(request) ||
    request.authority.outcome !== "allowed" ||
    Date.parse(request.authority.decided_at) > observed ||
    (request.authority.expires_at !== undefined &&
      Date.parse(request.authority.expires_at) <= observed)
  ) {
    throw new ComputerSandboxContractError(
      "computer session authority does not allow the exact request",
    );
  }
}

function validateComputerSandboxSessionRequestShape(
  request: ComputerSandboxSessionRequestV1,
): void {
  assertKnownKeys(request, [
    "allowed_origins",
    "authority",
    "expires_at",
    "idempotency_key",
    "identity_ref",
    "image_ref",
    "network_policy_ref",
    "provider_preferences",
    "request_id",
    "requested_at",
    "required_actions",
    "required_capabilities",
    "run_id",
    "schema_version",
    "step_id",
    "subject_ref",
  ], "computer sandbox session request");
  if (
    request.schema_version !== COMPUTER_SANDBOX_SESSION_REQUEST_SCHEMA_VERSION
  ) {
    throw new ComputerSandboxContractError(
      "computer sandbox session request schema version is unsupported",
    );
  }
  requireOpaque(request.request_id, "request_id");
  requireOpaque(request.run_id, "run_id");
  requireOpaque(request.step_id, "step_id");
  requireOpaque(request.subject_ref, "subject_ref");
  requireOpaque(request.idempotency_key, "idempotency_key");
  requireRef(request.identity_ref, "identity_ref");
  requireRef(request.image_ref, "image_ref");
  requireRef(request.network_policy_ref, "network_policy_ref");
  requireDistinctSet(
    request.required_capabilities,
    CAPABILITIES,
    MAX_COMPUTER_SANDBOX_CAPABILITIES,
    "required capability",
  );
  requireDistinctSet(
    request.required_actions,
    ACTIONS,
    MAX_COMPUTER_SANDBOX_ACTIONS,
    "required action",
  );
  if (
    request.required_capabilities.length === 0 ||
    request.required_actions.length === 0
  ) {
    throw new ComputerSandboxContractError(
      "computer session requires capabilities and actions",
    );
  }
  if (
    request.allowed_origins.length === 0 ||
    request.allowed_origins.length > MAX_COMPUTER_SANDBOX_ALLOWED_ORIGINS ||
    new Set(request.allowed_origins).size !== request.allowed_origins.length ||
    request.allowed_origins.some((origin) => !ORIGIN.test(origin))
  ) {
    throw new ComputerSandboxContractError(
      "allowed origins must be distinct bounded HTTPS origins",
    );
  }
  if (request.provider_preferences !== undefined) {
    if (
      request.provider_preferences.length > MAX_COMPUTER_SANDBOX_PROVIDERS ||
      new Set(request.provider_preferences).size !==
        request.provider_preferences.length ||
      request.provider_preferences.some((provider) => !PROVIDER_ID.test(provider))
    ) {
      throw new ComputerSandboxContractError(
        "provider preferences are malformed",
      );
    }
  }
  const requestedAt = requireTime(request.requested_at, "requested_at");
  const expiresAt = requireTime(request.expires_at, "expires_at");
  if (expiresAt <= requestedAt) {
    throw new ComputerSandboxContractError(
      "computer session expiry must follow request",
    );
  }
}

export function computerSandboxSessionRequestDigest(
  request: ComputerSandboxSessionRequestV1,
): string {
  validateComputerSandboxSessionRequestShape(request);
  return sessionRequestDigestValue(request);
}

export function computerSandboxSessionIdentity(
  request: ComputerSandboxSessionRequestV1,
): string {
  return `computer-session://sha256/${computerSandboxSessionRequestDigest(request).slice(7)}`;
}

export function validateComputerSandboxSession(
  session: ComputerSandboxSessionV1,
  request?: ComputerSandboxSessionRequestV1,
): void {
  assertKnownKeys(session, [
    "created_at",
    "expires_at",
    "generation",
    "provider_id",
    "provider_session_ref",
    "provider_version",
    "request_digest",
    "request_id",
    "revision",
    "schema_version",
    "session_id",
    "state",
  ], "computer sandbox session");
  if (session.schema_version !== COMPUTER_SANDBOX_SESSION_SCHEMA_VERSION) {
    throw new ComputerSandboxContractError(
      "computer sandbox session schema version is unsupported",
    );
  }
  if (!SESSION_ID.test(session.session_id)) {
    throw new ComputerSandboxContractError("session_id is malformed");
  }
  if (!PROVIDER_ID.test(session.provider_id)) {
    throw new ComputerSandboxContractError("session provider_id is malformed");
  }
  if (!SEMVER.test(session.provider_version)) {
    throw new ComputerSandboxContractError(
      "session provider_version is malformed",
    );
  }
  requireRef(session.provider_session_ref, "provider_session_ref");
  requireOpaque(session.request_id, "session request_id");
  requireDigest(session.request_digest, "session request_digest");
  if (
    !Number.isSafeInteger(session.generation) ||
    session.generation < 1 ||
    !Number.isSafeInteger(session.revision) ||
    session.revision < 1
  ) {
    throw new ComputerSandboxContractError(
      "session generation and revision must be positive integers",
    );
  }
  if (!["active", "closed", "closing", "unknown"].includes(session.state)) {
    throw new ComputerSandboxContractError("session state is unsupported");
  }
  const createdAt = requireTime(session.created_at, "session created_at");
  const expiresAt = requireTime(session.expires_at, "session expires_at");
  if (expiresAt <= createdAt) {
    throw new ComputerSandboxContractError(
      "session expiry must follow creation",
    );
  }
  if (request !== undefined) {
    validateComputerSandboxSessionRequest(request);
    if (
      session.session_id !== computerSandboxSessionIdentity(request) ||
      session.request_id !== request.request_id ||
      session.request_digest !== computerSandboxSessionRequestDigest(request) ||
      session.expires_at !== request.expires_at
    ) {
      throw new ComputerSandboxContractError(
        "session does not match its exact request",
      );
    }
  }
}

export function computerSandboxActionDigest(
  action: ComputerSandboxActionV1,
): string {
  return digest(stableStringify({
    action_id: action.action_id,
    idempotency_key: action.idempotency_key,
    input_digest: action.input_digest,
    input_ref: action.input_ref,
    kind: action.kind,
    requested_at: action.requested_at,
    run_id: action.run_id,
    schema_version: action.schema_version,
    sequence: action.sequence,
    session_id: action.session_id,
    step_id: action.step_id,
    subject_ref: action.subject_ref,
  }));
}

export function validateComputerSandboxAction(
  action: ComputerSandboxActionV1,
  session: ComputerSandboxSessionV1,
  observedAt: string,
): void {
  assertKnownKeys(action, [
    "action_id",
    "authority",
    "idempotency_key",
    "input_digest",
    "input_ref",
    "kind",
    "requested_at",
    "run_id",
    "schema_version",
    "sequence",
    "session_id",
    "step_id",
    "subject_ref",
  ], "computer sandbox action");
  if (action.schema_version !== COMPUTER_SANDBOX_ACTION_SCHEMA_VERSION) {
    throw new ComputerSandboxContractError(
      "computer sandbox action schema version is unsupported",
    );
  }
  validateComputerSandboxSession(session);
  requireOpaque(action.action_id, "action_id");
  requireOpaque(action.idempotency_key, "action idempotency_key");
  requireDigest(action.input_digest, "action input_digest");
  requireRef(action.input_ref, "action input_ref");
  requireOpaque(action.run_id, "action run_id");
  requireOpaque(action.step_id, "action step_id");
  requireOpaque(action.subject_ref, "action subject_ref");
  requireTime(action.requested_at, "action requested_at");
  const observed = requireTime(observedAt, "action observed_at");
  if (
    !Number.isSafeInteger(action.sequence) ||
    action.sequence < 1 ||
    action.session_id !== session.session_id ||
    session.state !== "active" ||
    Date.parse(session.expires_at) <= observed
  ) {
    throw new ComputerSandboxContractError(
      "action requires a current active session and positive sequence",
    );
  }
  if (!ACTIONS.has(action.kind)) {
    throw new ComputerSandboxContractError("computer action kind is unsupported");
  }
  assertToolAuthorityDecision(action.authority);
  const policy = computerSandboxActionPolicy(action.kind);
  const requestDigest = computerSandboxActionDigest(action);
  if (
    action.authority.invocation_id !== action.action_id ||
    action.authority.run_id !== action.run_id ||
    action.authority.step_id !== action.step_id ||
    action.authority.subject_ref !== action.subject_ref ||
    action.authority.tool_id !== policy.tool_id ||
    action.authority.tool_version !== policy.tool_version ||
    action.authority.request_digest !== requestDigest ||
    action.authority.outcome !== "allowed" ||
    Date.parse(action.authority.decided_at) > observed ||
    (action.authority.expires_at !== undefined &&
      Date.parse(action.authority.expires_at) <= observed)
  ) {
    throw new ComputerSandboxContractError(
      "computer action authority does not allow the exact invocation",
    );
  }
}

export function validateComputerSandboxActionResult(
  result: ComputerSandboxActionResultV1,
  action: ComputerSandboxActionV1,
  session: ComputerSandboxSessionV1,
): void {
  assertKnownKeys(result, [
    "action_digest",
    "action_id",
    "authority_decision_id",
    "outcome",
    "provider_id",
    "provider_version",
    "schema_version",
    "sequence",
    "session_id",
  ], "computer sandbox action result");
  if (
    result.schema_version !== COMPUTER_SANDBOX_ACTION_RESULT_SCHEMA_VERSION ||
    result.action_id !== action.action_id ||
    result.action_digest !== computerSandboxActionDigest(action) ||
    result.authority_decision_id !== action.authority.decision_id ||
    result.provider_id !== session.provider_id ||
    result.provider_version !== session.provider_version ||
    result.sequence !== action.sequence ||
    result.session_id !== session.session_id
  ) {
    throw new ComputerSandboxContractError(
      "computer action result does not match its action and session",
    );
  }
  assertKnownOutcome(result.outcome);
}

export function rankComputerSandboxProviders(
  request: ComputerSandboxSessionRequestV1,
  providers: readonly ComputerSandboxProviderV1[],
  observedAt: string,
): ComputerSandboxProviderRanking {
  validateComputerSandboxSessionRequest(request, observedAt);
  const observed = requireTime(observedAt, "provider ranking observed_at");
  if (providers.length > MAX_COMPUTER_SANDBOX_PROVIDERS) {
    throw new ComputerSandboxContractError(
      "computer sandbox provider set exceeds its bound",
    );
  }
  const seen = new Set<string>();
  const compatible: ComputerSandboxProviderCandidate[] = [];
  const rejected: Array<{ provider_id: string; reasons: string[] }> = [];
  const requestedSeconds =
    (Date.parse(request.expires_at) - Date.parse(request.requested_at)) / 1_000;

  for (const provider of providers) {
    validateComputerSandboxProvider(provider);
    if (seen.has(provider.provider_id)) {
      throw new ComputerSandboxContractError(
        "computer sandbox provider set contains a duplicate provider_id",
      );
    }
    seen.add(provider.provider_id);
    const reasons: string[] = [];
    if (provider.state === "offline") reasons.push("provider_offline");
    if (Date.parse(provider.valid_until) <= observed) {
      reasons.push("provider_presence_expired");
    }
    if (provider.max_session_seconds < requestedSeconds) {
      reasons.push("provider_session_limit");
    }
    for (const capability of request.required_capabilities) {
      if (!provider.capabilities.includes(capability)) {
        reasons.push(`provider_missing_capability_${capability}`);
      }
    }
    for (const action of request.required_actions) {
      if (!provider.supported_actions.includes(action)) {
        reasons.push(`provider_missing_action_${action}`);
      }
    }
    if (reasons.length > 0) {
      rejected.push({ provider_id: provider.provider_id, reasons });
      continue;
    }
    compatible.push({
      provider: structuredClone(provider),
      rank: providerRank(request, provider.provider_id),
    });
  }
  compatible.sort((left, right) => compareProviderCandidates(
    left,
    right,
    request.provider_preferences ?? [],
  ));
  rejected.sort((left, right) => left.provider_id.localeCompare(right.provider_id));
  return { compatible, rejected };
}

function actionPolicy(
  toolId: string,
  effectClass: ComputerSandboxActionPolicy["effect_class"],
  authorityClass: ComputerSandboxActionPolicy["authority_class"],
  replayPolicy: ComputerSandboxActionPolicy["replay_policy"],
): ComputerSandboxActionPolicy {
  return Object.freeze({
    authority_class: authorityClass,
    effect_class: effectClass,
    replay_policy: replayPolicy,
    tool_id: toolId,
    tool_version: "1.0.0",
  });
}

function sessionRequestDigestValue(
  request: ComputerSandboxSessionRequestV1,
): string {
  return digest(stableStringify({
    allowed_origins: request.allowed_origins,
    expires_at: request.expires_at,
    idempotency_key: request.idempotency_key,
    identity_ref: request.identity_ref,
    image_ref: request.image_ref,
    network_policy_ref: request.network_policy_ref,
    provider_preferences: request.provider_preferences ?? null,
    request_id: request.request_id,
    requested_at: request.requested_at,
    required_actions: request.required_actions,
    required_capabilities: request.required_capabilities,
    run_id: request.run_id,
    schema_version: request.schema_version,
    step_id: request.step_id,
    subject_ref: request.subject_ref,
  }));
}

function tool(
  toolId: string,
  title: string,
  summary: string,
  effectClass: ToolCatalogEntryV1["effect_class"],
  authorityClass: ToolCatalogEntryV1["authority_class"],
  replayPolicy: ToolCatalogEntryV1["replay_policy"],
  requiredCapabilities: readonly string[],
): ToolCatalogEntryV1 {
  return Object.freeze({
    authority_class: authorityClass,
    effect_class: effectClass,
    input_schema_ref: `schemas/computer/${toolId}/input/v1`,
    replay_policy: replayPolicy,
    required_capabilities: Object.freeze([...requiredCapabilities]),
    result_schema_ref: `schemas/computer/${toolId}/result/v1`,
    schema_version: "tool-catalog-entry/v1",
    summary,
    title,
    tool_id: toolId,
    tool_version: "1.0.0",
  });
}

function providerRank(
  request: ComputerSandboxSessionRequestV1,
  providerId: string,
): string {
  return createHash("sha256")
    .update(`${request.request_id}\u0000${providerId}`)
    .digest("hex");
}

function compareProviderCandidates(
  left: ComputerSandboxProviderCandidate,
  right: ComputerSandboxProviderCandidate,
  preferences: readonly string[],
): number {
  const leftPreference = preferences.indexOf(left.provider.provider_id);
  const rightPreference = preferences.indexOf(right.provider.provider_id);
  const leftOrder = leftPreference === -1 ? Number.MAX_SAFE_INTEGER : leftPreference;
  const rightOrder =
    rightPreference === -1 ? Number.MAX_SAFE_INTEGER : rightPreference;
  if (leftOrder !== rightOrder) return leftOrder - rightOrder;
  if (left.provider.state !== right.provider.state) {
    return left.provider.state === "ready" ? -1 : 1;
  }
  return (
    left.rank.localeCompare(right.rank) ||
    left.provider.provider_id.localeCompare(right.provider.provider_id)
  );
}

function assertKnownOutcome(
  outcome: ComputerSandboxActionResultV1["outcome"],
): void {
  if (outcome.outcome === "succeeded") {
    assertKnownKeys(outcome, [
      "completed_at",
      "outcome",
      "output_digest",
      "output_ref",
      "provider_receipt_ref",
    ], "computer action success");
    requireTime(outcome.completed_at, "action completed_at");
    requireDigest(outcome.output_digest, "action output_digest");
    requireRef(outcome.output_ref, "action output_ref");
    requireRef(outcome.provider_receipt_ref, "provider_receipt_ref");
    return;
  }
  if (outcome.outcome === "failed") {
    assertKnownKeys(outcome, [
      "completed_at",
      "error_code",
      "outcome",
      "retryable",
    ], "computer action failure");
    requireTime(outcome.completed_at, "action completed_at");
    if (!REASON_CODE.test(outcome.error_code)) {
      throw new ComputerSandboxContractError("action error_code is malformed");
    }
    if (typeof outcome.retryable !== "boolean") {
      throw new ComputerSandboxContractError("action retryable must be boolean");
    }
    return;
  }
  if (outcome.outcome === "unknown") {
    assertKnownKeys(outcome, [
      "observed_at",
      "outcome",
      "reconciliation_ref",
      "uncertainty_code",
    ], "computer action unknown");
    requireTime(outcome.observed_at, "action observed_at");
    requireRef(outcome.reconciliation_ref, "action reconciliation_ref");
    if (!REASON_CODE.test(outcome.uncertainty_code)) {
      throw new ComputerSandboxContractError(
        "action uncertainty_code is malformed",
      );
    }
    return;
  }
  throw new ComputerSandboxContractError("computer action outcome is unsupported");
}

function requireDistinctSet<T extends string>(
  values: readonly T[],
  allowed: ReadonlySet<T>,
  max: number,
  field: string,
): void {
  if (
    values.length > max ||
    new Set(values).size !== values.length ||
    values.some((value) => !allowed.has(value))
  ) {
    throw new ComputerSandboxContractError(
      `${field} values are unsupported, duplicated, or exceed their bound`,
    );
  }
}

function assertKnownKeys(
  value: object,
  known: readonly string[],
  field: string,
): void {
  const extras = Object.keys(value).filter((key) => !known.includes(key));
  if (extras.length > 0) {
    throw new ComputerSandboxContractError(
      `${field} contains unsupported fields: ${extras.join(", ")}`,
    );
  }
}

function requireOpaque(value: string, field: string): void {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 256 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new ComputerSandboxContractError(
      `${field} must be a bounded opaque value`,
    );
  }
}

function requireRef(value: string, field: string): void {
  if (
    typeof value !== "string" ||
    value.length > 1_024 ||
    !OPAQUE_REF.test(value)
  ) {
    throw new ComputerSandboxContractError(
      `${field} must be a bounded opaque reference`,
    );
  }
}

function requireDigest(value: string, field: string): void {
  if (!SHA256.test(value)) {
    throw new ComputerSandboxContractError(`${field} must be a SHA-256 digest`);
  }
}

function requireTime(value: string, field: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new ComputerSandboxContractError(
      `${field} must be a canonical UTC timestamp`,
    );
  }
  return parsed;
}

function digest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(",")}}`;
}
