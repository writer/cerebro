import { createHash } from "node:crypto";
import type { CapabilityRequirement } from "@writer/cerebro-sdk";

import {
  decodeSlackActionEnvelope,
  encodeSlackActionEnvelope,
  type SlackActionEnvelopeV1,
} from "./codec.js";

const ACTION_ID_PATTERN = /^[a-z][a-z0-9_.:-]{0,95}$/;
const CAPABILITY_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,95}$/;
const COMMAND_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/;
const SHA256_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const MAX_ACTIONS = 128;
const MAX_CAPABILITIES = 64;
const MAX_PARAMETERS = 16;
const ACTION_DECISION_REASONS: readonly SlackActionDecisionReasonV1[] = [
  "accepted",
  "action_command_mismatch",
  "missing_capability",
  "missing_parameter",
  "subject_forbidden",
  "subject_required",
  "unexpected_parameter",
  "unknown_action",
];

export type SlackActionSubjectRequirementV1 = "forbidden" | "optional" | "required";

export interface SlackActionParameterContractV1 {
  readonly name: string;
  readonly required: boolean;
}

export interface SlackActionContractV1 {
  readonly action_id: string;
  readonly command: string;
  readonly parameters: readonly SlackActionParameterContractV1[];
  readonly required_capabilities: readonly CapabilityRequirement[];
  readonly retry_policy: "idempotent";
  readonly schema_version: "slack-action-contract/v1";
  readonly subject_requirement: SlackActionSubjectRequirementV1;
}

export interface SlackActionCatalogV1 {
  readonly actions: readonly SlackActionContractV1[];
  readonly catalog_id: string;
  readonly revision: number;
  readonly schema_version: "slack-action-catalog/v1";
}

export type SlackActionDecisionReasonV1 =
  | "accepted"
  | "action_command_mismatch"
  | "missing_capability"
  | "missing_parameter"
  | "subject_forbidden"
  | "subject_required"
  | "unexpected_parameter"
  | "unknown_action";

export interface SlackActionDecisionReceiptV1 {
  readonly action_id: string;
  readonly catalog_id: string;
  readonly catalog_digest: string;
  readonly catalog_revision: number;
  readonly command: string;
  readonly idempotency_key: string;
  readonly outcome: "accepted" | "rejected";
  readonly reason_code: SlackActionDecisionReasonV1;
  readonly receipt_digest: string;
  readonly receipt_id: string;
  readonly request_digest: string;
  readonly schema_version: "slack-action-decision-receipt/v1";
}

export type SlackActionPolicyDecisionV1 =
  | {
      readonly disposition: "admit" | "reject";
      readonly reason_code: SlackActionDecisionReasonV1;
      readonly receipt: SlackActionDecisionReceiptV1;
      readonly schema_version: "slack-action-policy-decision/v1";
    }
  | {
      readonly disposition: "replay";
      readonly reason_code: "receipt_replayed";
      readonly receipt: SlackActionDecisionReceiptV1;
      readonly schema_version: "slack-action-policy-decision/v1";
    }
  | {
      readonly disposition: "reject";
      readonly reason_code: "idempotency_conflict";
      readonly receipt_ref: string;
      readonly schema_version: "slack-action-policy-decision/v1";
    };

export interface SlackActionPolicyInputV1 {
  readonly action: SlackActionEnvelopeV1;
  readonly available_capabilities: readonly CapabilityRequirement[];
  readonly existing_receipt?: SlackActionDecisionReceiptV1;
}

export interface SlackActionRegistryV1 {
  readonly catalog: SlackActionCatalogV1;
  readonly action: (actionId: string) => SlackActionContractV1 | undefined;
  readonly actions: () => readonly SlackActionContractV1[];
}

export class SlackActionContractError extends Error {}

/**
 * Snapshots a caller-owned action catalog into an immutable, deterministic registry.
 * The registry is portable metadata only; it does not register Slack handlers.
 */
export function createSlackActionRegistry(
  input: SlackActionCatalogV1,
): SlackActionRegistryV1 {
  const catalog = snapshotCatalog(input);
  const lookup = new Map(catalog.actions.map((action) => [action.action_id, action]));
  return Object.freeze({
    catalog,
    action(actionId: string): SlackActionContractV1 | undefined {
      return lookup.get(actionId);
    },
    actions(): readonly SlackActionContractV1[] {
      return catalog.actions;
    },
  });
}

/**
 * Makes a deterministic admission decision over a canonical V1 action envelope.
 * A host persists the returned receipt. Supplying that receipt on retry returns
 * the exact receipt; reusing its idempotency key for different bytes fails closed.
 */
export function decideSlackAction(
  registry: SlackActionRegistryV1,
  input: SlackActionPolicyInputV1,
): SlackActionPolicyDecisionV1 {
  const encoded = encodeSlackActionEnvelope(input.action);
  const action = decodeSlackActionEnvelope(encoded);
  const requestDigest = sha256(encoded);
  const capabilities = capabilitySet(input.available_capabilities);

  if (input.existing_receipt !== undefined) {
    const existingReceipt = snapshotExistingReceipt(
      registry.catalog,
      input.existing_receipt,
      action.idempotency_key,
    );
    if (existingReceipt.request_digest !== requestDigest) {
      return Object.freeze({
        disposition: "reject",
        reason_code: "idempotency_conflict",
        receipt_ref: existingReceipt.receipt_id,
        schema_version: "slack-action-policy-decision/v1",
      });
    }
    if (
      existingReceipt.action_id !== action.action
      || existingReceipt.command !== action.command
    ) {
      throw new SlackActionContractError(
        "The action decision receipt does not match its request digest.",
      );
    }
    return Object.freeze({
      disposition: "replay",
      reason_code: "receipt_replayed",
      receipt: existingReceipt,
      schema_version: "slack-action-policy-decision/v1",
    });
  }

  const reason = evaluateAction(registry, action, capabilities);
  const outcome = reason === "accepted" ? "accepted" : "rejected";
  const receipt = Object.freeze({
    action_id: action.action,
    catalog_id: registry.catalog.catalog_id,
    catalog_digest: catalogDigest(registry.catalog),
    catalog_revision: registry.catalog.revision,
    command: action.command,
    idempotency_key: action.idempotency_key,
    outcome,
    reason_code: reason,
    receipt_id: receiptIdentity(registry.catalog.catalog_id, action.idempotency_key),
    request_digest: requestDigest,
    schema_version: "slack-action-decision-receipt/v1" as const,
  });
  const completeReceipt = Object.freeze({
    ...receipt,
    receipt_digest: receiptDigest(receipt),
  });
  return Object.freeze({
    disposition: outcome === "accepted" ? "admit" : "reject",
    reason_code: reason,
    receipt: completeReceipt,
    schema_version: "slack-action-policy-decision/v1",
  });
}

function snapshotCatalog(input: SlackActionCatalogV1): SlackActionCatalogV1 {
  exactKeys(input, ["actions", "catalog_id", "revision", "schema_version"], "action catalog");
  if (input.schema_version !== "slack-action-catalog/v1") {
    throw new SlackActionContractError("The action catalog version is unsupported.");
  }
  requireActionId(input.catalog_id, "catalog_id");
  if (!Number.isSafeInteger(input.revision) || input.revision < 1) {
    throw new SlackActionContractError("The action catalog revision must be a positive integer.");
  }
  if (!Array.isArray(input.actions) || input.actions.length > MAX_ACTIONS) {
    throw new SlackActionContractError("The action catalog size is unsupported.");
  }

  const seen = new Set<string>();
  const actions = input.actions.map((action) => snapshotAction(action));
  for (const action of actions) {
    if (seen.has(action.action_id)) {
      throw new SlackActionContractError("The action catalog contains a duplicate action_id.");
    }
    seen.add(action.action_id);
  }
  actions.sort((left, right) => compareNames(left.action_id, right.action_id));
  return Object.freeze({
    actions: Object.freeze(actions),
    catalog_id: input.catalog_id,
    revision: input.revision,
    schema_version: "slack-action-catalog/v1",
  });
}

function snapshotAction(input: SlackActionContractV1): SlackActionContractV1 {
  exactKeys(input, [
    "action_id",
    "command",
    "parameters",
    "required_capabilities",
    "retry_policy",
    "schema_version",
    "subject_requirement",
  ], "action contract");
  if (input.schema_version !== "slack-action-contract/v1") {
    throw new SlackActionContractError("The action contract version is unsupported.");
  }
  requireActionId(input.action_id, "action_id");
  requireCommandName(input.command);
  if (input.retry_policy !== "idempotent") {
    throw new SlackActionContractError("Slack actions must use idempotent retry policy.");
  }
  if (!["forbidden", "optional", "required"].includes(input.subject_requirement)) {
    throw new SlackActionContractError("The action subject requirement is unsupported.");
  }
  if (!Array.isArray(input.parameters) || input.parameters.length > MAX_PARAMETERS) {
    throw new SlackActionContractError("The action parameter contract is too large.");
  }
  if (
    !Array.isArray(input.required_capabilities)
    || input.required_capabilities.length > MAX_CAPABILITIES
  ) {
    throw new SlackActionContractError("The action capability contract is too large.");
  }

  const parameterNames = new Set<string>();
  const parameters = input.parameters.map((parameter) => {
    exactKeys(parameter, ["name", "required"], "action parameter contract");
    requireActionId(parameter.name, "parameter name");
    if (typeof parameter.required !== "boolean") {
      throw new SlackActionContractError("Action parameter required must be boolean.");
    }
    if (parameterNames.has(parameter.name)) {
      throw new SlackActionContractError("The action contract contains a duplicate parameter.");
    }
    parameterNames.add(parameter.name);
    return Object.freeze({ name: parameter.name, required: parameter.required });
  });
  parameters.sort((left, right) => compareNames(left.name, right.name));

  const capabilities = canonicalCapabilities(
    input.required_capabilities,
    "action capability",
  );
  return Object.freeze({
    action_id: input.action_id,
    command: input.command,
    parameters: Object.freeze(parameters),
    required_capabilities: capabilities,
    retry_policy: "idempotent",
    schema_version: "slack-action-contract/v1",
    subject_requirement: input.subject_requirement,
  });
}

function evaluateAction(
  registry: SlackActionRegistryV1,
  action: SlackActionEnvelopeV1,
  capabilities: ReadonlySet<string>,
): SlackActionDecisionReasonV1 {
  const contract = registry.action(action.action);
  if (!contract) return "unknown_action";
  if (contract.command !== action.command) return "action_command_mismatch";
  if (contract.subject_requirement === "required" && action.subject_ref === undefined) {
    return "subject_required";
  }
  if (contract.subject_requirement === "forbidden" && action.subject_ref !== undefined) {
    return "subject_forbidden";
  }

  const supplied = new Set(Object.keys(action.parameters ?? {}));
  const parameterContracts = new Map(
    contract.parameters.map((parameter) => [parameter.name, parameter]),
  );
  if ([...supplied].some((name) => !parameterContracts.has(name))) {
    return "unexpected_parameter";
  }
  if (contract.parameters.some((parameter) => parameter.required && !supplied.has(parameter.name))) {
    return "missing_parameter";
  }
  const missingRequiredCapability = contract.required_capabilities.some(
    (capability) =>
      capability.level === "required"
      && !capabilities.has(capabilityIdentity(capability)),
  );
  if (missingRequiredCapability) return "missing_capability";
  return "accepted";
}

function capabilitySet(
  values: readonly CapabilityRequirement[],
): ReadonlySet<string> {
  if (!Array.isArray(values) || values.length > MAX_CAPABILITIES) {
    throw new SlackActionContractError("The available capability set is too large.");
  }
  return new Set(
    canonicalCapabilities(values, "available capability").map(capabilityIdentity),
  );
}

function canonicalCapabilities(
  values: readonly CapabilityRequirement[],
  label: string,
): readonly CapabilityRequirement[] {
  const capabilities = values.map((capability) => {
    exactKeys(
      capability,
      ["capability_id", "level", "version"],
      `${label} requirement`,
    );
    requireActionId(capability.capability_id, `${label} capability_id`);
    requireCapabilityVersion(capability.version, `${label} version`);
    if (capability.level !== "required" && capability.level !== "optional") {
      throw new SlackActionContractError(`The ${label} level is unsupported.`);
    }
    return Object.freeze({
      capability_id: capability.capability_id,
      level: capability.level,
      version: capability.version,
    });
  });
  const identities = capabilities.map(capabilityIdentity);
  if (new Set(identities).size !== identities.length) {
    throw new SlackActionContractError(`The ${label} list contains a duplicate.`);
  }
  capabilities.sort((left, right) => compareNames(
    `${capabilityIdentity(left)}\u0000${left.level}`,
    `${capabilityIdentity(right)}\u0000${right.level}`,
  ));
  return Object.freeze(capabilities);
}

function capabilityIdentity(capability: CapabilityRequirement): string {
  return `${capability.capability_id}\u0000${capability.version}`;
}

function compareNames(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function snapshotExistingReceipt(
  catalog: SlackActionCatalogV1,
  receipt: SlackActionDecisionReceiptV1,
  idempotencyKey: string,
): SlackActionDecisionReceiptV1 {
  exactKeys(receipt, [
    "action_id",
    "catalog_digest",
    "catalog_id",
    "catalog_revision",
    "command",
    "idempotency_key",
    "outcome",
    "reason_code",
    "receipt_digest",
    "receipt_id",
    "request_digest",
    "schema_version",
  ], "action decision receipt");
  if (receipt.schema_version !== "slack-action-decision-receipt/v1") {
    throw new SlackActionContractError("The action decision receipt version is unsupported.");
  }
  if (receipt.catalog_id !== catalog.catalog_id) {
    throw new SlackActionContractError("The action decision receipt catalog does not match.");
  }
  if (!Number.isSafeInteger(receipt.catalog_revision) || receipt.catalog_revision < 1) {
    throw new SlackActionContractError("The action decision receipt revision is invalid.");
  }
  if (!SHA256_DIGEST_PATTERN.test(receipt.catalog_digest)) {
    throw new SlackActionContractError("The action decision receipt catalog digest is invalid.");
  }
  if (receipt.idempotency_key !== idempotencyKey) {
    throw new SlackActionContractError("The action decision receipt lookup key does not match.");
  }
  if (receipt.receipt_id !== receiptIdentity(catalog.catalog_id, idempotencyKey)) {
    throw new SlackActionContractError("The action decision receipt identity is invalid.");
  }
  if (!SHA256_DIGEST_PATTERN.test(receipt.request_digest)) {
    throw new SlackActionContractError("The action decision receipt digest is invalid.");
  }
  requireActionId(receipt.action_id, "receipt action_id");
  requireCommandName(receipt.command);
  if (!ACTION_DECISION_REASONS.includes(receipt.reason_code)) {
    throw new SlackActionContractError("The action decision receipt reason is invalid.");
  }
  const accepted = receipt.outcome === "accepted" && receipt.reason_code === "accepted";
  const rejected = receipt.outcome === "rejected" && receipt.reason_code !== "accepted";
  if (!accepted && !rejected) {
    throw new SlackActionContractError("The action decision receipt outcome is inconsistent.");
  }
  const { receipt_digest: receiptDigestValue, ...receiptContent } = receipt;
  if (
    !SHA256_DIGEST_PATTERN.test(receiptDigestValue)
    || receiptDigestValue !== receiptDigest(receiptContent)
  ) {
    throw new SlackActionContractError("The action decision receipt integrity is invalid.");
  }
  return Object.freeze({ ...receipt });
}

function receiptIdentity(catalogId: string, idempotencyKey: string): string {
  return `slack-action-decision:${stableDigest([
    catalogId,
    idempotencyKey,
  ])}`;
}

function receiptDigest(
  receipt: Omit<SlackActionDecisionReceiptV1, "receipt_digest">,
): string {
  return `sha256:${stableDigest([
    receipt.schema_version,
    receipt.receipt_id,
    receipt.catalog_id,
    String(receipt.catalog_revision),
    receipt.catalog_digest,
    receipt.action_id,
    receipt.command,
    receipt.idempotency_key,
    receipt.request_digest,
    receipt.outcome,
    receipt.reason_code,
  ])}`;
}

function catalogDigest(catalog: SlackActionCatalogV1): string {
  return sha256(JSON.stringify(catalog));
}

function stableDigest(values: readonly string[]): string {
  return createHash("sha256").update(JSON.stringify(values), "utf8").digest("hex");
}

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function requireActionId(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !ACTION_ID_PATTERN.test(value)) {
    throw new SlackActionContractError(`The ${label} is invalid.`);
  }
}

function requireCommandName(value: unknown): asserts value is string {
  if (typeof value !== "string" || !COMMAND_NAME_PATTERN.test(value)) {
    throw new SlackActionContractError("The action command name is invalid.");
  }
}

function requireCapabilityVersion(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !CAPABILITY_VERSION_PATTERN.test(value)) {
    throw new SlackActionContractError(`The ${label} is invalid.`);
  }
}

function exactKeys(
  value: object,
  allowed: readonly string[],
  label: string,
): void {
  const allowedKeys = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    throw new SlackActionContractError(`The ${label} contains unknown fields.`);
  }
}
