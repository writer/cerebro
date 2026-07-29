import type {
  ToolAuthorityDecisionV1,
  ToolAuthorityClass,
  ToolEffectClass,
  ToolReplayPolicy,
} from "../tools/contracts.js";

export type {
  ToolAuthorityDecisionV1,
  ToolAuthorityClass,
  ToolEffectClass,
  ToolReplayPolicy,
};

export const COMPUTER_SANDBOX_PROVIDER_SCHEMA_VERSION =
  "computer-sandbox-provider/v1" as const;
export const COMPUTER_SANDBOX_SESSION_REQUEST_SCHEMA_VERSION =
  "computer-sandbox-session-request/v1" as const;
export const COMPUTER_SANDBOX_SESSION_SCHEMA_VERSION =
  "computer-sandbox-session/v1" as const;
export const COMPUTER_SANDBOX_ACTION_SCHEMA_VERSION =
  "computer-sandbox-action/v1" as const;
export const COMPUTER_SANDBOX_ACTION_RESULT_SCHEMA_VERSION =
  "computer-sandbox-action-result/v1" as const;

export const MAX_COMPUTER_SANDBOX_PROVIDERS = 32;
export const MAX_COMPUTER_SANDBOX_CAPABILITIES = 16;
export const MAX_COMPUTER_SANDBOX_ACTIONS = 16;
export const MAX_COMPUTER_SANDBOX_ALLOWED_ORIGINS = 32;

export type ComputerSandboxCapability =
  | "browser"
  | "desktop"
  | "downloads"
  | "files"
  | "uploads";

export const COMPUTER_SANDBOX_ACTION_KINDS = [
  "activate",
  "close",
  "download",
  "focus",
  "navigate",
  "observe",
  "scroll",
  "submit",
  "type",
  "upload",
] as const;

export type ComputerSandboxActionKind =
  (typeof COMPUTER_SANDBOX_ACTION_KINDS)[number];

export type ComputerSandboxProviderState =
  | "ready"
  | "degraded"
  | "offline";

/**
 * Portable provider inventory. Routes, credentials, account identifiers,
 * deployment placement, and provider payloads remain in the host adapter.
 */
export interface ComputerSandboxProviderV1 {
  capabilities: readonly ComputerSandboxCapability[];
  max_session_seconds: number;
  observed_at: string;
  provider_id: string;
  provider_version: string;
  schema_version: typeof COMPUTER_SANDBOX_PROVIDER_SCHEMA_VERSION;
  state: ComputerSandboxProviderState;
  supported_actions: readonly ComputerSandboxActionKind[];
  valid_until: string;
}

export interface ComputerSandboxSessionRequestV1 {
  allowed_origins: readonly string[];
  authority: ToolAuthorityDecisionV1;
  expires_at: string;
  idempotency_key: string;
  identity_ref: string;
  image_ref: string;
  network_policy_ref: string;
  provider_preferences?: readonly string[];
  request_id: string;
  requested_at: string;
  required_actions: readonly ComputerSandboxActionKind[];
  required_capabilities: readonly ComputerSandboxCapability[];
  run_id: string;
  schema_version: typeof COMPUTER_SANDBOX_SESSION_REQUEST_SCHEMA_VERSION;
  step_id: string;
  subject_ref: string;
}

export type ComputerSandboxSessionState =
  | "active"
  | "closed"
  | "closing"
  | "unknown";

/**
 * Host-neutral session binding. provider_session_ref is an opaque durable
 * reference, never a route, credential, cookie, or process-local handle.
 */
export interface ComputerSandboxSessionV1 {
  created_at: string;
  expires_at: string;
  generation: number;
  provider_id: string;
  provider_session_ref: string;
  provider_version: string;
  request_digest: string;
  request_id: string;
  revision: number;
  schema_version: typeof COMPUTER_SANDBOX_SESSION_SCHEMA_VERSION;
  session_id: string;
  state: ComputerSandboxSessionState;
}

export type ComputerSandboxSessionCreateResult =
  | {
      outcome: "created";
      replayed: boolean;
      session: ComputerSandboxSessionV1;
    }
  | {
      outcome: "unavailable";
      provider_id: string;
      reason_code: string;
    }
  | {
      outcome: "unknown";
      provider_id: string;
      reason_code: string;
      reconciliation_ref: string;
    };

export interface ComputerSandboxActionV1 {
  action_id: string;
  authority: ToolAuthorityDecisionV1;
  idempotency_key: string;
  input_digest: string;
  input_ref: string;
  kind: ComputerSandboxActionKind;
  requested_at: string;
  run_id: string;
  schema_version: typeof COMPUTER_SANDBOX_ACTION_SCHEMA_VERSION;
  sequence: number;
  session_id: string;
  step_id: string;
  subject_ref: string;
}

export interface ComputerSandboxActionSucceededV1 {
  completed_at: string;
  outcome: "succeeded";
  output_digest: string;
  output_ref: string;
  provider_receipt_ref: string;
}

export interface ComputerSandboxActionFailedV1 {
  completed_at: string;
  error_code: string;
  outcome: "failed";
  retryable: boolean;
}

export interface ComputerSandboxActionUnknownV1 {
  observed_at: string;
  outcome: "unknown";
  reconciliation_ref: string;
  uncertainty_code: string;
}

export type ComputerSandboxActionOutcomeV1 =
  | ComputerSandboxActionSucceededV1
  | ComputerSandboxActionFailedV1
  | ComputerSandboxActionUnknownV1;

/** Exact action receipt. Raw screenshots, page content, and files stay by ref. */
export interface ComputerSandboxActionResultV1 {
  action_digest: string;
  action_id: string;
  authority_decision_id: string;
  outcome: ComputerSandboxActionOutcomeV1;
  provider_id: string;
  provider_version: string;
  schema_version: typeof COMPUTER_SANDBOX_ACTION_RESULT_SCHEMA_VERSION;
  sequence: number;
  session_id: string;
}

export interface ComputerSandboxProviderAttempt {
  provider_id: string;
  reason_code?: string;
  status: "created" | "unavailable" | "unknown";
}

export type ComputerSandboxProvisionResult =
  | {
      attempts: readonly ComputerSandboxProviderAttempt[];
      session: ComputerSandboxSessionV1;
      status: "created";
    }
  | {
      attempts: readonly ComputerSandboxProviderAttempt[];
      reconciliation_ref: string;
      status: "unknown";
    }
  | {
      attempts: readonly ComputerSandboxProviderAttempt[];
      rejections: readonly ComputerSandboxProviderRejection[];
      status: "unavailable";
    };

export interface ComputerSandboxProviderCandidate {
  provider: ComputerSandboxProviderV1;
  rank: string;
}

export interface ComputerSandboxProviderRejection {
  provider_id: string;
  reasons: readonly string[];
}

export interface ComputerSandboxProviderRanking {
  compatible: readonly ComputerSandboxProviderCandidate[];
  rejected: readonly ComputerSandboxProviderRejection[];
}

export interface ComputerSandboxActionPolicy {
  authority_class: ToolAuthorityClass;
  effect_class: ToolEffectClass;
  replay_policy: ToolReplayPolicy;
  tool_id: string;
  tool_version: string;
}

export class ComputerSandboxContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ComputerSandboxContractError";
  }
}
