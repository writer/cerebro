import type {
  CanonicalWorkCaseV1,
  CanonicalWorkCommandApprovalV1,
  CanonicalWorkCommandIntentV1,
} from "@writer/cerebro-slack-companion";
import type {
  ComplianceWorkCommand,
  ComplianceWorkItemPage,
  ComplianceWorkItemRecord,
  ComplianceWorkItemState,
} from "@writer/cerebro-sdk";

export interface CanonicalHostBinding {
  credential_ref: string;
  integration_ref: string;
  tenant_ref: string;
}

/** Host-owned, already-bound transport. This package accepts no endpoint URL. */
export interface CanonicalWorkTransport {
  command(
    workItemId: string,
    command: ComplianceWorkCommand,
    context: { idempotency_key: string; tenant_ref: string },
  ): Promise<ComplianceWorkItemRecord>;
  get(workItemId: string, context: { tenant_ref: string }): Promise<ComplianceWorkItemRecord>;
  list(options: {
    cursor?: string;
    limit?: number;
    owner_id?: string;
    state?: ComplianceWorkItemState;
    tenant_ref: string;
  }): Promise<ComplianceWorkItemPage>;
}

export interface CanonicalWorkTransportFactory {
  bind(input: {
    credential_ref: string;
    integration_ref: string;
  }): Promise<CanonicalWorkTransport>;
}

export interface AtomicDocument<T = unknown> {
  token: string;
  value: T;
}

export interface AtomicDocumentStore {
  compareAndSwap(key: string, token: string, value: unknown): Promise<boolean>;
  putIfAbsent(key: string, value: unknown): Promise<boolean>;
  read(key: string): Promise<AtomicDocument | undefined>;
}

export interface CanonicalWorkHostContext {
  actor_ref: string;
  channel_ref?: string;
  request_ref: string;
  thread_ref?: string;
}

export interface CanonicalWorkGoalPort {
  recordIntent(
    intent: CanonicalWorkCommandIntentV1,
    approvalRef: string,
    context: CanonicalWorkHostContext,
  ): Promise<{ goal_receipt_ref: string }>;
  syncCase(
    caseRecord: CanonicalWorkCaseV1,
    context: CanonicalWorkHostContext,
  ): Promise<{ goal_receipt_ref: string }>;
}

export interface CanonicalWorkApprovalRequest {
  actor_ref: string;
  case_id: string;
  channel_ref?: string;
  command_digest: string;
  intent_id: string;
  request_ref: string;
  summary: string;
  thread_ref?: string;
}

export interface CanonicalWorkApprovalPort {
  approvedReceipt(
    approvalRef: string,
    expected: { command_digest: string; intent_id: string },
  ): Promise<CanonicalWorkCommandApprovalV1>;
  request(input: CanonicalWorkApprovalRequest): Promise<{ approval_ref: string }>;
}

export type CanonicalWorkHostEvidenceKind =
  | "approval_requested"
  | "case_durable"
  | "command_finished"
  | "goal_synced"
  | "route_registered";

export interface CanonicalWorkHostEvidenceEvent {
  case_ref?: string;
  intent_ref?: string;
  kind: CanonicalWorkHostEvidenceKind;
  occurred_at: string;
  outcome?: CanonicalWorkCommandIntentV1["status"];
  receipt_ref: string;
  request_ref?: string;
}

export interface CanonicalWorkEvidencePort {
  record(event: CanonicalWorkHostEvidenceEvent): Promise<void>;
}

export interface CanonicalWorkHostTool {
  description: string;
  execute(input: Record<string, unknown>, context: CanonicalWorkHostContext): Promise<unknown>;
  name: string;
  policy: CanonicalWorkToolPolicy;
}

export type CanonicalWorkToolTier = "read" | "autonomy_write" | "approval";

export interface CanonicalWorkToolPolicy {
  allowed_intents: Array<"security_answer" | "code_change" | "response_action">;
  approval_required: boolean;
  tier: CanonicalWorkToolTier;
}

export interface SlackToolPackRegistry {
  register(input: {
    generation: number;
    route_id: string;
    tool_pack_id: string;
    tools: CanonicalWorkHostTool[];
  }): Promise<{ registration_receipt_ref: string }>;
}
