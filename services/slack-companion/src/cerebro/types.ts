export type JsonRecord = Record<string, unknown>;

export interface DecisionPacketBuildRequest {
  workflow: string;
  question: string;
  scope_urn?: string;
  finding_ids?: string[];
  claim_ids?: string[];
  evidence_urns?: string[];
  audit_packet_ids?: string[];
  required_sources?: string[];
  requested_action?: string;
}

export interface DecisionPacketEvidenceReference {
  id: string;
  urn?: string;
  kind: string;
  source_id?: string;
  subject_urn?: string;
  predicate?: string;
  value?: string;
  observed_at?: string;
  valid_from?: string;
  valid_to?: string;
  digest?: string;
}

export interface DecisionPacket {
  schema_version: string;
  id: string;
  generated_at: string;
  workflow: { id: string; question: string };
  scope: { tenant_id?: string; actor_id?: string; urn?: string };
  inputs: {
    finding_ids: string[];
    claim_ids: string[];
    evidence_urns: string[];
    audit_packet_ids: string[];
    required_sources: string[];
    requested_action?: string;
  };
  decision: { state: string; rationale?: string; reasons: string[] };
  confidence: { level: string; basis: string[] };
  freshness: { state: string; oldest_observed_at?: string; newest_observed_at?: string; required_stale: boolean };
  evidence: DecisionPacketEvidenceReference[];
  contradictions: Array<{
    id: string;
    subject_urn: string;
    predicate: string;
    left: DecisionPacketEvidenceReference;
    right: DecisionPacketEvidenceReference;
    resolution_state: string;
    primary_claim: boolean;
  }>;
  coverage_gaps: Array<{
    id: string;
    source_id?: string;
    dimension?: string;
    state: string;
    required: boolean;
    could_change_conclusion: boolean;
    reason: string;
  }>;
  affected: Array<{ urn: string; kind: string; name?: string }>;
  controls: Array<{ id: string; framework?: string; applicability: string }>;
  audit_packets: Array<{ id: string; scope_urn?: string; digest: string; generated_at: string; freshness: string }>;
  actions: Array<{
    id: string;
    action_id: string;
    state: string;
    target_urns: string[];
    rationale: string;
    approval_requirements?: string[];
    catalog_version?: string;
    proposal_digest?: string;
  }>;
  provenance: {
    trace_id?: string;
    resolver_ids: string[];
    source_ids: string[];
    evidence_digest?: string;
    coverage_digest?: string;
  };
  limits?: JsonRecord;
}

export interface RuntimeHealth {
  runtime_id?: string;
  id?: string;
  source_id?: string;
  tenant_id?: string;
  status?: string;
  sync_status?: string;
  graph_status?: string;
  finding_status?: string;
  last_sync_at?: string;
  last_observed_at?: string;
  last_graph_ingest_at?: string;
  invalid_event_count?: number;
  open_finding_count?: number;
  [key: string]: unknown;
}

export interface Finding {
  id?: string;
  runtime_id?: string;
  tenant_id?: string;
  rule_id?: string;
  title?: string;
  summary?: string;
  severity?: string;
  status?: string;
  risk_score?: number;
  primary_resource_urn?: string;
  resource_urn?: string;
  assignee?: string;
  due_at?: string;
  last_observed_at?: string;
  observed_at?: string;
  attributes?: Record<string, string>;
  external_refs?: JsonRecord[];
  tickets?: JsonRecord[];
  [key: string]: unknown;
}

export interface FindingEvidence {
  id?: string;
  finding_id?: string;
  rule_id?: string;
  claim_id?: string;
  event_id?: string;
  summary?: string;
  evidence_type?: string;
  graph_root_urn?: string;
  graph_path_urn?: string;
  observed_at?: string;
  attributes?: Record<string, string>;
  [key: string]: unknown;
}

export interface RuntimeResponseCapability {
  action: string;
  mode: string;
  supported: boolean;
  requires_trusted_scope: boolean;
  provider?: string;
  external_owner?: string;
  target_types?: string[];
  required_context_keys?: string[];
  dry_run?: boolean;
  approval_required?: boolean;
}

export interface GraphActionRequest {
  action: "identity.okta.suspend_user" | "identity.okta.unsuspend_user" | "endpoint.cerebro.revoke_device";
  finding_id: string;
  target?: string;
  reason?: string;
  ticket_url?: string;
  idempotency_key?: string;
  dry_run?: boolean;
  approved?: boolean;
  parameters?: Record<string, string>;
}

export interface GraphReasonRequest {
  question: string;
  scope_urn?: string;
  model?: string;
  history?: Array<{ role: "user" | "assistant"; content: string }>;
}

export type ClaimVerificationFreshness = "fresh" | "stale" | "failed" | "unknown";

export type ClaimVerificationVerdict = "supported" | "weakly_supported" | "contradicted" | "unknown";

export type ClaimVerificationActionStage =
  | "observe"
  | "explain"
  | "recommend"
  | "dry_run"
  | "approve"
  | "execute"
  | "verify"
  | "close_loop";

export const CLAIM_VERIFICATION_ACTION_STAGES = [
  "observe",
  "explain",
  "recommend",
  "dry_run",
  "approve",
  "execute",
  "verify",
  "close_loop",
] as const satisfies readonly ClaimVerificationActionStage[];

export function isClaimVerificationActionStage(value: unknown): value is ClaimVerificationActionStage {
  return typeof value === "string" && CLAIM_VERIFICATION_ACTION_STAGES.includes(value as ClaimVerificationActionStage);
}

export interface AgentControlPlaneProfile {
  id: string;
  defaultOn: boolean;
  maxActionStage: ClaimVerificationActionStage;
  requiredVerifierIds: string[];
}

export interface AgentControlPlaneVerifier {
  id: string;
}

export interface AgentControlPlaneActionStage {
  id: ClaimVerificationActionStage;
  order: number;
  mutating: boolean;
  requiresApproval: boolean;
  verifierIds: string[];
}

export interface AgentControlPlaneEvalScenario {
  id: string;
  capability?: string;
}

export interface AgentControlPlaneSimulationHarness {
  id?: string;
  mode?: string;
  allowedInputs: string[];
  forbiddenInputs: string[];
}

export interface AgentControlPlane {
  version: string;
  agentProfiles: AgentControlPlaneProfile[];
  verifierLayer: AgentControlPlaneVerifier[];
  actionLadder: AgentControlPlaneActionStage[];
  evalScenarios: AgentControlPlaneEvalScenario[];
  connectorToolGateIds: string[];
  simulationHarness?: AgentControlPlaneSimulationHarness;
}

export interface ClaimVerificationRequest {
  claim: string;
  claim_type?: string;
  scope_urn?: string;
  supporting_evidence_urns?: string[];
  counter_evidence_urns?: string[];
  missing_evidence?: string[];
  freshness_state?: ClaimVerificationFreshness;
  requested_action_stage?: ClaimVerificationActionStage;
  human_approved?: boolean;
}

export interface ClaimVerificationBlocker {
  code?: string;
  message?: string;
  fields?: string[];
  [key: string]: unknown;
}

export interface ClaimVerification {
  version?: string;
  tenant_id?: string;
  actor_id?: string;
  claim: string;
  claim_type?: string;
  scope_urn?: string;
  verdict: ClaimVerificationVerdict;
  allowed_next_stage: ClaimVerificationActionStage;
  requested_action_stage?: ClaimVerificationActionStage;
  blockers?: ClaimVerificationBlocker[];
  warnings?: string[];
  supporting_evidence?: JsonRecord[];
  counter_evidence?: JsonRecord[];
  missing_evidence?: string[];
  freshness_state?: ClaimVerificationFreshness;
  verifier_results?: JsonRecord[];
  required_write_back?: string[];
  [key: string]: unknown;
}
