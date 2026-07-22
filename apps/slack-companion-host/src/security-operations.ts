export const SECURITY_OPERATION_WORKFLOWS = Object.freeze([
  { kind: "security_board", workflow_id: "security.board-daily/v1" },
  { kind: "repository_hygiene", workflow_id: "security.repo-hygiene-weekly/v1" },
] as const);

export type SecurityOperationDigestKind =
  (typeof SECURITY_OPERATION_WORKFLOWS)[number]["kind"];

export interface SecurityOperationSourceReceipt {
  coverage?: "complete" | "partial";
  fresh_until?: string;
  observed_at: string;
  required: boolean;
  result_digest?: string;
  result_ref?: string;
  source_id: string;
  state: "succeeded" | "unavailable";
}

export interface SecurityOperationDigestItem {
  detail: string;
  item_id: string;
  owner_ref?: string;
  priority: "critical" | "high" | "medium" | "low" | "none";
  source_ids: readonly string[];
  state: string;
  title: string;
}

export interface SecurityOperationDigestSection {
  items: readonly SecurityOperationDigestItem[];
  section_id: string;
  title: string;
}

export interface SecurityOperationArtifactSpec {
  artifact_id: string;
  format: "csv" | "png";
  purpose: "operator_queue" | "status_chart";
  title: string;
}

export interface SecurityOperationDigestPolicyInput {
  generated_at: string;
  kind: SecurityOperationDigestKind;
  previous_content_digest?: string;
  run_key: string;
  schema_version: "security-digest-policy-input/v1";
  sections: readonly SecurityOperationDigestSection[];
  sources: readonly SecurityOperationSourceReceipt[];
}

export type SecurityOperationDigestPlan =
  | {
      completeness: "complete" | "partial";
      artifact_specs: readonly SecurityOperationArtifactSpec[];
      content_digest: string;
      disposition: "publish";
      generated_at: string;
      kind: SecurityOperationDigestKind;
      plan_id: string;
      schema_version: "security-digest-plan/v1";
      sections: readonly SecurityOperationDigestSection[];
      source_refs: readonly string[];
      source_receipts: readonly SecurityOperationSourceReceipt[];
    }
  | {
      content_digest: string;
      disposition: "suppress";
      plan_id: string;
      reason_code: "unchanged";
      schema_version: "security-digest-plan/v1";
    }
  | {
      disposition: "unavailable";
      plan_id: string;
      reason_code: "item_source_unavailable" | "required_source_incomplete" | "required_source_stale" | "required_source_unavailable" | "no_successful_sources";
      schema_version: "security-digest-plan/v1";
    };

export interface SecurityOperationArtifact {
  alt_text: string;
  artifact_id: string;
  content_digest: string;
  content_ref: string;
  created_at: string;
  evidence_refs: readonly string[];
  mime_type: "application/pdf" | "image/png" | "text/csv";
  schema_version: "slack-artifact/v1";
  size_bytes: number;
  title: string;
}

export type SecurityOperationArtifactPlan =
  | {
      artifact_refs: readonly string[];
      delivery_id: string;
      destination_ref: string;
      disposition: "upload";
      message_ref: string;
      schema_version: "slack-artifact-delivery-plan/v1";
    }
  | {
      delivery_id: string;
      disposition: "unavailable";
      reason_code: "missing_artifact" | "missing_evidence" | "no_artifacts" | "unexpected_artifact";
      schema_version: "slack-artifact-delivery-plan/v1";
    };

export interface TranscriptActionSource {
  captured_at: string;
  schema_version: "transcript-source/v1";
  transcript_digest: string;
  transcript_ref: string;
}

export interface TranscriptActionDraft {
  action_id: string;
  description: string;
  due_at?: string;
  evidence: readonly { locator: string; transcript_ref: string }[];
  owner_ref?: string;
  schema_version: "transcript-action-draft/v1";
  state: "draft";
  ticket_system: "jira" | "linear";
  title: string;
}

export interface TranscriptActionApproval {
  approval_id: string;
  approved_action_ids: readonly string[];
  approved_at: string;
  approved_by_ref: string;
  plan_id: string;
  schema_version: "transcript-action-approval/v1";
}

export interface TranscriptTicketWriteIntent {
  action_id: string;
  description: string;
  due_at?: string;
  evidence: readonly { locator: string; transcript_ref: string }[];
  idempotency_key: string;
  owner_ref?: string;
  schema_version: "transcript-ticket-write-intent/v1";
  ticket_system: "jira" | "linear";
  title: string;
}

export type TranscriptActionPlan =
  | {
      action_ids: readonly string[];
      disposition: "await_approval";
      plan_id: string;
      proposal_digest: string;
      schema_version: "transcript-action-plan/v1";
    }
  | {
      disposition: "write_tickets";
      intents: readonly TranscriptTicketWriteIntent[];
      plan_id: string;
      approval_id: string;
      schema_version: "transcript-action-plan/v1";
    };

/** Exact public functions are injected after the security operations source lock passes. */
export interface PortableSecurityOperationsContract {
  planSecurityDigest(input: SecurityOperationDigestPolicyInput): SecurityOperationDigestPlan;
  planSlackArtifactDelivery(input: {
    artifact_specs: readonly SecurityOperationArtifactSpec[];
    artifacts: readonly SecurityOperationArtifact[];
    destination_ref: string;
    evidence_refs: readonly string[];
    message_ref: string;
    schema_version: "slack-artifact-delivery-policy-input/v1";
  }): SecurityOperationArtifactPlan;
  planTranscriptActions(input: {
    approval?: TranscriptActionApproval;
    drafts: readonly TranscriptActionDraft[];
    schema_version: "transcript-action-policy-input/v1";
    source: TranscriptActionSource;
  }): TranscriptActionPlan;
}

export interface SecurityOperationWorkflowBinding {
  destination_ref: string;
  schedule_ref: string;
  workflow_id: (typeof SECURITY_OPERATION_WORKFLOWS)[number]["workflow_id"];
}

export interface SecurityOperationCollectorPort {
  collect(input: {
    deadline_at: string;
    kind: SecurityOperationDigestKind;
    run_key: string;
  }): Promise<{
    sections: readonly SecurityOperationDigestSection[];
    sources: readonly SecurityOperationSourceReceipt[];
  }>;
}

export interface SecurityOperationArtifactRendererPort {
  render(input: {
    deadline_at: string;
    plan: Extract<SecurityOperationDigestPlan, { disposition: "publish" }>;
  }): Promise<readonly SecurityOperationArtifact[]>;
}

export interface SecurityOperationReceiptPort {
  previousContentDigest(workflowId: string): Promise<string | undefined>;
  persistArtifactPlan(plan: SecurityOperationArtifactPlan): Promise<{ receipt_ref: string }>;
  persistDigestPlan(workflowId: string, plan: SecurityOperationDigestPlan): Promise<{ receipt_ref: string }>;
  persistTranscriptPlan(plan: TranscriptActionPlan): Promise<{ receipt_ref: string }>;
}

export interface SecurityOperationSlackPort {
  deliverDigest(
    plan: Extract<SecurityOperationDigestPlan, { disposition: "publish" }>,
    context: { destination_ref: string; idempotency_key: string },
  ): Promise<SecurityOperationEffectResult>;
  uploadArtifacts(
    plan: Extract<SecurityOperationArtifactPlan, { disposition: "upload" }>,
    context: { idempotency_key: string },
  ): Promise<SecurityOperationEffectResult>;
}

export interface SecurityOperationSchedulePort {
  register(input: SecurityOperationWorkflowBinding & { kind: SecurityOperationDigestKind }): Promise<{ receipt_ref: string }>;
}

export interface SecurityOperationTicketPort {
  write(
    intent: TranscriptTicketWriteIntent,
    context: { approval_ref: string; idempotency_key: string },
  ): Promise<SecurityOperationEffectResult>;
}

export type SecurityOperationEffectResult =
  | { outcome: "accepted"; receipt_ref: string }
  | { outcome: "unknown"; receipt_ref: string };

export type SecurityOperationEvidenceEvent = {
  event_id: string;
  kind: "artifact_outcome_unknown" | "artifact_planned" | "artifact_uploaded" | "digest_delivered" | "digest_outcome_unknown" | "digest_planned" | "schedule_registered" | "ticket_outcome_unknown" | "ticket_written" | "transcript_planned";
  outcome: string;
  receipt_ref: string;
};

export interface SecurityOperationEvidencePort {
  recordIdempotent(event: SecurityOperationEvidenceEvent): Promise<void>;
}

export class SecurityOperationHostPolicyError extends Error {}
export class SecurityOperationOutcomeUnknownError extends Error {}

export class SecurityOperationsHostAdapter {
  constructor(
    private readonly contract: PortableSecurityOperationsContract,
    private readonly ports: {
      artifacts: SecurityOperationArtifactRendererPort;
      collector: SecurityOperationCollectorPort;
      evidence: SecurityOperationEvidencePort;
      receipts: SecurityOperationReceiptPort;
      schedules: SecurityOperationSchedulePort;
      slack: SecurityOperationSlackPort;
      tickets: SecurityOperationTicketPort;
    },
  ) {}

  async registerWorkflows(
    bindings: readonly SecurityOperationWorkflowBinding[],
  ): Promise<readonly string[]> {
    if (bindings.length !== SECURITY_OPERATION_WORKFLOWS.length) {
      throw new SecurityOperationHostPolicyError("Every security operation workflow requires one binding.");
    }
    const receipts: string[] = [];
    for (const workflow of SECURITY_OPERATION_WORKFLOWS) {
      const matches = bindings.filter((binding) => binding.workflow_id === workflow.workflow_id);
      if (matches.length !== 1) {
        throw new SecurityOperationHostPolicyError(`Workflow ${workflow.workflow_id} requires one binding.`);
      }
      const binding = matches[0]!;
      opaqueRef(binding.destination_ref, "destination_ref");
      opaqueRef(binding.schedule_ref, "schedule_ref");
      const registered = await this.ports.schedules.register({ ...binding, kind: workflow.kind });
      const receiptRef = receipt(registered.receipt_ref);
      await this.ports.evidence.recordIdempotent({
        event_id: `${workflow.workflow_id}:registered`,
        kind: "schedule_registered",
        outcome: "registered",
        receipt_ref: receiptRef,
      });
      receipts.push(receiptRef);
    }
    return Object.freeze(receipts);
  }

  async runDigest(input: {
    collection_deadline_at: string;
    destination_ref: string;
    generated_at: string;
    run_key: string;
    workflow_id: SecurityOperationWorkflowBinding["workflow_id"];
  }): Promise<SecurityOperationDigestPlan> {
    opaqueRef(input.destination_ref, "destination_ref");
    deadline(input.generated_at, input.collection_deadline_at);
    const workflow = SECURITY_OPERATION_WORKFLOWS.find((item) => item.workflow_id === input.workflow_id);
    if (!workflow) throw new SecurityOperationHostPolicyError("The security operation workflow is unknown.");
    const collected = await this.ports.collector.collect({ deadline_at: input.collection_deadline_at, kind: workflow.kind, run_key: input.run_key });
    const previous = await this.ports.receipts.previousContentDigest(workflow.workflow_id);
    const plan = this.contract.planSecurityDigest({
      generated_at: input.generated_at,
      kind: workflow.kind,
      previous_content_digest: previous,
      run_key: input.run_key,
      schema_version: "security-digest-policy-input/v1",
      sections: collected.sections,
      sources: collected.sources,
    });
    const durable = receipt((await this.ports.receipts.persistDigestPlan(workflow.workflow_id, plan)).receipt_ref);
    await this.ports.evidence.recordIdempotent({
      event_id: `${plan.plan_id}:planned`,
      kind: "digest_planned",
      outcome: plan.disposition,
      receipt_ref: durable,
    });
    if (plan.disposition !== "publish") return plan;

    const digestEffect = await this.ports.slack.deliverDigest(plan, {
      destination_ref: input.destination_ref,
      idempotency_key: plan.plan_id,
    });
    const delivered = receipt(digestEffect.receipt_ref);
    await this.ports.evidence.recordIdempotent({
      event_id: `${plan.plan_id}:${digestEffect.outcome}`,
      kind: digestEffect.outcome === "accepted" ? "digest_delivered" : "digest_outcome_unknown",
      outcome: digestEffect.outcome === "accepted" ? plan.completeness : "outcome_unknown",
      receipt_ref: delivered,
    });
    if (digestEffect.outcome === "unknown") {
      throw new SecurityOperationOutcomeUnknownError("Digest delivery outcome is unknown; reconcile the stable idempotency key before retrying.");
    }

    const artifacts = await this.ports.artifacts.render({ deadline_at: input.collection_deadline_at, plan });
    if (artifacts.length === 0) return plan;
    const artifactPlan = this.contract.planSlackArtifactDelivery({
      artifact_specs: plan.artifact_specs,
      artifacts,
      destination_ref: input.destination_ref,
      evidence_refs: plan.source_refs,
      message_ref: `digest:${plan.plan_id}`,
      schema_version: "slack-artifact-delivery-policy-input/v1",
    });
    const artifactDurable = receipt((await this.ports.receipts.persistArtifactPlan(artifactPlan)).receipt_ref);
    await this.ports.evidence.recordIdempotent({
      event_id: `${artifactPlan.delivery_id}:planned`,
      kind: "artifact_planned",
      outcome: artifactPlan.disposition,
      receipt_ref: artifactDurable,
    });
    if (artifactPlan.disposition !== "upload") return plan;
    const artifactEffect = await this.ports.slack.uploadArtifacts(artifactPlan, {
      idempotency_key: artifactPlan.delivery_id,
    });
    const uploaded = receipt(artifactEffect.receipt_ref);
    await this.ports.evidence.recordIdempotent({
      event_id: `${artifactPlan.delivery_id}:${artifactEffect.outcome}`,
      kind: artifactEffect.outcome === "accepted" ? "artifact_uploaded" : "artifact_outcome_unknown",
      outcome: artifactEffect.outcome === "accepted" ? `${artifactPlan.artifact_refs.length}` : "outcome_unknown",
      receipt_ref: uploaded,
    });
    if (artifactEffect.outcome === "unknown") {
      throw new SecurityOperationOutcomeUnknownError("Artifact delivery outcome is unknown; reconcile the stable idempotency key before retrying.");
    }
    return plan;
  }

  async prepareTranscriptActions(input: {
    drafts: readonly TranscriptActionDraft[];
    source: TranscriptActionSource;
  }): Promise<TranscriptActionPlan> {
    const plan = this.contract.planTranscriptActions({
      drafts: input.drafts,
      schema_version: "transcript-action-policy-input/v1",
      source: input.source,
    });
    if (plan.disposition !== "await_approval") {
      throw new SecurityOperationHostPolicyError("Unapproved transcript actions cannot create ticket writes.");
    }
    const durable = receipt((await this.ports.receipts.persistTranscriptPlan(plan)).receipt_ref);
    await this.ports.evidence.recordIdempotent({
      event_id: `${plan.plan_id}:drafted`,
      kind: "transcript_planned",
      outcome: plan.disposition,
      receipt_ref: durable,
    });
    return plan;
  }

  async executeApprovedTranscriptActions(input: {
    approval: TranscriptActionApproval;
    approval_ref: string;
    drafts: readonly TranscriptActionDraft[];
    source: TranscriptActionSource;
  }): Promise<readonly string[]> {
    opaqueRef(input.approval_ref, "approval_ref");
    const plan = this.contract.planTranscriptActions({
      approval: input.approval,
      drafts: input.drafts,
      schema_version: "transcript-action-policy-input/v1",
      source: input.source,
    });
    if (plan.disposition !== "write_tickets") {
      throw new SecurityOperationHostPolicyError("The public contract did not authorize ticket writes.");
    }
    const durable = receipt((await this.ports.receipts.persistTranscriptPlan(plan)).receipt_ref);
    await this.ports.evidence.recordIdempotent({
      event_id: `${plan.plan_id}:approved`,
      kind: "transcript_planned",
      outcome: plan.disposition,
      receipt_ref: durable,
    });
    const receipts: string[] = [];
    for (const intent of plan.intents) {
      const ticketEffect = await this.ports.tickets.write(intent, {
        approval_ref: input.approval_ref,
        idempotency_key: intent.idempotency_key,
      });
      const written = receipt(ticketEffect.receipt_ref);
      await this.ports.evidence.recordIdempotent({
        event_id: `${intent.idempotency_key}:${ticketEffect.outcome}`,
        kind: ticketEffect.outcome === "accepted" ? "ticket_written" : "ticket_outcome_unknown",
        outcome: ticketEffect.outcome === "accepted" ? intent.ticket_system : "outcome_unknown",
        receipt_ref: written,
      });
      if (ticketEffect.outcome === "unknown") {
        throw new SecurityOperationOutcomeUnknownError("Ticket write outcome is unknown; reconcile the stable idempotency key before retrying.");
      }
      receipts.push(written);
    }
    return Object.freeze(receipts);
  }
}

function opaqueRef(value: string, field: string): string {
  if (typeof value !== "string" || value.length > 2_048 || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/.test(value)) {
    throw new SecurityOperationHostPolicyError(`${field} must be an opaque reference.`);
  }
  return value;
}

function receipt(value: string): string {
  return opaqueRef(value, "receipt_ref");
}

function deadline(startedAt: string, deadlineAt: string): void {
  const started = Date.parse(startedAt);
  const limit = Date.parse(deadlineAt);
  if (!Number.isFinite(started) || !Number.isFinite(limit) || limit <= started || limit - started > 15 * 60_000) {
    throw new SecurityOperationHostPolicyError("collection_deadline_at must be within 15 minutes after generated_at.");
  }
}
