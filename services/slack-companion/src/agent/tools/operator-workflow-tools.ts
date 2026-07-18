import { createHash } from "node:crypto";
import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { RuntimeCodeWorkspace } from "../../code/runtime-code.js";
import type { Finding, RuntimeHealth } from "../../cerebro/types.js";
import { findingLifecyclePreflight } from "../../compliance/lifecycle-preflight.js";
import type { SecurityMemoryKind, SecurityMemoryPromotionState, SecurityMemoryStalenessPolicy } from "../../learning/memory-types.js";
import { trimForSlack } from "../../slack/format.js";
import { findingInvestigation } from "./cerebro-finding-tools.js";
import {
  limit,
  normalizeFindingOrder,
  normalizeFindingStatus,
  shortError,
  stringList,
  stringValue,
  unique,
} from "./normalizers.js";
import { ticketingStatus } from "./ticket-tools.js";
import type { SecurityToolDeps } from "./types.js";
import { safeToolResult, toolResult } from "./tool-result.js";
import { buildOperatorAgentRunContext, type OperatorAgentRunArgs } from "./agent-run-input.js";
import { securityMissionInputIdSchema, securityMissionPackIdSchema, type SecurityMissionInputId } from "../../autonomy/mission-types.js";

const sourceRunActions = ["sync", "graph_ingest", "finding_evaluate"] as const;
const findingUpdateActions = ["note", "assign", "due", "link_ticket", "resolve", "suppress"] as const;

type SourceRunAction = typeof sourceRunActions[number];
type FindingUpdateAction = typeof findingUpdateActions[number];

export function createOperatorWorkflowTools(deps: SecurityToolDeps): AgentTool[] {
  const statusParams = Type.Object({});
  const guardrailParams = Type.Object({
    action: Type.String(),
    target_system: Type.Optional(Type.String()),
    requested_stage: Type.Optional(Type.String()),
    has_human_approval: Type.Optional(Type.Boolean()),
    has_dry_run: Type.Optional(Type.Boolean()),
    evidence_refs: Type.Optional(Type.Array(Type.String())),
    ticket_refs: Type.Optional(Type.Array(Type.String())),
    changes_production: Type.Optional(Type.Boolean()),
    exposes_secret: Type.Optional(Type.Boolean()),
  });
  const auditParams = Type.Object({
    action: Type.String(),
    target_system: Type.String(),
    target_id: Type.Optional(Type.String()),
    status: Type.Optional(Type.String()),
    requested_by: Type.Optional(Type.String()),
    channel_id: Type.Optional(Type.String()),
    thread_ts: Type.Optional(Type.String()),
    evidence_refs: Type.Optional(Type.Array(Type.String())),
    ticket_refs: Type.Optional(Type.Array(Type.String())),
    decision: Type.Optional(Type.String()),
    result_url: Type.Optional(Type.String()),
    idempotency_key: Type.Optional(Type.String()),
  });
  const operatorMemoryParams = Type.Object({
    kind: Type.String(),
    topic: Type.String(),
    summary: Type.String(),
    details: Type.Optional(Type.String()),
    confidence: Type.Optional(Type.Number()),
    entities: Type.Optional(Type.Array(Type.String())),
    evidence_refs: Type.Optional(Type.Array(Type.String())),
    ticket_refs: Type.Optional(Type.Array(Type.String())),
    channel_id: Type.Optional(Type.String()),
    thread_ts: Type.Optional(Type.String()),
    source_ts: Type.Optional(Type.String()),
    verified_by: Type.Optional(Type.Array(Type.String())),
    staleness_policy: Type.Optional(Type.String()),
    promotion_state: Type.Optional(Type.String()),
  });
  const goalParams = Type.Object({
    objective: Type.String(),
    mission_pack_id: Type.Optional(Type.String()),
    mission_bindings: Type.Optional(Type.Record(Type.String(), Type.String(), { maxProperties: 20 })),
    channel_id: Type.Optional(Type.String()),
    thread_ts: Type.Optional(Type.String()),
    requested_by_slack_user_id: Type.Optional(Type.String()),
    requested_by_display_name: Type.Optional(Type.String()),
    assumptions: Type.Optional(Type.Array(Type.String(), { maxItems: 20 })),
    resources: Type.Optional(Type.Array(Type.Object({
      kind: Type.Union([
        Type.Literal("cerebro"),
        Type.Literal("github"),
        Type.Literal("slack"),
        Type.Literal("jira"),
        Type.Literal("linear"),
        Type.Literal("aws"),
        Type.Literal("panther"),
        Type.Literal("evidence"),
        Type.Literal("artifact"),
        Type.Literal("person"),
        Type.Literal("service"),
        Type.Literal("generic"),
      ]),
      id: Type.String(),
      source: Type.Optional(Type.String()),
      label: Type.Optional(Type.String()),
      observed_at: Type.Optional(Type.String()),
      valid_until: Type.Optional(Type.String()),
      evidence_receipt: Type.Optional(Type.String()),
      confidence: Type.Optional(Type.Number({ minimum: 0, maximum: 1 })),
      links: Type.Optional(Type.Array(Type.Object({ relation: Type.String(), target_uri: Type.String() }), { maxItems: 20 })),
    }), { maxItems: 40 })),
    acceptance_criteria: Type.Optional(Type.Array(Type.Object({
      id: Type.String(),
      description: Type.String(),
      kind: Type.Union([
        Type.Literal("tool_success"),
        Type.Literal("field_present"),
        Type.Literal("field_equals"),
        Type.Literal("resource_ref"),
        Type.Literal("artifact"),
        Type.Literal("manual"),
      ]),
      field: Type.Optional(Type.String()),
      expected: Type.Optional(Type.Union([Type.String(), Type.Number(), Type.Boolean()])),
    }), { maxItems: 40 })),
    plan: Type.Optional(Type.Array(Type.Object({
      id: Type.String(),
      title: Type.String(),
      depends_on: Type.Optional(Type.Array(Type.String(), { maxItems: 16 })),
      tool_name: Type.Optional(Type.String()),
      tool_arguments: Type.Optional(Type.Record(Type.String(), Type.Any(), { maxProperties: 40 })),
      verification_tool_name: Type.Optional(Type.String()),
      verification_arguments: Type.Optional(Type.Record(Type.String(), Type.Any(), { maxProperties: 40 })),
      approval_required: Type.Optional(Type.Boolean()),
      idempotency_key: Type.Optional(Type.String()),
      rollback: Type.Optional(Type.String()),
      max_attempts: Type.Optional(Type.Number({ minimum: 1, maximum: 3 })),
      acceptance_criteria_ids: Type.Optional(Type.Array(Type.String(), { maxItems: 40 })),
    }), { maxItems: 16 })),
  });
  const handoffParams = Type.Object({
    title: Type.String(),
    status: Type.Optional(Type.String()),
    summary: Type.String(),
    blockers: Type.Optional(Type.Array(Type.String())),
    next_actions: Type.Optional(Type.Array(Type.String())),
    evidence_refs: Type.Optional(Type.Array(Type.String())),
    ticket_refs: Type.Optional(Type.Array(Type.String())),
    owners: Type.Optional(Type.Array(Type.String())),
    channel_id: Type.Optional(Type.String()),
    thread_ts: Type.Optional(Type.String()),
  });
  const notificationParams = Type.Object({
    subject: Type.String(),
    status: Type.String(),
    summary: Type.String(),
    audience: Type.Optional(Type.String()),
    channel_id: Type.Optional(Type.String()),
    thread_ts: Type.Optional(Type.String()),
    owner: Type.Optional(Type.String()),
    next_actions: Type.Optional(Type.Array(Type.String())),
    evidence_refs: Type.Optional(Type.Array(Type.String())),
    ticket_refs: Type.Optional(Type.Array(Type.String())),
  });
  const playbookParams = Type.Object({
    playbook: Type.String(),
    action: Type.Optional(Type.String()),
    runtime_id: Type.Optional(Type.String()),
    finding_id: Type.Optional(Type.String()),
    issue_key: Type.Optional(Type.String()),
    target_system: Type.Optional(Type.String()),
  });
  const ownerParams = Type.Object({
    runtime_id: Type.Optional(Type.String()),
    finding_id: Type.Optional(Type.String()),
    resource_urn: Type.Optional(Type.String()),
    owner_hints: Type.Optional(Type.Array(Type.String())),
    context: Type.Optional(Type.String()),
    slack_channel_id: Type.Optional(Type.String()),
  });
  const evidenceBundleParams = Type.Object({
    runtime_id: Type.Optional(Type.String()),
    finding_id: Type.Optional(Type.String()),
    question: Type.Optional(Type.String()),
    entities: Type.Optional(Type.Array(Type.String())),
    evidence_limit: Type.Optional(Type.Number()),
    related_limit: Type.Optional(Type.Number()),
    include_graph: Type.Optional(Type.Boolean()),
  });
  const findingLookupParams = Type.Object({
    runtime_id: Type.Optional(Type.String()),
    runtime_ids: Type.Optional(Type.Array(Type.String())),
    status: Type.Optional(Type.String()),
    severity: Type.Optional(Type.String()),
    finding_id: Type.Optional(Type.String()),
    rule_id: Type.Optional(Type.String()),
    order: Type.Optional(Type.String()),
    limit: Type.Optional(Type.Number()),
  });
  const sourceRunStatusParams = Type.Object({
    runtime_id: Type.Optional(Type.String()),
    runtime_ids: Type.Optional(Type.Array(Type.String())),
    source_id: Type.Optional(Type.String()),
    max_stale_minutes: Type.Optional(Type.Number()),
    limit: Type.Optional(Type.Number()),
  });
  const sourceRunTriggerParams = Type.Object({
    runtime_id: Type.String(),
    action: Type.String(),
    reason: Type.Optional(Type.String()),
    ticket_url: Type.Optional(Type.String()),
    execute: Type.Optional(Type.Boolean()),
    approved: Type.Optional(Type.Boolean()),
  });
  const findingUpdateParams = Type.Object({
    finding_id: Type.String(),
    action: Type.String(),
    runtime_id: Type.Optional(Type.String()),
    note: Type.Optional(Type.String()),
    assignee: Type.Optional(Type.String()),
    due_at: Type.Optional(Type.String()),
    ticket_url: Type.Optional(Type.String()),
    ticket_name: Type.Optional(Type.String()),
    external_id: Type.Optional(Type.String()),
    reason: Type.Optional(Type.String()),
    evidence_refs: Type.Optional(Type.Array(Type.String())),
    ticket_refs: Type.Optional(Type.Array(Type.String())),
    exception_refs: Type.Optional(Type.Array(Type.String())),
    approval_refs: Type.Optional(Type.Array(Type.String())),
    dry_run_refs: Type.Optional(Type.Array(Type.String())),
    rollback_plan: Type.Optional(Type.String()),
    execute: Type.Optional(Type.Boolean()),
    approved: Type.Optional(Type.Boolean()),
  });

  return [
    {
      name: "operator_tool_status",
      label: "Operator tool status",
      description: "Read configured Cerebro, Slack, Jira, Infisical, EvidenceCAS, and runtime-code readiness without returning secret values.",
      parameters: statusParams,
      execute: async () => toolResult(operatorToolStatus(deps)),
    },
    {
      name: "operator_policy_guardrail_check",
      label: "Operator policy guardrail check",
      description: "Check whether a proposed operator action is read-only, approval-ready, approval-required, or blocked before using write tools.",
      parameters: guardrailParams,
      execute: async (_toolCallId, params) => toolResult(operatorPolicyGuardrailCheck(params as GuardrailArgs)),
    },
    {
      name: "operator_action_audit_log",
      label: "Operator action audit log",
      description: "Build a sanitized audit record for a planned, dry-run, approved, executed, blocked, or failed operator action. This returns the record; it does not persist it.",
      parameters: auditParams,
      execute: async (_toolCallId, params) => toolResult(operatorActionAuditRecord(params as AuditArgs)),
    },
    {
      name: "operator_memory_record",
      label: "Operator memory record",
      description: "Persist one non-secret operator record as a fact, claim, decision, risk, blocker, handoff, or source-health note. Use after source-backed checks so future work can resume from the operating state.",
      parameters: operatorMemoryParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => operatorMemoryRecord(deps, params as OperatorMemoryArgs)),
    },
    {
      name: "operator_goal_create",
      label: "Operator goal create",
      description: "Create one durable autonomous goal for broad security work that should continue beyond the current Slack answer. Use only after the normal assistant loop has inspected the request and the objective is safe to checkpoint.",
      parameters: goalParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => operatorGoalCreate(deps, params as OperatorGoalArgs)),
    },
    {
      name: "operator_handoff_packet",
      label: "Operator handoff packet",
      description: "Build a concise handoff packet with state, blockers, evidence, tickets, owners, and next actions for another operator or thread.",
      parameters: handoffParams,
      execute: async (_toolCallId, params) => toolResult(operatorHandoffPacket(params as HandoffArgs)),
    },
    {
      name: "operator_notification_plan",
      label: "Operator notification plan",
      description: "Draft a Slack-ready operator update for a channel or thread. This does not send a Slack message.",
      parameters: notificationParams,
      execute: async (_toolCallId, params) => toolResult(operatorNotificationPlan(params as NotificationArgs)),
    },
    {
      name: "operator_playbook_plan",
      label: "Operator playbook plan",
      description: "Return the next tool sequence for a common Cerebro operator playbook such as finding triage, Jira creation, source refresh, or approved finding update.",
      parameters: playbookParams,
      execute: async (_toolCallId, params) => toolResult(operatorPlaybookPlan(params as PlaybookArgs)),
    },
    {
      name: "owner_resolve",
      label: "Owner resolve",
      description: "Resolve likely owners from finding metadata, resource URNs, Slack context, and supplied hints. Returns candidates and evidence; it does not assign work.",
      parameters: ownerParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => ownerResolve(deps, params as OwnerArgs)),
    },
    {
      name: "evidence_bundle_get",
      label: "Evidence bundle get",
      description: "Build one operator evidence bundle from a finding investigation or a Cerebro evidence-packet question.",
      parameters: evidenceBundleParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => evidenceBundleGet(deps, params as EvidenceBundleArgs)),
    },
    {
      name: "finding_lookup",
      label: "Finding lookup",
      description: "Look up Cerebro findings across one runtime, a list of runtimes, or the configured default runtimes.",
      parameters: findingLookupParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => findingLookup(deps, params as FindingLookupArgs)),
    },
    {
      name: "source_run_status",
      label: "Source run status",
      description: "Read source runtime health and mark runtimes stale when returned timestamps exceed the supplied freshness window.",
      parameters: sourceRunStatusParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => sourceRunStatus(deps, params as SourceRunStatusArgs)),
    },
    {
      name: "source_run_trigger",
      label: "Source run trigger",
      description: "Plan or execute one approved Cerebro source run action: sync, graph_ingest, or finding_evaluate. Execution requires execute=true and approved=true.",
      parameters: sourceRunTriggerParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => sourceRunTrigger(deps, params as SourceRunTriggerArgs)),
    },
    {
      name: "finding_update",
      label: "Finding update",
      description: "Plan or execute one approved Cerebro finding update: note, assign, due, link_ticket, resolve, or suppress. Execution requires execute=true and approved=true.",
      parameters: findingUpdateParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => findingUpdate(deps, params as FindingUpdateArgs)),
    },
  ];
}

interface GuardrailArgs {
  action?: string;
  target_system?: string;
  requested_stage?: string;
  has_human_approval?: boolean;
  has_dry_run?: boolean;
  evidence_refs?: string[];
  ticket_refs?: string[];
  changes_production?: boolean;
  exposes_secret?: boolean;
}

interface AuditArgs {
  action?: string;
  target_system?: string;
  target_id?: string;
  status?: string;
  requested_by?: string;
  channel_id?: string;
  thread_ts?: string;
  evidence_refs?: string[];
  ticket_refs?: string[];
  decision?: string;
  result_url?: string;
  idempotency_key?: string;
}

interface OperatorMemoryArgs {
  kind?: string;
  topic?: string;
  summary?: string;
  details?: string;
  confidence?: number;
  entities?: string[];
  evidence_refs?: string[];
  ticket_refs?: string[];
  channel_id?: string;
  thread_ts?: string;
  source_ts?: string;
  verified_by?: string[];
  staleness_policy?: string;
  promotion_state?: string;
}

interface OperatorGoalArgs extends OperatorAgentRunArgs {
  objective?: string;
  channel_id?: string;
  thread_ts?: string;
  requested_by_slack_user_id?: string;
  requested_by_display_name?: string;
  mission_pack_id?: string;
  mission_bindings?: Record<string, string>;
}

interface HandoffArgs {
  title?: string;
  status?: string;
  summary?: string;
  blockers?: string[];
  next_actions?: string[];
  evidence_refs?: string[];
  ticket_refs?: string[];
  owners?: string[];
  channel_id?: string;
  thread_ts?: string;
}

interface NotificationArgs {
  subject?: string;
  status?: string;
  summary?: string;
  audience?: string;
  channel_id?: string;
  thread_ts?: string;
  owner?: string;
  next_actions?: string[];
  evidence_refs?: string[];
  ticket_refs?: string[];
}

interface PlaybookArgs {
  playbook?: string;
  action?: string;
  runtime_id?: string;
  finding_id?: string;
  issue_key?: string;
  target_system?: string;
}

interface OwnerArgs {
  runtime_id?: string;
  finding_id?: string;
  resource_urn?: string;
  owner_hints?: string[];
  context?: string;
  slack_channel_id?: string;
}

interface EvidenceBundleArgs {
  runtime_id?: string;
  finding_id?: string;
  question?: string;
  entities?: string[];
  evidence_limit?: number;
  related_limit?: number;
  include_graph?: boolean;
}

interface FindingLookupArgs {
  runtime_id?: string;
  runtime_ids?: string[];
  status?: string;
  severity?: string;
  finding_id?: string;
  rule_id?: string;
  order?: string;
  limit?: number;
}

interface SourceRunStatusArgs {
  runtime_id?: string;
  runtime_ids?: string[];
  source_id?: string;
  max_stale_minutes?: number;
  limit?: number;
}

interface SourceRunTriggerArgs {
  runtime_id?: string;
  action?: string;
  reason?: string;
  ticket_url?: string;
  execute?: boolean;
  approved?: boolean;
}

interface FindingUpdateArgs {
  finding_id?: string;
  action?: string;
  runtime_id?: string;
  note?: string;
  assignee?: string;
  due_at?: string;
  ticket_url?: string;
  ticket_name?: string;
  external_id?: string;
  reason?: string;
  evidence_refs?: string[];
  ticket_refs?: string[];
  exception_refs?: string[];
  approval_refs?: string[];
  dry_run_refs?: string[];
  rollback_plan?: string;
  execute?: boolean;
  approved?: boolean;
}

function operatorToolStatus(deps: SecurityToolDeps): Record<string, unknown> {
  const code = new RuntimeCodeWorkspace(deps.config);
  return {
    tenant_id: deps.config.cerebro.tenantId,
    companion_runtime_id: deps.config.cerebro.companionRuntimeId,
    default_runtime_ids: deps.config.cerebro.defaultRuntimeIds,
    cerebro: {
      base_url_configured: Boolean(deps.config.cerebro.baseUrl),
      web_base_url_configured: Boolean(deps.config.cerebro.webBaseUrl),
      read_key_configured: Boolean(deps.config.cerebro.apiKeys.read),
      findings_write_key_configured: Boolean(deps.config.cerebro.apiKeys.findings),
      source_write_key_configured: Boolean(deps.config.cerebro.apiKeys.source),
      runtime_response_key_configured: Boolean(deps.config.cerebro.apiKeys.runtimeResponse),
      graph_actions_key_configured: Boolean(deps.config.cerebro.apiKeys.graphActions),
    },
    slack: {
      bot_token_configured: Boolean(deps.config.slack.botToken),
      default_channel_configured: Boolean(deps.config.slack.defaultChannelId),
      triage_channels: [...deps.config.slack.triageChannelIds],
      operator_user_ids_configured: deps.config.slack.operatorUserIds.size,
      source_write_user_ids_configured: deps.config.slack.sourceWriteUserIds.size,
      finding_write_user_ids_configured: deps.config.slack.findingWriteUserIds.size,
      graph_action_user_ids_configured: deps.config.slack.graphActionUserIds.size,
    },
    ticketing: ticketingStatus(deps),
    infisical: {
      enabled: deps.config.infisical.enabled,
      project_configured: Boolean(deps.config.infisical.projectId || deps.config.infisical.projectSlug),
      identity_configured: Boolean(deps.config.infisical.identityId),
      environment: deps.config.infisical.environment,
      secret_path: deps.config.infisical.secretPath,
      secret_values_allowed: deps.config.infisical.allowSecretValues,
    },
    evidence_cas: {
      base_url_configured: Boolean(deps.config.evidenceCas.baseUrl),
      read_token_configured: Boolean(deps.config.evidenceCas.readToken || deps.config.evidenceCas.readTokenInfisicalSecretName),
      default_bucket: deps.config.evidenceCas.defaultBucket,
    },
    runtime_code: code.status(),
    note: "Status fields are configuration booleans and names only; secret values are not returned.",
  };
}

function operatorPolicyGuardrailCheck(args: GuardrailArgs): Record<string, unknown> {
  const action = stringValue(args.action) ?? "";
  const targetSystem = stringValue(args.target_system) ?? "unspecified";
  const normalized = `${action} ${targetSystem} ${args.requested_stage ?? ""}`.toLowerCase();
  const evidenceRefs = stringList(args.evidence_refs) ?? [];
  const ticketRefs = stringList(args.ticket_refs) ?? [];
  const blockers: string[] = [];
  if (args.exposes_secret === true || /\b(secret|token|api key|private key|credential)\b/.test(normalized) && /\b(show|print|dump|exfiltrate|copy|return|paste)\b/.test(normalized)) {
    blockers.push("Secret or credential exposure is blocked.");
  }
  if (/\b(disable|remove|bypass)\b/.test(normalized) && /\b(audit|exfil|guardrail|telemetry|logging)\b/.test(normalized)) {
    blockers.push("Disabling audit, telemetry, exfiltration, or guardrail controls is blocked.");
  }
  if (/\b(workspace escape|path traversal|outside workspace)\b/.test(normalized)) {
    blockers.push("Workspace escape is blocked.");
  }

  const ticketWrite = /\b(jira|linear|ticket)\b/.test(normalized) && /\b(create|update|comment|transition|label|link)\b/.test(normalized);
  const productionChange = args.changes_production === true
    || /\b(resolve|suppress|sync|ingest|evaluate|revoke|suspend|unsuspend|deploy|rollout|delete|disable|enable|apply|execute)\b/.test(normalized)
    || /\b(prod|production|infra|graph|finding|source runtime|data)\b/.test(normalized);
  const requirements = [
    productionChange && !args.has_dry_run ? "dry_run_evidence" : "",
    productionChange && evidenceRefs.length === 0 ? "evidence_refs" : "",
    productionChange && !args.has_human_approval ? "human_approval" : "",
    productionChange && ticketRefs.length === 0 ? "ticket_or_audit_reference" : "",
  ].filter(Boolean);

  if (blockers.length > 0) {
    return {
      action,
      target_system: targetSystem,
      decision: "blocked",
      allowed_next_stage: "stop",
      blockers,
      requirements,
    };
  }
  if (productionChange && requirements.length > 0) {
    return {
      action,
      target_system: targetSystem,
      decision: "approval_required",
      allowed_next_stage: "dry_run",
      blockers: [],
      requirements,
      note: "Collect dry-run evidence, an audit or ticket reference, and reviewed human approval before execution.",
    };
  }
  if (productionChange) {
    return {
      action,
      target_system: targetSystem,
      decision: "approval_ready",
      allowed_next_stage: "execute",
      blockers: [],
      requirements: [],
    };
  }
  if (ticketWrite) {
    return {
      action,
      target_system: targetSystem,
      decision: "response_action",
      allowed_next_stage: "ticket_write",
      blockers: [],
      requirements: [],
    };
  }
  return {
    action,
    target_system: targetSystem,
    decision: "read_only",
    allowed_next_stage: "investigate",
    blockers: [],
    requirements: [],
  };
}

function operatorActionAuditRecord(args: AuditArgs): Record<string, unknown> {
  const action = stringValue(args.action) ?? "unspecified";
  const targetSystem = stringValue(args.target_system) ?? "unspecified";
  const targetId = stringValue(args.target_id);
  const status = stringValue(args.status) ?? "planned";
  const evidenceRefs = stringList(args.evidence_refs) ?? [];
  const ticketRefs = stringList(args.ticket_refs) ?? [];
  const createdAt = new Date().toISOString();
  const auditId = stringValue(args.idempotency_key) ?? stableHash([
    action,
    targetSystem,
    targetId ?? "",
    status,
    evidenceRefs.join(","),
    ticketRefs.join(","),
  ]);
  return {
    stored: false,
    audit_id: auditId,
    created_at: createdAt,
    status,
    action,
    target_system: targetSystem,
    target_id: targetId,
    requested_by: stringValue(args.requested_by),
    slack: {
      channel_id: stringValue(args.channel_id),
      thread_ts: stringValue(args.thread_ts),
    },
    evidence_refs: evidenceRefs,
    ticket_refs: ticketRefs,
    decision: stringValue(args.decision),
    result_url: stringValue(args.result_url),
    secret_values_stored: false,
    note: "This tool returns a sanitized audit record only. Persist it in the approved system of record if durable audit storage is required.",
  };
}

async function operatorMemoryRecord(deps: SecurityToolDeps, args: OperatorMemoryArgs): Promise<Record<string, unknown>> {
  const kind = operatorMemoryKind(args.kind);
  if (!kind) {
    return {
      stored: false,
      error: "unsupported_operator_memory_kind",
      allowed_kinds: OPERATOR_MEMORY_KINDS,
    };
  }
  const topic = stringValue(args.topic);
  const summary = stringValue(args.summary);
  if (!topic || !summary) {
    return { stored: false, error: "topic_and_summary_required" };
  }
  const sourceArtifacts = unique([
    ...(stringList(args.evidence_refs) ?? []),
    ...(stringList(args.ticket_refs) ?? []),
  ]).slice(0, 16);
  const record = await deps.memory.remember({
    kind,
    topic,
    summary,
    details: stringValue(args.details),
    tags: unique(["operator-vault", kind, ...sourceArtifacts.map(sourceArtifactTag)]).slice(0, 12),
    channelId: stringValue(args.channel_id),
    sourceTs: stringValue(args.source_ts) ?? stringValue(args.thread_ts),
    classification: kind,
    confidence: boundedConfidence(args.confidence),
    sourceKind: "tool",
    entities: stringList(args.entities),
    scope: args.thread_ts ? `slack-thread:${args.channel_id ?? "unknown"}:${args.thread_ts}` : undefined,
    verifiedBy: stringList(args.verified_by),
    verifiedAt: new Date().toISOString(),
    sourceArtifacts,
    stalenessPolicy: operatorStalenessPolicy(args.staleness_policy),
    promotionState: operatorPromotionState(args.promotion_state),
  });
  return {
    stored: Boolean(record),
    record: record ? {
      id: record.id,
      kind: record.kind,
      topic: record.topic,
      summary: record.summary,
      source_artifacts: record.sourceArtifacts,
      staleness_policy: record.stalenessPolicy,
      promotion_state: record.promotionState,
    } : undefined,
  };
}

async function operatorGoalCreate(deps: SecurityToolDeps, args: OperatorGoalArgs): Promise<Record<string, unknown>> {
  if (!deps.autonomyGoals) {
    return {
      created: false,
      error: "autonomy_goals_unavailable",
      message: "Durable goal creation is not configured for this assistant run.",
    };
  }
  const objective = stringValue(args.objective);
  if (!objective) return { created: false, error: "objective_required" };
  const slackUserId = stringValue(args.requested_by_slack_user_id) ?? "unknown";
  const actor = {
    slackUserId,
    actorId: slackUserId === "unknown" ? "slack:unknown" : `slack:${slackUserId}`,
    displayName: stringValue(args.requested_by_display_name),
  };
  const parsedPackId = args.mission_pack_id ? securityMissionPackIdSchema.safeParse(args.mission_pack_id) : undefined;
  if (parsedPackId && !parsedPackId.success) return { created: false, error: "unsupported_mission_pack", available_pack_ids: securityMissionPackIdSchema.options };
  if (parsedPackId?.success && args.plan?.length) return { created: false, error: "mission_plan_is_host_compiled", message: "Create the mission from its pack and bindings, then bind waiting steps through operator_agent_run_step_bind." };
  const runContext = buildOperatorAgentRunContext(args);
  const { plan } = runContext;
  const hasRunContext = Boolean(args.resources?.length || args.acceptance_criteria?.length || args.assumptions?.length);
  if (plan.length === 0 && hasRunContext && !parsedPackId?.success) return { created: false, error: "plan_required_for_agent_run_context" };
  const missionBindings = parseMissionBindings(args.mission_bindings);
  let goal;
  if (plan.length > 0) {
    const createFromPlan = deps.autonomyGoals.createFromPlan;
    if (!createFromPlan) return { created: false, error: "executable_agent_runs_unavailable" };
    goal = await createFromPlan({
      objective,
      actor,
      channelId: stringValue(args.channel_id),
      threadTs: stringValue(args.thread_ts),
      plan,
      resourceRefs: runContext.resourceRefs,
      acceptanceCriteria: runContext.acceptanceCriteria,
      assumptions: runContext.assumptions,
    });
  } else {
    goal = await deps.autonomyGoals.createFromText({
      text: objective,
      actor,
      channelId: stringValue(args.channel_id),
      threadTs: stringValue(args.thread_ts),
      missionPackId: parsedPackId?.data,
      missionBindings,
      resourceRefs: runContext.resourceRefs,
      acceptanceCriteria: runContext.acceptanceCriteria,
      assumptions: runContext.assumptions,
    });
  }
  deps.researchState?.recordCreatedGoal(goal.id);
  return {
    created: true,
    goal: {
      id: goal.id,
      status: goal.status,
      objective: goal.objective,
      capability_id: goal.capabilityId,
      channel_id: goal.channelId,
      thread_ts: goal.threadTs,
      next_wake_at: goal.nextWakeAt,
      executable_step_count: goal.currentPlan?.filter((step) => Boolean(step.execution)).length ?? 0,
      resource_count: goal.resourceRefs?.length ?? 0,
      acceptance_criterion_count: goal.acceptanceCriteria?.length ?? 0,
      mission: goal.mission ? {
        pack_id: goal.mission.packId,
        pack_version: goal.mission.packVersion,
        status: goal.mission.status,
        missing_input_ids: goal.mission.missingInputIds,
        plan_digest: goal.mission.planDigest,
      } : undefined,
    },
  };
}

function parseMissionBindings(value: Record<string, string> | undefined): Partial<Record<SecurityMissionInputId, string>> | undefined {
  if (!value) return undefined;
  const bindings = Object.entries(value).flatMap(([id, binding]) => {
    const parsed = securityMissionInputIdSchema.safeParse(id);
    const cleaned = stringValue(binding);
    return parsed.success && cleaned ? [[parsed.data, cleaned] as const] : [];
  });
  return bindings.length > 0 ? Object.fromEntries(bindings) : undefined;
}

const OPERATOR_MEMORY_KINDS = [
  "operator_fact",
  "operator_claim",
  "operator_decision",
  "operator_correction",
  "operator_risk",
  "operator_blocker",
  "operator_handoff",
  "source_health_note",
] as const;

function operatorMemoryKind(value: string | undefined): SecurityMemoryKind | undefined {
  const normalized = value?.trim();
  return OPERATOR_MEMORY_KINDS.includes(normalized as typeof OPERATOR_MEMORY_KINDS[number])
    ? normalized as SecurityMemoryKind
    : undefined;
}

function operatorStalenessPolicy(value: string | undefined): SecurityMemoryStalenessPolicy {
  return value === "ephemeral" || value === "short_lived" || value === "until_reverified" || value === "durable"
    ? value
    : "until_reverified";
}

function operatorPromotionState(value: string | undefined): SecurityMemoryPromotionState {
  return value === "transient" || value === "candidate" || value === "promoted" || value === "rejected"
    ? value
    : "candidate";
}

function boundedConfidence(value: number | undefined): number | undefined {
  if (value === undefined || !Number.isFinite(value)) return undefined;
  return Math.max(0, Math.min(1, value));
}

function sourceArtifactTag(value: string): string {
  if (/^[A-Z][A-Z0-9]+-\d+$/.test(value)) return "ticket";
  if (/^evidence/i.test(value)) return "evidence";
  if (/^https?:\/\/github\.com\//i.test(value)) return "github";
  return "source";
}

function operatorHandoffPacket(args: HandoffArgs): Record<string, unknown> {
  const packet = {
    title: stringValue(args.title) ?? "Operator handoff",
    status: stringValue(args.status) ?? "in_progress",
    summary: stringValue(args.summary) ?? "",
    blockers: stringList(args.blockers) ?? [],
    next_actions: stringList(args.next_actions) ?? [],
    evidence_refs: stringList(args.evidence_refs) ?? [],
    ticket_refs: stringList(args.ticket_refs) ?? [],
    owners: stringList(args.owners) ?? [],
    slack: {
      channel_id: stringValue(args.channel_id),
      thread_ts: stringValue(args.thread_ts),
    },
  };
  return {
    ...packet,
    ready_for_handoff: Boolean(packet.summary && (packet.next_actions.length || packet.blockers.length)),
    markdown: handoffMarkdown(packet),
  };
}

function operatorNotificationPlan(args: NotificationArgs): Record<string, unknown> {
  const nextActions = stringList(args.next_actions) ?? [];
  const evidenceRefs = stringList(args.evidence_refs) ?? [];
  const ticketRefs = stringList(args.ticket_refs) ?? [];
  const message = trimForSlack([
    `*${stringValue(args.subject) ?? "Cerebro update"}*`,
    `Status: ${stringValue(args.status) ?? "in progress"}`,
    stringValue(args.owner) ? `Owner: ${stringValue(args.owner)}` : "",
    stringValue(args.summary) ?? "",
    nextActions.length ? `Next: ${nextActions.join("; ")}` : "",
    ticketRefs.length ? `Tickets: ${ticketRefs.join(", ")}` : "",
    evidenceRefs.length ? `Evidence: ${evidenceRefs.join(", ")}` : "",
  ].filter(Boolean).join("\n"), 2400);
  return {
    send: false,
    audience: stringValue(args.audience),
    channel_id: stringValue(args.channel_id),
    thread_ts: stringValue(args.thread_ts),
    message,
    evidence_refs: evidenceRefs,
    ticket_refs: ticketRefs,
    next_actions: nextActions,
    note: "This is a message plan only. Use Slack posting through an approved send path.",
  };
}

function operatorPlaybookPlan(args: PlaybookArgs): Record<string, unknown> {
  const requested = `${args.playbook ?? ""} ${args.action ?? ""} ${args.target_system ?? ""}`.toLowerCase();
  const runtimeId = stringValue(args.runtime_id);
  const findingId = stringValue(args.finding_id);
  const issueKey = stringValue(args.issue_key);
  const sourcePlaybook = /\b(source|sync|ingest|evaluate|refresh)\b/.test(requested);
  const jiraPlaybook = /\b(jira|ticket|issue)\b/.test(requested);
  const updatePlaybook = /\b(resolve|suppress|assign|due|note|link|update)\b/.test(requested);
  const steps = sourcePlaybook
    ? sourceRefreshSteps(runtimeId)
    : updatePlaybook
      ? findingUpdateSteps(runtimeId, findingId, issueKey)
      : jiraPlaybook
        ? jiraCreationSteps(runtimeId, findingId)
        : findingTriageSteps(runtimeId, findingId);
  return {
    playbook: stringValue(args.playbook) ?? "finding_triage",
    runtime_id: runtimeId,
    finding_id: findingId,
    issue_key: issueKey,
    steps,
    note: "This plan does not execute tools. Run each step, check returned evidence, then use approved write tools only when needed.",
  };
}

async function ownerResolve(deps: SecurityToolDeps, args: OwnerArgs): Promise<Record<string, unknown>> {
  const finding = await optionalFinding(deps, args.runtime_id, args.finding_id);
  const hints: OwnerHint[] = [];
  for (const hint of stringList(args.owner_hints) ?? []) hints.push({ value: hint, source: "provided_hint", confidence: 0.7 });
  for (const hint of parseOwnerHints(args.context)) hints.push({ value: hint, source: "context", confidence: 0.55 });
  if (args.slack_channel_id) hints.push({ value: args.slack_channel_id, source: "slack_channel", confidence: 0.35 });
  if (args.resource_urn) hints.push(...resourceOwnerHints(args.resource_urn));
  if (finding) hints.push(...findingOwnerHints(finding));
  const candidates = uniqueOwnerHints(hints).slice(0, 12);
  return {
    resolved: candidates.length > 0,
    runtime_id: stringValue(args.runtime_id),
    finding_id: stringValue(args.finding_id),
    resource_urn: stringValue(args.resource_urn ?? finding?.primary_resource_urn ?? finding?.resource_urn),
    candidates,
    finding_found: Boolean(finding),
    note: "Candidates are ownership hints, not assignment authority. Confirm in source data or with the owning team before assigning work.",
  };
}

async function evidenceBundleGet(deps: SecurityToolDeps, args: EvidenceBundleArgs): Promise<Record<string, unknown>> {
  const runtimeId = stringValue(args.runtime_id);
  const findingId = stringValue(args.finding_id);
  if (runtimeId && findingId) {
    const investigation = await findingInvestigation(deps, {
      runtimeId,
      findingId,
      evidenceLimit: limit(args.evidence_limit, 12),
      relatedLimit: limit(args.related_limit, 8),
      includeGraph: args.include_graph !== false,
    });
    return {
      bundle_type: "finding_investigation",
      ...investigation,
    };
  }
  const question = stringValue(args.question);
  if (question) {
    const packet = await deps.cerebro.buildEvidencePacket({
      question,
      entities: stringList(args.entities) ?? [],
      capability_ids: ["security-alert-triage", "graph-reasoning"],
    });
    return {
      bundle_type: "question_evidence_packet",
      packet,
    };
  }
  return {
    error: "missing_evidence_target",
    missing: ["runtime_id+finding_id or question"],
  };
}

async function findingLookup(deps: SecurityToolDeps, args: FindingLookupArgs): Promise<Record<string, unknown>> {
  const runtimeIds = unique([
    stringValue(args.runtime_id),
    ...(stringList(args.runtime_ids) ?? []),
    ...(args.runtime_id || args.runtime_ids?.length ? [] : deps.config.cerebro.defaultRuntimeIds),
  ].filter((value): value is string => Boolean(value))).slice(0, 8);
  if (runtimeIds.length === 0) {
    return {
      error: "missing_runtime_id",
      missing: ["runtime_id"],
    };
  }
  const perRuntime = await Promise.all(runtimeIds.map(async (runtimeId) => {
    try {
      const findings = await deps.cerebro.listFindings(runtimeId, {
        status: normalizeFindingStatus(args.status),
        severity: stringValue(args.severity),
        findingId: stringValue(args.finding_id),
        ruleId: stringValue(args.rule_id),
        order: normalizeFindingOrder(args.order),
        limit: limit(args.limit, 10),
      });
      return { runtime_id: runtimeId, findings };
    } catch (error) {
      return { runtime_id: runtimeId, error: shortError(error), findings: [] as Finding[] };
    }
  }));
  return {
    runtime_ids: runtimeIds,
    findings: perRuntime.flatMap((row) => row.findings.map((finding) => ({ runtime_id: row.runtime_id, ...finding }))),
    per_runtime: perRuntime,
  };
}

async function sourceRunStatus(deps: SecurityToolDeps, args: SourceRunStatusArgs): Promise<Record<string, unknown>> {
  const runtimes = await deps.cerebro.listRuntimeHealth({
    runtimeId: stringValue(args.runtime_id),
    runtimeIds: stringList(args.runtime_ids),
    sourceId: stringValue(args.source_id),
    limit: limit(args.limit, 20),
  });
  const maxStaleMinutes = args.max_stale_minutes && !Number.isNaN(args.max_stale_minutes)
    ? Math.max(1, Math.floor(args.max_stale_minutes))
    : undefined;
  return {
    max_stale_minutes: maxStaleMinutes,
    runtimes: runtimes.map((runtime) => runtimeStatusSummary(runtime, maxStaleMinutes)),
  };
}

async function sourceRunTrigger(deps: SecurityToolDeps, args: SourceRunTriggerArgs): Promise<Record<string, unknown>> {
  const runtimeId = stringValue(args.runtime_id);
  const action = normalizeSourceRunAction(args.action);
  const plan = {
    runtime_id: runtimeId,
    action: action ?? args.action,
    reason: stringValue(args.reason),
    ticket_url: stringValue(args.ticket_url),
    approval_required: true,
    execute_requested: args.execute === true,
    approved: args.approved === true,
  };
  if (!runtimeId || !action) {
    return {
      ...plan,
      attempted: false,
      error: "invalid_source_run_request",
      missing: [
        runtimeId ? undefined : "runtime_id",
        action ? undefined : "action",
      ].filter(Boolean),
      allowed_actions: [...sourceRunActions],
    };
  }
  if (args.execute !== true) {
    return {
      ...plan,
      attempted: false,
      dry_run: true,
      next_step: "Set execute=true and approved=true after reviewed approval to start the source run.",
    };
  }
  if (args.approved !== true) {
    return {
      ...plan,
      attempted: false,
      error: "approval_required",
      next_step: "Run a guardrail check and capture reviewed approval before executing this source action.",
    };
  }
  const result = action === "sync"
    ? await deps.cerebro.syncRuntime(runtimeId)
    : action === "graph_ingest"
      ? await deps.cerebro.runGraphIngest(runtimeId)
      : await deps.cerebro.evaluateFindings(runtimeId);
  return {
    ...plan,
    attempted: true,
    dry_run: false,
    result,
  };
}

async function findingUpdate(deps: SecurityToolDeps, args: FindingUpdateArgs): Promise<Record<string, unknown>> {
  const findingId = stringValue(args.finding_id);
  const action = normalizeFindingUpdateAction(args.action);
  const requiredMissing = findingUpdateMissing(action, args);
  const plan = {
    runtime_id: stringValue(args.runtime_id),
    finding_id: findingId,
    action: action ?? args.action,
    approval_required: true,
    execute_requested: args.execute === true,
    approved: args.approved === true,
    update: {
      note: stringValue(args.note),
      assignee: stringValue(args.assignee),
      due_at: stringValue(args.due_at),
      ticket_url: stringValue(args.ticket_url),
      ticket_name: stringValue(args.ticket_name),
      external_id: stringValue(args.external_id),
      reason: stringValue(args.reason),
    },
  };
  const missing = [
    findingId ? undefined : "finding_id",
    action ? undefined : "action",
    ...requiredMissing,
  ].filter((item): item is string => Boolean(item));
  if (missing.length > 0) {
    return {
      ...plan,
      attempted: false,
      error: "invalid_finding_update_request",
      missing,
      allowed_actions: [...findingUpdateActions],
    };
  }
  if (args.execute !== true) {
    return {
      ...plan,
      attempted: false,
      dry_run: true,
      next_step: "Set execute=true and approved=true after reviewed approval to write this finding update.",
    };
  }
  if (args.approved !== true) {
    return {
      ...plan,
      attempted: false,
      error: "approval_required",
      next_step: "Run a guardrail check and capture reviewed approval before updating this finding.",
    };
  }
  const lifecycle = terminalFindingUpdateAction(action) ? findingLifecyclePreflight({
    ...args,
    action,
    desired_state: action,
    ticket_refs: unique([
      ...(stringList(args.ticket_refs) ?? []),
      stringValue(args.ticket_url),
    ].filter((value): value is string => Boolean(value))),
  }) as Record<string, unknown> : undefined;
  if (lifecycle && lifecycle.ready_for_execution !== true) {
    return {
      ...plan,
      attempted: false,
      error: "finding_lifecycle_preflight_required",
      lifecycle_preflight: lifecycle,
      next_step: lifecycle.next_step,
    };
  }
  const result = await executeFindingUpdate(deps, findingId ?? "", action ?? "note", args);
  return {
    ...plan,
    attempted: true,
    dry_run: false,
    result,
  };
}

function terminalFindingUpdateAction(action: FindingUpdateAction | undefined): boolean {
  return action === "resolve" || action === "suppress";
}

function normalizeSourceRunAction(value: string | undefined): SourceRunAction | undefined {
  const normalized = value?.trim().toLowerCase().replace(/[-\s]+/g, "_");
  return sourceRunActions.includes(normalized as SourceRunAction) ? normalized as SourceRunAction : undefined;
}

function normalizeFindingUpdateAction(value: string | undefined): FindingUpdateAction | undefined {
  const normalized = value?.trim().toLowerCase().replace(/[-\s]+/g, "_");
  return findingUpdateActions.includes(normalized as FindingUpdateAction) ? normalized as FindingUpdateAction : undefined;
}

function findingUpdateMissing(action: FindingUpdateAction | undefined, args: FindingUpdateArgs): string[] {
  switch (action) {
    case "note":
      return stringValue(args.note) ? [] : ["note"];
    case "assign":
      return stringValue(args.assignee) ? [] : ["assignee"];
    case "due":
      return stringValue(args.due_at) ? [] : ["due_at"];
    case "link_ticket":
      return stringValue(args.ticket_url) ? [] : ["ticket_url"];
    case "resolve":
    case "suppress":
      return stringValue(args.reason) ? [] : ["reason"];
    default:
      return [];
  }
}

async function executeFindingUpdate(
  deps: SecurityToolDeps,
  findingId: string,
  action: FindingUpdateAction,
  args: FindingUpdateArgs,
): Promise<Record<string, unknown>> {
  switch (action) {
    case "note":
      return deps.cerebro.addFindingNote(findingId, stringValue(args.note) ?? "");
    case "assign":
      return deps.cerebro.assignFinding(findingId, stringValue(args.assignee) ?? "");
    case "due":
      return deps.cerebro.setFindingDueDate(findingId, stringValue(args.due_at) ?? "");
    case "link_ticket":
      return deps.cerebro.linkFindingTicket(findingId, {
        url: stringValue(args.ticket_url) ?? "",
        name: stringValue(args.ticket_name),
        externalId: stringValue(args.external_id),
      });
    case "resolve":
      return deps.cerebro.resolveFinding(findingId, stringValue(args.reason) ?? "");
    case "suppress":
      return deps.cerebro.suppressFinding(findingId, stringValue(args.reason) ?? "");
  }
}

async function optionalFinding(deps: SecurityToolDeps, runtimeId: string | undefined, findingId: string | undefined): Promise<Finding | undefined> {
  const normalizedRuntime = stringValue(runtimeId);
  const normalizedFinding = stringValue(findingId);
  if (!normalizedRuntime || !normalizedFinding) return undefined;
  try {
    const findings = await deps.cerebro.listFindings(normalizedRuntime, { findingId: normalizedFinding, limit: 5 });
    return findings.find((finding) => finding.id === normalizedFinding) ?? findings[0];
  } catch {
    return undefined;
  }
}

interface OwnerHint {
  value: string;
  source: string;
  confidence: number;
}

function parseOwnerHints(value: string | undefined): string[] {
  const text = value ?? "";
  const mentions = [...text.matchAll(/<@([A-Z0-9]+)>/g)].map((match) => `<@${match[1]}>`);
  const emails = [...text.matchAll(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi)].map((match) => match[0]);
  const keyed = [...text.matchAll(/\b(?:owner|team|service_owner|oncall)\s*[:=]\s*([^\n,;]+)/gi)].map((match) => match[1]?.trim()).filter(Boolean) as string[];
  return unique([...mentions, ...emails, ...keyed]);
}

function resourceOwnerHints(resourceUrn: string): OwnerHint[] {
  const hints: OwnerHint[] = [];
  const accountMatch = resourceUrn.match(/(?:account|aws_account|project|repo|service)[:=/]([^:/]+)/i);
  if (accountMatch?.[1]) hints.push({ value: accountMatch[1], source: "resource_urn", confidence: 0.35 });
  return hints;
}

function findingOwnerHints(finding: Finding): OwnerHint[] {
  const attributes = finding.attributes ?? {};
  const keys = ["owner", "team", "service_owner", "oncall", "slack_channel", "email"];
  const hints: OwnerHint[] = [];
  if (finding.assignee) hints.push({ value: finding.assignee, source: "finding_assignee", confidence: 0.85 });
  for (const key of keys) {
    const value = stringValue(attributes[key]);
    if (value) hints.push({ value, source: `finding_attribute:${key}`, confidence: 0.65 });
  }
  for (const ref of finding.external_refs ?? []) {
    const value = stringValue(ref.owner ?? ref.team ?? ref.name ?? ref.url);
    if (value) hints.push({ value, source: "finding_external_ref", confidence: 0.45 });
  }
  for (const ticket of finding.tickets ?? []) {
    const value = stringValue(ticket.owner ?? ticket.assignee ?? ticket.name ?? ticket.url);
    if (value) hints.push({ value, source: "finding_ticket", confidence: 0.4 });
  }
  return hints;
}

function uniqueOwnerHints(hints: OwnerHint[]): OwnerHint[] {
  const best = new Map<string, OwnerHint>();
  for (const hint of hints) {
    const value = hint.value.trim();
    if (!value) continue;
    const key = value.toLowerCase();
    const existing = best.get(key);
    if (!existing || hint.confidence > existing.confidence) {
      best.set(key, { ...hint, value });
    }
  }
  return [...best.values()].sort((a, b) => b.confidence - a.confidence);
}

function runtimeStatusSummary(runtime: RuntimeHealth, maxStaleMinutes: number | undefined): Record<string, unknown> {
  const timestamps = [
    stringValue(runtime.last_sync_at),
    stringValue(runtime.last_observed_at),
    stringValue(runtime.last_graph_ingest_at),
  ].map((value) => value ? Date.parse(value) : Number.NaN).filter((value) => Number.isFinite(value));
  const latest = timestamps.length ? Math.max(...timestamps) : undefined;
  const stale = maxStaleMinutes && latest
    ? Date.now() - latest > maxStaleMinutes * 60_000
    : undefined;
  return {
    runtime_id: runtime.runtime_id ?? runtime.id,
    source_id: runtime.source_id,
    status: runtime.status,
    sync_status: runtime.sync_status,
    graph_status: runtime.graph_status,
    finding_status: runtime.finding_status,
    last_sync_at: runtime.last_sync_at,
    last_observed_at: runtime.last_observed_at,
    last_graph_ingest_at: runtime.last_graph_ingest_at,
    invalid_event_count: runtime.invalid_event_count,
    open_finding_count: runtime.open_finding_count,
    stale,
  };
}

function findingTriageSteps(runtimeId: string | undefined, findingId: string | undefined): Array<Record<string, unknown>> {
  return [
    { order: 1, tool: "evidence_bundle_get", input: { runtime_id: runtimeId, finding_id: findingId } },
    { order: 2, tool: "owner_resolve", input: { runtime_id: runtimeId, finding_id: findingId } },
    { order: 3, tool: "jira_issue_search", input: { query: findingId } },
    { order: 4, tool: "operator_policy_guardrail_check", input: { action: "triage finding", target_system: "cerebro" } },
    { order: 5, tool: "operator_notification_plan", input: { subject: findingId ?? "finding", status: "triaged" } },
  ];
}

function jiraCreationSteps(runtimeId: string | undefined, findingId: string | undefined): Array<Record<string, unknown>> {
  return [
    { order: 1, tool: "evidence_bundle_get", input: { runtime_id: runtimeId, finding_id: findingId } },
    { order: 2, tool: "owner_resolve", input: { runtime_id: runtimeId, finding_id: findingId } },
    { order: 3, tool: "jira_issue_search", input: { query: findingId } },
    { order: 4, tool: "jira_issue_draft", input: { finding_id: findingId, runtime_id: runtimeId } },
    { order: 5, tool: "jira_issue_create", input: { finding_id: findingId, runtime_id: runtimeId } },
    { order: 6, tool: "finding_update", input: { finding_id: findingId, action: "link_ticket" } },
  ];
}

function sourceRefreshSteps(runtimeId: string | undefined): Array<Record<string, unknown>> {
  return [
    { order: 1, tool: "source_run_status", input: { runtime_id: runtimeId } },
    { order: 2, tool: "operator_policy_guardrail_check", input: { action: "source sync", target_system: "cerebro", changes_production: true } },
    { order: 3, tool: "source_run_trigger", input: { runtime_id: runtimeId, action: "sync" } },
    { order: 4, tool: "source_run_status", input: { runtime_id: runtimeId } },
    { order: 5, tool: "operator_action_audit_log", input: { action: "source sync", target_system: "cerebro", target_id: runtimeId } },
  ];
}

function findingUpdateSteps(runtimeId: string | undefined, findingId: string | undefined, issueKey: string | undefined): Array<Record<string, unknown>> {
  return [
    { order: 1, tool: "evidence_bundle_get", input: { runtime_id: runtimeId, finding_id: findingId } },
    { order: 2, tool: "operator_policy_guardrail_check", input: { action: "finding update", target_system: "cerebro", changes_production: true } },
    { order: 3, tool: "finding_update", input: { finding_id: findingId } },
    issueKey
      ? { order: 4, tool: "jira_issue_update", input: { issue_key: issueKey } }
      : { order: 4, tool: "jira_issue_search", input: { query: findingId } },
    { order: 5, tool: "operator_action_audit_log", input: { action: "finding update", target_system: "cerebro", target_id: findingId } },
  ];
}

function handoffMarkdown(packet: {
  title: string;
  status: string;
  summary: string;
  blockers: string[];
  next_actions: string[];
  evidence_refs: string[];
  ticket_refs: string[];
  owners: string[];
}): string {
  return trimForSlack([
    `# ${packet.title}`,
    `Status: ${packet.status}`,
    packet.summary,
    packet.owners.length ? `Owners: ${packet.owners.join(", ")}` : "",
    packet.blockers.length ? `Blockers: ${packet.blockers.join("; ")}` : "",
    packet.next_actions.length ? `Next actions: ${packet.next_actions.join("; ")}` : "",
    packet.ticket_refs.length ? `Tickets: ${packet.ticket_refs.join(", ")}` : "",
    packet.evidence_refs.length ? `Evidence: ${packet.evidence_refs.join(", ")}` : "",
  ].filter(Boolean).join("\n"), 4000);
}

function stableHash(parts: string[]): string {
  return createHash("sha256").update(parts.join("\u0000")).digest("hex").slice(0, 40);
}
