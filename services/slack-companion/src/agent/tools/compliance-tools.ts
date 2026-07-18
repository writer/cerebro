import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { complianceContextService } from "../../compliance/context.js";
import { complianceGapJiraDraft } from "../../compliance/gap-routing.js";
import { findingLifecyclePreflight } from "../../compliance/lifecycle-preflight.js";
import { compliancePacketStore, type StoredCompliancePacket } from "../../compliance/packet-store.js";
import { buildCompliancePacket, type CompliancePacket } from "../../compliance/work-packets.js";
import type { ScheduledJobDraft } from "../../schedules/schedule-parser.js";
import type { SecurityToolDeps } from "./types.js";
import { safeToolResult, toolResult } from "./tool-result.js";

export function createComplianceTools(deps: SecurityToolDeps): AgentTool[] {
  const complianceContext = deps.complianceContext ?? complianceContextService(deps.config);
  const packetStore = deps.compliancePacketStore ?? compliancePacketStore(deps.config);
  const complianceContextParams = Type.Object({
    query: Type.String(),
    limit: Type.Optional(Type.Number()),
    paths: Type.Optional(Type.Array(Type.String())),
    include_overview: Type.Optional(Type.Boolean()),
  });
  const compliancePacketParams = Type.Object({
    packet_type: Type.String(),
    title: Type.Optional(Type.String()),
    control_id: Type.Optional(Type.String()),
    control_ids: Type.Optional(Type.Array(Type.String())),
    framework: Type.Optional(Type.String()),
    period: Type.Optional(Type.String()),
    scope: Type.Optional(Type.String()),
    audience: Type.Optional(Type.String()),
    owner: Type.Optional(Type.String()),
    assertion: Type.Optional(Type.String()),
    runtime_id: Type.Optional(Type.String()),
    finding_id: Type.Optional(Type.String()),
    action: Type.Optional(Type.String()),
    current_state: Type.Optional(Type.String()),
    desired_state: Type.Optional(Type.String()),
    severity: Type.Optional(Type.String()),
    risk: Type.Optional(Type.String()),
    remediation: Type.Optional(Type.String()),
    reviewer: Type.Optional(Type.String()),
    due_at: Type.Optional(Type.String()),
    expires_at: Type.Optional(Type.String()),
    rollback_plan: Type.Optional(Type.String()),
    cadence: Type.Optional(Type.String()),
    time_zone: Type.Optional(Type.String()),
    channel_id: Type.Optional(Type.String()),
    runtime_ids: Type.Optional(Type.Array(Type.String())),
    hour: Type.Optional(Type.Number()),
    minute: Type.Optional(Type.Number()),
    interval_minutes: Type.Optional(Type.Number()),
    threshold: Type.Optional(Type.Number()),
    cooldown_minutes: Type.Optional(Type.Number()),
    policy_refs: Type.Optional(Type.Array(Type.String())),
    system_refs: Type.Optional(Type.Array(Type.String())),
    source_refs: Type.Optional(Type.Array(Type.String())),
    evidence_refs: Type.Optional(Type.Array(Type.String())),
    ticket_refs: Type.Optional(Type.Array(Type.String())),
    finding_refs: Type.Optional(Type.Array(Type.String())),
    exception_refs: Type.Optional(Type.Array(Type.String())),
    approval_refs: Type.Optional(Type.Array(Type.String())),
    dry_run_refs: Type.Optional(Type.Array(Type.String())),
    compensating_controls: Type.Optional(Type.Array(Type.String())),
    facts: Type.Optional(Type.Array(Type.String())),
    caveats: Type.Optional(Type.Array(Type.String())),
    evidence_age_days: Type.Optional(Type.Number()),
    actor_slack_user_id: Type.Optional(Type.String()),
    actor_id: Type.Optional(Type.String()),
    actor_display_name: Type.Optional(Type.String()),
    packet_id: Type.Optional(Type.String()),
    project_key: Type.Optional(Type.String()),
    issue_type: Type.Optional(Type.String()),
    labels: Type.Optional(Type.Array(Type.String())),
    approved: Type.Optional(Type.Boolean()),
    approval_ref: Type.Optional(Type.String()),
    execute: Type.Optional(Type.Boolean()),
  });
  const compliancePacketLookupParams = Type.Object({
    packet_id: Type.Optional(Type.String()),
    limit: Type.Optional(Type.Number()),
  });
  return [
    {
      name: "cerebro_compliance_context",
      label: "Cerebro compliance context",
      description: "Search bounded source context from github.com/writer/cerebro for compliance controls, GRC architecture, control profiles, policy lifecycle, policy rule extensions, and checked-in compliance policy rules. Use for compliance, audit, control, policy, framework, and evidence expectation questions; then verify live tenant state with Cerebro tools when the answer makes current-state claims.",
      parameters: complianceContextParams,
      execute: async (_toolCallId, params) => {
        const args = params as { query: string; limit?: number; paths?: string[]; include_overview?: boolean };
        return safeToolResult(async () => complianceContext.search({
          query: args.query,
          limit: args.limit,
          paths: args.paths,
          includeOverview: args.include_overview,
        }));
      },
    },
    {
      name: "cerebro_compliance_context_status",
      label: "Cerebro compliance context status",
      description: "Read the compliance context cache source, corpus size, mode, skipped sources, and digest. Use when debugging whether Cerebro has loaded writer/cerebro compliance context.",
      parameters: Type.Object({}),
      execute: async () => toolResult(await complianceContext.status()),
    },
    {
      name: "cerebro_compliance_packet",
      label: "Cerebro compliance packet",
      description: "Build a bounded compliance work packet for control_evidence, policy_system_map, audit_safe_report, finding_lifecycle, exception_management, triage_quality, approval_remediation, or continuous_monitor. Use after reading compliance context and before sharing audit, policy, control evidence, finding disposition, exception, triage, remediation, or monitor plans; returns gaps, review actions, redacted report-safe fields, and scheduler-compatible monitor drafts without writing external systems.",
      parameters: compliancePacketParams,
      execute: async (_toolCallId, params) => toolResult(buildCompliancePacket(params as Parameters<typeof buildCompliancePacket>[0])),
    },
    {
      name: "cerebro_compliance_packet_store",
      label: "Store compliance packet",
      description: "Build and persist a redacted compliance packet as durable evidence. Use after reviewing packet gaps and before linking a packet to Jira, audit evidence, approvals, or scheduled monitors. The tool stores packet metadata and sanitized packet content; it never stores secret values.",
      parameters: compliancePacketParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as Parameters<typeof buildCompliancePacket>[0] & ActorParams;
        const packet = buildCompliancePacket(args);
        if (!isCompliancePacket(packet)) return packet;
        const record = await packetStore.put(packet, actorFromParams(args));
        return {
          stored: true,
          storage_mode: record.storage_mode,
          record: packetRecordSummary(record),
          packet: record.packet,
        };
      }),
    },
    {
      name: "cerebro_compliance_packet_lookup",
      label: "Lookup compliance packets",
      description: "Read stored compliance packets by packet_id or list recent packet records. Use before attaching packet evidence to Jira, approvals, monitors, or audit summaries.",
      parameters: compliancePacketLookupParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as { packet_id?: string; limit?: number };
        if (args.packet_id) {
          const record = await packetStore.get(args.packet_id);
          return record
            ? { found: true, storage_mode: record.storage_mode, record: packetRecordSummary(record), packet: record.packet }
            : { found: false, packet_id: args.packet_id, storage_mode: packetStore.storageMode };
        }
        const records = await packetStore.list(args.limit);
        return {
          storage_mode: packetStore.storageMode,
          records: records.map(packetRecordSummary),
        };
      }),
    },
    {
      name: "cerebro_compliance_gap_jira_draft",
      label: "Compliance gap Jira draft",
      description: "Build a Jira draft from a compliance packet's current gaps. Read-only; use before creating or updating Jira so packet gaps, evidence refs, review actions, and duplicate-search JQL are explicit.",
      parameters: compliancePacketParams,
      execute: async (_toolCallId, params) => toolResult(complianceGapJiraDraft(deps.config, params as Parameters<typeof complianceGapJiraDraft>[1])),
    },
    {
      name: "cerebro_finding_lifecycle_preflight",
      label: "Finding lifecycle preflight",
      description: "Check finding lifecycle readiness before terminal finding updates. Read-only; returns missing evidence, ticket or exception, approval, dry-run, rollback, guardrail, update, and audit inputs.",
      parameters: compliancePacketParams,
      execute: async (_toolCallId, params) => toolResult(findingLifecyclePreflight(params as Parameters<typeof findingLifecyclePreflight>[0])),
    },
    {
      name: "cerebro_compliance_monitor_create",
      label: "Create compliance monitor",
      description: "Create a scheduled job from an approved continuous_monitor compliance packet. Requires approved=true and approval_ref; use packet_id for a stored packet or pass packet fields to build and store one before scheduling.",
      parameters: compliancePacketParams,
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const args = params as Parameters<typeof buildCompliancePacket>[0] & ActorParams & {
          packet_id?: string;
          approved?: boolean;
          approval_ref?: string;
        };
        if (args.approved !== true || !clean(args.approval_ref)) {
          return {
            scheduled: false,
            status: "approval_required",
            required: ["approved", "approval_ref"],
          };
        }
        if (!deps.scheduler) {
          return {
            scheduled: false,
            status: "scheduler_unavailable",
            approval_ref: args.approval_ref,
          };
        }
        const packetResult = await packetForMonitor(args, packetStore);
        if (!isCompliancePacket(packetResult.packet)) return packetResult.packet;
        const packet = packetResult.packet;
        if (packet.packet_type !== "continuous_monitor") {
          return {
            scheduled: false,
            status: "wrong_packet_type",
            packet_id: packet.packet_id,
            packet_type: packet.packet_type,
            required_packet_type: "continuous_monitor",
          };
        }
        if (!packet.ready_for_review) {
          return {
            scheduled: false,
            status: "packet_not_ready",
            packet_id: packet.packet_id,
            readiness: packet.readiness,
            gaps: packet.gaps,
            review_actions: packet.review_actions,
          };
        }
        const draft = scheduleDraftFromPacket(packet);
        if (!draft) {
          return {
            scheduled: false,
            status: "schedule_draft_missing",
            packet_id: packet.packet_id,
          };
        }
        const actor = actorFromParams(args) ?? {
          slackUserId: "system",
          actorId: "cerebro:compliance-monitor",
          displayName: "Cerebro",
        };
        const stored = packetResult.record ?? await packetStore.put(packet, actor);
        const job = await deps.scheduler.createFromDraft({ draft, actor });
        return {
          scheduled: true,
          approval_ref: args.approval_ref,
          packet_id: stored.packet_id,
          storage_mode: stored.storage_mode,
          job,
        };
      }),
    },
  ];
}

interface ActorParams {
  actor_slack_user_id?: string;
  actor_id?: string;
  actor_display_name?: string;
}

function isCompliancePacket(value: CompliancePacket | { error: string }): value is CompliancePacket {
  return !("error" in value);
}

function actorFromParams(params: ActorParams) {
  const slackUserId = clean(params.actor_slack_user_id);
  const actorId = clean(params.actor_id);
  if (!slackUserId || !actorId) return undefined;
  return {
    slackUserId,
    actorId,
    displayName: clean(params.actor_display_name),
  };
}

function packetRecordSummary(record: StoredCompliancePacket) {
  return {
    packet_id: record.packet_id,
    packet_type: record.packet_type,
    title: record.title,
    readiness: record.readiness,
    ready_for_review: record.ready_for_review,
    gaps: record.gaps,
    review_actions: record.review_actions,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    createdBy: record.createdBy,
    storage_mode: record.storage_mode,
    secret_values_stored: false,
  };
}

async function packetForMonitor(
  args: Parameters<typeof buildCompliancePacket>[0] & { packet_id?: string },
  packetStore: Pick<StoredCompliancePacketStore, "get" | "put">,
): Promise<{ packet: CompliancePacket | { error: string }; record?: StoredCompliancePacket }> {
  const packetId = clean(args.packet_id);
  if (packetId) {
    const record = await packetStore.get(packetId);
    return record
      ? { packet: record.packet, record }
      : { packet: { error: "packet_not_found" } };
  }
  const packet = buildCompliancePacket({ ...args, packet_type: args.packet_type ?? "continuous_monitor" });
  return { packet };
}

interface StoredCompliancePacketStore {
  get(packetId: string): Promise<StoredCompliancePacket | undefined>;
  put(packet: CompliancePacket, actor?: ReturnType<typeof actorFromParams>): Promise<StoredCompliancePacket>;
}

function scheduleDraftFromPacket(packet: CompliancePacket): ScheduledJobDraft | undefined {
  const draft = objectValue(packet.schedule_draft);
  if (!draft || typeof draft.description !== "string" || !Array.isArray(draft.steps)) return undefined;
  const schedule = objectValue(draft.schedule) as ScheduledJobDraft["schedule"];
  const trigger = objectValue(draft.trigger) as ScheduledJobDraft["trigger"];
  if (!schedule && !trigger) return undefined;
  return {
    description: draft.description,
    schedule,
    trigger,
    steps: draft.steps as ScheduledJobDraft["steps"],
    contextProviders: Array.isArray(draft.contextProviders) ? draft.contextProviders.map(String) as ScheduledJobDraft["contextProviders"] : [],
    channelId: typeof draft.channelId === "string" ? draft.channelId : undefined,
    nextRunAt: typeof draft.nextRunAt === "string" ? draft.nextRunAt : undefined,
    warnings: Array.isArray(draft.warnings) ? draft.warnings.map(String) : [],
  };
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function clean(value: string | undefined): string | undefined {
  const trimmed = value?.replace(/\s+/g, " ").trim();
  return trimmed || undefined;
}
