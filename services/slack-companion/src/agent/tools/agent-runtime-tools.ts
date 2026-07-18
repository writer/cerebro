import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import { AgentToolCatalog } from "../tool-catalog.js";
import {
  agentArtifactSchema,
  agentResourceKindSchema,
  agentStepExecutionSchema,
  canonicalResourceRef,
  createAgentCorrection,
} from "../../autonomy/agent-run.js";
import { compileSecurityMission, missionToolMatches } from "../../autonomy/mission-compiler.js";
import { securityMissionInputIdSchema, securityMissionPackIdSchema, type SecurityMissionInputId } from "../../autonomy/mission-types.js";
import type { SecurityToolAuthority, SecurityToolFamily } from "./tool-metadata.js";
import { safeToolResult } from "./tool-result.js";
import type { SecurityToolDeps } from "./types.js";

export function createAgentRuntimeTools(deps: SecurityToolDeps, catalog: () => AgentToolCatalog): AgentTool[] {
  return [
    {
      name: "operator_tool_catalog_search",
      label: "Tool catalog search",
      description: "Search registered Cerebro tools by capability, family, and authority. Use this when the current tool pack does not expose an exact source or action tool. The result is discovery metadata, not authority to execute a tool.",
      parameters: Type.Object({
        query: Type.Optional(Type.String()),
        families: Type.Optional(Type.Array(Type.String(), { maxItems: 8 })),
        authorities: Type.Optional(Type.Array(Type.String(), { maxItems: 8 })),
        limit: Type.Optional(Type.Number({ minimum: 1, maximum: 20 })),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const input = params as { query?: string; families?: string[]; authorities?: string[]; limit?: number };
        const matches = catalog().search({
          query: input.query,
          families: normalizeFamilies(input.families),
          authorities: normalizeAuthorities(input.authorities),
          limit: input.limit,
        });
        return { matches, count: matches.length, note: "Add an exact returned tool name to the research plan or durable run before execution." };
      }),
    },
    {
      name: "operator_context_resolve",
      label: "Canonical context resolver",
      description: "Convert source identifiers already present in the request or tool evidence into typed canonical resource references. This tool does not fetch external state; verify current state with the owning source tool.",
      parameters: Type.Object({
        resources: Type.Array(Type.Object({
          kind: Type.String(),
          id: Type.String(),
          source: Type.Optional(Type.String()),
          label: Type.Optional(Type.String()),
          observed_at: Type.Optional(Type.String()),
          valid_until: Type.Optional(Type.String()),
          evidence_receipt: Type.Optional(Type.String()),
          confidence: Type.Optional(Type.Number({ minimum: 0, maximum: 1 })),
          links: Type.Optional(Type.Array(Type.Object({ relation: Type.String(), target_uri: Type.String() }), { maxItems: 20 })),
        }), { minItems: 1, maxItems: 40 }),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const input = params as { resources: Array<Record<string, unknown>> };
        const resources = input.resources.map((resource) => canonicalResourceRef({
          kind: agentResourceKindSchema.parse(resource.kind),
          id: String(resource.id),
          source: stringValue(resource.source),
          label: stringValue(resource.label),
          observedAt: stringValue(resource.observed_at),
          validUntil: stringValue(resource.valid_until),
          evidenceReceipt: stringValue(resource.evidence_receipt),
          confidence: typeof resource.confidence === "number" ? resource.confidence : undefined,
          links: Array.isArray(resource.links) ? resource.links.flatMap((link) => {
            const value = objectValue(link);
            return value && stringValue(value.relation) && stringValue(value.target_uri)
              ? [{ relation: stringValue(value.relation)!, targetUri: stringValue(value.target_uri)! }]
              : [];
          }) : undefined,
        }));
        return { resources, count: resources.length, live_state_verified: false };
      }),
    },
    {
      name: "operator_agent_run_status",
      label: "Agent run status",
      description: "Read the durable objective, executable plan, canonical resources, artifacts, acceptance criteria, corrections, approvals, and completion receipt for one agent run.",
      parameters: Type.Object({ goal_id: Type.String() }),
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const goalId = stringValue((params as Record<string, unknown>).goal_id);
        if (!goalId || !deps.autonomyGoals?.get) return { found: false, error: goalId ? "agent_run_store_unavailable" : "goal_id_required" };
        const goal = await deps.autonomyGoals.get(goalId);
        return goal ? {
          found: true,
          run: {
            id: goal.id,
            status: goal.status,
            objective: goal.objective,
            mission: goal.mission,
            mission_state: goal.mission ? {
              active_step_id: goal.activeStepId,
              pending_approval_count: goal.approvals.filter((approval) => approval.status === "pending").length,
              bound_step_count: goal.currentPlan.filter((step) => step.mission?.bindingState === "bound").length,
              waiting_step_count: goal.currentPlan.filter((step) => step.status === "waiting").length,
            } : undefined,
            plan: goal.currentPlan,
            resources: goal.resourceRefs,
            artifacts: goal.artifacts,
            acceptance_criteria: goal.acceptanceCriteria,
            corrections: goal.corrections,
            blockers: goal.blockers,
            approvals: goal.approvals,
            completion_receipt: goal.completionReceipt,
            next_wake_at: goal.nextWakeAt,
          },
        } : { found: false, error: "agent_run_not_found" };
      }),
    },
    {
      name: "operator_mission_compile",
      label: "Security mission compiler",
      description: "Compile an AppSec remediation, identity access-risk, or detection-response objective into a versioned resumable plan with inputs, evidence, action boundaries, approvals, rollback, verification, owner, and service level. This does not create or execute a goal.",
      parameters: Type.Object({
        objective: Type.String(),
        pack_id: Type.Optional(Type.String()),
        bindings: Type.Optional(Type.Record(Type.String(), Type.String(), { maxProperties: 20 })),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const input = params as { objective?: string; pack_id?: string; bindings?: Record<string, string> };
        const objective = stringValue(input.objective);
        if (!objective) return { matched: false, error: "objective_required" };
        const requestedPack = input.pack_id ? securityMissionPackIdSchema.safeParse(input.pack_id) : undefined;
        if (requestedPack && !requestedPack.success) return { matched: false, error: "unsupported_mission_pack", available_pack_ids: securityMissionPackIdSchema.options };
        const compilation = compileSecurityMission({
          objective,
          requestedPackId: requestedPack?.data,
          bindings: input.bindings as Partial<Record<SecurityMissionInputId, string>> | undefined,
        });
        return compilation ? {
          matched: true,
          mission: compilation.receipt,
          pack: {
            id: compilation.pack.id,
            version: compilation.pack.version,
            title: compilation.pack.title,
            purpose: compilation.pack.purpose,
            domain: compilation.pack.domain,
            owner: compilation.pack.owner,
            escalation_path: compilation.pack.escalationPath,
            event_triggers: compilation.pack.eventTriggers,
            allowed_actions: compilation.pack.allowedActions,
          },
          plan: compilation.plan,
          acceptance_criteria: compilation.acceptanceCriteria,
        } : { matched: false, available_pack_ids: securityMissionPackIdSchema.options };
      }),
    },
    {
      name: "operator_agent_run_step_bind",
      label: "Agent run step binding",
      description: "Bind one exact registered tool to a waiting compiled mission step. The host enforces the pack selector, arguments, approval, rollback, and independent verification before resuming the run.",
      parameters: Type.Object({
        goal_id: Type.String(),
        step_id: Type.String(),
        tool_name: Type.String(),
        tool_arguments: Type.Record(Type.String(), Type.Any(), { maxProperties: 40 }),
        verification_tool_name: Type.Optional(Type.String()),
        verification_arguments: Type.Optional(Type.Record(Type.String(), Type.Any(), { maxProperties: 40 })),
        approval_required: Type.Optional(Type.Boolean()),
        idempotency_key: Type.Optional(Type.String()),
        rollback: Type.Optional(Type.String()),
        max_attempts: Type.Optional(Type.Number({ minimum: 1, maximum: 3 })),
        acceptance_criteria_ids: Type.Array(Type.String(), { minItems: 1, maxItems: 40 }),
        mission_bindings: Type.Optional(Type.Record(Type.String(), Type.String(), { maxProperties: 20 })),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const input = params as Record<string, unknown>;
        const goalId = stringValue(input.goal_id);
        const stepId = stringValue(input.step_id);
        const toolName = stringValue(input.tool_name);
        if (!goalId || !stepId || !toolName) return { bound: false, error: "goal_id_step_id_and_tool_name_required" };
        if (!deps.autonomyGoals?.get || !deps.autonomyGoals.bindMissionStep) return { bound: false, error: "agent_run_store_unavailable" };
        const goal = await deps.autonomyGoals.get(goalId);
        const step = goal?.currentPlan.find((candidate) => candidate.id === stepId);
        if (!goal?.mission || !step?.mission) return { bound: false, error: "mission_step_not_found" };
        const entry = catalog().entry(toolName);
        if (!entry) return { bound: false, error: "tool_not_registered", tool_name: toolName };
        if (!missionToolMatches(step.mission.toolSelector, entry)) return { bound: false, error: "tool_outside_mission_selector", tool: entry, selector: step.mission.toolSelector };
        const reviewedWrite = entry.authority === "cerebro_write" || entry.authority === "security_write";
        if (reviewedWrite && input.approval_required !== true) return { bound: false, error: "reviewed_approval_required" };
        if (reviewedWrite && !stringValue(input.idempotency_key)) return { bound: false, error: "idempotency_key_required" };
        if (reviewedWrite && !stringValue(input.rollback)) return { bound: false, error: "rollback_required" };
        if (reviewedWrite && !stringValue(input.verification_tool_name)) return { bound: false, error: "independent_verification_required" };
        const argumentsValue = objectValue(input.tool_arguments) ?? {};
        const argumentCheck = catalog().validateArguments(toolName, argumentsValue);
        if (!argumentCheck.valid || !argumentCheck.arguments) return { bound: false, error: "invalid_tool_arguments", details: argumentCheck.errors };
        const verificationToolName = stringValue(input.verification_tool_name);
        const verificationArguments = objectValue(input.verification_arguments) ?? {};
        if (verificationToolName) {
          const verificationEntry = catalog().entry(verificationToolName);
          if (!verificationEntry || verificationEntry.authority !== "read" || verificationEntry.sideEffect !== "none") {
            return { bound: false, error: "verification_tool_must_be_read_only" };
          }
          const verificationCheck = catalog().validateArguments(verificationToolName, verificationArguments);
          if (!verificationCheck.valid) return { bound: false, error: "invalid_verification_arguments", details: verificationCheck.errors };
        }
        const execution = agentStepExecutionSchema.parse({
          toolName,
          arguments: argumentCheck.arguments,
          verificationToolName,
          verificationArguments,
          approvalRequired: input.approval_required === true,
          idempotencyKey: stringValue(input.idempotency_key),
          rollback: stringValue(input.rollback),
          maxAttempts: typeof input.max_attempts === "number" ? input.max_attempts : 1,
          attempts: 0,
        });
        const updated = await deps.autonomyGoals.bindMissionStep({
          goalId: goal.id,
          stepId: step.id,
          execution,
          toolMetadata: entry,
          acceptanceCriteriaIds: stringArray(input.acceptance_criteria_ids),
          missionBindings: parseMissionBindings(input.mission_bindings),
        });
        return { bound: true, goal_id: updated.id, status: updated.status, step: updated.currentPlan.find((candidate) => candidate.id === step.id), next_wake_at: updated.nextWakeAt };
      }),
    },
    {
      name: "operator_agent_run_step_decide",
      label: "Agent run decision record",
      description: "Complete one non-action mission decision with a concrete outcome and reopenable evidence. Approval decisions still require the reviewed Slack approval record.",
      parameters: Type.Object({
        goal_id: Type.String(),
        step_id: Type.String(),
        summary: Type.String(),
        evidence_refs: Type.Array(Type.String(), { minItems: 1, maxItems: 24 }),
        approval_id: Type.Optional(Type.String()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const input = params as Record<string, unknown>;
        const goalId = stringValue(input.goal_id);
        const stepId = stringValue(input.step_id);
        const summary = stringValue(input.summary);
        if (!goalId || !stepId || !summary || !deps.autonomyGoals?.recordMissionDecision) return { recorded: false, error: "decision_input_or_store_unavailable" };
        const updated = await deps.autonomyGoals.recordMissionDecision({
          goalId,
          stepId,
          summary,
          evidenceRefs: stringArray(input.evidence_refs),
          approvalId: stringValue(input.approval_id),
        });
        return { recorded: true, goal_id: updated.id, status: updated.status, next_wake_at: updated.nextWakeAt };
      }),
    },
    {
      name: "operator_task_artifact_record",
      label: "Task artifact record",
      description: "Attach a bounded file, report, patch, commit, pull request, ticket, evidence packet, or decision artifact to an existing agent run after the artifact exists.",
      parameters: Type.Object({
        goal_id: Type.String(),
        kind: Type.String(),
        title: Type.String(),
        status: Type.Optional(Type.String()),
        path: Type.Optional(Type.String()),
        url: Type.Optional(Type.String()),
        content_hash: Type.Optional(Type.String()),
        source_refs: Type.Optional(Type.Array(Type.String(), { maxItems: 24 })),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const input = params as Record<string, unknown>;
        const goalId = stringValue(input.goal_id);
        if (!goalId || !deps.autonomyGoals?.appendArtifact) return { stored: false, error: goalId ? "agent_run_store_unavailable" : "goal_id_required" };
        const artifact = agentArtifactSchema.omit({ id: true, createdAt: true }).parse({
          kind: input.kind,
          title: String(input.title),
          status: stringValue(input.status) ?? "ready",
          path: stringValue(input.path),
          url: stringValue(input.url),
          contentHash: stringValue(input.content_hash),
          sourceRefs: stringArray(input.source_refs),
        });
        const goal = await deps.autonomyGoals.appendArtifact(goalId, artifact);
        return { stored: true, goal_id: goal.id, artifact: goal.artifacts.at(-1) };
      }),
    },
    {
      name: "operator_correction_record",
      label: "Correction record",
      description: "Record a verified replacement for an earlier Cerebro claim. Recheck the owning source first and include reopenable source references. This stores the correction as context, not authority.",
      parameters: Type.Object({
        goal_id: Type.Optional(Type.String()),
        previous_claim: Type.String(),
        replacement: Type.String(),
        reason: Type.String(),
        source_refs: Type.Array(Type.String(), { minItems: 1, maxItems: 24 }),
        expires_at: Type.Optional(Type.String()),
        channel_id: Type.Optional(Type.String()),
        source_ts: Type.Optional(Type.String()),
      }),
      execute: async (_toolCallId, params) => safeToolResult(async () => {
        const input = params as Record<string, unknown>;
        const sourceRefs = stringArray(input.source_refs);
        const correction = createAgentCorrection({
          previousClaim: String(input.previous_claim),
          replacement: String(input.replacement),
          reason: String(input.reason),
          sourceRefs,
          expiresAt: stringValue(input.expires_at),
        });
        const memory = await deps.memory.remember({
          kind: "operator_correction",
          topic: correction.replacement,
          summary: correction.replacement,
          details: `Previous claim: ${correction.previousClaim}\nReason: ${correction.reason}`,
          tags: ["correction", "verified-replacement"],
          channelId: stringValue(input.channel_id),
          sourceTs: stringValue(input.source_ts),
          sourceKind: "tool",
          sourceArtifacts: correction.sourceRefs,
          verifiedBy: ["operator_correction_record"],
          verifiedAt: correction.createdAt,
          expiresAt: correction.expiresAt,
          stalenessPolicy: correction.expiresAt ? "until_reverified" : "durable",
          promotionState: "candidate",
          confidence: 0.95,
        });
        const goalId = stringValue(input.goal_id);
        if (goalId && deps.autonomyGoals?.appendCorrection) await deps.autonomyGoals.appendCorrection(goalId, correction);
        return { stored: Boolean(memory), correction, memory_id: memory?.id, goal_id: goalId };
      }),
    },
  ];
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean).slice(0, 24) : [];
}

function parseMissionBindings(value: unknown): Partial<Record<SecurityMissionInputId, string>> | undefined {
  const record = objectValue(value);
  if (!record) return undefined;
  const bindings = Object.entries(record).flatMap(([id, binding]) => {
    const parsed = securityMissionInputIdSchema.safeParse(id);
    const cleaned = stringValue(binding);
    return parsed.success && cleaned ? [[parsed.data, cleaned] as const] : [];
  });
  return bindings.length > 0 ? Object.fromEntries(bindings) : undefined;
}

const toolFamilies = new Set<SecurityToolFamily>([
  "cerebro", "compliance", "evidence_cas", "graph", "infisical", "learning_docs", "memory", "operator",
  "panther_mcp", "runtime_code", "self_context", "skills", "slack", "ticketing", "other",
]);
const toolAuthorities = new Set<SecurityToolAuthority>([
  "autonomy_write", "cerebro_write", "security_write", "read", "memory_write", "workspace_write", "github_write", "ticket_write", "bounded_shell",
]);

function normalizeFamilies(values: string[] | undefined): SecurityToolFamily[] | undefined {
  const normalized = values?.filter((value): value is SecurityToolFamily => toolFamilies.has(value as SecurityToolFamily));
  return normalized?.length ? normalized : undefined;
}

function normalizeAuthorities(values: string[] | undefined): SecurityToolAuthority[] | undefined {
  const normalized = values?.filter((value): value is SecurityToolAuthority => toolAuthorities.has(value as SecurityToolAuthority));
  return normalized?.length ? normalized : undefined;
}
