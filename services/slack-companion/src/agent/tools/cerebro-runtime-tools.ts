import type { AgentTool } from "@earendil-works/pi-agent-core";
import { StringEnum, Type } from "@earendil-works/pi-ai";
import type { ClaimVerificationActionStage, ClaimVerificationFreshness } from "../../cerebro/types.js";
import { limit, stringList } from "./normalizers.js";
import type { SecurityToolDeps } from "./types.js";
import { toolResult } from "./tool-result.js";

const claimFreshnessValues = ["fresh", "stale", "failed", "unknown"] as const;
const claimStageValues = ["observe", "explain", "recommend", "dry_run", "approve", "execute", "verify", "close_loop"] as const;

export function createCerebroRuntimeTools(deps: SecurityToolDeps): AgentTool[] {
  const evidencePacketParams = Type.Object({
    question: Type.String(),
    entities: Type.Optional(Type.Array(Type.String())),
    capability_ids: Type.Optional(Type.Array(Type.String())),
  });
  const runtimeHealthParams = Type.Object({
    runtime_id: Type.Optional(Type.String()),
    runtime_ids: Type.Optional(Type.Array(Type.String())),
    source_id: Type.Optional(Type.String()),
    limit: Type.Optional(Type.Number()),
  });
  const claimVerificationParams = Type.Object({
    claim: Type.String(),
    claim_type: Type.Optional(Type.String()),
    scope_urn: Type.Optional(Type.String()),
    supporting_evidence_urns: Type.Optional(Type.Array(Type.String())),
    counter_evidence_urns: Type.Optional(Type.Array(Type.String())),
    missing_evidence: Type.Optional(Type.Array(Type.String())),
    freshness_state: Type.Optional(StringEnum([...claimFreshnessValues])),
    requested_action_stage: Type.Optional(StringEnum([...claimStageValues])),
    human_approved: Type.Optional(Type.Boolean()),
  });

  return [
    {
      name: "cerebro_evidence_packet",
      label: "Cerebro evidence packet",
      description: "Build a Cerebro evidence packet for a Slack security question, alert, identity, resource, or finding.",
      parameters: evidencePacketParams,
      execute: async (_toolCallId, params) => {
        const args = params as { question: string; entities?: string[]; capability_ids?: string[] };
        const response = await deps.cerebro.buildEvidencePacket({
          question: args.question,
          entities: args.entities ?? [],
          capability_ids: args.capability_ids ?? ["security-alert-triage", "graph-reasoning"],
        });
        return toolResult(response);
      },
    },
    {
      name: "cerebro_agent_claim_verify",
      label: "Cerebro agent claim verify",
      description: "Verify an agent conclusion before recommending a finding update, memory write, graph action, or production change. Returns evidence coverage, blockers, and the allowed next stage.",
      parameters: claimVerificationParams,
      execute: async (_toolCallId, params) => {
        const args = params as {
          claim: string;
          claim_type?: string;
          scope_urn?: string;
          supporting_evidence_urns?: string[];
          counter_evidence_urns?: string[];
          missing_evidence?: string[];
          freshness_state?: string;
          requested_action_stage?: string;
          human_approved?: boolean;
        };
        const freshness = normalizeClaimFreshness(args.freshness_state);
        if (!freshness.ok) return toolResult({ error: freshness.error });
        const stage = normalizeClaimStage(args.requested_action_stage);
        if (!stage.ok) return toolResult({ error: stage.error });
        const response = await deps.cerebro.verifyAgentClaim({
          claim: args.claim,
          claim_type: args.claim_type,
          scope_urn: args.scope_urn,
          supporting_evidence_urns: stringList(args.supporting_evidence_urns),
          counter_evidence_urns: stringList(args.counter_evidence_urns),
          missing_evidence: stringList(args.missing_evidence),
          freshness_state: freshness.value,
          requested_action_stage: stage.value,
          human_approved: args.human_approved,
        });
        return toolResult(response);
      },
    },
    {
      name: "cerebro_runtime_health",
      label: "Cerebro runtime health",
      description: "Read source runtime health for Cerebro security sources.",
      parameters: runtimeHealthParams,
      execute: async (_toolCallId, params) => {
        const args = params as { runtime_id?: string; runtime_ids?: string[]; source_id?: string; limit?: number };
        const response = await deps.cerebro.listRuntimeHealth({
          runtimeId: args.runtime_id,
          runtimeIds: args.runtime_ids,
          sourceId: args.source_id,
          limit: limit(args.limit, 20),
        });
        return toolResult({ runtimes: response });
      },
    },
  ];
}

type NormalizedClaimValue<T> = { ok: true; value?: T } | { ok: false; error: string };

function normalizeClaimFreshness(value: string | undefined): NormalizedClaimValue<ClaimVerificationFreshness> {
  if (value === undefined || value.trim() === "") return { ok: true };
  const normalized = value.trim();
  if (isClaimFreshness(normalized)) return { ok: true, value: normalized };
  return { ok: false, error: `freshness_state must be one of: ${claimFreshnessValues.join(", ")}` };
}

function normalizeClaimStage(value: string | undefined): NormalizedClaimValue<ClaimVerificationActionStage> {
  if (value === undefined || value.trim() === "") return { ok: true };
  const normalized = value.trim();
  if (isClaimStage(normalized)) return { ok: true, value: normalized };
  return { ok: false, error: `requested_action_stage must be one of: ${claimStageValues.join(", ")}` };
}

function isClaimFreshness(value: string): value is ClaimVerificationFreshness {
  return claimFreshnessValues.includes(value as ClaimVerificationFreshness);
}

function isClaimStage(value: string): value is ClaimVerificationActionStage {
  return claimStageValues.includes(value as ClaimVerificationActionStage);
}
