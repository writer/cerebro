import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import type { AgentControlPlane, DecisionPacket, DecisionPacketBuildRequest } from "../../cerebro/types.js";
import type { SecurityToolDeps } from "./types.js";
import { toolResult } from "./tool-result.js";

export function createCerebroAgentPlatformTools(deps: SecurityToolDeps): AgentTool[] {
  const decisionPacketParams = Type.Object({
    mode: Type.Union([Type.Literal("build"), Type.Literal("reopen"), Type.Literal("recheck"), Type.Literal("diff")]),
    packet_id: Type.Optional(Type.String()),
    compare_to_packet_id: Type.Optional(Type.String()),
    workflow: Type.Optional(Type.String()),
    question: Type.Optional(Type.String()),
    scope_urn: Type.Optional(Type.String()),
    finding_ids: Type.Optional(Type.Array(Type.String(), { maxItems: 25 })),
    claim_ids: Type.Optional(Type.Array(Type.String(), { maxItems: 25 })),
    evidence_urns: Type.Optional(Type.Array(Type.String(), { maxItems: 50 })),
    audit_packet_ids: Type.Optional(Type.Array(Type.String(), { maxItems: 25 })),
    required_sources: Type.Optional(Type.Array(Type.String(), { maxItems: 25 })),
    requested_action: Type.Optional(Type.String()),
  });
  return [
    {
      name: "cerebro_agent_control_plane",
      label: "Cerebro agent control plane",
      description: "Read Cerebro's security-agent contract: approved profiles, verifier gates, action ladder, eval scenarios, connector gates, and simulation bounds.",
      parameters: Type.Object({}),
      execute: async () => {
        const controlPlane = await deps.cerebro.getAgentControlPlane();
        return toolResult(agentControlPlaneDetails(controlPlane));
      },
    },
    {
      name: "cerebro_decision_packet",
      label: "Cerebro decision packet",
      description: "Build, reopen, recheck, or compare a read-only Cerebro decision receipt. Use it for evidence-backed conclusions, freshness checks, coverage gaps, contradictions, affected resources, controls, and action previews. Action previews are not executed.",
      parameters: decisionPacketParams,
      execute: async (_toolCallId, params) => toolResult(await decisionPacketDetails(deps, params as DecisionPacketArgs)),
    },
  ];
}

interface DecisionPacketArgs extends Partial<DecisionPacketBuildRequest> {
  mode: "build" | "reopen" | "recheck" | "diff";
  packet_id?: string;
  compare_to_packet_id?: string;
}

async function decisionPacketDetails(deps: SecurityToolDeps, args: DecisionPacketArgs): Promise<Record<string, unknown>> {
  if (args.mode === "build") {
    const request = buildRequest(args);
    if (!request) return { error: "workflow_and_question_required", message: "Pass workflow and question to build a decision packet." };
    return { mode: args.mode, decision_packet: packetDetails(await deps.cerebro.buildDecisionPacket(request)) };
  }
  const packetId = cleanPacketId(args.packet_id);
  if (!packetId) return { error: "packet_id_required", message: `Pass packet_id to ${args.mode} a decision packet.` };
  const receipt = await deps.cerebro.getDecisionPacket(packetId);
  if (args.mode === "reopen") return { mode: args.mode, decision_packet: packetDetails(receipt) };
  if (args.mode === "recheck") {
    const current = await deps.cerebro.buildDecisionPacket(recheckRequest(receipt, args));
    return {
      mode: args.mode,
      previous_packet: packetDetails(receipt),
      decision_packet: packetDetails(current),
      changes: packetChanges(receipt, current),
    };
  }
  const compareId = cleanPacketId(args.compare_to_packet_id);
  if (!compareId) return { error: "compare_to_packet_id_required", message: "Pass compare_to_packet_id to compare two decision packets." };
  const comparison = await deps.cerebro.getDecisionPacket(compareId);
  return {
    mode: args.mode,
    left_packet: packetDetails(receipt),
    right_packet: packetDetails(comparison),
    changes: packetChanges(receipt, comparison),
  };
}

function buildRequest(args: DecisionPacketArgs): DecisionPacketBuildRequest | undefined {
  const workflow = cleanText(args.workflow, 120);
  const question = cleanText(args.question, 2_000);
  if (!workflow || !question) return undefined;
  return {
    workflow,
    question,
    scope_urn: cleanText(args.scope_urn, 500),
    finding_ids: cleanList(args.finding_ids, 25),
    claim_ids: cleanList(args.claim_ids, 25),
    evidence_urns: cleanList(args.evidence_urns, 50),
    audit_packet_ids: cleanList(args.audit_packet_ids, 25),
    required_sources: cleanList(args.required_sources, 25),
    requested_action: cleanText(args.requested_action, 500),
  };
}

function recheckRequest(packet: DecisionPacket, args: DecisionPacketArgs): DecisionPacketBuildRequest {
  return {
    workflow: cleanText(args.workflow, 120) ?? packet.workflow.id,
    question: cleanText(args.question, 2_000) ?? packet.workflow.question,
    scope_urn: cleanText(args.scope_urn, 500) ?? packet.scope.urn,
    finding_ids: cleanList(args.finding_ids, 25).length > 0 ? cleanList(args.finding_ids, 25) : packet.inputs.finding_ids,
    claim_ids: cleanList(args.claim_ids, 25).length > 0 ? cleanList(args.claim_ids, 25) : packet.inputs.claim_ids,
    evidence_urns: cleanList(args.evidence_urns, 50).length > 0
      ? cleanList(args.evidence_urns, 50)
      : packet.inputs.evidence_urns,
    audit_packet_ids: cleanList(args.audit_packet_ids, 25).length > 0
      ? cleanList(args.audit_packet_ids, 25)
      : packet.inputs.audit_packet_ids,
    required_sources: cleanList(args.required_sources, 25).length > 0
      ? cleanList(args.required_sources, 25)
      : packet.inputs.required_sources,
    requested_action: cleanText(args.requested_action, 500) ?? packet.inputs.requested_action,
  };
}

function packetDetails(packet: DecisionPacket): Record<string, unknown> {
  return {
    schema_version: packet.schema_version,
    id: packet.id,
    generated_at: packet.generated_at,
    workflow: packet.workflow,
    scope: { urn: packet.scope.urn },
    inputs: packet.inputs,
    decision: packet.decision,
    confidence: packet.confidence,
    freshness: packet.freshness,
    evidence: packet.evidence,
    contradictions: packet.contradictions,
    coverage_gaps: packet.coverage_gaps,
    affected: packet.affected,
    controls: packet.controls,
    audit_packets: packet.audit_packets,
    actions: packet.actions.map((action) => ({ ...action, executed: false })),
    provenance: packet.provenance,
    limits: packet.limits,
    receipt: { immutable: true, reopen_with: packet.id },
  };
}

function packetChanges(left: DecisionPacket, right: DecisionPacket): Record<string, unknown> {
  return {
    changed: left.id !== right.id,
    decision: valueChange(left.decision.state, right.decision.state),
    confidence: valueChange(left.confidence.level, right.confidence.level),
    freshness: valueChange(left.freshness.state, right.freshness.state),
    evidence_digest: valueChange(left.provenance.evidence_digest, right.provenance.evidence_digest),
    coverage_digest: valueChange(left.provenance.coverage_digest, right.provenance.coverage_digest),
    evidence: idChanges(left.evidence, right.evidence),
    contradictions: idChanges(left.contradictions, right.contradictions),
    coverage_gaps: idChanges(left.coverage_gaps, right.coverage_gaps),
    affected: stringChanges(left.affected.map((item) => item.urn), right.affected.map((item) => item.urn)),
    controls: idChanges(left.controls, right.controls),
    action_previews: idChanges(left.actions, right.actions),
  };
}

function valueChange(previous: unknown, current: unknown): Record<string, unknown> {
  return { previous, current, changed: previous !== current };
}

function idChanges(left: Array<{ id: string }>, right: Array<{ id: string }>): Record<string, string[]> {
  return stringChanges(left.map((item) => item.id), right.map((item) => item.id));
}

function stringChanges(left: string[], right: string[]): Record<string, string[]> {
  const previous = new Set(left);
  const current = new Set(right);
  return {
    added: [...current].filter((item) => !previous.has(item)).sort(),
    removed: [...previous].filter((item) => !current.has(item)).sort(),
  };
}

function cleanPacketId(value: unknown): string | undefined {
  const cleaned = cleanText(value, 40);
  return cleaned && /^dpr_[0-9a-f]{32}$/.test(cleaned) ? cleaned : undefined;
}

function cleanText(value: unknown, max: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const cleaned = value.replace(/\s+/g, " ").trim().slice(0, max);
  return cleaned || undefined;
}

function cleanList(value: unknown, max: number): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.flatMap((item) => cleanText(item, 500) ?? []))].slice(0, max);
}

function agentControlPlaneDetails(controlPlane: AgentControlPlane): Record<string, unknown> {
  return {
    version: controlPlane.version,
    default_on_profiles: controlPlane.agentProfiles
      .filter((profile) => profile.defaultOn)
      .map((profile) => ({
        id: profile.id,
        max_action_stage: profile.maxActionStage,
        required_verifiers: profile.requiredVerifierIds,
      })),
    verifier_ids: controlPlane.verifierLayer.map((verifier) => verifier.id),
    action_ladder: controlPlane.actionLadder.map((stage) => ({
      id: stage.id,
      order: stage.order,
      mutating: stage.mutating,
      requires_approval: stage.requiresApproval,
      verifier_ids: stage.verifierIds,
    })),
    eval_scenarios: controlPlane.evalScenarios.map((scenario) => ({
      id: scenario.id,
      capability: scenario.capability,
    })),
    connector_gate_ids: controlPlane.connectorToolGateIds,
    simulation_harness: controlPlane.simulationHarness ? {
      id: controlPlane.simulationHarness.id,
      mode: controlPlane.simulationHarness.mode,
      allowed_inputs: controlPlane.simulationHarness.allowedInputs,
      forbidden_inputs: controlPlane.simulationHarness.forbiddenInputs,
    } : undefined,
    note: "Use this contract before planning autonomous security work. It is read-only and does not grant write authority.",
  };
}
