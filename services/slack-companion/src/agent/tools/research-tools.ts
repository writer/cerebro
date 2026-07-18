import type { AgentTool } from "@earendil-works/pi-agent-core";
import { Type } from "@earendil-works/pi-ai";
import type {
  ActionSimulationInput,
  AttentionDecisionInput,
  DecisionInput,
  HypothesisInput,
  WorkflowCompileInput,
  WorldFactInput,
} from "../operational-intelligence.js";
import {
  ACTION_SIMULATION_TOOL,
  ATTENTION_DECISION_TOOL,
  CLAIM_LEDGER_TOOL,
  DECISION_LEDGER_TOOL,
  HYPOTHESIS_LEDGER_TOOL,
  RESEARCH_PLAN_TOOL,
  WORKFLOW_COMPILE_TOOL,
  WORLD_STATE_TOOL,
  type ClaimLedgerInput,
  type ResearchPlanInput,
} from "../research-state.js";
import { toolResult } from "./tool-result.js";
import type { SecurityToolDeps } from "./types.js";

export function createResearchTools(deps: SecurityToolDeps): AgentTool[] {
  return [
    {
      name: RESEARCH_PLAN_TOOL,
      label: "Research plan",
      description: "Establish the decision, execution style, entities, required claims, candidate source tools, stop conditions, and visible checks before using evidence tools. Use direct for one or two simple calls and code for composition, filtering, joins, pagination, or repeated calls. This stores only per-answer in-memory state.",
      parameters: Type.Object({
        decision: Type.String(),
        execution_lane: Type.Union([
          Type.Literal("ignore"),
          Type.Literal("converse"),
          Type.Literal("continue"),
          Type.Literal("lookup"),
          Type.Literal("investigate"),
          Type.Literal("act"),
        ]),
        execution_style: Type.Optional(Type.Union([
          Type.Literal("direct"),
          Type.Literal("code"),
        ])),
        domain_lenses: Type.Optional(Type.Array(Type.Union([
          Type.Literal("identity"),
          Type.Literal("delivery"),
          Type.Literal("cloud"),
          Type.Literal("detection"),
          Type.Literal("compliance"),
          Type.Literal("incident"),
          Type.Literal("self"),
          Type.Literal("general"),
        ]))),
        entities: Type.Optional(Type.Array(Type.String())),
        claims: Type.Array(Type.Object({
          id: Type.String(),
          claim: Type.String(),
          required: Type.Optional(Type.Boolean()),
          source_candidates: Type.Optional(Type.Array(Type.String())),
        }), { minItems: 1, maxItems: 12 }),
        source_candidates: Type.Optional(Type.Array(Type.String())),
        selected_tools: Type.Optional(Type.Array(Type.String(), { maxItems: 12 })),
        stop_conditions: Type.Optional(Type.Array(Type.String())),
        user_visible_work: Type.Optional(Type.Array(Type.String())),
        missing_context: Type.Optional(Type.Array(Type.String())),
      }),
      execute: async (_toolCallId, params) => deps.researchState
        ? toolResult(deps.researchState.establishPlan(params as ResearchPlanInput))
        : toolResult({ error: "research_state_unavailable" }),
    },
    {
      name: CLAIM_LEDGER_TOOL,
      label: "Claim ledger",
      description: "Close the research plan before answering. Mark each planned claim supported, contradicted, unverified, or blocked. Supported or contradicted claims must cite the successful source tool and its exact evidence receipt.",
      parameters: Type.Object({
        claims: Type.Array(Type.Object({
          id: Type.String(),
          status: Type.String(),
          source_tools: Type.Optional(Type.Array(Type.String())),
          evidence_receipts: Type.Optional(Type.Array(Type.String())),
          evidence_refs: Type.Optional(Type.Array(Type.String())),
          freshness: Type.Optional(Type.String()),
          source_scope: Type.Optional(Type.String()),
          coverage: Type.Optional(Type.String()),
          absence_meaning: Type.Optional(Type.String()),
          notes: Type.Optional(Type.String()),
        })),
        remaining_gaps: Type.Optional(Type.Array(Type.String())),
        answer_ready: Type.Optional(Type.Boolean()),
      }),
      execute: async (_toolCallId, params) => deps.researchState
        ? toolResult(deps.researchState.closeClaimLedger(params as ClaimLedgerInput))
        : toolResult({ error: "research_state_unavailable" }),
    },
    {
      name: WORLD_STATE_TOOL,
      label: "Operational world state",
      description: "Record bounded observed, inferred, expected, and desired facts for this investigation. Observed facts require the exact evidence receipt from the successful source tool; otherwise they remain inferred.",
      parameters: Type.Object({
        facts: Type.Array(Type.Object({
          id: Type.String(),
          statement: Type.String(),
          state: Type.Union([Type.Literal("observed"), Type.Literal("inferred"), Type.Literal("expected"), Type.Literal("desired")]),
          confidence: Type.Number({ minimum: 0, maximum: 1 }),
          source_tool: Type.Optional(Type.String()),
          evidence_receipt: Type.Optional(Type.String()),
          source_refs: Type.Optional(Type.Array(Type.String())),
          observed_at: Type.Optional(Type.String()),
          freshness: Type.Optional(Type.String()),
          scope: Type.Optional(Type.String()),
          valid_until: Type.Optional(Type.String()),
        }), { maxItems: 16 }),
      }),
      execute: async (_toolCallId, params) => deps.researchState
        ? toolResult(deps.researchState.updateWorldState(params as { facts?: WorldFactInput[] }))
        : toolResult({ error: "research_state_unavailable" }),
    },
    {
      name: HYPOTHESIS_LEDGER_TOOL,
      label: "Hypothesis ledger",
      description: "Maintain competing explanations for an investigation. Name falsifying evidence and the next discriminating check. Supported and contradicted states require successful evidence receipts.",
      parameters: Type.Object({
        hypotheses: Type.Array(Type.Object({
          id: Type.String(),
          statement: Type.String(),
          status: Type.Union([Type.Literal("open"), Type.Literal("supported"), Type.Literal("contradicted"), Type.Literal("eliminated")]),
          confidence: Type.Number({ minimum: 0, maximum: 1 }),
          supporting_receipts: Type.Optional(Type.Array(Type.String())),
          counterevidence_receipts: Type.Optional(Type.Array(Type.String())),
          falsifier: Type.Optional(Type.String()),
          next_check: Type.Optional(Type.String()),
        }), { maxItems: 16 }),
      }),
      execute: async (_toolCallId, params) => deps.researchState
        ? toolResult(deps.researchState.updateHypotheses(params as { hypotheses?: HypothesisInput[] }))
        : toolResult({ error: "research_state_unavailable" }),
    },
    {
      name: DECISION_LEDGER_TOOL,
      label: "Decision ledger",
      description: "Record a proposed, approved, executed, or superseded decision with rationale, owner, review date, and supporting evidence receipts.",
      parameters: Type.Object({
        decisions: Type.Array(Type.Object({
          id: Type.String(),
          decision: Type.String(),
          rationale: Type.String(),
          owner: Type.Optional(Type.String()),
          status: Type.Union([Type.Literal("proposed"), Type.Literal("approved"), Type.Literal("executed"), Type.Literal("superseded")]),
          review_at: Type.Optional(Type.String()),
          evidence_receipts: Type.Optional(Type.Array(Type.String())),
          source_refs: Type.Optional(Type.Array(Type.String())),
        }), { maxItems: 16 }),
      }),
      execute: async (_toolCallId, params) => deps.researchState
        ? toolResult(deps.researchState.recordDecisions(params as { decisions?: DecisionInput[] }))
        : toolResult({ error: "research_state_unavailable" }),
    },
    {
      name: WORKFLOW_COMPILE_TOOL,
      label: "Workflow compiler",
      description: "Compile a resumable observe-to-verify workflow DAG. Action steps require an approval gate, idempotency key, rollback, and post-action verification.",
      parameters: Type.Object({
        objective: Type.String(),
        owner: Type.Optional(Type.String()),
        steps: Type.Array(Type.Object({
          id: Type.String(),
          kind: Type.Union([Type.Literal("observe"), Type.Literal("compare"), Type.Literal("verify"), Type.Literal("decide"), Type.Literal("act"), Type.Literal("monitor"), Type.Literal("rollback")]),
          title: Type.String(),
          depends_on: Type.Optional(Type.Array(Type.String())),
          tool: Type.Optional(Type.String()),
          tool_arguments: Type.Optional(Type.Record(Type.String(), Type.Any(), { maxProperties: 40 })),
          approval_required: Type.Optional(Type.Boolean()),
          idempotency_key: Type.Optional(Type.String()),
          verification: Type.Optional(Type.String()),
          verification_tool: Type.Optional(Type.String()),
          verification_arguments: Type.Optional(Type.Record(Type.String(), Type.Any(), { maxProperties: 40 })),
          rollback: Type.Optional(Type.String()),
          max_attempts: Type.Optional(Type.Number({ minimum: 1, maximum: 3 })),
          acceptance_criteria_ids: Type.Optional(Type.Array(Type.String(), { maxItems: 40 })),
        }), { minItems: 1, maxItems: 16 }),
        completion_condition: Type.String(),
      }),
      execute: async (_toolCallId, params) => deps.researchState
        ? toolResult(deps.researchState.compileWorkflow(params as WorkflowCompileInput))
        : toolResult({ error: "research_state_unavailable" }),
    },
    {
      name: ACTION_SIMULATION_TOOL,
      label: "Action simulation",
      description: "Record counterfactual blast radius before a security write. Requires affected resources, risks, verified evidence, rollback, approval state, and post-action verification; it never performs the action.",
      parameters: Type.Object({
        action: Type.String(),
        target: Type.String(),
        affected_resources: Type.Array(Type.String()),
        affected_owners: Type.Optional(Type.Array(Type.String())),
        risks: Type.Array(Type.String()),
        evidence_receipts: Type.Array(Type.String()),
        approval_required: Type.Optional(Type.Boolean()),
        rollback: Type.String(),
        verification: Type.String(),
      }),
      execute: async (_toolCallId, params) => deps.researchState
        ? toolResult(deps.researchState.simulateAction(params as ActionSimulationInput))
        : toolResult({ error: "research_state_unavailable" }),
    },
    {
      name: ATTENTION_DECISION_TOOL,
      label: "Earned attention decision",
      description: "Score whether a proactive or automated signal contains a novel, material, urgent, actionable, high-confidence delta or a decision request. This advises the model; it does not suppress human questions.",
      parameters: Type.Object({
        signal: Type.String(),
        dedup_key: Type.String(),
        novelty: Type.Number({ minimum: 0, maximum: 1 }),
        materiality: Type.Number({ minimum: 0, maximum: 1 }),
        urgency: Type.Number({ minimum: 0, maximum: 1 }),
        actionability: Type.Number({ minimum: 0, maximum: 1 }),
        confidence: Type.Number({ minimum: 0, maximum: 1 }),
        decision_needed: Type.Boolean(),
        reason: Type.String(),
      }),
      execute: async (_toolCallId, params) => deps.researchState
        ? toolResult(deps.researchState.decideAttention(params as AttentionDecisionInput))
        : toolResult({ error: "research_state_unavailable" }),
    },
  ];
}
