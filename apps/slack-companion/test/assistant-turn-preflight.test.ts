import assert from "node:assert/strict";
import test from "node:test";
import {
  assistantTurnBudget,
  createToolCatalog,
  preflightAssistantTurnInvocation,
  type SourceHealthSnapshotV1,
  type ToolAuthorityDecisionV1,
} from "../src/index.js";

const digest = `sha256:${"a".repeat(64)}` as const;
const catalog = createToolCatalog([{
  authority_class: "observe",
  effect_class: "read",
  input_schema_ref: "schemas/tools/findings-input/v1",
  replay_policy: "safe",
  required_capabilities: ["source:findings"],
  result_schema_ref: "schemas/tools/findings-result/v1",
  schema_version: "tool-catalog-entry/v1",
  summary: "Read current findings.",
  title: "Findings",
  tool_id: "cerebro.findings",
  tool_version: "1.0.0",
}]);

test("preflight allows one healthy authorized invocation inside the lane", () => {
  const result = preflightAssistantTurnInvocation({
    budget: assistantTurnBudget("lookup"),
    catalog,
    completed_tool_calls: 0,
    elapsed_ms: 10_000,
    invocation: invocation(),
    observed_at: "2026-07-21T12:00:01.000Z",
    replan_count: 0,
    selected_capability_refs: ["source:findings"],
    source_health: [health(true)],
  });

  assert.deepEqual(result, {
    allowed: true,
    blockers: [],
    cutoff_ms: 24_000,
    remaining_ms: 20_000,
    schema_version: "assistant-turn-plan-preflight/v1",
    tool_calls_after_start: 1,
  });
});

test("preflight stops new tools at 80 percent of the lane budget", () => {
  const result = preflightAssistantTurnInvocation({
    budget: assistantTurnBudget("lookup"),
    catalog,
    completed_tool_calls: 1,
    elapsed_ms: 24_000,
    invocation: invocation(),
    observed_at: "2026-07-21T12:00:01.000Z",
    replan_count: 1,
    selected_capability_refs: ["source:findings"],
    source_health: [health(true)],
  });

  assert.equal(result.allowed, false);
  assert.deepEqual(result.blockers, ["turn_start_tool_cutoff"]);
});

test("preflight rejects blocked plans before execution", () => {
  const planned = invocation();
  const result = preflightAssistantTurnInvocation({
    budget: assistantTurnBudget("lookup"),
    catalog,
    completed_tool_calls: 3,
    elapsed_ms: 25_000,
    invocation: {
      ...planned,
      authority: { ...planned.authority!, request_digest: `sha256:${"b".repeat(64)}` },
    },
    observed_at: "2026-07-21T12:00:01.000Z",
    replan_count: 2,
    selected_capability_refs: ["source:other"],
    source_health: [health(false)],
  });

  assert.deepEqual(result.blockers, [
    "authority_request_mismatch",
    "lane_tool_budget",
    "outside_selected_tool_pack",
    "replan_limit",
    "source_unavailable",
    "turn_start_tool_cutoff",
  ]);
});

test("preflight requires exact authority and source-health metadata", () => {
  const result = preflightAssistantTurnInvocation({
    budget: assistantTurnBudget("investigate"),
    catalog,
    completed_tool_calls: 0,
    elapsed_ms: 0,
    invocation: { ...invocation(), authority: undefined },
    observed_at: "2026-07-21T12:00:01.000Z",
    replan_count: 0,
    selected_capability_refs: ["source:findings"],
    source_health: [],
  });

  assert.deepEqual(result.blockers, [
    "authority_metadata_required",
    "source_health_required",
  ]);
});

test("preflight rejects authority that is expired at execution time", () => {
  const planned = invocation();
  const result = preflightAssistantTurnInvocation({
    budget: assistantTurnBudget("lookup"),
    catalog,
    completed_tool_calls: 0,
    elapsed_ms: 1_000,
    invocation: {
      ...planned,
      authority: {
        ...planned.authority!,
        expires_at: "2026-07-21T12:00:01.000Z",
      },
    },
    observed_at: "2026-07-21T12:00:01.000Z",
    replan_count: 0,
    selected_capability_refs: ["source:findings"],
    source_health: [health(true)],
  });

  assert.deepEqual(result.blockers, ["authority_expired"]);
});

function invocation() {
  return {
    authority: authority(),
    invocation_id: "invocation-1",
    request_digest: digest,
    run_id: "run-1",
    source_ref: "source:cerebro:findings",
    step_id: "step-1",
    subject_ref: "subject-1",
    tool_id: "cerebro.findings",
    tool_version: "1.0.0",
  };
}

function authority(): ToolAuthorityDecisionV1 {
  return {
    authority_ref: "authority-1",
    decided_at: "2026-07-21T12:00:00.000Z",
    decision_id: "decision-1",
    invocation_id: "invocation-1",
    outcome: "allowed",
    reason_code: "policy_allowed",
    request_digest: digest,
    run_id: "run-1",
    schema_version: "tool-authority-decision/v1",
    step_id: "step-1",
    subject_ref: "subject-1",
    tool_id: "cerebro.findings",
    tool_version: "1.0.0",
  };
}

function health(allowed: boolean): SourceHealthSnapshotV1 {
  return {
    allowed,
    attempts: 4,
    average_latency_ms: 1_000,
    consecutive_failures: allowed ? 0 : 2,
    retry_after_ms: allowed ? undefined : 30_000,
    schema_version: "source-health-snapshot/v1",
    slow: false,
    source_ref: "source:cerebro:findings",
    status: allowed ? "healthy" : "cooldown",
    success_rate: allowed ? 1 : 0.5,
  };
}
