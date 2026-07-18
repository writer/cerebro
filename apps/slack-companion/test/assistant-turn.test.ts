import assert from "node:assert/strict";
import test from "node:test";
import {
  AssistantTurnInputError,
  assistantTurnBudget,
  normalizeAssistantTurnProgress,
} from "../src/index.js";

test("assistant turn budgets bind model-selected lanes to proportional work", () => {
  assert.deepEqual(assistantTurnBudget("converse"), {
    execution_lane: "converse",
    latency_budget_ms: 5_000,
    max_selected_capabilities: 0,
    max_tool_calls: 0,
    schema_version: "assistant-turn-budget/v1",
  });
  assert.equal(assistantTurnBudget("lookup").max_tool_calls, 3);
  assert.equal(assistantTurnBudget("investigate").max_tool_calls, 8);
  assert.equal(assistantTurnBudget("act").max_tool_calls, 12);
});

test("assistant turn budgets cannot expand host bounds", () => {
  assert.equal(assistantTurnBudget("investigate", { max_tool_calls: 4 }).max_tool_calls, 4);
  assert.equal(assistantTurnBudget("act", { timeout_ms: 45_000 }).latency_budget_ms, 45_000);
  assert.throws(
    () => assistantTurnBudget("lookup", { max_tool_calls: -1 }),
    AssistantTurnInputError,
  );
});
test("assistant progress is concrete, bounded, and safe to persist", () => {
  const progress = normalizeAssistantTurnProgress({
    capability_ref: "source://github/membership",
    execution_lane: "lookup",
    occurred_at: "2026-07-18T12:00:00.000Z",
    phase: "checking",
    sequence: 2,
    status: "  Checking\nGitHub membership  ",
  });
  assert.deepEqual(progress, {
    capability_ref: "source://github/membership",
    execution_lane: "lookup",
    occurred_at: "2026-07-18T12:00:00.000Z",
    phase: "checking",
    schema_version: "assistant-turn-progress/v1",
    sequence: 2,
    status: "Checking GitHub membership",
  });
  assert.throws(
    () => normalizeAssistantTurnProgress({ occurred_at: "bad", phase: "checking", sequence: 1, status: "Checking GitHub" }),
    AssistantTurnInputError,
  );
});
