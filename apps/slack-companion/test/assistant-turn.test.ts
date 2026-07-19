import assert from "node:assert/strict";
import test from "node:test";
import {
  AssistantTurnInputError,
  MAX_ASSISTANT_TURN_ANSWER_LENGTH,
  assistantTurnBudget,
  normalizeAssistantTurnOutput,
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

test("assistant output normalizes deterministic user-facing answer content", () => {
  const first = normalizeAssistantTurnOutput({
    answer: "  First line\r\nSecond line  ",
    next_action: "  Check the remaining item.  ",
    state: "answered",
  });
  const replay = normalizeAssistantTurnOutput({
    answer: "First line\nSecond line",
    next_action: "Check the remaining item.",
    state: "answered",
  });

  assert.deepEqual(first, replay);
  assert.deepEqual(first, {
    answer: "First line\nSecond line",
    content_digest: first.content_digest,
    next_action: "Check the remaining item.",
    schema_version: "assistant-turn-output/v1",
    state: "answered",
  });
  assert.match(first.content_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(Object.isFrozen(first), true);
});

test("assistant output represents partial, input-required, and blocked truth explicitly", () => {
  assert.deepEqual(
    normalizeAssistantTurnOutput({
      answer: "Two records matched.",
      coverage_notice: "One source did not respond.",
      state: "partial",
    }).state,
    "partial",
  );
  assert.deepEqual(
    normalizeAssistantTurnOutput({
      coverage_notice: "I can check either workspace.",
      question: "Which workspace should I check?",
      state: "needs_input",
    }).state,
    "needs_input",
  );
  assert.deepEqual(
    normalizeAssistantTurnOutput({
      coverage_notice: "The required source is unavailable.",
      next_action: "Retry after the source recovers.",
      state: "blocked",
    }).state,
    "blocked",
  );
});

test("assistant output fails closed on invalid state combinations and extra records", () => {
  assert.throws(
    () => normalizeAssistantTurnOutput({ state: "answered" }),
    /requires an answer/,
  );
  assert.throws(
    () => normalizeAssistantTurnOutput({ answer: "Done.", state: "partial" }),
    /coverage notice/,
  );
  assert.throws(
    () => normalizeAssistantTurnOutput({
      answer: "Done.",
      question: "Continue?",
      state: "needs_input",
    }),
    /cannot include an answer/,
  );
  assert.throws(
    () => normalizeAssistantTurnOutput({
      coverage_notice: "Unavailable.",
      raw_result: { record: "not display content" },
      state: "blocked",
    }),
    /unsupported field/,
  );
  assert.throws(
    () => normalizeAssistantTurnOutput(new (class Output { state = "answered"; })()),
    /plain object/,
  );
  let accessorCalled = false;
  const accessorOutput: Record<string, unknown> = { answer: "Done." };
  Object.defineProperty(accessorOutput, "state", {
    enumerable: true,
    get: () => {
      accessorCalled = true;
      return "answered";
    },
  });
  assert.throws(
    () => normalizeAssistantTurnOutput(accessorOutput),
    /data fields/,
  );
  assert.equal(accessorCalled, false);
});

test("assistant output enforces code-point and control-character bounds", () => {
  assert.equal(
    normalizeAssistantTurnOutput({
      answer: "🙂".repeat(MAX_ASSISTANT_TURN_ANSWER_LENGTH),
      state: "answered",
    }).answer?.length,
    MAX_ASSISTANT_TURN_ANSWER_LENGTH * 2,
  );
  assert.throws(
    () => normalizeAssistantTurnOutput({
      answer: "🙂".repeat(MAX_ASSISTANT_TURN_ANSWER_LENGTH + 1),
      state: "answered",
    }),
    /answer is invalid/,
  );
  assert.throws(
    () => normalizeAssistantTurnOutput({
      answer: "Visible\u0000hidden",
      state: "answered",
    }),
    /answer is invalid/,
  );
  assert.throws(
    () => normalizeAssistantTurnOutput({
      answer: "a".repeat(MAX_ASSISTANT_TURN_ANSWER_LENGTH),
      coverage_notice: "c".repeat(600),
      next_action: "n".repeat(600),
      state: "partial",
    }),
    /total text bound/,
  );
});
