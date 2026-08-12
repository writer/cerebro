import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgentGymToolRegistry,
  injectAgentGymToolError,
  recordAgentGymToolResult,
} from "../src/index.js";

test("tool error injection preserves retryability as fixture data", () => {
  assert.deepEqual(injectAgentGymToolError({
    call_ref: "tool-call://one",
    error_code: "source.unavailable",
    message: "The evidence source is unavailable.",
    retryable: true,
    tool_id: "cerebro.search",
  }), {
    call_ref: "tool-call://one",
    error_code: "source.unavailable",
    message: "The evidence source is unavailable.",
    retryable: true,
    schema_version: "agent-gym-tool-error-fixture/v1",
    tool_id: "cerebro.search",
  });
});

test("tool error injection rejects display text as an error code", () => {
  assert.throws(() => injectAgentGymToolError({
    call_ref: "tool-call://one",
    error_code: "Source Unavailable",
    message: "The evidence source is unavailable.",
    retryable: true,
    tool_id: "cerebro.search",
  }), /error fixture is invalid/u);
});

test("recorded tool results bind output to exact input", () => {
  const result = recordAgentGymToolResult({
    call_ref: "tool-call://one",
    input: { query: "current evidence" },
    output: { records: [{ ref: "evidence://one" }] },
    recorded_at: "2026-08-12T08:58:00.000Z",
    tool_id: "cerebro.search",
  });
  assert.match(result.input_digest, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(Object.isFrozen(result.output), true);
  assert.equal(Object.isFrozen(result.output.records), true);
});

test("recorded tool results require canonical time", () => {
  assert.throws(() => recordAgentGymToolResult({
    call_ref: "tool-call://one",
    input: {},
    output: {},
    recorded_at: "2026-08-12T08:58:00Z",
    tool_id: "cerebro.search",
  }), /recorded tool result is invalid/u);
});

test("tool registry is stable across declaration order", () => {
  const first = {
    description: "Read current evidence.",
    input_schema: { properties: { query: { type: "string" } }, type: "object" },
    tool_id: "cerebro.search",
  };
  const second = {
    description: "Read one work item.",
    input_schema: { properties: { ref: { type: "string" } }, type: "object" },
    tool_id: "work.get",
  };
  const registry = createAgentGymToolRegistry([second, first]);
  assert.deepEqual(registry, createAgentGymToolRegistry([first, second]));
  assert.deepEqual(registry.tools.map((tool) => tool.tool_id), [
    "cerebro.search",
    "work.get",
  ]);
  assert.match(registry.registry_digest, /^sha256:[0-9a-f]{64}$/u);
});

test("tool registry rejects duplicate identities", () => {
  const tool = {
    description: "Read current evidence.",
    input_schema: { type: "object" },
    tool_id: "cerebro.search",
  };
  assert.throws(() => createAgentGymToolRegistry([tool, tool]), /registry is invalid/u);
});
