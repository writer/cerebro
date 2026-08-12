import assert from "node:assert/strict";
import test from "node:test";

import { createAgentGymToolRegistry } from "../src/index.js";

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
