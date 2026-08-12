import assert from "node:assert/strict";
import test from "node:test";

import { AgentGymContractError, CEREBRO_AGENT_GYM } from "../src/index.js";

test("agent gym exposes a stable public contract identity", () => {
  assert.deepEqual(CEREBRO_AGENT_GYM, {
    artifact_namespace: "cerebro-agent-gym",
    schema_version: "cerebro-agent-gym/v1",
  });
  assert.equal(Object.isFrozen(CEREBRO_AGENT_GYM), true);
  assert.equal(new AgentGymContractError("invalid").name, "AgentGymContractError");
});
