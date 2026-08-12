import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalAgentGymJson,
  digestAgentGymJson,
} from "../src/index.js";

test("canonical agent-gym JSON ignores object insertion order", () => {
  const first = { beta: [true, null], alpha: { two: 2, one: 1 } };
  const second = { alpha: { one: 1, two: 2 }, beta: [true, null] };
  assert.equal(canonicalAgentGymJson(first), canonicalAgentGymJson(second));
  assert.equal(digestAgentGymJson(first), digestAgentGymJson(second));
});

test("canonical agent-gym JSON rejects non-data properties", () => {
  const value = Object.defineProperty({ visible: true }, "hidden", { value: 1 });
  assert.throws(
    () => canonicalAgentGymJson(value),
    /canonical JSON is invalid/u,
  );
});
