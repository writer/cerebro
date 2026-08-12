import assert from "node:assert/strict";
import test from "node:test";

import { planAgentGymSlackAcknowledgement } from "../src/index.js";

test("acknowledgement simulation waits for durable admission", () => {
  assert.deepEqual(planAgentGymSlackAcknowledgement({
    durable_admission: false,
    event_received_at: "2026-08-12T08:52:00.000Z",
    maximum_ack_latency_ms: 3_000,
  }), {
    disposition: "withhold",
    schema_version: "agent-gym-slack-acknowledgement/v1",
  });
  assert.equal(planAgentGymSlackAcknowledgement({
    admitted_at: "2026-08-12T08:52:02.500Z",
    durable_admission: true,
    event_received_at: "2026-08-12T08:52:00.000Z",
    maximum_ack_latency_ms: 3_000,
  }).disposition, "acknowledge");
});

test("acknowledgement simulation reports a missed deadline", () => {
  const receipt = planAgentGymSlackAcknowledgement({
    admitted_at: "2026-08-12T08:52:03.001Z",
    durable_admission: true,
    event_received_at: "2026-08-12T08:52:00.000Z",
    maximum_ack_latency_ms: 3_000,
  });
  assert.equal(receipt.disposition, "deadline_missed");
  assert.equal(receipt.ack_latency_ms, 3_001);
});
