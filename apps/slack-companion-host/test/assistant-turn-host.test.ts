import assert from "node:assert/strict";
import test from "node:test";
import {
  AssistantTurnHostAdapter,
  AssistantTurnHostPolicyError,
  type AssistantTurnHostTelemetryEvent,
  type PortableAssistantTurnContract,
  type SlackMultipartProjection,
  type SlackStatusProjection,
} from "../src/index.js";

test("assistant-turn host enforces the selected lane budget before execution", () => {
  const host = hostFixture().host;
  assert.equal(host.enforceBudget({
    execution_lane: "lookup",
    planned_tool_call_count: 3,
    selected_capability_count: 4,
  }).max_tool_calls, 3);

  assert.throws(
    () => host.enforceBudget({
      execution_lane: "lookup",
      planned_tool_call_count: 4,
      selected_capability_count: 4,
    }),
    AssistantTurnHostPolicyError,
  );
  assert.throws(
    () => host.enforceBudget({
      execution_lane: "lookup",
      planned_tool_call_count: 3,
      selected_capability_count: 5,
    }),
    AssistantTurnHostPolicyError,
  );
});

test("assistant-turn host blocks a tool start rejected by the portable preflight", () => {
  const host = hostFixture().host;
  const result = host.preflightInvocation({
    budget: host.enforceBudget({
      execution_lane: "lookup",
      planned_tool_call_count: 1,
      selected_capability_count: 1,
    }),
    catalog: { list: () => [], resolve: () => undefined },
    completed_tool_calls: 0,
    elapsed_ms: 24_000,
    invocation: {
      invocation_id: "invocation-1",
      request_digest: "sha256:request",
      run_id: "run-1",
      step_id: "step-1",
      subject_ref: "subject://tenant/one",
      tool_id: "security.source_read",
      tool_version: "1.0.0",
    },
    observed_at: "2026-07-18T10:00:00.000Z",
    replan_count: 0,
    selected_capability_refs: ["security:source_read"],
    source_health: [],
  });

  assert.equal(result.allowed, false);
  assert.deepEqual(result.blockers, ["tool_not_registered", "turn_start_tool_cutoff"]);
});

test("assistant-turn host returns a bounded evidence fallback", () => {
  const output = hostFixture().host.buildEvidenceFallback({
    evidence: [],
    gaps: [{
      scope: "current findings",
      source_label: "Security source",
      source_ref: "source://security/one",
      state: "unavailable",
    }],
    next_action: "Retry the configured source after its health check passes.",
  });

  assert.equal(output.state, "blocked");
  assert.match(output.coverage_notice ?? "", /Security source/);
});

test("assistant-turn host persists the measured outcome before bounded telemetry", async () => {
  const fixture = hostFixture();
  const assessment = await fixture.host.recordOutcome({
    assessment_at: "2026-07-19T10:00:00.000Z",
    evaluation_blockers: [],
    execution_lane: "lookup",
    latency_budget_ms: 30_000,
    negative_feedback_count: 0,
    opened_at: "2026-07-18T10:00:00.000Z",
    outcome_state: "completed",
    request_id: "request-1",
    request_kind: "human",
    user_correction_count: 0,
    useful_answer_at: "2026-07-18T10:00:10.000Z",
    verified: true,
  });

  assert.equal(assessment.qualification, "eligible_success");
  assert.deepEqual(fixture.order, ["persist:outcome", "telemetry:outcome"]);
  assert.doesNotMatch(JSON.stringify(fixture.telemetry), /request-1/);
});

test("assistant-turn host persists accepted parts before bounded delivery telemetry", async () => {
  const fixture = hostFixture();
  const projection = await fixture.host.recordDelivery({ opaque: true });

  assert.equal(projection.accepted_part_count, 1);
  assert.equal(projection.parts[0]?.acceptance?.destination_receipt, "receipt-one");
  assert.deepEqual(fixture.order, ["persist:delivery", "telemetry:delivery"]);
  assert.deepEqual(fixture.telemetry, [{
    accepted_part_count: 1,
    event_id: "delivery-1:revision-2:persisted",
    kind: "assistant_turn_delivery_persisted",
    part_count: 2,
    receipt_ref: "receipt://delivery/revision-2",
    state: "delivering",
    undelivered_part_count: 1,
  }]);
  const telemetryJson = JSON.stringify(fixture.telemetry);
  assert.doesNotMatch(telemetryJson, /destination_ref|payload_ref|destination_receipt/);
});

test("assistant-turn host persists progress before idempotent telemetry", async () => {
  const fixture = hostFixture();
  const projection = await fixture.host.recordProgress("run-1", {
    execution_lane: "lookup",
    occurred_at: "2026-07-18T10:00:01.000Z",
    phase: "checking",
    schema_version: "assistant-turn-progress/v1",
    sequence: 2,
    status: "Checking the available evidence",
  });

  assert.equal(projection.projection_id, "run-1:assistant-progress:2");
  assert.deepEqual(fixture.order, ["persist:status", "telemetry:status"]);
});

test("assistant-turn host emits no delivery telemetry when persistence fails", async () => {
  const telemetry: AssistantTurnHostTelemetryEvent[] = [];
  const contract = hostFixture().contract;
  const host = new AssistantTurnHostAdapter(
    contract,
    {
      persistMultipartDelivery: async () => {
        throw new Error("durable store unavailable");
      },
      persistStatus: async () => ({ receipt_ref: "receipt://status/one" }),
      persistOutcome: async () => ({ receipt_ref: "receipt://outcome/one" }),
    },
    {
      recordIdempotent: async (event) => {
        telemetry.push(event);
      },
    },
  );

  await assert.rejects(
    host.recordDelivery({ opaque: true }),
    /durable store unavailable/,
  );
  assert.deepEqual(telemetry, []);
});

function hostFixture(): {
  contract: PortableAssistantTurnContract;
  host: AssistantTurnHostAdapter;
  order: string[];
  telemetry: AssistantTurnHostTelemetryEvent[];
} {
  const order: string[] = [];
  const telemetry: AssistantTurnHostTelemetryEvent[] = [];
  const contract: PortableAssistantTurnContract = {
    assistantTurnBudget: (lane, configured) => ({
      execution_lane: lane,
      latency_budget_ms: Math.min(configured?.timeout_ms ?? 30_000, 30_000),
      max_selected_capabilities: lane === "lookup" ? 4 : 0,
      max_tool_calls: Math.min(configured?.max_tool_calls ?? 3, 3),
      schema_version: "assistant-turn-budget/v1",
    }),
    preflightAssistantTurnInvocation: () => ({
      allowed: false,
      blockers: ["tool_not_registered", "turn_start_tool_cutoff"],
      cutoff_ms: 24_000,
      remaining_ms: 6_000,
      schema_version: "assistant-turn-plan-preflight/v1",
      tool_calls_after_start: 1,
    }),
    buildAssistantTurnEvidenceFallback: () => ({
      content_digest: `sha256:${"c".repeat(64)}`,
      coverage_notice: "Security source: current findings (unavailable).",
      next_action: "Retry the configured source after its health check passes.",
      schema_version: "assistant-turn-output/v1",
      state: "blocked",
    }),
    assessAssistantTurnOutcome: (input) => ({
      ...input,
      assessment_digest: `sha256:${"d".repeat(64)}`,
      eligible: true,
      observation_window_complete: true,
      qualification: "eligible_success",
      schema_version: "assistant-turn-outcome-assessment/v1",
      useful_answer_latency_ms: 10_000,
      verified_outcome_within_slo: true,
    }),
    projectAssistantTurnProgress: (runId, progress): SlackStatusProjection => ({
      code: `assistant_${progress.phase}`,
      kind: "assistant_progress",
      observed_at: progress.occurred_at,
      operation: "upsert",
      projection_id: `${runId}:assistant-progress:${progress.sequence}`,
      run_id: runId,
      schema_version: "slack-status-projection/v1",
      sequence: progress.sequence,
      text: progress.status,
    }),
    projectSlackMultipartDelivery: (): SlackMultipartProjection => ({
      accepted_part_count: 1,
      delivery_id: "delivery-1",
      destination_ref: "opaque://destination/one",
      part_count: 2,
      parts: [
        {
          acceptance: {
            accepted_at: "2026-07-18T10:00:02.000Z",
            destination_receipt: "receipt-one",
          },
          client_message_id: "delivery-1:part:1",
          part_id: "part-1",
          payload_digest: "sha256:one",
          payload_ref: "opaque://payload/one",
          schema_version: "slack-multipart-part-projection/v1",
          sequence: 1,
          state: "delivered",
        },
        {
          client_message_id: "delivery-1:part:2",
          part_id: "part-2",
          payload_digest: "sha256:two",
          payload_ref: "opaque://payload/two",
          schema_version: "slack-multipart-part-projection/v1",
          sequence: 2,
          state: "pending",
        },
      ],
      projection_id: "delivery-1:revision-2",
      run_id: "run-1",
      schema_version: "slack-multipart-projection/v1",
      state: "delivering",
      undelivered_part_count: 1,
      updated_at: "2026-07-18T10:00:02.000Z",
    }),
  };
  return {
    contract,
    host: new AssistantTurnHostAdapter(
      contract,
      {
        persistMultipartDelivery: async () => {
          order.push("persist:delivery");
          return { receipt_ref: "receipt://delivery/revision-2" };
        },
        persistStatus: async () => {
          order.push("persist:status");
          return { receipt_ref: "receipt://status/revision-2" };
        },
        persistOutcome: async () => {
          order.push("persist:outcome");
          return { receipt_ref: "receipt://outcome/revision-1" };
        },
      },
      {
        recordIdempotent: async (event) => {
          telemetry.push(event);
          order.push(event.kind === "assistant_turn_delivery_persisted"
            ? "telemetry:delivery"
            : event.kind === "assistant_turn_outcome_persisted"
              ? "telemetry:outcome"
              : "telemetry:status");
        },
      },
    ),
    order,
    telemetry,
  };
}
