import assert from "node:assert/strict";
import test from "node:test";

import {
  evaluateMemoryRetrieval,
  planSlackNotification,
  planSlackRichMessage,
  projectSlackEffectApproval,
  projectSlackOperatorHome,
  recordAnswerFeedback,
} from "../src/index.js";

test("answer feedback becomes immutable category-specific improvement evidence", () => {
  const input = {
    actor_ref: "slack-user://U123",
    answer_ref: "slack-message://C123/1754000000.000100",
    category: "missed_source" as const,
    feedback_key: "answer:one",
    observed_at: "2026-08-12T04:00:00.000Z",
    request_ref: "request://slack/one",
    tenant_ref: "tenant://writer",
    thread_ref: "slack-thread://T123/C123/1753999999.000100",
  };
  const first = recordAnswerFeedback(input);
  assert.deepEqual(recordAnswerFeedback({ ...input }), first);
  assert.equal(first.improvement_signal, "source_gap");
  assert.match(first.record_ref, /^feedback:\/\/answer\/[0-9a-f]{64}$/u);
  assert.equal(Object.isFrozen(first), true);
});

test("source cards retain a resolvable HTTPS record and freshness time", () => {
  const plan = planSlackRichMessage("answer:source-card", {
    schema_version: "slack-rich-message-input/v1",
    segments: [{
      evidence_ref: "evidence://finding/one",
      label: "Current finding",
      observed_at: "2026-08-12T04:00:00.000Z",
      source_system: "Cerebro",
      source_url: "https://cerebro.example.com/evidence/one",
      type: "source",
    }],
  });
  assert.match(plan.parts[0]?.payload.text ?? "", /Record: https:\/\/cerebro\.example\.com\/evidence\/one/u);
  assert.match(plan.parts[0]?.payload.text ?? "", /Observed: 2026-08-12T04:00:00.000Z/u);
  assert.throws(() => planSlackRichMessage("answer:bad-source", {
    schema_version: "slack-rich-message-input/v1",
    segments: [{
      evidence_ref: "evidence://finding/one",
      label: "Current finding",
      observed_at: "2026-08-12T04:00:00.000Z",
      source_system: "Cerebro",
      source_url: "http://cerebro.example.com/evidence/one",
      type: "source",
    }],
  }), /safe HTTPS URL/u);
});

test("memory retrieval evaluation is separate, bounded, and explicit when unavailable", () => {
  const result = evaluateMemoryRetrieval({
    available: true,
    expected_memory_refs: ["memory://decision/one", "memory://preference/two"],
    retrieved_memory_refs: ["memory://decision/one", "memory://stale/three"],
    stale_memory_refs: ["memory://stale/three"],
  });
  assert.equal(result.recall_at_1, 0.5);
  assert.equal(result.recall_at_10, 0.5);
  assert.equal(result.precision, 0.5);
  assert.deepEqual(result.blockers, ["expected_memory_missed", "stale_memory_retrieved"]);
  assert.deepEqual(evaluateMemoryRetrieval({
    available: false,
    expected_memory_refs: [], retrieved_memory_refs: [], stale_memory_refs: [],
  }), {
    blockers: [], evaluated: false, precision: null, recall_at_1: null,
    recall_at_5: null, recall_at_10: null,
    schema_version: "memory-retrieval-evaluation/v1",
  });
});

test("operator Home reports scope, source health, memory, and follow-through", () => {
  const projection = projectSlackOperatorHome({
    enabled_capabilities: ["security findings", "source health"],
    memory_note_count: 7,
    notification_mode: "digest",
    pending_outcome_count: 2,
    projection_key: "operator-home:U123",
    source_states: [
      { label: "Graph", state: "available" },
      { label: "Audit logs", state: "degraded" },
    ],
    statuses: [],
    view_selector: "tenant-user:U123",
  });
  const rendered = JSON.stringify(projection.view.blocks);
  assert.match(rendered, /Scope: security findings, source health/u);
  assert.match(rendered, /Audit logs: degraded; Graph: available/u);
  assert.match(rendered, /Memory: 7 retained notes/u);
  assert.match(rendered, /Outcome checks: 2 pending; notifications digest/u);

  const unavailable = projectSlackOperatorHome({
    enabled_capabilities: [],
    notification_mode: "muted",
    pending_outcome_count: 0,
    projection_key: "operator-home:unknown-memory",
    source_states: [],
    statuses: [],
    view_selector: "tenant-user:unknown-memory",
  });
  assert.match(JSON.stringify(unavailable.view.blocks), /Memory: unavailable/u);
});

test("effect approvals expose exact-input controls without authorizing the click", () => {
  const projection = projectSlackEffectApproval({
    approval_ref: "approval://agent-effect/one",
    expires_at: "2026-08-12T04:15:00.000Z",
    input_digest: `sha256:${"a".repeat(64)}`,
    purpose: "Disable connector alpha.",
    requester_ref: "slack-user://U123",
    target_ref: "connector://alpha",
    tool_id: "connector.update",
  });
  assert.deepEqual(projection.actions.map((action) => action.label), ["Approve", "Deny"]);
  assert.match(projection.sections[1] ?? "", /connector:\/\/alpha/u);
  assert.match(projection.actions[0]?.value ?? "", /"binding":"[0-9a-f]{64}"/u);
});

test("notification preferences gate follow-through and preserve critical alerts", () => {
  const preferences = {
    digest_hour: 8,
    enabled_classes: ["alert", "digest", "followup"] as const,
    minimum_severity: "medium" as const,
    quiet_hours_end: 7,
    quiet_hours_start: 22,
    schema_version: "slack-notification-preferences/v1" as const,
    timezone: "America/Los_Angeles",
  };
  assert.equal(planSlackNotification(preferences, {
    class: "followup", observed_at: "2026-08-12T06:00:00.000Z", severity: "high",
  }).disposition, "digest");
  assert.equal(planSlackNotification(preferences, {
    class: "alert", observed_at: "2026-08-12T06:00:00.000Z", severity: "critical",
  }).disposition, "deliver");
  assert.equal(planSlackNotification(preferences, {
    class: "followup", observed_at: "2026-08-12T18:00:00.000Z", severity: "low",
  }).disposition, "suppress");
});
