import assert from "node:assert/strict";
import test from "node:test";

import {
  decodeSlackActionEnvelope,
  parseArchetypeDailyDigest,
  parseArchetypeFindingActionExecution,
  parseArchetypeFindingActionIntent,
  projectArchetypeStartWorkConfirmation,
  projectArchetypeToday,
} from "../src/index.js";

const finding = {
  assignee: null,
  description: "The production dependency has a reachable critical advisory.",
  due_at: "2026-07-23T18:00:00.000Z",
  finding_uuid: "018f6b96-a7b8-8c9d-8e0f-123456789abc",
  fingerprint: "a".repeat(64),
  priority_reasons: ["critical severity", "runtime reachable"],
  priority_score: 98,
  repository: "writer/service",
  severity: "critical",
  sla_state: "overdue",
  status: "actionable",
};

const digest = {
  actor_id: "person@writer.com",
  date: "2026-07-23",
  generated_at: "2026-07-23T16:00:00.000Z",
  saved_views: [{
    id: "018f6b96-a7b8-8c9d-8e0f-123456789abd",
    name: "Critical work",
    queue_mode: "investigations",
  }],
  today: {
    actor_id: "person@writer.com",
    assigned_to_me: [],
    counts: {
      assigned_to_me: 0,
      changed_last_24_hours: 1,
      due_soon: 0,
      overdue: 1,
      unassigned_critical: 1,
    },
    generated_at: "2026-07-23T16:00:00.000Z",
    needs_attention: [finding],
    recent_changes: [{
      actor: "security@writer.com",
      finding_ref: finding.finding_uuid,
      occurred_at: "2026-07-23T15:00:00.000Z",
      status: "actionable",
      summary: "The finding reopened after the latest scan.",
    }],
  },
};

test("parses a source-backed actor-scoped daily digest and projects exact work", () => {
  const parsed = parseArchetypeDailyDigest(digest);
  const projection = projectArchetypeToday(parsed);

  assert.equal(parsed.actor_id, "person@writer.com");
  assert.equal(parsed.today.needs_attention[0]?.priority_score, 98);
  assert.match(projection.fallback_text, /1 overdue/);
  assert.match(
    projection.blocks.blocks.map((block) =>
      "text" in block ? block.text.text : ""
    ).join("\n"),
    /writer\/service/,
  );

  const actionBlock = projection.blocks.blocks.find((block) =>
    block.type === "actions"
  );
  assert.ok(actionBlock && actionBlock.type === "actions");
  assert.equal(actionBlock.elements.length, 1);
  assert.match(
    actionBlock.elements[0]!.action_id,
    /^archetype_start_work_[0-9a-f]+$/,
  );
  const envelope = decodeSlackActionEnvelope(actionBlock.elements[0]!.value);
  assert.equal(envelope.action, "archetype.start_work.preview");
  assert.equal(
    envelope.subject_ref,
    `archetype-finding://${finding.finding_uuid}`,
  );
});

test("rejects actor drift, oversized source collections, and fabricated counts", () => {
  assert.throws(
    () => parseArchetypeDailyDigest({
      ...digest,
      today: { ...digest.today, actor_id: "other@writer.com" },
    }),
    /different actors/,
  );
  assert.throws(
    () => parseArchetypeDailyDigest({
      ...digest,
      today: {
        ...digest.today,
        needs_attention: Array.from({ length: 26 }, () => finding),
      },
    }),
    /bounded array/,
  );
  assert.throws(
    () => parseArchetypeDailyDigest({
      ...digest,
      today: {
        ...digest.today,
        counts: { ...digest.today.counts, overdue: -1 },
      },
    }),
    /must be an integer/,
  );
});

test("projects preview and explicit confirmation without executing a finding", () => {
  const intent = parseArchetypeFindingActionIntent({
    action: "start_work",
    created_at: "2026-07-23T16:05:00.000Z",
    executed_at: null,
    expires_at: "2026-07-23T16:20:00.000Z",
    finding_ref: finding.finding_uuid,
    id: "018f6b96-a7b8-8c9d-8e0f-123456789abe",
    status: "pending",
    summary: "Assign this finding to Person Writer and mark it in progress.",
  });
  const confirmation = projectArchetypeStartWorkConfirmation(intent);
  const envelope = decodeSlackActionEnvelope(confirmation.action.value);

  assert.equal(confirmation.action.label, "Assign to me");
  assert.equal(envelope.action, "archetype.start_work.confirm");
  assert.equal(
    envelope.subject_ref,
    "archetype-intent://018f6b96-a7b8-8c9d-8e0f-123456789abe",
  );

  const execution = parseArchetypeFindingActionExecution({
    finding: {
      ...finding,
      assignee: {
        display_name: "Person Writer",
        email: "person@writer.com",
        id: "00u-active",
        kind: "user",
        source: "okta",
      },
      status: "in_progress",
    },
    intent: {
      ...intent,
      executed_at: "2026-07-23T16:06:00.000Z",
      status: "executed",
    },
  });
  assert.equal(execution.finding.assignee?.source, "okta");
  assert.equal(execution.intent.status, "executed");
});
