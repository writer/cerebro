import assert from "node:assert/strict";
import { describe, test } from "node:test";

import type {
  TranscriptActionDraftV1,
  TranscriptActionPolicyInputV1,
} from "../src/transcripts/contracts.js";
import {
  planTranscriptActions,
  TranscriptActionPolicyError,
} from "../src/transcripts/policy.js";

const transcriptRef = "transcript:incident-review-2030-01-02";

function draft(overrides: Partial<TranscriptActionDraftV1> = {}): TranscriptActionDraftV1 {
  return {
    action_id: "rotate_key",
    description: "Rotate the affected integration key and attach the completion receipt.",
    evidence: [{ locator: "00:12:40-00:13:15", transcript_ref: transcriptRef }],
    owner_ref: "user:owner-1",
    schema_version: "transcript-action-draft/v1",
    state: "draft",
    ticket_system: "jira",
    title: "Rotate the affected integration key",
    ...overrides,
  };
}

function input(
  overrides: Partial<TranscriptActionPolicyInputV1> = {},
): TranscriptActionPolicyInputV1 {
  return {
    drafts: [draft()],
    schema_version: "transcript-action-policy-input/v1",
    source: {
      captured_at: "2030-01-02T03:04:05.000Z",
      schema_version: "transcript-source/v1",
      transcript_digest: `sha256:${"c".repeat(64)}`,
      transcript_ref: transcriptRef,
    },
    ...overrides,
  };
}

describe("transcript action policy", () => {
  test("keeps extracted actions in draft until approval", () => {
    const plan = planTranscriptActions(input());
    assert.deepEqual(plan, {
      action_ids: ["rotate_key"],
      disposition: "await_approval",
      plan_id: plan.plan_id,
      schema_version: "transcript-action-plan/v1",
    });
  });

  test("creates deterministic write intents for approved drafts only", () => {
    const approved = planTranscriptActions(input({
      approval: {
        approval_id: "approval_1",
        approved_action_ids: ["rotate_key"],
        approved_at: "2030-01-02T04:00:00.000Z",
        approved_by_ref: "user:security-lead",
        schema_version: "transcript-action-approval/v1",
      },
    }));
    assert.equal(approved.disposition, "write_tickets");
    if (approved.disposition !== "write_tickets") assert.fail("expected write intents");
    assert.equal(approved.intents.length, 1);
    assert.equal(approved.intents[0]?.ticket_system, "jira");
    assert.match(approved.intents[0]?.idempotency_key ?? "", /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(
      approved,
      planTranscriptActions(input({
        approval: {
          approval_id: "approval_1",
          approved_action_ids: ["rotate_key"],
          approved_at: "2030-01-02T04:00:00.000Z",
          approved_by_ref: "user:security-lead",
          schema_version: "transcript-action-approval/v1",
        },
      })),
    );
    const reapproved = planTranscriptActions(input({
      approval: {
        approval_id: "approval_2",
        approved_action_ids: ["rotate_key"],
        approved_at: "2030-01-02T05:00:00.000Z",
        approved_by_ref: "user:security-lead",
        schema_version: "transcript-action-approval/v1",
      },
    }));
    assert.equal(reapproved.disposition, "write_tickets");
    if (reapproved.disposition !== "write_tickets") assert.fail("expected write intents");
    assert.equal(reapproved.intents[0]?.idempotency_key, approved.intents[0]?.idempotency_key);
  });

  test("rejects unknown approvals and evidence from another transcript", () => {
    assert.throws(() => planTranscriptActions(input({
      approval: {
        approval_id: "approval_2",
        approved_action_ids: ["invented_action"],
        approved_at: "2030-01-02T04:00:00.000Z",
        approved_by_ref: "user:security-lead",
        schema_version: "transcript-action-approval/v1",
      },
    })), TranscriptActionPolicyError);
    assert.throws(() => planTranscriptActions(input({
      drafts: [draft({
        evidence: [{ locator: "line:9", transcript_ref: "transcript:other" }],
      })],
    })), TranscriptActionPolicyError);
  });
});
