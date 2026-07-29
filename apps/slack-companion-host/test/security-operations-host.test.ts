import assert from "node:assert/strict";
import { describe, test } from "node:test";

import {
  SECURITY_OPERATION_WORKFLOWS,
  SecurityOperationHostPolicyError,
  SecurityOperationOutcomeUnknownError,
  SecurityOperationsHostAdapter,
  type PortableSecurityOperationsContract,
  type SecurityOperationArtifactPlan,
  type SecurityOperationDigestPlan,
  type SecurityOperationEvidenceEvent,
  type TranscriptActionApproval,
  type TranscriptActionDraft,
  type TranscriptActionPlan,
  type TranscriptActionSource,
} from "../src/security-operations.js";

const source: TranscriptActionSource = {
  captured_at: "2030-01-02T03:04:05.000Z",
  schema_version: "transcript-source/v1",
  transcript_digest: `sha256:${"c".repeat(64)}`,
  transcript_ref: "transcript:review-1",
};

const draft: TranscriptActionDraft = {
  action_id: "rotate_key",
  description: "Rotate the integration key.",
  evidence: [{ locator: "00:12:40", transcript_ref: source.transcript_ref }],
  schema_version: "transcript-action-draft/v1",
  state: "draft",
  ticket_system: "jira",
  title: "Rotate the integration key",
};

const approval: TranscriptActionApproval = {
  approval_id: "approval_1",
  approved_action_ids: [draft.action_id],
  approved_at: "2030-01-02T04:00:00.000Z",
  approved_by_ref: "user:security-lead",
  plan_id: "transcript-action-plan:one",
  schema_version: "transcript-action-approval/v1",
};

describe("private security operations host", () => {
  test("registers both fixed workflows through host-supplied schedule and destination refs", async () => {
    const fixture = hostFixture();
    const receipts = await fixture.host.registerWorkflows([
      {
        destination_ref: "slack-channel://security-team",
        schedule_ref: "schedule://weekday-morning",
        workflow_id: "security.board-daily/v1",
      },
      {
        destination_ref: "slack-channel://security-team",
        schedule_ref: "schedule://weekly-morning",
        workflow_id: "security.repo-hygiene-weekly/v1",
      },
    ]);

    assert.equal(receipts.length, 2);
    assert.deepEqual(fixture.scheduled.map((item) => item.kind), [
      "security_board",
      "repository_hygiene",
    ]);
    assert.deepEqual(
      fixture.events.map((event) => event.kind),
      ["schedule_registered", "schedule_registered"],
    );
    await assert.rejects(
      fixture.host.registerWorkflows([{
        destination_ref: "slack-channel://security-team",
        schedule_ref: "schedule://weekday-morning",
        workflow_id: "security.board-daily/v1",
      }]),
      SecurityOperationHostPolicyError,
    );
  });

  test("persists a complete digest before full Slack delivery and evidence-bound uploads", async () => {
    const fixture = hostFixture();
    const plan = await fixture.host.runDigest({
      collection_deadline_at: "2030-01-02T03:09:05.000Z",
      destination_ref: "slack-channel://security-team",
      generated_at: "2030-01-02T03:04:05.000Z",
      run_key: "weekday-2030-01-02",
      workflow_id: "security.board-daily/v1",
    });

    assert.equal(plan.disposition, "publish");
    assert.deepEqual(fixture.order, [
      "collect:security_board",
      "persist:digest",
      "evidence:digest_planned",
      "slack:digest",
      "evidence:digest_delivered",
      "render:artifacts",
      "persist:artifacts",
      "evidence:artifact_planned",
      "slack:artifacts",
      "evidence:artifact_uploaded",
    ]);
    assert.equal(fixture.deliveredSections, 2);
    assert.equal(fixture.uploadedArtifactRefs, 1);
  });

  test("does not deliver or render a suppressed digest", async () => {
    const fixture = hostFixture({ previousDigest: `sha256:${"d".repeat(64)}` });
    fixture.contract.planSecurityDigest = (input): SecurityOperationDigestPlan => ({
      content_digest: input.previous_content_digest!,
      disposition: "suppress",
      plan_id: "security-digest-plan:suppressed",
      reason_code: "unchanged",
      schema_version: "security-digest-plan/v1",
    });

    const plan = await fixture.host.runDigest({
      collection_deadline_at: "2030-01-02T03:09:05.000Z",
      destination_ref: "slack-channel://security-team",
      generated_at: "2030-01-02T03:04:05.000Z",
      run_key: "weekday-2030-01-02",
      workflow_id: "security.board-daily/v1",
    });

    assert.equal(plan.disposition, "suppress");
    assert.deepEqual(fixture.order, [
      "collect:security_board",
      "persist:digest",
      "evidence:digest_planned",
    ]);
  });

  test("persists transcript drafts and requires the public approval plan before ticket writes", async () => {
    const fixture = hostFixture();
    const pending = await fixture.host.prepareTranscriptActions({ drafts: [draft], source });
    assert.equal(pending.disposition, "await_approval");
    assert.equal(fixture.ticketWrites.length, 0);

    const receipts = await fixture.host.executeApprovedTranscriptActions({
      approval,
      approval_ref: "approval://security/one",
      drafts: [draft],
      source,
    });
    assert.deepEqual(receipts, ["receipt://ticket/rotate_key"]);
    assert.equal(fixture.ticketWrites[0]?.context.idempotency_key, "sha256:ticket-intent-1");
    assert.equal(fixture.ticketWrites[0]?.context.approval_ref, "approval://security/one");
    assert.deepEqual(fixture.order.slice(-4), [
      "persist:transcript:write_tickets",
      "evidence:transcript_planned",
      "ticket:write",
      "evidence:ticket_written",
    ]);
  });

  test("records an unknown Slack outcome and stops before rendering follow-on artifacts", async () => {
    const fixture = hostFixture({ digestOutcome: "unknown" });
    await assert.rejects(fixture.host.runDigest({
      collection_deadline_at: "2030-01-02T03:09:05.000Z",
      destination_ref: "slack-channel://security-team",
      generated_at: "2030-01-02T03:04:05.000Z",
      run_key: "weekday-2030-01-02",
      workflow_id: "security.board-daily/v1",
    }), SecurityOperationOutcomeUnknownError);
    assert.equal(fixture.events.at(-1)?.kind, "digest_outcome_unknown");
    assert.equal(fixture.order.includes("render:artifacts"), false);
  });

  test("rejects unbounded collection windows before a provider is called", async () => {
    const fixture = hostFixture();
    await assert.rejects(fixture.host.runDigest({
      collection_deadline_at: "2030-01-02T04:04:05.000Z",
      destination_ref: "slack-channel://security-team",
      generated_at: "2030-01-02T03:04:05.000Z",
      run_key: "weekday-2030-01-02",
      workflow_id: "security.board-daily/v1",
    }), SecurityOperationHostPolicyError);
    assert.equal(fixture.order.length, 0);
  });
});

function hostFixture(options: { digestOutcome?: "accepted" | "unknown"; previousDigest?: string } = {}) {
  const order: string[] = [];
  const events: SecurityOperationEvidenceEvent[] = [];
  const scheduled: Array<{ kind: string; workflow_id: string }> = [];
  const ticketWrites: Array<{
    context: { approval_ref: string; idempotency_key: string };
    intent: { action_id: string };
  }> = [];
  let deliveredSections = 0;
  let uploadedArtifactRefs = 0;
  const contract: PortableSecurityOperationsContract = {
    planSecurityDigest: (input): SecurityOperationDigestPlan => ({
      artifact_specs: [{ artifact_id: "work_age", format: "png", purpose: "status_chart", title: "Security work age" }],
      completeness: "complete",
      content_digest: `sha256:${"d".repeat(64)}`,
      disposition: "publish",
      generated_at: input.generated_at,
      kind: input.kind,
      plan_id: "security-digest-plan:one",
      schema_version: "security-digest-plan/v1",
      sections: input.sections,
      source_refs: ["result:security-board"],
      source_receipts: input.sources,
    }),
    planSlackArtifactDelivery: (input): SecurityOperationArtifactPlan => ({
      artifact_refs: input.artifacts.map((artifact) => artifact.content_ref),
      delivery_id: "slack-artifact-delivery:one",
      destination_ref: input.destination_ref,
      disposition: "upload",
      message_ref: input.message_ref,
      schema_version: "slack-artifact-delivery-plan/v1",
    }),
    planTranscriptActions: (input): TranscriptActionPlan => input.approval === undefined
      ? {
          action_ids: input.drafts.map((item) => item.action_id),
          disposition: "await_approval",
          plan_id: "transcript-action-plan:one",
          proposal_digest: `sha256:${"f".repeat(64)}`,
          schema_version: "transcript-action-plan/v1",
        }
      : {
          approval_id: input.approval.approval_id,
          disposition: "write_tickets",
          intents: input.drafts.map((item) => ({
            action_id: item.action_id,
            description: item.description,
            evidence: item.evidence,
            idempotency_key: "sha256:ticket-intent-1",
            schema_version: "transcript-ticket-write-intent/v1",
            ticket_system: item.ticket_system,
            title: item.title,
          })),
          plan_id: "transcript-action-plan:one",
          schema_version: "transcript-action-plan/v1",
        },
  };
  const host = new SecurityOperationsHostAdapter(contract, {
    artifacts: {
      render: async () => {
        order.push("render:artifacts");
        return [{
          alt_text: "Open and blocked work by age.",
          artifact_id: "work_age",
          content_digest: `sha256:${"e".repeat(64)}`,
          content_ref: "blob://security/work-age.png",
          created_at: "2030-01-02T03:04:05.000Z",
          evidence_refs: ["result:security-board"],
          mime_type: "image/png",
          schema_version: "slack-artifact/v1",
          size_bytes: 42_000,
          title: "Security work age",
        }];
      },
    },
    collector: {
      collect: async ({ kind }) => {
        order.push(`collect:${kind}`);
        return {
          sections: [
            { items: [], section_id: "blocked", title: "Blocked work" },
            { items: [], section_id: "changes", title: "Recent changes" },
          ],
          sources: [{
            coverage: "complete",
            fresh_until: "2030-01-02T03:10:00.000Z",
            observed_at: "2030-01-02T03:00:00.000Z",
            required: true,
            result_digest: `sha256:${"a".repeat(64)}`,
            result_ref: "result:security-board",
            source_id: "tickets",
            state: "succeeded",
          }],
        };
      },
    },
    evidence: {
      recordIdempotent: async (event) => {
        events.push(event);
        order.push(`evidence:${event.kind}`);
      },
    },
    receipts: {
      persistArtifactPlan: async () => {
        order.push("persist:artifacts");
        return { receipt_ref: "receipt://artifact-plan/one" };
      },
      persistDigestPlan: async () => {
        order.push("persist:digest");
        return { receipt_ref: "receipt://digest-plan/one" };
      },
      persistTranscriptPlan: async (plan) => {
        order.push(`persist:transcript:${plan.disposition}`);
        return { receipt_ref: "receipt://transcript-plan/one" };
      },
      previousContentDigest: async () => options.previousDigest,
    },
    schedules: {
      register: async (input) => {
        scheduled.push({ kind: input.kind, workflow_id: input.workflow_id });
        return { receipt_ref: `receipt://schedule/${input.workflow_id}` };
      },
    },
    slack: {
      deliverDigest: async (plan) => {
        order.push("slack:digest");
        deliveredSections = plan.sections.length;
        return { outcome: options.digestOutcome ?? "accepted", receipt_ref: "receipt://slack/digest-one" };
      },
      uploadArtifacts: async (plan) => {
        order.push("slack:artifacts");
        uploadedArtifactRefs = plan.artifact_refs.length;
        return { outcome: "accepted", receipt_ref: "receipt://slack/artifacts-one" };
      },
    },
    tickets: {
      write: async (intent, context) => {
        order.push("ticket:write");
        ticketWrites.push({ context, intent });
        return { outcome: "accepted", receipt_ref: `receipt://ticket/${intent.action_id}` };
      },
    },
  });
  return {
    contract,
    events,
    get deliveredSections() { return deliveredSections; },
    host,
    order,
    scheduled,
    ticketWrites,
    get uploadedArtifactRefs() { return uploadedArtifactRefs; },
  };
}

assert.equal(SECURITY_OPERATION_WORKFLOWS.length, 2);
