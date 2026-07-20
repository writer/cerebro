import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  ComplianceWorkCommand,
  ComplianceWorkItemPage,
  ComplianceWorkItemRecord,
  ComplianceWorkItemState,
} from "@writer/cerebro-sdk";
import type { CanonicalWorkCommandApprovalV1 } from "../src/canonical-work/contracts.js";
import {
  CanonicalWorkConflictError,
  CanonicalWorkCoordinator,
  CanonicalWorkInputError,
} from "../src/canonical-work/coordinator.js";
import type { CanonicalWorkItemPort } from "../src/canonical-work/ports.js";
import { ReferenceMemoryCanonicalWorkCaseStore } from "../src/canonical-work/reference-store.js";

const NOW = "2026-07-18T12:00:00.000Z";

describe("CanonicalWorkCoordinator", () => {
  test("opens one deterministic case and projects canonical state without owning a second queue", async () => {
    const fixture = makeFixture();
    const first = await fixture.coordinator.open({ work_item_id: "work-1" });
    assert.equal(first.created, true);
    assert.match(first.case.case_id, /^canonical-work-case-[a-f0-9]{32}$/);
    assert.equal(first.case.state, "ready_to_act");
    assert.equal(first.case.work_item_id, "work-1");
    assert.equal(first.case.work_item_version, 1);
    assert.deepEqual(first.case.finding_ids, ["finding-1"]);
    assert.equal(first.case.next_action, "Record the completed remediation");

    const duplicate = await fixture.coordinator.open({ work_item_id: "work-1" });
    assert.equal(duplicate.created, false);
    assert.equal(duplicate.case.case_id, first.case.case_id);
    assert.equal(duplicate.case.revision, 1);

    await assert.rejects(
      fixture.coordinator.open({ title: "Changed intent", work_item_id: "work-1" }),
      /case changed intent/,
    );
    const page = await fixture.coordinator.list({ owner_id: "team-security", state: "open" });
    assert.equal(page.items[0]?.id, "work-1");
    assert.deepEqual(fixture.canonical.lastList, { owner_id: "team-security", state: "open" });
  });

  test("fences stale versions before an approval can be requested", async () => {
    const fixture = makeFixture();
    const opened = await fixture.coordinator.open({ work_item_id: "work-1" });
    await assert.rejects(
      fixture.coordinator.planCommand(opened.case.case_id, {
        action: "remediate",
        expected_version: 2,
        operation: "action",
        rationale: "The access grant was removed.",
      }),
      CanonicalWorkConflictError,
    );
    await assert.rejects(
      fixture.coordinator.planCommand(opened.case.case_id, {
        action: "verify_assurance",
        expected_version: 1,
        operation: "action",
      }),
      CanonicalWorkInputError,
    );
    assert.equal(fixture.canonical.commands.length, 0);
  });

  test("binds approval to one command and keeps remediation separate from fresh assurance", async () => {
    const fixture = makeFixture();
    const opened = await fixture.coordinator.open({ work_item_id: "work-1" });
    const remediation = await fixture.coordinator.planCommand(opened.case.case_id, {
      action: "remediate",
      expected_version: 1,
      operation: "action",
      rationale: "The access grant was removed.",
    });
    assert.equal(remediation.created, true);
    const duplicatePlan = await fixture.coordinator.planCommand(
      opened.case.case_id,
      remediation.intent.command,
    );
    assert.equal(duplicatePlan.created, false);
    assert.equal(duplicatePlan.intent.intent_id, remediation.intent.intent_id);
    await assert.rejects(
      fixture.coordinator.executeApproved(
        remediation.intent.intent_id,
        approval(remediation.intent.intent_id, "sha256:wrong-command"),
      ),
      /does not match the exact command intent/,
    );
    assert.equal(fixture.canonical.commands.length, 0);

    const remediated = await fixture.coordinator.executeApproved(
      remediation.intent.intent_id,
      approval(remediation.intent.intent_id, remediation.intent.command_digest),
    );
    assert.equal(remediated.outcome, "applied");
    assert.equal(remediated.case.state, "needs_evidence");
    assert.equal(remediated.case.work_item_version, 2);
    assert.equal(remediated.case.steps[1]?.state, "completed");
    assert.equal(remediated.case.steps[2]?.state, "pending");
    assert.equal(fixture.canonical.commands.length, 1);

    const duplicate = await fixture.coordinator.executeApproved(
      remediation.intent.intent_id,
      approval(remediation.intent.intent_id, remediation.intent.command_digest),
    );
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.outcome, "applied");
    assert.equal(fixture.canonical.commands.length, 1);
    await assert.rejects(
      fixture.coordinator.executeApproved(
        remediation.intent.intent_id,
        {
          ...approval(remediation.intent.intent_id, remediation.intent.command_digest),
          approval_digest: "sha256:different-approval",
        },
      ),
      /does not match the recorded execution receipt/,
    );

    const verification = await fixture.coordinator.planCommand(opened.case.case_id, {
      action: "verify_assurance",
      assurance_decision_id: "decision-post-change",
      expected_version: 2,
      operation: "action",
      rationale: "Fresh evidence satisfies the control objective.",
    });
    const verified = await fixture.coordinator.executeApproved(
      verification.intent.intent_id,
      approval(verification.intent.intent_id, verification.intent.command_digest),
    );
    assert.equal(verified.outcome, "applied");
    assert.equal(verified.case.state, "closed");
    assert.equal(verified.case.work_item_state, "resolved");
    assert.equal(verified.case.work_item_version, 3);
    assert.equal(
      verified.case.verification?.assurance_decision_id,
      "decision-post-change",
    );
    assert.deepEqual(
      verified.case.steps.map((step) => step.state),
      ["completed", "completed", "completed", "completed"],
    );
  });

  test("reconciles an unknown result without executing the versioned command twice", async () => {
    const fixture = makeFixture();
    fixture.canonical.throwAfterApply = true;
    const opened = await fixture.coordinator.open({ work_item_id: "work-1" });
    const planned = await fixture.coordinator.planCommand(opened.case.case_id, {
      action: "remediate",
      expected_version: 1,
      operation: "action",
      rationale: "The access grant was removed.",
    });
    const receipt = approval(planned.intent.intent_id, planned.intent.command_digest);

    const unknown = await fixture.coordinator.executeApproved(planned.intent.intent_id, receipt);
    assert.equal(unknown.outcome, "unknown");
    assert.equal(unknown.intent.reason_code, "canonical_command_result_unknown");
    assert.equal(fixture.canonical.commands.length, 1);

    const recovered = await fixture.coordinator.executeApproved(planned.intent.intent_id, receipt);
    assert.equal(recovered.outcome, "applied");
    assert.equal(recovered.duplicate, true);
    assert.equal(recovered.intent.reason_code, "canonical_effect_already_applied");
    assert.equal(recovered.case.work_item_version, 2);
    assert.equal(fixture.canonical.commands.length, 1);
  });

  test("does not mistake unrelated version advancement for a lost remediation response", async () => {
    const fixture = makeFixture();
    fixture.canonical.replace({
      ...fixture.canonical.record.item,
      last_remediated_at: "2026-07-17T12:00:00.000Z",
      last_remediated_by: "actor://opaque/earlier",
    });
    const opened = await fixture.coordinator.open({ work_item_id: "work-1" });
    const planned = await fixture.coordinator.planCommand(opened.case.case_id, {
      action: "remediate",
      expected_version: 1,
      operation: "action",
      rationale: "Record the current remediation.",
    });
    fixture.canonical.replace({
      ...fixture.canonical.record.item,
      blocker_reason: "Independent review is pending.",
      state: "blocked",
      updated_at: "2026-07-18T12:01:00.000Z",
      version: 2,
    });

    const result = await fixture.coordinator.executeApproved(
      planned.intent.intent_id,
      approval(planned.intent.intent_id, planned.intent.command_digest),
    );
    assert.equal(result.outcome, "conflicted");
    assert.equal(result.intent.reason_code, "canonical_version_advanced");
    assert.equal(result.case.state, "blocked");
    assert.equal(fixture.canonical.commands.length, 0);
  });

  test("rejects unsupported runtime commands and records non-advancing responses as unknown", async () => {
    const fixture = makeFixture();
    const opened = await fixture.coordinator.open({ work_item_id: "work-1" });
    await assert.rejects(
      fixture.coordinator.planCommand(opened.case.case_id, {
        action: "unsupported" as never,
        expected_version: 1,
        operation: "action",
      }),
      /supported action/,
    );

    fixture.canonical.doNotAdvance = true;
    const planned = await fixture.coordinator.planCommand(opened.case.case_id, {
      action: "remediate",
      expected_version: 1,
      operation: "action",
      rationale: "The change is complete.",
    });
    const result = await fixture.coordinator.executeApproved(
      planned.intent.intent_id,
      approval(planned.intent.intent_id, planned.intent.command_digest),
    );
    assert.equal(result.outcome, "unknown");
    assert.equal(result.intent.reason_code, "canonical_command_version_not_advanced");
  });

  test("reports canonical terminal and operator-waiting states after independent refresh", async () => {
    const fixture = makeFixture();
    const opened = await fixture.coordinator.open({ work_item_id: "work-1" });
    fixture.canonical.replace({
      ...fixture.canonical.record.item,
      snooze_until: "2026-07-20T12:00:00.000Z",
      state: "snoozed",
      updated_at: "2026-07-18T12:01:00.000Z",
      version: 2,
    });
    const waiting = await fixture.coordinator.refresh(opened.case.case_id);
    assert.equal(waiting.state, "waiting_on_owner");

    fixture.canonical.replace({
      ...fixture.canonical.record.item,
      state: "accepted",
      updated_at: "2026-07-18T12:02:00.000Z",
      version: 3,
    });
    const closed = await fixture.coordinator.refresh(opened.case.case_id);
    assert.equal(closed.state, "closed");
    assert.equal(closed.steps.at(-1)?.state, "completed");
  });
});

function makeFixture() {
  const canonical = new FakeCanonicalWorkPort(workItemRecord());
  const store = new ReferenceMemoryCanonicalWorkCaseStore();
  return {
    canonical,
    coordinator: new CanonicalWorkCoordinator({
      canonical,
      clock: { now: () => new Date(NOW) },
      store,
    }),
    store,
  };
}

class FakeCanonicalWorkPort implements CanonicalWorkItemPort {
  readonly commands: ComplianceWorkCommand[] = [];
  lastList: Parameters<CanonicalWorkItemPort["list"]>[0];
  record: ComplianceWorkItemRecord;
  doNotAdvance = false;
  throwAfterApply = false;

  constructor(record: ComplianceWorkItemRecord) {
    this.record = structuredClone(record);
  }

  async get(workItemId: string): Promise<ComplianceWorkItemRecord> {
    assert.equal(workItemId, this.record.item.id);
    return structuredClone(this.record);
  }

  async list(options: {
    cursor?: string;
    limit?: number;
    owner_id?: string;
    state?: ComplianceWorkItemState;
  } = {}): Promise<ComplianceWorkItemPage> {
    this.lastList = structuredClone(options);
    return { items: [structuredClone(this.record.item)] };
  }

  async command(
    workItemId: string,
    command: ComplianceWorkCommand,
    context: { idempotency_key: string },
  ): Promise<ComplianceWorkItemRecord> {
    assert.equal(workItemId, this.record.item.id);
    assert.match(context.idempotency_key, /^canonical-command-/);
    assert.equal(command.expected_version, this.record.item.version);
    this.commands.push(structuredClone(command));
    if (this.doNotAdvance) return structuredClone(this.record);
    if (command.action === "remediate") {
      this.replace({
        ...this.record.item,
        last_remediated_at: "2026-07-18T12:01:00.000Z",
        last_remediated_by: "operator://approved",
        state: "in_progress",
        updated_at: "2026-07-18T12:01:00.000Z",
        version: this.record.item.version + 1,
      });
    } else if (command.action === "verify_assurance") {
      this.replace({
        ...this.record.item,
        state: "resolved",
        updated_at: "2026-07-18T12:02:00.000Z",
        verification: {
          assessment_run_id: "assessment-post-change",
          assurance_decision_id: command.assurance_decision_id!,
          decision_as_of: "2026-07-18T12:02:00.000Z",
          decision_digest: "sha256:decision-post-change",
          evaluated_at: "2026-07-18T12:02:00.000Z",
          evidence_ids: ["evidence-post-change"],
          objective_result_id: "objective-result-post-change",
          record_digest: "sha256:verification-record",
        },
        version: this.record.item.version + 1,
      });
    }
    if (this.throwAfterApply) {
      this.throwAfterApply = false;
      throw new Error("response lost after canonical commit");
    }
    return structuredClone(this.record);
  }

  replace(item: ComplianceWorkItemRecord["item"]): void {
    this.record = { ...this.record, item: structuredClone(item) };
  }
}

function approval(intentId: string, commandDigest: string): CanonicalWorkCommandApprovalV1 {
  return {
    approval_digest: "sha256:approval-receipt",
    approval_ref: "approval://opaque/1",
    approved_at: "2026-07-18T12:00:30.000Z",
    approved_by_ref: "actor://opaque/operator-1",
    command_digest: commandDigest,
    intent_id: intentId,
    schema_version: "canonical-work-command-approval/v1",
  };
}

function workItemRecord(): ComplianceWorkItemRecord {
  return {
    actions: [],
    item: {
      basis: {
        control_id: "control-access",
        kind: "remediate_finding",
        objective_id: "objective-access",
        program_id: "program-assurance",
        reason: "Privileged access lacks current evidence.",
        scope_revision_id: "scope-revision-1",
        source_id: "source-identity",
        subject_id: "subject://identity/operator",
        tenant_id: "tenant-example",
      },
      due_at: "2026-07-25T00:00:00.000Z",
      fingerprint: "sha256:work-1",
      fingerprint_version: "compliance-work-fingerprint/v1",
      id: "work-1",
      occurrences: [{
        assessment_run_id: "assessment-before-change",
        automated_result_hash: "sha256:automated-result",
        evidence_ids: ["evidence-before-change"],
        finding_ids: ["finding-1", "finding-1"],
        id: "occurrence-1",
        objective_result_id: "objective-result-before-change",
        occurred_at: "2026-07-17T23:00:00.000Z",
        occurrence_hash: "sha256:occurrence-1",
        work_item_id: "work-1",
      }],
      owner_id: "team-security",
      priority: "high",
      state: "open",
      updated_at: "2026-07-17T23:00:00.000Z",
      verification_required: true,
      version: 1,
    },
    occurrences: [],
  };
}
