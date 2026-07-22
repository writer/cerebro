import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  CanonicalWorkCoordinator,
  type CanonicalWorkCommandApprovalV1,
} from "@writer/cerebro-slack-companion";
import type {
  ComplianceWorkCommand,
  ComplianceWorkItem,
  ComplianceWorkItemPage,
  ComplianceWorkItemRecord,
} from "@writer/cerebro-sdk";
import {
  installCanonicalWorkHost,
  verifyCanonicalWorkHostEvidence,
  type CanonicalWorkHostRuntimeEvidenceV1,
} from "../src/activation.js";
import { PrivateCanonicalWorkItemAdapter } from "../src/canonical-client.js";
import { AtomicCanonicalWorkCaseStore } from "../src/persistence.js";
import { REQUIRED_CANONICAL_WORK_TOOL_IDS } from "../src/policy.js";
import { createCanonicalWorkHostTools } from "../src/tools.js";
import type {
  AtomicDocument,
  AtomicDocumentStore,
  CanonicalWorkApprovalPort,
  CanonicalWorkEvidencePort,
  CanonicalWorkGoalPort,
  CanonicalWorkHostEvidenceEvent,
  CanonicalWorkTransport,
  CanonicalWorkTransportFactory,
} from "../src/types.js";

const NOW = "2026-07-18T12:00:00.000Z";

describe("private canonical-work host", () => {
  test("binds opaque credentials and preserves command idempotency", async () => {
    const transport = new FakeCanonicalTransport(workItemRecord());
    const factory = new FakeTransportFactory(transport);
    const adapter = new PrivateCanonicalWorkItemAdapter(
      {
        credential_ref: "secret://canonical-work/runtime",
        integration_ref: "integration://canonical-work/runtime",
        tenant_ref: "tenant://canonical-work/primary",
      },
      factory,
    );

    await adapter.get("work-1");
    await adapter.list({ owner_id: "team-security", state: "open" });
    await adapter.command(
      "work-1",
      remediationCommand(1),
      { idempotency_key: "canonical-command-1" },
    );

    assert.deepEqual(factory.lastBinding, {
      credential_ref: "secret://canonical-work/runtime",
      integration_ref: "integration://canonical-work/runtime",
    });
    assert.equal(transport.commands[0]?.context.idempotency_key, "canonical-command-1");
    assert.equal(transport.commands[0]?.context.tenant_ref, "tenant://canonical-work/primary");
    assert.equal(transport.lastList?.tenant_ref, "tenant://canonical-work/primary");

    assert.throws(
      () => new PrivateCanonicalWorkItemAdapter(
        {
          credential_ref: "https://request-controlled.invalid/token",
          integration_ref: "integration://canonical-work/runtime",
          tenant_ref: "tenant://canonical-work/primary",
        },
        factory,
      ),
      /must not be an endpoint URL/,
    );
  });

  test("implements durable case and intent transitions with compare-and-swap fencing", async () => {
    const fixture = makeFixture();
    const opened = await fixture.coordinator.open({ work_item_id: "work-1" });
    const duplicate = await fixture.coordinator.open({ work_item_id: "work-1" });
    assert.equal(opened.created, true);
    assert.equal(duplicate.created, false);
    assert.equal(opened.case.case_id, duplicate.case.case_id);

    await assert.rejects(
      fixture.coordinator.open({ title: "Changed intent", work_item_id: "work-1" }),
      /changed intent/,
    );

    const planned = await fixture.coordinator.planCommand(
      opened.case.case_id,
      remediationCommand(1),
    );
    const duplicatePlan = await fixture.coordinator.planCommand(
      opened.case.case_id,
      remediationCommand(1),
    );
    assert.equal(planned.created, true);
    assert.equal(duplicatePlan.created, false);

    const applied = await fixture.coordinator.executeApproved(
      planned.intent.intent_id,
      approval(planned.intent.intent_id, planned.intent.command_digest),
    );
    assert.equal(applied.outcome, "applied");
    assert.equal(applied.case.state, "needs_evidence");
    assert.equal(fixture.transport.commands.length, 1);
    assert.equal(
      fixture.transport.commands[0]?.context.idempotency_key,
      planned.intent.intent_id,
    );

    const duplicateExecution = await fixture.coordinator.executeApproved(
      planned.intent.intent_id,
      approval(planned.intent.intent_id, planned.intent.command_digest),
    );
    assert.equal(duplicateExecution.duplicate, true);
    assert.equal(fixture.transport.commands.length, 1);
  });

  test("wires fixed tools through goal and digest-bound approval runners", async () => {
    const fixture = makeFixture();
    const events: CanonicalWorkHostEvidenceEvent[] = [];
    const goals: CanonicalWorkGoalPort = {
      recordIntent: async () => {
        return { goal_receipt_ref: "receipt://goal/intent" };
      },
      syncCase: async (caseRecord) => {
        fixture.goalCases.push(caseRecord.case_id);
        return { goal_receipt_ref: "receipt://goal/case" };
      },
    };
    const approvals = new FakeApprovalPort();
    const evidence: CanonicalWorkEvidencePort = {
      record: async (event) => {
        events.push(event);
      },
    };
    const deps = {
      approvals,
      clock: fixture.clock,
      coordinator: fixture.coordinator,
      evidence,
      goals,
      store: fixture.store,
    };
    const tools = createCanonicalWorkHostTools(deps);
    assert.deepEqual(tools.map((tool) => tool.name).sort(), REQUIRED_CANONICAL_WORK_TOOL_IDS);
    assert.equal(
      tools.find((tool) => tool.name === "operator_security_case_execute_command")?.policy.approval_required,
      true,
    );
    const context = {
      actor_ref: "actor://slack/operator",
      channel_ref: "channel://slack/security",
      request_ref: "request-1",
      thread_ref: "thread://slack/1",
    };
    const opened = await tool(tools, "operator_security_case_open_work_item").execute(
      { work_item_id: "work-1" },
      context,
    ) as { case: { case_id: string } };
    const planned = await tool(tools, "operator_security_case_command").execute(
      {
        action: "remediate",
        case_id: opened.case.case_id,
        expected_version: 1,
        rationale: "The remediation is complete.",
      },
      context,
    ) as { approval_ref: string; intent: { command_digest: string; intent_id: string } };
    approvals.approve(planned.approval_ref, planned.intent.intent_id, planned.intent.command_digest);
    const executed = await tool(tools, "operator_security_case_execute_command").execute(
      { approval_ref: planned.approval_ref, intent_id: planned.intent.intent_id },
      context,
    ) as { outcome: string };

    assert.equal(executed.outcome, "applied");
    assert.equal(approvals.requests.length, 1);
    assert.match(approvals.requests[0]?.summary ?? "", /version 1/);
    assert.equal(fixture.goalCases.length, 2);
    assert.deepEqual(events.map((event) => event.kind), [
      "case_durable",
      "goal_synced",
      "approval_requested",
      "goal_synced",
      "command_finished",
      "goal_synced",
    ]);
  });

  test("blocks route registration until exact runtime evidence is present", async () => {
    const fixture = makeFixture();
    const approvals = new FakeApprovalPort();
    const events: CanonicalWorkHostEvidenceEvent[] = [];
    const evidencePort: CanonicalWorkEvidencePort = {
      record: async (event) => {
        events.push(event);
      },
    };
    const evidence = runtimeEvidence();
    assert.deepEqual(verifyCanonicalWorkHostEvidence(evidence), {
      eligible: true,
      reason_code: "verified",
    });
    assert.equal(
      verifyCanonicalWorkHostEvidence({ ...evidence, tool_ids: evidence.tool_ids.slice(1) }).reason_code,
      "tool_pack_incomplete",
    );
    assert.equal(
      verifyCanonicalWorkHostEvidence({
        ...evidence,
        receipt_refs: {},
      } as unknown as CanonicalWorkHostRuntimeEvidenceV1).reason_code,
      "runtime_receipt_missing",
    );
    assert.equal(
      verifyCanonicalWorkHostEvidence({
        ...evidence,
        receipt_refs: {
          ...evidence.receipt_refs,
          durable_store: undefined,
        },
      } as unknown as CanonicalWorkHostRuntimeEvidenceV1).reason_code,
      "runtime_receipt_missing",
    );

    let registered = false;
    const result = await installCanonicalWorkHost({
      deps: {
        approvals,
        clock: fixture.clock,
        coordinator: fixture.coordinator,
        evidence: evidencePort,
        goals: {
          recordIntent: async () => ({ goal_receipt_ref: "receipt://goal/intent" }),
          syncCase: async () => ({ goal_receipt_ref: "receipt://goal/case" }),
        },
        store: fixture.store,
      },
      evidence,
      evidence_port: evidencePort,
      registry: {
        register: async (input) => {
          registered = true;
          assert.equal(input.route_id, "slack.canonical-work");
          assert.deepEqual(input.tools.map((item) => item.name).sort(), REQUIRED_CANONICAL_WORK_TOOL_IDS);
          return { registration_receipt_ref: "receipt://runtime/route-registration" };
        },
      },
    });

    assert.equal(registered, true);
    assert.equal(result.reason_code, "registered");
    assert.equal(events.at(-1)?.kind, "route_registered");
  });
});

function makeFixture() {
  const documents = new MemoryAtomicDocumentStore();
  const store = new AtomicCanonicalWorkCaseStore(documents);
  const transport = new FakeCanonicalTransport(workItemRecord());
  const canonical = new PrivateCanonicalWorkItemAdapter(
    {
      credential_ref: "secret://canonical-work/runtime",
      integration_ref: "integration://canonical-work/runtime",
      tenant_ref: "tenant://canonical-work/primary",
    },
    new FakeTransportFactory(transport),
  );
  const clock = { now: () => new Date(NOW) };
  return {
    clock,
    coordinator: new CanonicalWorkCoordinator({ canonical, clock, store }),
    documents,
    goalCases: [] as string[],
    store,
    transport,
  };
}

class FakeTransportFactory implements CanonicalWorkTransportFactory {
  lastBinding?: { credential_ref: string; integration_ref: string };

  constructor(private readonly transport: CanonicalWorkTransport) {}

  async bind(input: { credential_ref: string; integration_ref: string }) {
    this.lastBinding = input;
    return this.transport;
  }
}

class FakeCanonicalTransport implements CanonicalWorkTransport {
  commands: Array<{
    command: ComplianceWorkCommand;
    context: { idempotency_key: string; tenant_ref: string };
  }> = [];
  lastList?: { tenant_ref: string };

  constructor(private record: ComplianceWorkItemRecord) {}

  async command(
    _workItemId: string,
    command: ComplianceWorkCommand,
    context: { idempotency_key: string; tenant_ref: string },
  ) {
    this.commands.push({ command: structuredClone(command), context: { ...context } });
    this.record = {
      ...this.record,
      item: {
        ...this.record.item,
        last_remediated_at: NOW,
        last_remediated_by: "actor://slack/operator",
        state: "in_progress",
        updated_at: NOW,
        version: command.expected_version + 1,
      },
    };
    return structuredClone(this.record);
  }

  async get() {
    return structuredClone(this.record);
  }

  async list(options: { tenant_ref: string }): Promise<ComplianceWorkItemPage> {
    this.lastList = options;
    return { items: [structuredClone(this.record.item)] };
  }
}

class MemoryAtomicDocumentStore implements AtomicDocumentStore {
  private readonly documents = new Map<string, AtomicDocument>();
  private sequence = 0;

  async compareAndSwap(key: string, token: string, value: unknown): Promise<boolean> {
    const current = this.documents.get(key);
    if (current?.token !== token) return false;
    this.documents.set(key, { token: this.nextToken(), value: structuredClone(value) });
    return true;
  }

  async putIfAbsent(key: string, value: unknown): Promise<boolean> {
    if (this.documents.has(key)) return false;
    this.documents.set(key, { token: this.nextToken(), value: structuredClone(value) });
    return true;
  }

  async read(key: string): Promise<AtomicDocument | undefined> {
    const document = this.documents.get(key);
    return document === undefined ? undefined : structuredClone(document);
  }

  private nextToken(): string {
    this.sequence += 1;
    return `token-${this.sequence}`;
  }
}

class FakeApprovalPort implements CanonicalWorkApprovalPort {
  requests: Array<{ approval_ref: string; command_digest: string; intent_id: string; summary: string }> = [];
  private readonly receipts = new Map<string, CanonicalWorkCommandApprovalV1>();

  async request(input: { command_digest: string; intent_id: string; summary: string }) {
    const approvalRef = `receipt://approval/${this.requests.length + 1}`;
    this.requests.push({
      approval_ref: approvalRef,
      command_digest: input.command_digest,
      intent_id: input.intent_id,
      summary: input.summary,
    });
    return { approval_ref: approvalRef };
  }

  approve(approvalRef: string, intentId: string, commandDigest: string): void {
    this.receipts.set(approvalRef, approval(intentId, commandDigest, approvalRef));
  }

  async approvedReceipt(
    approvalRef: string,
    expected: { command_digest: string; intent_id: string },
  ) {
    const receipt = this.receipts.get(approvalRef);
    if (
      receipt === undefined ||
      receipt.command_digest !== expected.command_digest ||
      receipt.intent_id !== expected.intent_id
    ) {
      throw new Error("Approval receipt does not match the exact command intent.");
    }
    return structuredClone(receipt);
  }
}

function tool(tools: ReturnType<typeof createCanonicalWorkHostTools>, name: string) {
  const found = tools.find((candidate) => candidate.name === name);
  if (found === undefined) throw new Error(`Missing tool ${name}`);
  return found;
}

function remediationCommand(expectedVersion: number): ComplianceWorkCommand {
  return {
    action: "remediate",
    expected_version: expectedVersion,
    operation: "action",
    rationale: "The remediation is complete.",
  };
}

function approval(
  intentId: string,
  commandDigest: string,
  approvalRef = "receipt://approval/1",
): CanonicalWorkCommandApprovalV1 {
  return {
    approval_digest: "sha256:approval",
    approval_ref: approvalRef,
    approved_at: NOW,
    approved_by_ref: "actor://slack/approver",
    command_digest: commandDigest,
    intent_id: intentId,
    schema_version: "canonical-work-command-approval/v1",
  };
}

function runtimeEvidence(): CanonicalWorkHostRuntimeEvidenceV1 {
  return {
    generation: 1,
    observed_at: NOW,
    package_tree_sha: "b57d4c322fb01ec1edbc95b845ae14812abe2476",
    public_commit_sha: "722dba5aade977067d492c4d8012bb1d98b78804",
    receipt_refs: {
      approval_digest_binding: "receipt://runtime/approval-digest",
      credential_binding: "receipt://runtime/credential-binding",
      durable_store: "receipt://runtime/durable-store",
      goal_runner: "receipt://runtime/goal-runner",
      idempotent_command: "receipt://runtime/idempotent-command",
      route_probe: "receipt://runtime/route-probe",
      unknown_result_recovery: "receipt://runtime/unknown-recovery",
    },
    schema_version: "canonical-work-host-runtime-evidence/v1",
    tool_ids: [...REQUIRED_CANONICAL_WORK_TOOL_IDS],
  };
}

function workItemRecord(): ComplianceWorkItemRecord {
  const item: ComplianceWorkItem = {
    basis: {
      control_id: "control-1",
      kind: "remediate_finding",
      objective_id: "objective-1",
      program_id: "program-1",
      reason: "Current evidence requires remediation.",
      scope_revision_id: "scope-1",
      source_id: "source-1",
      subject_id: "subject-1",
      tenant_id: "tenant-1",
    },
    due_at: "2026-07-25T12:00:00.000Z",
    fingerprint: "sha256:work-1",
    fingerprint_version: "compliance-work-fingerprint/v1",
    id: "work-1",
    occurrences: [
      {
        assessment_run_id: "run-1",
        automated_result_hash: "sha256:result",
        evidence_ids: ["evidence-1"],
        finding_ids: ["finding-1"],
        id: "occurrence-1",
        objective_result_id: "result-1",
        occurred_at: "2026-07-18T11:00:00.000Z",
        occurrence_hash: "sha256:occurrence",
        work_item_id: "work-1",
      },
    ],
    owner_id: "team-security",
    priority: "high",
    state: "open",
    updated_at: "2026-07-18T11:00:00.000Z",
    verification_required: true,
    version: 1,
  };
  return { actions: [], item, occurrences: item.occurrences };
}
