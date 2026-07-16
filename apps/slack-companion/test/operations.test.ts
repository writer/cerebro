import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  CapabilityManifestV1,
  PresenceSnapshotV1,
  ReleaseReceiptV2,
  RunReceiptV1,
  SchemaCompatibility,
} from "@writer/cerebro-sdk";
import {
  assessCompatibility,
  newLeaseGate,
  readinessGate,
} from "../src/operations/compatibility.js";
import {
  planMaintenance,
  verifyReleaseReceipt,
} from "../src/operations/maintenance.js";
import {
  advanceMigration,
  createMigrationReceipt,
  cutOverRoute,
  rollBackRoute,
  type SlackThreadIdentity,
} from "../src/operations/migration.js";
import {
  acquireScheduledOccurrence,
  createScheduledOccurrence,
  planMisfires,
  scheduledOccurrenceIdentity,
  updateScheduledOccurrence,
} from "../src/operations/schedules.js";
import { deriveSlackVisibleStatuses } from "../src/operations/status.js";

const now = "2026-07-16T12:00:00.000Z";

describe("scheduled operation continuity", () => {
  test("uses schedule, due time, and revision as deterministic identity", () => {
    const first = createScheduledOccurrence(
      {
        due_at: "2026-07-16T11:00:00Z",
        generation: 3,
        misfire_policy: "coalesce_once",
        schedule_id: "daily summary",
        schedule_revision: 4,
      },
      now,
    );
    const retried = createScheduledOccurrence(
      {
        due_at: "2026-07-16T11:00:00.000Z",
        generation: 4,
        misfire_policy: "coalesce_once",
        schedule_id: "daily summary",
        schedule_revision: 4,
      },
      now,
    );

    assert.equal(first.occurrence_id, retried.occurrence_id);
    assert.equal(first.idempotency_key, retried.idempotency_key);
    assert.equal(
      first.occurrence_id,
      scheduledOccurrenceIdentity(
        "daily summary",
        "2026-07-16T11:00:00Z",
        4,
      ),
    );
    assert.notEqual(
      first.occurrence_id,
      scheduledOccurrenceIdentity(
        "daily summary",
        "2026-07-16T11:00:00Z",
        5,
      ),
    );
  });

  test("applies skip, coalesce, and bounded catch-up policies", () => {
    const due = [
      "2026-07-16T09:00:00Z",
      "2026-07-16T10:00:00Z",
      "2026-07-16T11:00:00Z",
      "2026-07-16T13:00:00Z",
    ];

    assert.deepEqual(planMisfires(due, now, "skip"), {
      enqueue: [],
      pending: ["2026-07-16T13:00:00.000Z"],
      skip: [
        "2026-07-16T09:00:00.000Z",
        "2026-07-16T10:00:00.000Z",
        "2026-07-16T11:00:00.000Z",
      ],
    });
    assert.deepEqual(planMisfires(due, now, "coalesce_once"), {
      enqueue: ["2026-07-16T11:00:00.000Z"],
      pending: ["2026-07-16T13:00:00.000Z"],
      skip: [
        "2026-07-16T09:00:00.000Z",
        "2026-07-16T10:00:00.000Z",
      ],
    });
    assert.deepEqual(planMisfires(due, now, "run_all_bounded", 2), {
      enqueue: [
        "2026-07-16T09:00:00.000Z",
        "2026-07-16T10:00:00.000Z",
      ],
      pending: [
        "2026-07-16T11:00:00.000Z",
        "2026-07-16T13:00:00.000Z",
      ],
      skip: [],
    });
  });

  test("fences overlapping schedulers and stale completion", () => {
    const occurrence = createScheduledOccurrence(
      {
        due_at: "2026-07-16T11:00:00Z",
        generation: 3,
        misfire_policy: "coalesce_once",
        schedule_id: "summary",
        schedule_revision: 2,
      },
      now,
    );
    const first = acquireScheduledOccurrence(occurrence, {
      fencing_token: 10,
      generation: 3,
      lease_expires_at: "2026-07-16T12:01:00Z",
      lease_token: "lease-a",
      now,
      owner_id: "worker-a",
    });
    assert.equal(first.acquired, true);
    if (!first.acquired) {
      assert.fail("expected first scheduler to acquire the occurrence");
    }

    const overlap = acquireScheduledOccurrence(first.occurrence, {
      fencing_token: 11,
      generation: 4,
      lease_expires_at: "2026-07-16T12:02:00Z",
      lease_token: "lease-b",
      now: "2026-07-16T12:00:30Z",
      owner_id: "worker-b",
    });
    assert.deepEqual(overlap, { acquired: false, reason: "active_lease" });

    const recovered = acquireScheduledOccurrence(first.occurrence, {
      fencing_token: 11,
      generation: 4,
      lease_expires_at: "2026-07-16T12:04:00Z",
      lease_token: "lease-b",
      now: "2026-07-16T12:02:00Z",
      owner_id: "worker-b",
    });
    assert.equal(recovered.acquired, true);
    if (!recovered.acquired) {
      assert.fail("expected expired lease to be recovered");
    }

    assert.equal(
      updateScheduledOccurrence(
        recovered.occurrence,
        {
          fencing_token: 10,
          generation: 3,
          lease_token: "lease-a",
          owner_id: "worker-a",
        },
        "completed",
        "2026-07-16T12:02:30Z",
      ),
      undefined,
    );
    assert.equal(
      updateScheduledOccurrence(
        recovered.occurrence,
        {
          fencing_token: 11,
          generation: 4,
          lease_token: "lease-b",
          owner_id: "worker-b",
        },
        "completed",
        "2026-07-16T12:02:30Z",
      )?.state,
      "completed",
    );
  });

  test("rejects invalid schedule and lease identity fields", () => {
    assert.throws(
      () =>
        createScheduledOccurrence(
          {
            due_at: "2026-07-16T11:00:00Z",
            generation: 0,
            misfire_policy: "coalesce_once",
            schedule_id: "summary",
            schedule_revision: 2,
          },
          now,
        ),
      /generation must be a positive integer/,
    );

    const occurrence = createScheduledOccurrence(
      {
        due_at: "2026-07-16T11:00:00Z",
        generation: 1,
        misfire_policy: "coalesce_once",
        schedule_id: "summary",
        schedule_revision: 2,
      },
      now,
    );
    const lease = {
      fencing_token: 1,
      generation: 1,
      lease_expires_at: "2026-07-16T12:01:00Z",
      lease_token: "lease-1",
      now,
      owner_id: "worker-1",
    };

    assert.deepEqual(
      acquireScheduledOccurrence(occurrence, { ...lease, generation: 0 }),
      { acquired: false, reason: "invalid_generation" },
    );
    assert.deepEqual(
      acquireScheduledOccurrence(occurrence, { ...lease, fencing_token: 0 }),
      { acquired: false, reason: "invalid_fencing_token" },
    );
    assert.deepEqual(
      acquireScheduledOccurrence(occurrence, { ...lease, owner_id: " " }),
      { acquired: false, reason: "invalid_lease_identity" },
    );
    assert.deepEqual(
      acquireScheduledOccurrence(occurrence, { ...lease, lease_token: "" }),
      { acquired: false, reason: "invalid_lease_identity" },
    );
  });
});

describe("compatibility and service gates", () => {
  test("requires bidirectional reads, a shared write version, and required capabilities", () => {
    const supported = assessCompatibility({
      companion_manifest: manifest("companion", ["v1", "v2"]),
      companion_schema: schema("v2", ["v1", "v2"], ["v2"]),
      core_manifest: manifest("core", ["v1", "v2"]),
      core_schema: schema("v1", ["v1", "v2"], ["v2"]),
    });
    assert.deepEqual(supported, {
      decision: "supported",
      negotiated_write_version: "v2",
      reasons: [],
    });

    const blocked = assessCompatibility({
      companion_manifest: manifest("companion", ["v1", "v2"], []),
      companion_schema: schema("v2", ["v1", "v2"], ["v2"]),
      core_manifest: manifest("core", ["v1", "v2"]),
      core_schema: schema("v1", ["v1", "v2"], ["v2"]),
    });
    assert.equal(blocked.decision, "blocked");
    assert.deepEqual(blocked.reasons, ["companion_missing_turns@1"]);
  });

  test("blocks readiness and leases on stale presence, recovery, or generation changes", () => {
    const assessment = {
      decision: "supported" as const,
      negotiated_write_version: "v1",
      reasons: [],
    };
    assert.equal(readinessGate(presence(), assessment, now).allowed, true);
    assert.deepEqual(
      newLeaseGate(presence(), assessment, 1, 2, now),
      { allowed: true, reason: "lease_allowed" },
    );
    assert.deepEqual(
      newLeaseGate(presence({ route_generation: 3 }), assessment, 1, 2, now),
      { allowed: false, reason: "route_generation_changed" },
    );
    assert.deepEqual(
      readinessGate(
        presence({ service_state: "recovering" }),
        assessment,
        now,
      ),
      { allowed: false, reason: "service_recovering" },
    );
    assert.deepEqual(
      readinessGate(
        presence({ compatibility: "blocked" }),
        assessment,
        now,
      ),
      { allowed: false, reason: "presence_compatibility_blocked" },
    );
    assert.deepEqual(
      readinessGate(
        presence({ expires_at: "2026-07-16T11:59:59Z" }),
        assessment,
        now,
      ),
      { allowed: false, reason: "presence_expired" },
    );
  });
});

describe("Slack-visible continuity status", () => {
  test("derives queued, degraded, and partial-source facts with expiry", () => {
    const statuses = deriveSlackVisibleStatuses(
      run(),
      presence({ service_state: "degraded" }),
      now,
      { available_source_count: 2, expected_source_count: 3 },
    );

    assert.deepEqual(
      statuses.map((status) => status.code),
      ["queued", "degraded", "partial_source"],
    );
    assert.equal(statuses.every((status) => status.expires_at === "2026-07-16T12:05:00.000Z"), true);
    assert.equal(new Set(statuses.map((status) => status.idempotency_key)).size, 3);
  });

  test("does not show stale recovery state", () => {
    assert.deepEqual(
      deriveSlackVisibleStatuses(
        run(),
        presence({
          expires_at: "2026-07-16T11:59:00Z",
          service_state: "recovering",
        }),
        now,
      ),
      [],
    );
  });
});

describe("maintenance and release continuity", () => {
  test("keeps a graceful drain blocked until replacement and active work are safe", () => {
    const plan = planMaintenance({
      active_runs: [
        { checkpointable: true, run_id: "run-1" },
        { checkpointable: false, run_id: "run-2" },
      ],
      compatibility: "supported",
      deliveries: [{ delivery_id: "delivery-1", state: "delivering" }],
      mode: "graceful",
      now,
      replacement_presence: presence(),
    });

    assert.equal(plan.new_leases_allowed, false);
    assert.equal(plan.admission_behavior, "durable_queue");
    assert.equal(plan.safe_to_stop, false);
    assert.equal(plan.forced_stop_permitted_after_actions, false);
    assert.deepEqual(plan.blockers, ["run_not_checkpointable:run-2"]);
    assert.equal(
      plan.actions.some((action) => action.action === "checkpoint_and_pause"),
      true,
    );
    assert.equal(
      plan.actions.some((action) => action.action === "drain_delivery"),
      true,
    );
  });

  test("keeps forced maintenance unsafe until reconciliation and delivery pause finish", () => {
    const plan = planMaintenance({
      active_runs: [{ checkpointable: false, run_id: "run-1" }],
      compatibility: "supported",
      deliveries: [{ delivery_id: "delivery-1", state: "pending" }],
      mode: "forced",
      now,
    });

    assert.equal(plan.safe_to_stop, false);
    assert.equal(plan.forced_stop_permitted_after_actions, true);
    assert.deepEqual(plan.blockers, []);
    assert.equal(
      plan.actions.some(
        (action) => action.action === "mark_for_reconciliation",
      ),
      true,
    );
    assert.equal(
      plan.actions.some((action) => action.action === "pause_delivery"),
      true,
    );
  });

  test("marks a clean graceful drain safe after replacement readiness", () => {
    const plan = planMaintenance({
      active_runs: [],
      compatibility: "supported",
      deliveries: [],
      mode: "graceful",
      now,
      replacement_presence: presence(),
    });

    assert.equal(plan.safe_to_stop, true);
    assert.equal(plan.forced_stop_permitted_after_actions, false);
    assert.deepEqual(plan.blockers, []);
    assert.deepEqual(plan.actions, [
      { action: "stop_new_leases", subject_id: "service" },
    ]);
  });

  test("fails release verification for orphaned work and stuck delivery", () => {
    const verification = verifyReleaseReceipt(
      releaseReceipt({ orphaned_run_count: 1, stuck_delivery_count: 2 }),
    );
    assert.deepEqual(verification, {
      passed: false,
      reasons: ["orphaned_runs_present", "stuck_deliveries_present"],
    });
    assert.equal(verifyReleaseReceipt(releaseReceipt()).passed, true);
  });
});

describe("topology-neutral route migration", () => {
  test("uses route-generation compare-and-swap and preserves Slack thread identity", () => {
    let receipt = createMigrationReceipt({
      binding_id: "binding-1",
      checkpoint_count: 2,
      created_at: now,
      migration_id: "migration-1",
      pending_delivery_count: 1,
      rollback_generation: 8,
      route_generation: 12,
      source_generation: 8,
      target_generation: 9,
    });
    for (const state of ["validating", "draining", "cutting_over"] as const) {
      const advanced = advanceMigration(receipt, state, now);
      assert.equal(advanced.changed, true);
      if (!advanced.changed) {
        assert.fail(`expected transition to ${state}`);
      }
      receipt = advanced.receipt;
    }

    const conflict = cutOverRoute(receipt, 11, identity(), identity(), now);
    assert.deepEqual(conflict, {
      changed: false,
      reason: "route_generation_conflict",
      receipt,
    });

    const cutover = cutOverRoute(receipt, 12, identity(), identity(), now);
    assert.equal(cutover.changed, true);
    if (!cutover.changed) {
      assert.fail("expected route cutover");
    }
    assert.equal(cutover.receipt.route_generation, 13);
    assert.equal(cutover.receipt.state, "recovering");
    assert.equal(cutover.receipt.source_generation, 8);
    assert.equal(cutover.receipt.target_generation, 9);
  });

  test("fails cutover if app, binding, conversation, thread, or durable state changes", () => {
    const receipt = receiptAtCutover();
    const changed = identity({ durable_thread_state_digest: "sha256:changed" });
    const result = cutOverRoute(receipt, 12, identity(), changed, now);

    assert.equal(result.changed, false);
    assert.equal(result.reason, "identity_changed");
    assert.equal(result.receipt.state, "failed");
    assert.equal(result.receipt.route_generation, 12);
  });

  test("rolls back through the same route-generation compare-and-swap", () => {
    const receipt = {
      ...receiptAtCutover(),
      route_generation: 13,
      state: "rolling_back" as const,
    };
    const stale = rollBackRoute(receipt, 12, identity(), identity(), now);
    assert.equal(stale.changed, false);
    assert.equal(stale.reason, "route_generation_conflict");

    const rolledBack = rollBackRoute(
      receipt,
      13,
      identity(),
      identity(),
      now,
    );
    assert.equal(rolledBack.changed, true);
    if (!rolledBack.changed) {
      assert.fail("expected route rollback");
    }
    assert.equal(rolledBack.receipt.state, "rolled_back");
    assert.equal(rolledBack.receipt.route_generation, 14);
    assert.equal(rolledBack.receipt.rollback_generation, 8);
  });
});

function schema(
  currentVersion: string,
  readVersions: string[],
  writeVersions: string[],
): SchemaCompatibility {
  return {
    capability_decisions: ["supported", "degraded", "blocked", "incompatible"],
    current_version: currentVersion,
    read_versions: readVersions,
    rolling_upgrade_rule: "Readers accept the previous version during rollout.",
    write_versions: writeVersions,
  };
}

function manifest(
  serviceId: string,
  contractVersions: string[],
  capabilities: CapabilityManifestV1["capabilities"] = [
    { capability_id: "turns", level: "required", version: "1" },
  ],
): CapabilityManifestV1 {
  return {
    capabilities,
    contract_versions: contractVersions,
    digest: `sha256:${serviceId}`,
    generation: 1,
    produced_at: now,
    schema_version: "capability-manifest/v1",
    service_id: serviceId,
  };
}

function presence(
  changes: Partial<PresenceSnapshotV1> = {},
): PresenceSnapshotV1 {
  return {
    active_generation: 1,
    binding_id: "binding-1",
    compatibility: "supported",
    expires_at: "2026-07-16T12:05:00.000Z",
    observed_at: now,
    reason_code: "ready",
    route_generation: 2,
    schema_version: "presence-snapshot/v1",
    service_state: "ready",
    ...changes,
  };
}

function run(): RunReceiptV1 {
  return {
    admitted_at: now,
    binding_id: "binding-1",
    idempotency_key: "event-1",
    input_digest: "sha256:input",
    receipt_id: "receipt-1",
    received_at: now,
    required_capabilities: [],
    retention_policy_ref: "retention://standard",
    revision: 1,
    run_id: "run-1",
    run_kind: "interactive",
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: "conversation://thread-1",
    tenant_id: "tenant-1",
    updated_at: now,
  };
}

function releaseReceipt(
  changes: Partial<ReleaseReceiptV2> = {},
): ReleaseReceiptV2 {
  return {
    active_lease_count: 0,
    compatibility: "supported",
    created_at: now,
    drained_run_count: 3,
    generation: 2,
    orphaned_run_count: 0,
    pending_delivery_count: 0,
    recoverable_run_count: 0,
    release_id: "release-2",
    resumed_run_count: 3,
    schema_version: "release-receipt/v2",
    service_id: "companion",
    state: "active",
    stuck_delivery_count: 0,
    updated_at: now,
    verification_receipt_refs: ["verification://release-2"],
    ...changes,
  };
}

function identity(
  changes: Partial<SlackThreadIdentity> = {},
): SlackThreadIdentity {
  return {
    binding_id: "binding-1",
    conversation_id: "conversation-1",
    durable_thread_state_digest: "sha256:thread-state",
    installation_id: "installation-1",
    slack_app_id: "app-1",
    thread_id: "thread-1",
    ...changes,
  };
}

function receiptAtCutover() {
  return {
    binding_id: "binding-1",
    checkpoint_count: 2,
    created_at: now,
    migration_id: "migration-1",
    pending_delivery_count: 1,
    rollback_generation: 8,
    route_generation: 12,
    schema_version: "migration-receipt/v1" as const,
    source_generation: 8,
    state: "cutting_over" as const,
    target_generation: 9,
    updated_at: now,
  };
}
