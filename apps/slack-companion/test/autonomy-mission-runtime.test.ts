import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { RunReceiptV1, WorkLeaseV1 } from "@writer/cerebro-sdk";
import {
  createMissionWake,
  decideMissionWorkDispatch,
  MissionLedger,
  MissionLedgerIdempotencyConflictError,
  MissionLedgerStaleLeaseError,
  MissionLedgerStaleOccurrenceError,
  MissionLedgerStaleRevisionError,
} from "../src/autonomy/ledger.js";
import { ReferenceMemoryMissionLedgerStore } from "../src/autonomy/reference-store.js";
import type {
  AuthoritativeMissionLeaseRead,
  MissionLeaseAuthorityPort,
} from "../src/autonomy/ports.js";
import { ExecutionCoordinator } from "../src/execution/coordinator.js";
import type { ExecutionSession } from "../src/execution/model.js";
import { ReferenceMemoryExecutionStore } from "../src/execution/reference-store.js";
import type { MissionPlanProjectionV1 } from "../src/mission/model.js";
import {
  NATIVE_MISSION_CONTRACT_ID,
  NATIVE_MISSION_SCHEMA_VERSION,
} from "../src/mission/model.js";
import { acquireScheduledOccurrence } from "../src/operations/schedules.js";

const BASE_TIME = "2026-07-16T12:00:00.000Z";

describe("portable autonomy mission ledger", () => {
  test("commits one snapshot, event, and deterministic wake work item atomically", async () => {
    const store = new ReferenceMemoryMissionLedgerStore();
    const ledger = new MissionLedger({ store });
    const run = runReceipt("run-due-a", "subject-due-a");
    const plan = missionPlan(run, "mission-due-a");
    const wake = createMissionWake({
      created_at: "2026-07-16T11:00:00.000Z",
      due_at: "2026-07-16T11:30:00.000Z",
      generation: 1,
      misfire_policy: "coalesce_once",
      mission_ref: plan.mission_ref,
      mission_revision: plan.mission_revision,
      wake_condition_ref: "wake/source-revision",
    });
    assert.deepEqual(
      createMissionWake({
        created_at: "2026-07-16T11:00:00.000Z",
        due_at: "2026-07-16T11:30:00.000Z",
        generation: 1,
        misfire_policy: "coalesce_once",
        mission_ref: plan.mission_ref,
        mission_revision: plan.mission_revision,
        wake_condition_ref: "wake/source-revision",
      }),
      wake,
    );

    const input = {
      event: eventContext("2026-07-16T11:00:00.000Z", "mission.created"),
      operation_id: "create-mission-due-a",
      seed: { plan, run, wake },
    };
    const first = await ledger.initialize(input);
    const replay = await ledger.initialize(input);

    assert.equal(first.created, true);
    assert.equal(replay.created, false);
    assert.deepEqual(replay.snapshot, first.snapshot);
    assert.equal(first.snapshot.revision, 1);
    assert.equal(first.event.sequence, 1);
    assert.equal(first.snapshot.recent_event_refs.length, 1);
    assert.equal(
      first.snapshot.wake?.occurrence_ref,
      wake.occurrence.occurrence_id,
    );
    assert.deepEqual(
      await store.readOccurrence(wake.occurrence.occurrence_id),
      wake.occurrence,
    );
    assert.deepEqual(
      await ledger.readBySubject(run.subject_ref),
      first.snapshot,
    );
    assert.deepEqual(
      await ledger.readByMissionRef(plan.mission_ref),
      first.snapshot,
    );
    assert.equal((await ledger.listEvents(run.subject_ref, 0, 10)).length, 1);
    assert.deepEqual(
      (await ledger.listDue(BASE_TIME, 10)).map(
        (record) => record.snapshot.subject_ref,
      ),
      [run.subject_ref],
    );

    await assert.rejects(
      ledger.initialize({
        ...input,
        event: eventContext(
          "2026-07-16T11:00:00.000Z",
          "mission.changed-intent",
        ),
      }),
      MissionLedgerIdempotencyConflictError,
    );
    assert.equal((await ledger.listEvents(run.subject_ref, 0, 10)).length, 1);
  });

  test("orders due wakes deterministically and applies the requested limit", async () => {
    const store = new ReferenceMemoryMissionLedgerStore();
    const ledger = new MissionLedger({ store });
    for (const [suffix, dueAt] of [
      ["b", "2026-07-16T11:00:00.000Z"],
      ["a", "2026-07-16T11:00:00.000Z"],
      ["later", "2026-07-16T13:00:00.000Z"],
    ] as const) {
      const run = runReceipt(`run-${suffix}`, `subject-${suffix}`);
      const plan = missionPlan(run, `mission-${suffix}`);
      await ledger.initialize({
        event: eventContext("2026-07-16T10:00:00.000Z", "mission.created"),
        operation_id: `create-${suffix}`,
        seed: {
          plan,
          run,
          wake: createMissionWake({
            created_at: "2026-07-16T10:00:00.000Z",
            due_at: dueAt,
            generation: 1,
            misfire_policy: "coalesce_once",
            mission_ref: plan.mission_ref,
            mission_revision: plan.mission_revision,
            wake_condition_ref: "wake/deadline",
          }),
        },
      });
    }

    const due = await ledger.listDue(BASE_TIME, 2);
    assert.deepEqual(
      due.map((record) => record.snapshot.mission_ref),
      ["mission-a", "mission-b"],
    );
    assert.deepEqual(
      (await ledger.listDue(BASE_TIME, 1)).map(
        (record) => record.snapshot.mission_ref,
      ),
      ["mission-a"],
    );
  });

  test("consumes superseded wake work and retries work claimed elsewhere", async () => {
    const store = new ReferenceMemoryMissionLedgerStore();
    const ledger = new MissionLedger({ store });
    const run = runReceipt("run-dispatch", "subject-dispatch");
    const plan = {
      ...missionPlan(run, "mission-dispatch"),
      mission_revision: 2,
      plan_revision: 2,
    };
    const currentWake = createMissionWake({
      created_at: "2026-07-16T11:00:00.000Z",
      due_at: "2026-07-16T11:30:00.000Z",
      generation: 2,
      misfire_policy: "coalesce_once",
      mission_ref: plan.mission_ref,
      mission_revision: plan.mission_revision,
      wake_condition_ref: "wake/dispatch",
    });
    const initialized = await ledger.initialize({
      event: eventContext("2026-07-16T11:00:00.000Z", "mission.created"),
      operation_id: "create-dispatch",
      seed: { plan, run, wake: currentWake },
    });
    const staleWake = createMissionWake({
      created_at: "2026-07-16T10:00:00.000Z",
      due_at: "2026-07-16T11:30:00.000Z",
      generation: 1,
      misfire_policy: "coalesce_once",
      mission_ref: plan.mission_ref,
      mission_revision: 1,
      wake_condition_ref: "wake/dispatch",
    });

    assert.deepEqual(
      decideMissionWorkDispatch(
        initialized.snapshot,
        staleWake.occurrence,
        BASE_TIME,
      ),
      { disposition: "consume_stale", reason: "revision_superseded" },
    );
    assert.deepEqual(
      decideMissionWorkDispatch(
        initialized.snapshot,
        currentWake.occurrence,
        BASE_TIME,
      ),
      { disposition: "claim" },
    );

    const lease = {
      fencing_token: 7,
      generation: 3,
      lease_expires_at: "2026-07-16T12:01:00.000Z",
      lease_token: "scheduled-lease-dispatch",
      now: BASE_TIME,
      owner_id: "scheduler-dispatch",
    };
    const acquired = acquireScheduledOccurrence(currentWake.occurrence, lease);
    if (!acquired.acquired) assert.fail(`expected lease: ${acquired.reason}`);

    assert.deepEqual(
      decideMissionWorkDispatch(
        initialized.snapshot,
        acquired.occurrence,
        BASE_TIME,
      ),
      { disposition: "retry_claimed", reason: "active_lease" },
    );
    assert.deepEqual(
      decideMissionWorkDispatch(
        initialized.snapshot,
        acquired.occurrence,
        BASE_TIME,
        lease,
      ),
      { disposition: "execute" },
    );
  });

  test("persists one scheduled claim across restart and reclaims it only with a newer fence", async () => {
    const store = new ReferenceMemoryMissionLedgerStore();
    const ledger = new MissionLedger({ store });
    const run = runReceipt("run-durable-claim", "subject-durable-claim");
    const plan = missionPlan(run, "mission-durable-claim");
    const wake = createMissionWake({
      created_at: "2026-07-16T11:00:00.000Z",
      due_at: "2026-07-16T11:30:00.000Z",
      generation: 1,
      misfire_policy: "coalesce_once",
      mission_ref: plan.mission_ref,
      mission_revision: plan.mission_revision,
      wake_condition_ref: "wake/durable-claim",
    });
    await ledger.initialize({
      event: eventContext("2026-07-16T11:00:00.000Z", "mission.created"),
      operation_id: "create-durable-claim",
      seed: { plan, run, wake },
    });
    const due = (await ledger.listDue(BASE_TIME, 1))[0]!;
    const firstClaim = {
      fencing_token: 7,
      generation: 2,
      lease_expires_at: "2026-07-16T12:01:00.000Z",
      lease_token: "scheduled-lease-durable",
      now: BASE_TIME,
      owner_id: "scheduler-durable",
    };

    const claimed = await ledger.claimDue(due, firstClaim);
    assert.equal(claimed.acquired, true);
    if (!claimed.acquired) assert.fail("expected the first claim to succeed");
    assert.equal(claimed.created, true);
    assert.equal(
      (await store.readOccurrence(wake.occurrence.occurrence_id))?.state,
      "leased",
    );
    assert.equal((await ledger.listDue(BASE_TIME, 1)).length, 0);

    const restarted = new MissionLedger({ store });
    const replay = await restarted.claimDue(due, firstClaim);
    assert.equal(replay.acquired, true);
    if (!replay.acquired) assert.fail("expected the claim replay to succeed");
    assert.equal(replay.created, false);
    assert.deepEqual(replay.occurrence, claimed.occurrence);
    assert.deepEqual(
      await restarted.claimDue(due, {
        ...firstClaim,
        lease_token: "scheduled-lease-competing",
        owner_id: "scheduler-competing",
      }),
      { acquired: false, reason: "active_lease" },
    );

    const afterExpiry = "2026-07-16T12:02:00.000Z";
    const expiredDue = (await restarted.listDue(afterExpiry, 1))[0]!;
    assert.equal(expiredDue.occurrence.state, "leased");
    assert.deepEqual(
      await restarted.claimDue(expiredDue, {
        ...firstClaim,
        lease_expires_at: "2026-07-16T12:03:00.000Z",
        now: afterExpiry,
      }),
      { acquired: false, reason: "stale_fencing_token" },
    );
    const reclaimed = await restarted.claimDue(expiredDue, {
      ...firstClaim,
      fencing_token: 8,
      generation: 3,
      lease_expires_at: "2026-07-16T12:03:00.000Z",
      lease_token: "scheduled-lease-recovered",
      now: afterExpiry,
      owner_id: "scheduler-recovered",
    });
    assert.equal(reclaimed.acquired, true);
    if (!reclaimed.acquired) assert.fail("expected the expired claim to recover");
    assert.equal(reclaimed.created, true);
    assert.equal(reclaimed.occurrence.fencing_token, 8);
    assert.equal(
      reclaimed.occurrence.occurrence_id,
      claimed.occurrence.occurrence_id,
    );
    assert.equal(reclaimed.occurrence.run_id, claimed.occurrence.run_id);
    assert.equal(
      reclaimed.occurrence.idempotency_key,
      claimed.occurrence.idempotency_key,
    );
    assert.deepEqual(
      await store.readOccurrence(wake.occurrence.occurrence_id),
      reclaimed.occurrence,
    );
  });

  test("consumes a claimed wake with the mission transition and records its replacement", async () => {
    const authority = new MutableMissionLeaseAuthority(BASE_TIME);
    const store = new ReferenceMemoryMissionLedgerStore({
      lease_authority: authority,
    });
    const ledger = new MissionLedger({ store });
    const run = runReceipt("run-consume-wake", "subject-consume-wake");
    const plan = missionPlan(run, "mission-consume-wake");
    const wake = createMissionWake({
      created_at: "2026-07-16T11:00:00.000Z",
      due_at: "2026-07-16T11:30:00.000Z",
      generation: 1,
      misfire_policy: "coalesce_once",
      mission_ref: plan.mission_ref,
      mission_revision: plan.mission_revision,
      wake_condition_ref: "wake/consume",
    });
    await ledger.initialize({
      event: eventContext("2026-07-16T11:00:00.000Z", "mission.created"),
      operation_id: "create-consume-wake",
      seed: { plan, run, wake },
    });

    const claim = {
      fencing_token: 5,
      generation: 2,
      lease_expires_at: "2026-07-16T12:01:00.000Z",
      lease_token: "scheduled-lease-consume",
      now: BASE_TIME,
      owner_id: "scheduler-consume",
    };
    const due = (await ledger.listDue(BASE_TIME, 1))[0]!;
    const claimed = await ledger.claimDue(due, claim);
    if (!claimed.acquired) assert.fail("expected scheduled claim");

    const execution = executionFixture(run, 2);
    const session = await execution.session;
    authority.install(session.lease);
    const nextWake = createMissionWake({
      created_at: BASE_TIME,
      due_at: "2026-07-16T13:00:00.000Z",
      generation: 2,
      misfire_policy: "coalesce_once",
      mission_ref: plan.mission_ref,
      mission_revision: plan.mission_revision,
      wake_condition_ref: "wake/consume",
    });
    const input = {
      ...transitionInput(
        session,
        1,
        "consume-scheduled-wake",
        "2026-07-16T12:00:01.000Z",
      ),
      occurrence_outcome: {
        claim: {
          fencing_token: claim.fencing_token,
          generation: claim.generation,
          lease_token: claim.lease_token,
          owner_id: claim.owner_id,
        },
        occurrence_id: claimed.occurrence.occurrence_id,
        state: "completed" as const,
      },
      wake: nextWake,
    };

    const committed = await ledger.transition(input);
    const replay = await ledger.transition(input);

    assert.equal(committed.created, true);
    assert.equal(committed.consumed_occurrence?.state, "completed");
    assert.equal(
      committed.consumed_occurrence?.updated_at,
      new Date(BASE_TIME).toISOString(),
    );
    assert.deepEqual(committed.occurrence, nextWake.occurrence);
    assert.equal(
      committed.snapshot.wake?.occurrence_ref,
      nextWake.occurrence.occurrence_id,
    );
    assert.deepEqual(
      await store.readOccurrence(claimed.occurrence.occurrence_id),
      committed.consumed_occurrence,
    );
    assert.deepEqual(
      await store.readOccurrence(nextWake.occurrence.occurrence_id),
      nextWake.occurrence,
    );
    assert.equal((await ledger.listDue(BASE_TIME, 10)).length, 0);
    assert.equal(replay.created, false);
    assert.deepEqual(replay.consumed_occurrence, committed.consumed_occurrence);
    assert.deepEqual(replay.snapshot, committed.snapshot);
  });

  test("rejects an expired scheduled claim without partially committing the mission", async () => {
    const authority = new MutableMissionLeaseAuthority(BASE_TIME);
    const store = new ReferenceMemoryMissionLedgerStore({
      lease_authority: authority,
    });
    const ledger = new MissionLedger({ store });
    const run = runReceipt("run-expired-wake", "subject-expired-wake");
    const plan = missionPlan(run, "mission-expired-wake");
    const wake = createMissionWake({
      created_at: "2026-07-16T11:00:00.000Z",
      due_at: "2026-07-16T11:30:00.000Z",
      generation: 1,
      misfire_policy: "coalesce_once",
      mission_ref: plan.mission_ref,
      mission_revision: plan.mission_revision,
      wake_condition_ref: "wake/expired",
    });
    await ledger.initialize({
      event: eventContext("2026-07-16T11:00:00.000Z", "mission.created"),
      operation_id: "create-expired-wake",
      seed: { plan, run, wake },
    });
    const claim = {
      fencing_token: 8,
      generation: 2,
      lease_expires_at: "2026-07-16T12:00:30.000Z",
      lease_token: "scheduled-lease-expired",
      now: BASE_TIME,
      owner_id: "scheduler-expired",
    };
    const due = (await ledger.listDue(BASE_TIME, 1))[0]!;
    const claimed = await ledger.claimDue(due, claim);
    if (!claimed.acquired) assert.fail("expected scheduled claim");

    const execution = executionFixture(run, 2);
    const session = await execution.session;
    authority.install(session.lease);
    authority.setObservedAt("2026-07-16T12:00:45.000Z");

    await assert.rejects(
      ledger.transition({
        ...transitionInput(
          session,
          1,
          "consume-expired-wake",
          "2026-07-16T12:00:01.000Z",
        ),
        occurrence_outcome: {
          claim: {
            fencing_token: claim.fencing_token,
            generation: claim.generation,
            lease_token: claim.lease_token,
            owner_id: claim.owner_id,
          },
          occurrence_id: claimed.occurrence.occurrence_id,
          state: "completed",
        },
        wake: null,
      }),
      MissionLedgerStaleOccurrenceError,
    );

    assert.deepEqual(
      await store.readOccurrence(claimed.occurrence.occurrence_id),
      claimed.occurrence,
    );
    assert.equal((await ledger.readBySubject(run.subject_ref))?.revision, 1);
    assert.equal((await ledger.listEvents(run.subject_ref, 0, 10)).length, 1);
  });

  test("retries scheduled claims after a transient snapshot revision race", async () => {
    const store = new StaleOnceMissionLedgerStore();
    const ledger = new MissionLedger({ store });
    const run = runReceipt("run-stale-claim", "subject-stale-claim");
    const plan = missionPlan(run, "mission-stale-claim");
    await ledger.initialize({
      event: eventContext("2026-07-16T11:00:00.000Z", "mission.created"),
      operation_id: "create-stale-claim",
      seed: {
        plan,
        run,
        wake: createMissionWake({
          created_at: "2026-07-16T11:00:00.000Z",
          due_at: "2026-07-16T11:30:00.000Z",
          generation: 1,
          misfire_policy: "coalesce_once",
          mission_ref: plan.mission_ref,
          mission_revision: plan.mission_revision,
          wake_condition_ref: "wake/stale-claim",
        }),
      },
    });

    const due = (await ledger.listDue(BASE_TIME, 1))[0]!;
    const claimed = await ledger.claimDue(due, {
      fencing_token: 3,
      generation: 2,
      lease_expires_at: "2026-07-16T12:01:00.000Z",
      lease_token: "scheduled-lease-stale-retry",
      now: BASE_TIME,
      owner_id: "scheduler-stale-retry",
    });

    assert.equal(claimed.acquired, true);
    assert.equal(store.compareAttempts, 2);
    if (!claimed.acquired) assert.fail("expected claim retry to succeed");
    assert.equal(claimed.created, true);
  });

  test("keeps complete ordered events behind a bounded snapshot and fences transitions", async () => {
    const authority = new MutableMissionLeaseAuthority(BASE_TIME);
    const store = new ReferenceMemoryMissionLedgerStore({
      lease_authority: authority,
    });
    const ledger = new MissionLedger({ recent_event_ref_limit: 2, store });
    const run = runReceipt("run-fenced", "subject-fenced");
    const plan = missionPlan(run, "mission-fenced");
    await ledger.initialize({
      event: eventContext("2026-07-16T12:00:00.000Z", "mission.created"),
      operation_id: "create-fenced",
      seed: { plan, run },
    });

    const execution = executionFixture(run, 2);
    const firstSession = await execution.session;
    authority.install(firstSession.lease);
    const firstTransition = transitionInput(
      firstSession,
      1,
      "record-running",
      "2026-07-16T12:00:01.000Z",
    );
    const recorded = await ledger.transition(firstTransition);
    const replay = await ledger.transition(firstTransition);
    assert.equal(recorded.created, true);
    assert.equal(replay.created, false);
    assert.equal(replay.snapshot.revision, 2);

    await ledger.transition(
      transitionInput(
        firstSession,
        2,
        "record-checkpoint-a",
        "2026-07-16T12:00:02.000Z",
      ),
    );
    const fourth = await ledger.transition(
      transitionInput(
        firstSession,
        3,
        "record-checkpoint-b",
        "2026-07-16T12:00:03.000Z",
      ),
    );
    assert.equal(fourth.snapshot.revision, 4);
    assert.equal(fourth.snapshot.recent_event_refs.length, 2);

    const firstPage = await ledger.listEvents(run.subject_ref, 0, 2);
    const secondPage = await ledger.listEvents(
      run.subject_ref,
      firstPage.at(-1)!.sequence,
      10,
    );
    assert.deepEqual(
      [...firstPage, ...secondPage].map((event) => event.sequence),
      [1, 2, 3, 4],
    );

    await assert.rejects(
      ledger.transition(
        transitionInput(
          firstSession,
          1,
          "stale-revision",
          "2026-07-16T12:00:04.000Z",
        ),
      ),
      MissionLedgerStaleRevisionError,
    );
    await assert.rejects(
      ledger.transition({
        ...transitionInput(
          firstSession,
          4,
          "stale-generation",
          "2026-07-16T12:00:04.000Z",
        ),
        session: {
          ...firstSession,
          lease: { ...firstSession.lease, generation: 1 },
        },
      }),
      MissionLedgerStaleLeaseError,
    );

    await execution.coordinator.release(firstSession);
    const replacement = await execution.coordinator.start({
      generation: 3,
      lease_token: "lease-replacement",
      owner_id: "executor-replacement",
      run_id: run.run_id,
      service_state: "ready",
    });
    if (replacement.status === "not_runnable") {
      assert.fail("expected a replacement execution session");
    }
    authority.install(replacement.session.lease);
    const fifth = await ledger.transition(
      transitionInput(
        replacement.session,
        4,
        "record-replacement",
        "2026-07-16T12:00:05.000Z",
      ),
    );
    assert.equal(fifth.snapshot.revision, 5);
    assert.ok(
      replacement.session.lease.fencing_token >
        firstSession.lease.fencing_token,
    );
    await assert.rejects(
      ledger.transition({
        ...transitionInput(
          replacement.session,
          5,
          "stale-fence",
          "2026-07-16T12:00:06.000Z",
        ),
        session: {
          ...replacement.session,
          lease: {
            ...replacement.session.lease,
            fencing_token: firstSession.lease.fencing_token,
          },
        },
      }),
      MissionLedgerStaleLeaseError,
    );
    assert.equal((await ledger.readBySubject(run.subject_ref))?.revision, 5);
    assert.equal((await ledger.listEvents(run.subject_ref, 0, 10)).length, 5);
  });

  test("rejects forged or expired lease proof using authority time, not event time", async () => {
    const authority = new MutableMissionLeaseAuthority(
      "2026-07-16T12:02:00.000Z",
    );
    const store = new ReferenceMemoryMissionLedgerStore({
      lease_authority: authority,
    });
    const ledger = new MissionLedger({ store });
    const run = runReceipt("run-authority", "subject-authority");
    await ledger.initialize({
      event: eventContext("2026-07-16T11:00:00.000Z", "mission.created"),
      operation_id: "create-authority",
      seed: { plan: missionPlan(run, "mission-authority"), run },
    });
    const expiredLease: WorkLeaseV1 = {
      fencing_token: 9,
      generation: 9,
      heartbeat_at: "2026-07-16T12:00:00.000Z",
      lease_expires_at: "2026-07-16T12:01:00.000Z",
      lease_token: "lease-authority",
      owner_id: "executor-authority",
      run_id: run.run_id,
      schema_version: "work-lease/v1",
    };
    authority.install(expiredLease);
    const backdatedSession: ExecutionSession = {
      lease: expiredLease,
      run: {
        ...run,
        revision: 2,
        state: "running",
        updated_at: "2026-07-16T12:00:30.000Z",
      },
    };

    await assert.rejects(
      ledger.transition(
        transitionInput(
          backdatedSession,
          1,
          "backdated-expired-lease",
          "2026-07-16T12:00:30.000Z",
        ),
      ),
      MissionLedgerStaleLeaseError,
    );
    authority.setObservedAt("2026-07-16T12:00:30.000Z");
    await assert.rejects(
      ledger.transition({
        ...transitionInput(
          backdatedSession,
          1,
          "forged-lease",
          "2026-07-16T12:00:30.000Z",
        ),
        session: {
          ...backdatedSession,
          lease: {
            ...expiredLease,
            fencing_token: 99,
            lease_token: "lease-forged",
            owner_id: "executor-forged",
          },
        },
      }),
      MissionLedgerStaleLeaseError,
    );
    assert.equal((await ledger.readBySubject(run.subject_ref))?.revision, 1);
  });

  test("promotes once and never lets a legacy candidate replace current state", async () => {
    const store = new ReferenceMemoryMissionLedgerStore();
    const ledger = new MissionLedger({ store });
    const promotedRun = runReceipt("run-promoted", "subject-promoted");
    const promotedPlan = missionPlan(promotedRun, "mission-promoted");
    const promotion = {
      candidate: {
        adapter_ref: "legacy-adapter/v1",
        seed: { plan: promotedPlan, run: promotedRun },
        source_ref: "legacy-record/promoted",
      },
      event: eventContext("2026-07-16T11:00:00.000Z", "mission.promoted"),
      operation_id: "promote-once",
    };

    const first = await ledger.promoteLegacy(promotion);
    const replay = await ledger.promoteLegacy(promotion);
    assert.equal(first.created, true);
    assert.equal(replay.created, false);
    assert.deepEqual(replay.snapshot, first.snapshot);
    assert.equal(
      (await ledger.listEvents(promotedRun.subject_ref, 0, 10)).length,
      1,
    );

    const currentRun = runReceipt("run-current", "subject-current");
    const currentPlan = missionPlan(currentRun, "mission-current");
    const current = await ledger.initialize({
      event: eventContext("2026-07-16T11:10:00.000Z", "mission.created"),
      operation_id: "create-current",
      seed: { plan: currentPlan, run: currentRun },
    });
    const candidatePlan = missionPlan(currentRun, "mission-legacy-candidate");
    const currentWins = await ledger.promoteLegacy({
      candidate: {
        adapter_ref: "legacy-adapter/v1",
        seed: { plan: candidatePlan, run: currentRun },
        source_ref: "legacy-record/current-subject",
      },
      event: eventContext("2026-07-16T11:11:00.000Z", "mission.promoted"),
      operation_id: "promote-current-subject",
    });
    assert.equal(currentWins.created, false);
    assert.equal(currentWins.event, undefined);
    assert.deepEqual(currentWins.snapshot, current.snapshot);
    assert.deepEqual(
      await ledger.readByMissionRef(currentPlan.mission_ref),
      current.snapshot,
    );
    assert.equal(await ledger.readByMissionRef(candidatePlan.mission_ref), undefined);
    assert.equal(
      (await ledger.listEvents(currentRun.subject_ref, 0, 10)).length,
      1,
    );
  });
});

function runReceipt(runId: string, subjectRef: string): RunReceiptV1 {
  return {
    admitted_at: "2026-07-16T11:00:00.000Z",
    binding_id: "binding-portable",
    idempotency_key: `admission/${runId}`,
    input_digest: `sha256:${runId}`,
    receipt_id: `receipt-${runId}`,
    received_at: "2026-07-16T11:00:00.000Z",
    required_capabilities: [],
    retention_policy_ref: "retention/portable",
    revision: 1,
    run_id: runId,
    run_kind: "autonomy",
    schema_version: "run-receipt/v1",
    state: "queued",
    subject_ref: subjectRef,
    tenant_id: "tenant-portable",
    updated_at: "2026-07-16T11:00:00.000Z",
  };
}

function missionPlan(
  run: RunReceiptV1,
  missionRef: string,
): MissionPlanProjectionV1 {
  return {
    mission_contract_id: NATIVE_MISSION_CONTRACT_ID,
    mission_ref: missionRef,
    mission_revision: 1,
    mission_schema_version: NATIVE_MISSION_SCHEMA_VERSION,
    plan_digest: `sha256:${missionRef}`,
    plan_ref: `plan/${missionRef}`,
    plan_revision: 1,
    run_id: run.run_id,
    schema_version: "mission-plan-projection/v1",
    steps: [
      {
        approval_required: false,
        capability_ref: "capability/portable",
        capability_version: "v1",
        effect_id: `effect/${missionRef}`,
        idempotency_key: `effect/${missionRef}/1`,
        request_digest: `sha256:request-${missionRef}`,
        rollback_plan_ref: `rollback/${missionRef}`,
        step_id: "step-1",
        target_ref: `target/${missionRef}`,
      },
    ],
  };
}

function eventContext(occurredAt: string, code: string) {
  return {
    occurred_at: occurredAt,
    observed_at: occurredAt,
    producer: { component: "slack-companion", version: "test" },
    reason: { code, summary: code },
    service_id: "service-portable",
  };
}

function transitionInput(
  session: ExecutionSession,
  expectedRevision: number,
  operationId: string,
  occurredAt: string,
) {
  return {
    attempt: 1,
    event: eventContext(occurredAt, operationId),
    expected_revision: expectedRevision,
    operation_id: operationId,
    session,
  };
}

function executionFixture(run: RunReceiptV1, generation: number) {
  const store = new ReferenceMemoryExecutionStore();
  store.seedRun(run);
  const coordinator = new ExecutionCoordinator({
    clock: { now: () => new Date(BASE_TIME) },
    lease_duration_ms: 60_000,
    store,
  });
  return {
    coordinator,
    session: coordinator
      .start({
        generation,
        lease_token: "lease-initial",
        owner_id: "executor-initial",
        run_id: run.run_id,
        service_state: "ready",
      })
      .then((started) => {
        if (started.status === "not_runnable") {
          throw new Error("expected an execution session");
        }
        return started.session;
      }),
  };
}

class MutableMissionLeaseAuthority implements MissionLeaseAuthorityPort {
  private readonly leases = new Map<string, WorkLeaseV1>();

  constructor(private observedAt: string) {}

  install(lease: WorkLeaseV1): void {
    this.leases.set(lease.run_id, structuredClone(lease));
  }

  setObservedAt(observedAt: string): void {
    this.observedAt = observedAt;
  }

  withCurrentLease<T>(
    runId: string,
    operation: (current: AuthoritativeMissionLeaseRead | undefined) => T,
  ): Promise<T> {
    const lease = this.leases.get(runId);
    return Promise.resolve(
      operation(
        lease === undefined
          ? undefined
          : { lease: structuredClone(lease), observed_at: this.observedAt },
      ),
    );
  }
}

class StaleOnceMissionLedgerStore extends ReferenceMemoryMissionLedgerStore {
  compareAttempts = 0;
  private staleOnce = true;

  compareAndSetOccurrence(
    request: Parameters<ReferenceMemoryMissionLedgerStore["compareAndSetOccurrence"]>[0],
  ) {
    this.compareAttempts += 1;
    if (this.staleOnce) {
      this.staleOnce = false;
      throw new MissionLedgerStaleRevisionError(
        request.expected_snapshot_revision,
        request.expected_snapshot_revision + 1,
      );
    }
    return super.compareAndSetOccurrence(request);
  }
}
