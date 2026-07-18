import assert from "node:assert/strict";
import { describe, test } from "node:test";
import {
  CapacityIdempotencyConflictError,
  CapacityInvariantError,
  StaleCapacityPermitError,
  runWithCapacityPermit,
} from "../src/execution/capacity.js";
import type {
  CapacityAcquireRequest,
  CapacityPermitV1,
  CapacityReleaseRequest,
} from "../src/execution/capacity.js";
import { ReferenceMemoryCapacityStore } from "../src/execution/capacity-reference-store.js";

describe("durable shared capacity", () => {
  test("bounds slots and replays exact acquisition outcomes", async () => {
    const store = new ReferenceMemoryCapacityStore();
    const first = await store.acquire(acquisition());
    const duplicate = await store.acquire(acquisition());
    assert.equal(first.status, "acquired");
    assert.equal(duplicate.status, "acquired");
    if (first.status !== "acquired" || duplicate.status !== "acquired") {
      assert.fail("expected an acquired permit");
    }
    assert.equal(first.replayed, false);
    assert.equal(duplicate.replayed, true);
    assert.equal(first.permit.slot, 0);
    assert.equal(duplicate.permit.fencing_token, first.permit.fencing_token);

    const unavailableRequest = acquisition({
      acquisition_key: "acquire-2",
      owner_id: "owner-2",
      permit_id: "permit-2",
      run_id: "run-2",
    });
    const unavailable = await store.acquire(unavailableRequest);
    const unavailableReplay = await store.acquire(unavailableRequest);
    assert.deepEqual(unavailable, {
      next_available_at: time(60_000),
      reason: "capacity",
      replayed: false,
      status: "unavailable",
    });
    assert.deepEqual(unavailableReplay, {
      ...unavailable,
      replayed: true,
    });

    await assert.rejects(
      store.acquire({ ...acquisition(), permit_id: "changed" }),
      CapacityIdempotencyConflictError,
    );
  });

  test("releases only an exact current proof and replays cleanup safely", async () => {
    const store = new ReferenceMemoryCapacityStore();
    const acquired = await store.acquire(acquisition());
    if (acquired.status !== "acquired") {
      assert.fail("expected an acquired permit");
    }
    const request = release(acquired.permit);

    await assert.rejects(
      store.release({ ...request, owner_id: "stale-owner" }),
      StaleCapacityPermitError,
    );
    const first = await store.release(request);
    const duplicate = await store.release(request);
    assert.equal(first.replayed, false);
    assert.equal(duplicate.replayed, true);
    assert.equal(duplicate.permit.state, "released");
    assert.deepEqual(duplicate.receipt, first.receipt);

    await assert.rejects(
      store.release({ ...request, released_at: time(2_000) }),
      CapacityIdempotencyConflictError,
    );
    await assert.rejects(
      store.release({ ...request, release_key: "release-other" }),
      StaleCapacityPermitError,
    );
  });

  test("persists resource cooldown across restart without shortening it", async () => {
    const store = new ReferenceMemoryCapacityStore();
    const first = await store.recordCooldown({
      cooldown_key: "cooldown-1",
      cooldown_until: time(30_000),
      observed_at: time(0),
      resource_ref: "capacity://opaque-a",
    });
    await store.recordCooldown({
      cooldown_key: "cooldown-2",
      cooldown_until: time(20_000),
      observed_at: time(1_000),
      resource_ref: "capacity://opaque-a",
    });
    const restarted = new ReferenceMemoryCapacityStore(store.snapshot());
    const replay = await restarted.recordCooldown({
      cooldown_key: "cooldown-1",
      cooldown_until: time(30_000),
      observed_at: time(0),
      resource_ref: "capacity://opaque-a",
    });
    assert.equal(first.effective_cooldown_until, time(30_000));
    assert.equal(replay.replayed, true);
    assert.equal(replay.effective_cooldown_until, time(30_000));

    const blocked = await restarted.acquire(
      acquisition({ acquired_at: time(10_000), expires_at: time(70_000) }),
    );
    assert.deepEqual(blocked, {
      next_available_at: time(30_000),
      reason: "cooldown",
      replayed: false,
      status: "unavailable",
    });

    const admitted = await restarted.acquire(
      acquisition({
        acquired_at: time(30_001),
        acquisition_key: "acquire-after-cooldown",
        expires_at: time(90_001),
        permit_id: "permit-after-cooldown",
      }),
    );
    assert.equal(admitted.status, "acquired");
  });

  test("requires durable expiry reconciliation and advances the fence after restart", async () => {
    const original = new ReferenceMemoryCapacityStore();
    const acquired = await original.acquire(
      acquisition({ expires_at: time(10_000) }),
    );
    if (acquired.status !== "acquired") {
      assert.fail("expected an acquired permit");
    }

    const restarted = new ReferenceMemoryCapacityStore(original.snapshot());
    const beforeReclaim = await restarted.acquire(
      acquisition({
        acquired_at: time(11_000),
        acquisition_key: "acquire-before-reclaim",
        expires_at: time(71_000),
        generation: 2,
        owner_id: "owner-2",
        permit_id: "permit-2",
      }),
    );
    assert.deepEqual(beforeReclaim, {
      next_available_at: time(10_000),
      reason: "reconciliation_required",
      replayed: false,
      status: "unavailable",
    });

    const reclaimed = await restarted.reclaimExpired(
      "capacity://opaque-a",
      time(11_000),
    );
    assert.equal(reclaimed.length, 1);
    assert.equal(reclaimed[0]?.permit.state, "expired");
    assert.deepEqual(
      await restarted.reclaimExpired("capacity://opaque-a", time(11_000)),
      [],
    );

    const replacement = await restarted.acquire(
      acquisition({
        acquired_at: time(11_000),
        acquisition_key: "acquire-after-reclaim",
        expires_at: time(71_000),
        generation: 2,
        owner_id: "owner-2",
        permit_id: "permit-3",
      }),
    );
    if (replacement.status !== "acquired") {
      assert.fail("expected a replacement permit");
    }
    assert.equal(replacement.permit.slot, acquired.permit.slot);
    assert.equal(
      replacement.permit.fencing_token,
      acquired.permit.fencing_token + 1,
    );
    await assert.rejects(
      restarted.release(release(acquired.permit)),
      StaleCapacityPermitError,
    );
    await assert.rejects(
      restarted.acquire(
        acquisition({
          acquired_at: time(12_000),
          acquisition_key: "stale-generation",
          expires_at: time(72_000),
          generation: 1,
          permit_id: "permit-stale-generation",
        }),
      ),
      StaleCapacityPermitError,
    );
  });

  test("fails closed on malformed requests and snapshots", async () => {
    const store = new ReferenceMemoryCapacityStore();
    for (const invalid of [
      acquisition({ resource_ref: " " }),
      acquisition({ permit_limit: 0 }),
      acquisition({ generation: 0 }),
      acquisition({ acquired_at: "2026-01-01T00:00:00Z" }),
      acquisition({ expires_at: time(0) }),
    ]) {
      await assert.rejects(store.acquire(invalid), CapacityInvariantError);
    }
    await assert.rejects(
      store.recordCooldown({
        cooldown_key: "cooldown-invalid",
        cooldown_until: time(0),
        observed_at: time(1_000),
        resource_ref: "capacity://opaque-a",
      }),
      CapacityInvariantError,
    );

    const snapshot = new ReferenceMemoryCapacityStore().snapshot();
    assert.throws(
      () =>
        new ReferenceMemoryCapacityStore({
          ...snapshot,
          schema_version: "invalid" as never,
        }),
      CapacityInvariantError,
    );
  });

  test("preserves work outcomes when permit cleanup is unavailable", async () => {
    const permit = activePermit();
    const failures: unknown[] = [];
    const result = await runWithCapacityPermit(
      permit,
      async () => "completed",
      async () => {
        throw new Error("cleanup unavailable");
      },
      ({ error }) => {
        failures.push(error);
      },
    );
    assert.equal(result, "completed");
    assert.equal(failures.length, 1);

    const workError = new Error("work failed");
    await assert.rejects(
      runWithCapacityPermit(
        permit,
        async () => Promise.reject(workError),
        async () => Promise.reject(new Error("cleanup unavailable")),
      ),
      (error: unknown) => error === workError,
    );
  });
});

function acquisition(
  overrides: Partial<CapacityAcquireRequest> = {},
): CapacityAcquireRequest {
  return {
    acquired_at: time(0),
    acquisition_key: "acquire-1",
    expires_at: time(60_000),
    generation: 1,
    owner_id: "owner-1",
    permit_id: "permit-1",
    permit_limit: 1,
    resource_ref: "capacity://opaque-a",
    run_id: "run-1",
    ...overrides,
  };
}

function release(permit: CapacityPermitV1): CapacityReleaseRequest {
  return {
    fencing_token: permit.fencing_token,
    generation: permit.generation,
    owner_id: permit.owner_id,
    permit_id: permit.permit_id,
    release_key: `release-${permit.permit_id}`,
    released_at: time(1_000),
    resource_ref: permit.resource_ref,
    run_id: permit.run_id,
  };
}

function activePermit(): CapacityPermitV1 {
  return {
    acquired_at: time(0),
    acquisition_key: "acquire-1",
    expires_at: time(60_000),
    fencing_token: 1,
    generation: 1,
    owner_id: "owner-1",
    permit_id: "permit-1",
    resource_ref: "capacity://opaque-a",
    run_id: "run-1",
    schema_version: "capacity-permit/v1",
    slot: 0,
    state: "active",
  };
}

function time(offsetMs: number): string {
  return new Date(Date.UTC(2026, 0, 1) + offsetMs).toISOString();
}
