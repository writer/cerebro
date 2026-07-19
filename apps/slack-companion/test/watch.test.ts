import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type {
  AnswerWatchAuthorityV1,
  AnswerWatchMaterialStateV1,
  AnswerWatchObservationReceiptV1,
  AnswerWatchObservationStatusV1,
  AnswerWatchObservationV1,
  StopAnswerWatchReceiptV1,
  AnswerWatchV1,
} from "../src/watch/contracts.js";
import { ANSWER_WATCH_LIMITS } from "../src/watch/contracts.js";
import {
  answerWatchMaterialDigest,
  answerWatchObservationReceiptIdentity,
  answerWatchStopReceiptIdentity,
  applyAnswerWatchObservation,
  authorizeAnswerWatch,
  beginAnswerWatchOccurrence,
  bindAnswerWatchTarget,
  createAnswerWatchObservation,
  createAnswerWatchOccurrence,
  projectSlackAnswerWatchStatus,
  startAnswerWatch,
  stopAnswerWatch,
} from "../src/watch/policy.js";

const createdAt = "2030-01-02T03:04:05.000Z";

describe("server-bound answer watch admission", () => {
  test("binds exactly one read-only target from delivered-answer evidence", () => {
    assert.throws(
      () => bindAnswerWatchTarget({
        answer_ref: "answer://sample/1",
        candidates: [],
        evidence_ref: "evidence://sample/1",
        resolved_at: createdAt,
      }),
      /exactly one watch target/,
    );
    assert.throws(
      () => bindAnswerWatchTarget({
        answer_ref: "answer://sample/1",
        candidates: [candidate(), { ...candidate(), target_ref: "target://sample/2" }],
        evidence_ref: "evidence://sample/1",
        resolved_at: createdAt,
      }),
      /exactly one watch target/,
    );

    const first = binding();
    const replay = binding();
    assert.deepEqual(replay, first);
    assert.equal(first.authority, "read");
    assert.match(first.binding_digest, /^sha256:[0-9a-f]{64}$/);
  });

  test("authorizes only the requester or a recorded operator", () => {
    assert.deepEqual(authorizeAnswerWatch("principal://requester", authority(), binding()), {
      allowed: true,
      role: "requester",
      schema_version: "answer-watch-authorization/v1",
    });
    assert.deepEqual(authorizeAnswerWatch("principal://operator", authority(), binding()), {
      allowed: true,
      role: "operator",
      schema_version: "answer-watch-authorization/v1",
    });
    assert.deepEqual(authorizeAnswerWatch("principal://other", authority(), binding()), {
      allowed: false,
      reason_code: "actor_not_authorized",
      schema_version: "answer-watch-authorization/v1",
    });
  });

  test("replays one stable watch and rejects a changed server binding", () => {
    const first = startedWatch();
    const replay = startAnswerWatch({ ...startInput(), prior_watch: first });
    assert.equal(replay.disposition, "started");
    if (replay.disposition !== "started") assert.fail("expected a started watch");
    assert.equal(replay.created, false);
    assert.deepEqual(replay.watch, first);

    assert.throws(
      () => startAnswerWatch({
        ...startInput(),
        binding: bindAnswerWatchTarget({
          answer_ref: "answer://sample/1",
          candidates: [{ ...candidate(), target_ref: "target://sample/other" }],
          evidence_ref: "evidence://sample/1",
          resolved_at: createdAt,
        }),
        prior_watch: first,
      }),
      /different server-side binding/,
    );
  });

  test("bounds persisted identifiers, summaries, and operator sets", () => {
    assert.doesNotThrow(() => bindAnswerWatchTarget({
      answer_ref: "answer://sample/1",
      candidates: [{
        ...candidate(),
        target_ref: "r".repeat(ANSWER_WATCH_LIMITS.ref_utf8_bytes),
      }],
      evidence_ref: "evidence://sample/1",
      resolved_at: createdAt,
    }));
    assert.throws(
      () => bindAnswerWatchTarget({
        answer_ref: "answer://sample/1",
        candidates: [{
          ...candidate(),
          target_ref: "r".repeat(ANSWER_WATCH_LIMITS.ref_utf8_bytes + 1),
        }],
        evidence_ref: "evidence://sample/1",
        resolved_at: createdAt,
      }),
      /UTF-8 bytes/,
    );

    const requestBoundary = startAnswerWatch({
      ...startInput(),
      request_key: "k".repeat(ANSWER_WATCH_LIMITS.request_key_utf8_bytes),
    });
    assert.equal(requestBoundary.disposition, "started");
    assert.throws(
      () => startAnswerWatch({
        ...startInput(),
        request_key: "k".repeat(ANSWER_WATCH_LIMITS.request_key_utf8_bytes + 1),
      }),
      /UTF-8 bytes/,
    );
    assert.throws(
      () => startAnswerWatch({ ...startInput(), request_key: "key with whitespace" }),
      /without whitespace/,
    );

    const operatorRefs = Array.from(
      { length: ANSWER_WATCH_LIMITS.operator_refs },
      (_, index) => `principal://operator/${index}`,
    );
    assert.equal(authorizeAnswerWatch("principal://requester", {
      ...authority(),
      operator_refs: operatorRefs,
    }, binding()).allowed, true);
    assert.throws(
      () => authorizeAnswerWatch("principal://requester", {
        ...authority(),
        operator_refs: [...operatorRefs, "principal://operator/overflow"],
      }, binding()),
      /at most 64 references/,
    );

    const watch = startedWatch();
    const occurrence = scheduled(watch);
    assert.doesNotThrow(() => observation(occurrence.occurrence.occurrence_id, watch, {
      summary: "é".repeat(ANSWER_WATCH_LIMITS.summary_utf8_bytes / 2),
    }));
    assert.throws(
      () => observation(occurrence.occurrence.occurrence_id, watch, {
        summary: `${"é".repeat(ANSWER_WATCH_LIMITS.summary_utf8_bytes / 2)}é`,
      }),
      /UTF-8 bytes/,
    );
    assert.throws(
      () => observation(occurrence.occurrence.occurrence_id, watch, {
        summary: "Unsafe\u0000summary",
      }),
      /unsafe control character/,
    );
  });

  test("rejects noncanonical timestamps on persisted records", () => {
    assert.throws(
      () => authorizeAnswerWatch("principal://requester", authority(), {
        ...binding(),
        resolved_at: "2030-01-02T03:04:05Z",
      }),
      /canonical UTC timestamp/,
    );
    assert.throws(
      () => projectSlackAnswerWatchStatus({
        ...startedWatch(),
        updated_at: "2030-01-02T03:04:05Z",
      }),
      /canonical UTC timestamp/,
    );

    const watch = startedWatch();
    const occurrence = scheduled(watch);
    assert.throws(
      () => beginAnswerWatchOccurrence({
        ...occurrence,
        occurrence: {
          ...occurrence.occurrence,
          created_at: "2030-01-02T03:04:05Z",
        },
      }, leaseRequest(watch.revision)),
      /canonical UTC timestamp/,
    );
  });
});

describe("durable answer watch recurrence", () => {
  test("reuses canonical scheduled occurrence generation and fencing", () => {
    const watch = startedWatch();
    const first = scheduled(watch);
    const replay = scheduled(watch);
    assert.equal(replay.occurrence.occurrence_id, first.occurrence.occurrence_id);

    const claim = beginAnswerWatchOccurrence(first, leaseRequest(watch.revision));
    assert.equal(claim.acquired, true);
    if (!claim.acquired) assert.fail("expected the occurrence lease");
    assert.equal(claim.occurrence.occurrence.state, "running");
    assert.equal(claim.occurrence.occurrence.fencing_token, watch.revision);

    const resumed = beginAnswerWatchOccurrence(claim.occurrence, {
      ...leaseRequest(watch.revision),
      now: "2030-01-02T03:05:02Z",
    });
    assert.equal(resumed.acquired, true);
    if (!resumed.acquired) assert.fail("expected an idempotent claim");
    assert.equal(resumed.created, false);

    const stale = beginAnswerWatchOccurrence(scheduled(watch), {
      ...leaseRequest(watch.revision),
      fencing_token: 0,
    });
    assert.deepEqual(stale, { acquired: false, reason: "invalid_fencing_token" });
  });
});

describe("answer watch observation policy", () => {
  test("canonical material identity covers checks, draft, merge state, head, and terminal state", () => {
    const base: AnswerWatchMaterialStateV1 = {
      checks: { failed: 0, passed: 1, pending: 2 },
      draft: false,
      head_ref: "revision://sample/a",
      merge_state: "blocked",
      schema_version: "answer-watch-material-state/v1",
      terminal_state: "open",
    };
    const digest = answerWatchMaterialDigest(base);
    const changed = [
      { ...base, checks: { ...base.checks, passed: 2 } },
      { ...base, draft: true },
      { ...base, merge_state: "ready" },
      { ...base, head_ref: "revision://sample/b" },
      { ...base, terminal_state: "satisfied" as const },
    ];
    for (const material of changed) {
      assert.notEqual(answerWatchMaterialDigest(material), digest);
    }
  });

  test("uses structured state for material changes and suppresses unchanged checks", () => {
    const first = observe(startedWatch(), {
      head_ref: "revision://sample/a",
      observation_id: "observation://sample/1",
      summary: "Two checks remain.",
    });
    assert.equal(first.update.publish, true);
    assert.equal(first.watch.state, "active");

    const unchanged = observe(first.watch, {
      head_ref: "revision://sample/a",
      observation_id: "observation://sample/2",
      summary: "Display text changed, but the checked state did not.",
    });
    assert.equal(unchanged.update.material_change, false);
    assert.equal(unchanged.update.publish, false);

    const changed = observe(unchanged.watch, {
      checks: { failed: 0, passed: 2, pending: 1 },
      head_ref: "revision://sample/b",
      observation_id: "observation://sample/3",
      summary: "One check remains on a new revision.",
    });
    assert.equal(changed.update.material_change, true);
    assert.equal(changed.update.publish, true);
  });

  test("publishes degradation, recovery, and explicit satisfied completion", () => {
    const active = observe(startedWatch()).watch;
    const degraded = observe(active, {
      merge_state: "unknown",
      observation_id: "observation://sample/unavailable",
      status: "unavailable",
      summary: "Watch degraded. The target could not be read.",
    });
    assert.equal(degraded.watch.state, "degraded");
    assert.equal(projectSlackAnswerWatchStatus(degraded.watch).state, "degraded");

    const recovered = observe(degraded.watch, {
      observation_id: "observation://sample/recovered",
      summary: "Watch recovered. One check remains.",
    });
    assert.equal(recovered.watch.state, "active");
    assert.equal(recovered.update.publish, true);

    const completed = observe(recovered.watch, {
      checks: { failed: 0, passed: 3, pending: 0 },
      merge_state: "complete",
      observation_id: "observation://sample/satisfied",
      status: "satisfied",
      summary: "Watch completed. The condition is satisfied.",
    });
    assert.equal(completed.watch.state, "completed");
    assert.equal(completed.update.terminal, true);
    assert.equal(projectSlackAnswerWatchStatus(completed.watch).state, "completed");
    assert.throws(() => observe(completed.watch), /terminal/);
  });

  test("distinguishes closed without satisfaction from completion", () => {
    const closed = observe(startedWatch(), {
      merge_state: "closed",
      observation_id: "observation://sample/closed",
      status: "closed",
      summary: "The target closed before the condition was satisfied.",
    });
    assert.equal(closed.watch.state, "closed");
    assert.equal(closed.update.to_state, "closed");
    assert.equal(projectSlackAnswerWatchStatus(closed.watch).state, "closed");
  });

  test("replays only an observation bound to the same canonical payload", () => {
    const first = observe(startedWatch(), {
      observation_id: "observation://sample/stable",
    });
    const replay = applyAnswerWatchObservation({
      claim: first.claim,
      occurrence: first.occurrence,
      observation: first.observation,
      receipt_lookup: observationReceiptFound(first.receipt),
      watch: first.watch,
    });
    assert.equal(replay.replayed, true);
    assert.deepEqual(replay.update, first.update);

    assert.throws(
      () => applyAnswerWatchObservation({
        claim: first.claim,
        occurrence: first.occurrence,
        observation: { ...first.observation, summary: "Changed after digesting." },
        receipt_lookup: observationReceiptFound(first.receipt),
        watch: first.watch,
      }),
      /digest does not match its canonical payload/,
    );

    const otherOccurrence = scheduled(first.watch);
    assert.notEqual(
      otherOccurrence.occurrence.occurrence_id,
      first.occurrence.occurrence.occurrence_id,
    );
    assert.throws(
      () => applyAnswerWatchObservation({
        claim: first.claim,
        occurrence: otherOccurrence,
        observation: {
          ...first.observation,
          occurrence_id: otherOccurrence.occurrence.occurrence_id,
        },
        receipt_lookup: observationReceiptFound(first.receipt),
        watch: first.watch,
      }),
      /digest does not match its canonical payload/,
    );

    const later = observe(first.watch, {
      observation_id: "observation://sample/later",
      summary: "A later observation is now current.",
    });
    const nonAdjacentReplay = applyAnswerWatchObservation({
      claim: first.claim,
      occurrence: first.occurrence,
      observation: first.observation,
      receipt_lookup: observationReceiptFound(first.receipt),
      watch: later.watch,
    });
    assert.equal(nonAdjacentReplay.replayed, true);
    assert.deepEqual(nonAdjacentReplay.update, first.update);
    assert.deepEqual(nonAdjacentReplay.watch, later.watch);

    assert.throws(
      () => applyAnswerWatchObservation({
        claim: first.claim,
        occurrence: first.occurrence,
        observation: first.observation,
        receipt_lookup: observationReceiptMiss(first.observation),
        watch: first.watch,
      }),
      /lookup missed an already recorded observation/,
    );
  });

  test("rejects a stale fencing claim", () => {

    const watch = startedWatch();
    const due = scheduled(watch);
    const acquired = beginAnswerWatchOccurrence(due, leaseRequest(watch.revision));
    if (!acquired.acquired) assert.fail("expected the occurrence lease");
    assert.throws(
      () => applyAnswerWatchObservation({
        claim: { ...acquired.claim, fencing_token: acquired.claim.fencing_token + 1 },
        occurrence: acquired.occurrence,
        observation: observation(acquired.occurrence.occurrence.occurrence_id, watch),
        receipt_lookup: observationReceiptMiss(
          observation(acquired.occurrence.occurrence.occurrence_id, watch),
        ),
        watch,
      }),
      /active generation and fencing claim/,
    );
  });

  test("projects cancellation and retirement as terminal Slack states", () => {
    const queued = startedWatch();
    const cancelRequest = stopRequest(queued, {
      occurred_at: "2030-01-02T03:05:00.000Z",
      reason_code: "requester_cancelled",
      request_key: "cancel-request-1",
      to_state: "cancelled",
    });
    const cancelled = stopAnswerWatch(queued, cancelRequest, stopReceiptMiss(cancelRequest));
    assert.equal(cancelled.replayed, false);
    assert.deepEqual(projectSlackAnswerWatchStatus(cancelled.watch), {
      schema_version: "slack-answer-watch-status/v1",
      should_publish: true,
      state: "stopped",
      terminal: true,
      text: "Watch cancelled.",
      watch_id: queued.watch_id,
    });

    const replay = stopAnswerWatch(
      cancelled.watch,
      cancelRequest,
      stopReceiptFound(cancelled.receipt),
    );
    assert.equal(replay.replayed, true);
    assert.deepEqual(replay.watch, cancelled.watch);
    assert.deepEqual(replay.update, cancelled.update);

    assert.throws(
      () => stopAnswerWatch(
        cancelled.watch,
        { ...cancelRequest, reason_code: "operator_cancelled" },
        stopReceiptFound(cancelled.receipt),
      ),
      /different content/,
    );
    assert.throws(
      () => stopAnswerWatch(
        cancelled.watch,
        { ...cancelRequest, to_state: "retired" },
        stopReceiptFound(cancelled.receipt),
      ),
      /different content/,
    );

    const retireRequest = stopRequest(cancelled.watch, {
      occurred_at: "2030-01-02T03:06:00.000Z",
      reason_code: "retention_complete",
      request_key: "retire-request-1",
      to_state: "retired",
    });
    const retired = stopAnswerWatch(
      cancelled.watch,
      retireRequest,
      stopReceiptMiss(retireRequest),
    );
    assert.equal(retired.watch.state, "retired");

    const nonAdjacentCancelReplay = stopAnswerWatch(
      retired.watch,
      cancelRequest,
      stopReceiptFound(cancelled.receipt),
    );
    assert.equal(nonAdjacentCancelReplay.replayed, true);
    assert.deepEqual(nonAdjacentCancelReplay.update, cancelled.update);
    assert.deepEqual(nonAdjacentCancelReplay.watch, retired.watch);
  });

  test("bounds stop request identities", () => {
    const queued = startedWatch();
    const boundaryRequest = stopRequest(queued, {
      request_key: "k".repeat(ANSWER_WATCH_LIMITS.request_key_utf8_bytes),
    });
    assert.doesNotThrow(() => stopAnswerWatch(
      queued,
      boundaryRequest,
      stopReceiptMiss(boundaryRequest),
    ));
    const overflowRequest = stopRequest(queued, {
      request_key: "k".repeat(ANSWER_WATCH_LIMITS.request_key_utf8_bytes + 1),
    });
    assert.throws(
      () => stopAnswerWatch(queued, overflowRequest, {
        found: false,
        receipt_id: "receipt://overflow",
        schema_version: "stop-answer-watch-receipt-lookup/v1",
      }),
      /UTF-8 bytes/,
    );
    const whitespaceRequest = stopRequest(queued, { request_key: "bad key" });
    assert.throws(
      () => stopAnswerWatch(queued, whitespaceRequest, {
        found: false,
        receipt_id: "receipt://whitespace",
        schema_version: "stop-answer-watch-receipt-lookup/v1",
      }),
      /without whitespace/,
    );
  });

  test("fails closed on invalid discriminants and watch update correlations", () => {
    assert.throws(
      () => projectSlackAnswerWatchStatus({
        ...startedWatch(),
        state: "unknown",
      } as unknown as AnswerWatchV1),
      /state has an unsupported value/,
    );
    assert.throws(
      () => projectSlackAnswerWatchStatus({
        ...startedWatch(),
        state: "active",
      }),
      /Initial watch state must be queued/,
    );

    const activeResult = observe(startedWatch());
    const active = activeResult.watch;
    assert.throws(
      () => projectSlackAnswerWatchStatus({
        ...active,
        last_update: { ...active.last_update!, to_state: "unknown" },
      } as unknown as AnswerWatchV1),
      /to_state has an unsupported value/,
    );
    for (const changed of [
      { ...active, revision: active.revision + 1 },
      { ...active, state: "degraded" as const },
      { ...active, updated_at: "2030-01-02T03:07:00.000Z" },
      {
        ...active,
        last_update: { ...active.last_update!, watch_id: "answer-watch://other" },
      },
    ]) {
      assert.throws(
        () => projectSlackAnswerWatchStatus(changed),
        /revision, state, identity, and time/,
      );
    }

    assert.throws(
      () => answerWatchMaterialDigest({
        ...activeResult.observation.material_state,
        terminal_state: "unknown",
      } as unknown as AnswerWatchMaterialStateV1),
      /terminal_state has an unsupported value/,
    );
    assert.throws(
      () => applyAnswerWatchObservation({
        claim: activeResult.claim,
        occurrence: activeResult.occurrence,
        observation: {
          ...activeResult.observation,
          status: "unknown",
        } as unknown as AnswerWatchObservationV1,
        receipt_lookup: observationReceiptFound(activeResult.receipt),
        watch: active,
      }),
      /status has an unsupported value/,
    );
  });
});

function candidate() {
  return {
    authority: "read" as const,
    target_kind: "change-request",
    target_ref: "target://sample/change-1",
    target_version: "version://sample/1",
  };
}

function binding() {
  return bindAnswerWatchTarget({
    answer_ref: "answer://sample/1",
    candidates: [candidate()],
    evidence_ref: "evidence://sample/1",
    resolved_at: createdAt,
  });
}

function authority(): AnswerWatchAuthorityV1 {
  return {
    answer_ref: "answer://sample/1",
    operator_refs: ["principal://operator"],
    requester_ref: "principal://requester",
    schema_version: "answer-watch-authority/v1",
  };
}

function startInput() {
  return {
    actor_ref: "principal://requester",
    authority: authority(),
    binding: binding(),
    conversation_ref: "conversation://sample/thread-1",
    created_at: createdAt,
    request_key: "watch-answer-1",
    schedule_ref: "schedule://sample/watch-1",
  };
}

function startedWatch(): AnswerWatchV1 {
  const result = startAnswerWatch(startInput());
  if (result.disposition !== "started") assert.fail("expected a started watch");
  return result.watch;
}

function scheduled(watch: AnswerWatchV1) {
  return createAnswerWatchOccurrence({
    created_at: watch.updated_at,
    due_at: "2030-01-02T03:05:00Z",
    generation: 1,
    misfire_policy: "coalesce_once",
    schedule_revision: watch.revision,
    watch,
  });
}

function leaseRequest(fencingToken: number) {
  return {
    fencing_token: fencingToken,
    generation: 1,
    lease_expires_at: "2030-01-02T03:15:00Z",
    lease_token: `lease-token-${fencingToken}`,
    now: "2030-01-02T03:05:01Z",
    owner_id: "worker://sample/1",
  };
}

function stopRequest(
  watch: AnswerWatchV1,
  overrides: Partial<{
    occurred_at: string;
    reason_code: string;
    request_key: string;
    to_state: "cancelled" | "retired";
  }> = {},
) {
  return {
    occurred_at: overrides.occurred_at ?? "2030-01-02T03:05:00.000Z",
    reason_code: overrides.reason_code ?? "requester_cancelled",
    request_key: overrides.request_key ?? "cancel-request-1",
    schema_version: "stop-answer-watch-request/v1" as const,
    to_state: overrides.to_state ?? "cancelled",
    watch_id: watch.watch_id,
  };
}

function observationReceiptMiss(observationValue: AnswerWatchObservationV1) {
  return {
    found: false as const,
    receipt_id: answerWatchObservationReceiptIdentity(
      observationValue.watch_id,
      observationValue.observation_id,
    ),
    schema_version: "answer-watch-observation-receipt-lookup/v1" as const,
  };
}

function observationReceiptFound(
  receipt: AnswerWatchObservationReceiptV1,
) {
  return {
    found: true as const,
    receipt,
    schema_version: "answer-watch-observation-receipt-lookup/v1" as const,
  };
}

function stopReceiptMiss(request: ReturnType<typeof stopRequest>) {
  return {
    found: false as const,
    receipt_id: answerWatchStopReceiptIdentity(request.watch_id, request.request_key),
    schema_version: "stop-answer-watch-receipt-lookup/v1" as const,
  };
}

function stopReceiptFound(
  receipt: StopAnswerWatchReceiptV1,
) {
  return {
    found: true as const,
    receipt,
    schema_version: "stop-answer-watch-receipt-lookup/v1" as const,
  };
}

function observe(
  watch: AnswerWatchV1,
  options: {
    checks?: AnswerWatchMaterialStateV1["checks"];
    draft?: boolean;
    head_ref?: string;
    merge_state?: string;
    observation_id?: string;
    status?: AnswerWatchObservationStatusV1;
    summary?: string;
  } = {},
) {
  const due = scheduled(watch);
  const acquired = beginAnswerWatchOccurrence(due, leaseRequest(watch.revision));
  if (!acquired.acquired) assert.fail(`expected occurrence lease: ${acquired.reason}`);
  const recordedObservation = observation(
    acquired.occurrence.occurrence.occurrence_id,
    watch,
    options,
  );
  return {
    ...applyAnswerWatchObservation({
      claim: acquired.claim,
      occurrence: acquired.occurrence,
      observation: recordedObservation,
      receipt_lookup: observationReceiptMiss(recordedObservation),
      watch,
    }),
    claim: acquired.claim,
    observation: recordedObservation,
  };
}

function observation(
  occurrenceId: string,
  watch: AnswerWatchV1,
  options: {
    checks?: AnswerWatchMaterialStateV1["checks"];
    draft?: boolean;
    head_ref?: string;
    merge_state?: string;
    observation_id?: string;
    status?: AnswerWatchObservationStatusV1;
    summary?: string;
  } = {},
): AnswerWatchObservationV1 {
  const status = options.status ?? "pending";
  const materialState: AnswerWatchMaterialStateV1 = {
    checks: options.checks ?? { failed: 0, passed: 1, pending: 2 },
    draft: options.draft ?? false,
    head_ref: options.head_ref ?? "revision://sample/a",
    merge_state: options.merge_state ?? "blocked",
    schema_version: "answer-watch-material-state/v1",
    terminal_state: status === "satisfied"
      ? "satisfied"
      : status === "closed"
        ? "closed_without_satisfaction"
        : status === "failed"
          ? "failed"
          : "open",
  };
  const observationId = options.observation_id ?? `observation://sample/${watch.revision}`;
  return createAnswerWatchObservation({
    material_state: materialState,
    observation_id: observationId,
    observed_at: "2030-01-02T03:06:00.000Z",
    occurrence_id: occurrenceId,
    reason_code: `watch_${status}`,
    status,
    summary: options.summary ?? "The condition is pending.",
    target_ref: watch.target_ref,
    target_version: `version://sample/${watch.revision + 1}`,
    watch_id: watch.watch_id,
  });
}
