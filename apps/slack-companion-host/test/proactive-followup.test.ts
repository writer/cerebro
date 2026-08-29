import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  CerebroAskClient,
  CerebroAskError,
  type RustProactiveFollowupOffer,
} from "../src/runtime/cerebro-ask-client.js";
import { ProactiveFollowupCoordinator } from "../src/runtime/proactive-followup.js";
import { FileProactiveFollowupStore } from "../src/runtime/proactive-followup-store.js";
import type { SlackAnswerAuthorityPort } from "../src/runtime/slack-answer-authority-client.js";

const answerAuthority: SlackAnswerAuthorityPort = {
  async authorizeQuestion(candidate) {
    return {
      authorized: true,
      execution_lane: "lookup",
      request_id: candidate.request_id,
      schema_version: "slack-question-decision/v1",
      tenant_id: candidate.tenant_id,
    };
  },
  async validate() {
    throw new Error("The Rust agent path must not invoke legacy answer validation.");
  },
};

test("the complete Rust offer is prepared before Slack and immutable on replay", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-followup-prepare-"));
  try {
    const store = new FileProactiveFollowupStore(root);
    const prepared = await store.prepare(offer());
    assert.equal(prepared.state, "prepared");
    assert.deepEqual((await store.list())[0], prepared);
    assert.deepEqual(await store.prepare(offer()), prepared);

    await assert.rejects(
      store.prepare({ ...offer(), action: "start a different follow-up" }),
      /changed for an existing identity/u,
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("the existing answer receipt repairs a prepared offer after restart", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-followup-replay-"));
  try {
    const firstStore = new FileProactiveFollowupStore(root);
    const prepared = await firstStore.prepare(offer());
    assert.equal(prepared.state, "prepared");

    // The existing agent delivery outbox owns Slack reconciliation. Simulate a
    // process loss after its Slack/Rust acknowledgement but before this local
    // projection, then apply the same receipt after restart.
    const restarted = new FileProactiveFollowupStore(root);
    const delivered = await restarted.markDeliveredForTurn("slack-request-one", {
      deliveredAt: "2026-08-28T07:00:01.000Z",
      deliveryRef: "slack-message://sha256/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      payloadDigest: "sha256:9aa4c8c404f5a13282e0dd832b1d3add24e2cb4f8eb9d804d34f0aaf5a275020",
    });
    assert.equal(delivered?.state, "delivered");
    assert.equal((await restarted.list())[0]?.state, "delivered");
    assert.deepEqual(
      await restarted.markDeliveredForTurn("slack-request-one", delivered!.delivery!),
      delivered,
      "replaying the exact answer receipt must be idempotent",
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("acceptance uses the Rust expiry exactly and rejects future or prepared offers", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-followup-expiry-"));
  try {
    let now = new Date("2026-08-28T08:00:00.000Z");
    const store = new FileProactiveFollowupStore(root);
    const coordinator = new ProactiveFollowupCoordinator(store, () => now);
    const prepared = await coordinator.prepareDelivery(offer());
    assert.equal(await coordinator.beginAcceptance(acceptanceInput()), undefined);
    assert.equal(
      await coordinator.beginAcceptance({
        ...acceptanceInput(),
        offerRef: `proactive-followup://sha256/${"f".repeat(64)}`,
      }),
      undefined,
      "an unoffered identity must not create an acceptance claim",
    );
    await store.markDeliveredForTurn(prepared.sourceRequestId, {
      deliveredAt: "2026-08-28T07:00:01.000Z",
      deliveryRef: "slack-message://sha256/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      payloadDigest: "sha256:9aa4c8c404f5a13282e0dd832b1d3add24e2cb4f8eb9d804d34f0aaf5a275020",
    });
    assert.ok(await coordinator.beginAcceptance(acceptanceInput()));

    const lateRoot = await mkdtemp(join(tmpdir(), "cerebro-followup-late-"));
    try {
      const lateStore = new FileProactiveFollowupStore(lateRoot);
      const lateCoordinator = new ProactiveFollowupCoordinator(lateStore, () =>
        new Date("2026-08-28T08:00:00.001Z")
      );
      const late = await lateStore.prepare(offer());
      await lateStore.markDeliveredForTurn(late.sourceRequestId, {
        deliveredAt: "2026-08-28T07:00:01.000Z",
        deliveryRef: "slack-message://sha256/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        payloadDigest: "sha256:9aa4c8c404f5a13282e0dd832b1d3add24e2cb4f8eb9d804d34f0aaf5a275020",
      });
      assert.equal(await lateCoordinator.beginAcceptance(acceptanceInput()), undefined);
    } finally {
      await rm(lateRoot, { force: true, recursive: true });
    }

    const futureRoot = await mkdtemp(join(tmpdir(), "cerebro-followup-future-"));
    try {
      const futureOffer = offer({
        created_at: "2026-08-28T09:00:00.000Z",
        expires_at: "2026-08-28T10:00:00.000Z",
      });
      const futureStore = new FileProactiveFollowupStore(futureRoot);
      const future = await futureStore.prepare(futureOffer);
      await futureStore.markDeliveredForTurn(future.sourceRequestId, {
        deliveredAt: "2026-08-28T07:00:01.000Z",
        deliveryRef: "slack-message://sha256/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        payloadDigest: "sha256:9aa4c8c404f5a13282e0dd832b1d3add24e2cb4f8eb9d804d34f0aaf5a275020",
      });
      const futureCoordinator = new ProactiveFollowupCoordinator(futureStore, () => now);
      assert.equal(await futureCoordinator.beginAcceptance(acceptanceInput()), undefined);
    } finally {
      await rm(futureRoot, { force: true, recursive: true });
    }
    await assert.rejects(
      store.prepare(offer({ expires_at: "2026-08-28T08:00:00+00:00" })),
      /expiry is invalid/u,
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("Rust refusal remains retryable and only its exact acknowledgement accepts", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-followup-accept-"));
  try {
    const store = new FileProactiveFollowupStore(root);
    const coordinator = new ProactiveFollowupCoordinator(
      store,
      () => new Date("2026-08-28T07:30:00.000Z"),
    );
    const prepared = await store.prepare(offer());
    await store.markDeliveredForTurn(prepared.sourceRequestId, {
      deliveredAt: "2026-08-28T07:00:01.000Z",
      deliveryRef: "slack-message://sha256/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      payloadDigest: "sha256:9aa4c8c404f5a13282e0dd832b1d3add24e2cb4f8eb9d804d34f0aaf5a275020",
    });
    const accepting = await coordinator.beginAcceptance(acceptanceInput());
    assert.ok(accepting);
    assert.equal((await store.list())[0]!.state, "accepting");
    assert.deepEqual(
      await coordinator.beginAcceptance(acceptanceInput()),
      accepting,
      "the same ingress retry must retain a byte-stable claim",
    );
    assert.equal(
      await coordinator.beginAcceptance({
        ...acceptanceInput(),
        ingressRequestKey: "T:C:thread:event-two",
      }),
      undefined,
      "another ingress request cannot steal an accepting offer",
    );
    await assert.rejects(
      coordinator.acknowledgeAcceptance(accepting, "followup://wrong"),
      /does not match/u,
    );
    assert.equal((await store.list())[0]!.state, "accepting");
    await coordinator.releaseAcceptance(accepting);
    assert.equal((await store.list())[0]!.state, "delivered");

    const retried = await coordinator.beginAcceptance(acceptanceInput());
    assert.ok(retried);
    await coordinator.acknowledgeAcceptance(retried, offer().offer_ref);
    assert.equal((await store.list())[0]!.state, "accepted");
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("the original ingress replays accepting and accepted claims after expiry", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-followup-expired-replay-"));
  try {
    let now = new Date("2026-08-28T07:30:00.000Z");
    const store = new FileProactiveFollowupStore(root);
    const coordinator = new ProactiveFollowupCoordinator(store, () => now);
    const prepared = await store.prepare(offer());
    await store.markDeliveredForTurn(prepared.sourceRequestId, {
      deliveredAt: "2026-08-28T07:00:01.000Z",
      deliveryRef: "slack-message://sha256/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      payloadDigest: "sha256:9aa4c8c404f5a13282e0dd832b1d3add24e2cb4f8eb9d804d34f0aaf5a275020",
    });
    const accepting = await coordinator.beginAcceptance(acceptanceInput());
    assert.ok(accepting);

    now = new Date("2026-08-28T08:00:00.001Z");
    assert.deepEqual(
      await coordinator.beginAcceptance(acceptanceInput()),
      accepting,
      "the original ingress must recover its accepting claim after expiry",
    );
    assert.equal(
      await coordinator.beginAcceptance({
        ...acceptanceInput(),
        ingressRequestKey: "T:C:thread:event-two",
      }),
      undefined,
      "another ingress must not acquire an expired accepting offer",
    );

    await coordinator.acknowledgeAcceptance(accepting, offer().offer_ref);
    assert.deepEqual(
      await coordinator.beginAcceptance(acceptanceInput()),
      accepting,
      "the original ingress must recover its accepted claim after expiry",
    );
    assert.equal(
      await coordinator.beginAcceptance({
        ...acceptanceInput(),
        ingressRequestKey: "T:C:thread:event-three",
      }),
      undefined,
      "another ingress must not acquire an expired accepted offer",
    );
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("typed offer lookup selects only the exact delivered offer identity", async () => {
  const root = await mkdtemp(join(tmpdir(), "cerebro-followup-same-action-"));
  try {
    let now = new Date("2026-08-28T07:30:00.000Z");
    const store = new FileProactiveFollowupStore(root);
    const coordinator = new ProactiveFollowupCoordinator(store, () => now);
    const offerRefs = [
      `proactive-followup://sha256/${"a".repeat(64)}`,
      `proactive-followup://sha256/${"b".repeat(64)}`,
    ];
    const byDescendingRecordRef = [...offerRefs].sort((left, right) =>
      followupRecordRef(right).localeCompare(followupRecordRef(left))
    );
    const older = offer({
      created_at: "2026-08-28T07:00:00.000Z",
      expires_at: "2026-08-28T08:00:00.000Z",
      offer_ref: byDescendingRecordRef[0]!,
      turn_ref: "agent-turn://slack-request-older",
    });
    const newer = offer({
      created_at: "2026-08-28T07:15:00.000Z",
      expires_at: "2026-08-28T08:00:00.000Z",
      offer_ref: byDescendingRecordRef[1]!,
      turn_ref: "agent-turn://slack-request-newer",
    });
    assert.ok(
      followupRecordRef(older.offer_ref) > followupRecordRef(newer.offer_ref),
      "the older offer must sort first under the former reversed-hash lookup",
    );
    for (const [candidate, deliveredAt, deliveryByte] of [
      [older, "2026-08-28T07:01:00.000Z", "d"],
      [newer, "2026-08-28T07:16:00.000Z", "e"],
    ] as const) {
      const prepared = await store.prepare(candidate);
      await store.markDeliveredForTurn(prepared.sourceRequestId, {
        deliveredAt,
        deliveryRef: `slack-message://sha256/${deliveryByte.repeat(64)}`,
        payloadDigest: `sha256:${"f".repeat(64)}`,
      });
    }

    const exactAcceptance = {
      ...acceptanceInput(),
      offerRef: newer.offer_ref,
    };
    const accepting = await coordinator.beginAcceptance(exactAcceptance);
    assert.equal(accepting?.offer.offer_ref, newer.offer_ref);
    now = new Date("2026-08-28T08:00:00.001Z");
    assert.deepEqual(await coordinator.beginAcceptance(exactAcceptance), accepting);
    assert.equal(await coordinator.beginAcceptance({
      ...exactAcceptance,
      ingressRequestKey: "T:C:thread:event-two",
    }), undefined);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
});

test("the client sends the exact offer to Rust and requires a matching acknowledgement", async () => {
  const requests: Record<string, unknown>[] = [];
  const client = new CerebroAskClient({
    agentRuntimeUrl: "https://agent.example.com",
    answerAuthority,
    apiKey: "runtime-bound",
    baseUrl: "https://cerebro.example.com",
    fetchImpl: async (_input, init) => {
      requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return new Response(JSON.stringify({
        accepted_followup_ref: offer().offer_ref,
        evidence_refs: ["evidence://graph/one"],
        final_state: "answered",
        proactive_followup_offer: null,
        lane: "investigate",
        markdown: "The follow-up is scheduled.",
        outcome: "pending_delivery",
        working_state: null,
      }), { status: 200 });
    },
    tenantId: "writer",
  });
  const result = await client.runAgentTurn({
    actorRef: "slack-user://operator",
    assessmentAt: "2026-08-28T07:30:00.000Z",
    followupAcceptance: offer(),
    question: offer().action,
    requestId: "slack-request-two",
    signal: new AbortController().signal,
    threadRef: offer().thread_ref,
  });
  assert.deepEqual(requests[0]!.followup_acceptance, {
    offer: offer(),
    schema_version: "proactive-followup-acceptance/v1",
  });
  assert.deepEqual(requests[0]!.capabilities, ["proactive_followup_offer/v1"]);
  assert.equal(result.acceptedFollowupRef, offer().offer_ref);
});

test("the client trusts only the explicit Rust no-commit failure code", async () => {
  for (const [code, status, expected] of [
    ["followup_acceptance_not_committed", 422, "not_committed"],
    ["agent_turn_failed", 503, "unknown"],
  ] as const) {
    const client = new CerebroAskClient({
      agentRuntimeUrl: "https://agent.example.com",
      answerAuthority,
      apiKey: "runtime-bound",
      baseUrl: "https://cerebro.example.com",
      fetchImpl: async () => Response.json({ code, message: "bounded failure" }, { status }),
      tenantId: "writer",
    });
    await assert.rejects(client.runAgentTurn({
      actorRef: "slack-user://operator",
      assessmentAt: "2026-08-28T07:30:00.000Z",
      followupAcceptance: offer(),
      question: offer().action,
      requestId: `slack-request-${status}`,
      signal: new AbortController().signal,
      threadRef: offer().thread_ref,
    }), (error: unknown) =>
      error instanceof CerebroAskError && error.turnCommitState === expected
    );
  }
});

test("the host rejects Rust offers outside the exact tenant, thread, or time contract", async () => {
  for (const invalidOffer of [
    offer({ tenant_id: "another-tenant" }),
    offer({ thread_ref: "slack-scratchpad://sha256/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }),
    offer({ expires_at: "2026-08-28T07:00:00.000Z" }),
  ]) {
    const client = new CerebroAskClient({
      agentRuntimeUrl: "https://agent.example.com",
      answerAuthority,
      apiKey: "runtime-bound",
      baseUrl: "https://cerebro.example.com",
      fetchImpl: async () => new Response(JSON.stringify({
        accepted_followup_ref: null,
        evidence_refs: ["evidence://graph/one"],
        final_state: "answered",
        proactive_followup_offer: invalidOffer,
        lane: "investigate",
        markdown: "Current evidence supports a follow-up.",
        outcome: "pending_delivery",
        working_state: null,
      }), { status: 200 }),
      tenantId: "writer",
    });
    await assert.rejects(
      client.runAgentTurn({
        actorRef: "slack-user://operator",
        assessmentAt: "2026-08-28T07:30:00.000Z",
        question: "What changed?",
        requestId: "slack-request-three",
        signal: new AbortController().signal,
        threadRef: offer().thread_ref,
      }),
      /proactive follow-up offer is invalid/u,
    );
  }
});

function offer(
  overrides: Partial<RustProactiveFollowupOffer> = {},
): RustProactiveFollowupOffer {
  return {
    action: "start this follow-up",
    action_key: "start_followup:one",
    created_at: "2026-08-28T07:00:00.000Z",
    expires_at: "2026-08-28T08:00:00.000Z",
    grounding_refs: ["evidence://graph/one"],
    offer_ref: "proactive-followup://sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    schema_version: "proactive-followup-offer/v1",
    tenant_id: "writer",
    thread_ref: "slack-scratchpad://sha256/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    title: "Keep checking the missing evidence",
    turn_ref: "agent-turn://slack-request-one",
    ...overrides,
  };
}

function acceptanceInput(): {
  actorRef: string;
  ingressRequestKey: string;
  offerRef: string;
  threadRef: string;
} {
  return {
    actorRef: "slack-user://operator",
    ingressRequestKey: "T:C:thread:event-one",
    offerRef: offer().offer_ref,
    threadRef: offer().thread_ref,
  };
}

function followupRecordRef(offerRef: string): string {
  return `slack-proactive-followup://sha256/${createHash("sha256").update([
    offer().tenant_id,
    offer().thread_ref,
    offerRef,
  ].join("\n")).digest("hex")}`;
}
