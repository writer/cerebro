import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { describe, test } from "node:test";
import type {
  SlackAdmissionResult,
  SlackIngressEnvelope,
} from "../src/contracts.js";
import type {
  DurableInboundPayloadPort,
  InboundPayloadCommit,
  InboundPayloadReceipt,
  SlackEventNormalizationInput,
  SlackEventsApiRequest,
  SlackInvocationNormalizationInput,
  SlackSignedInvocationRequest,
  SlackSocketModeEnvelope,
} from "../src/transport/contracts.js";
import {
  handleEventsApiRequest,
  handleInteractiveRequest,
  handleSlashCommandRequest,
  handleSocketModeRequest,
} from "../src/transport/handler.js";
import {
  StructuralSlackEventNormalizer,
  StructuralSlackInvocationNormalizer,
} from "../src/transport/normalization.js";
import { evaluateSlackIngressReadiness } from "../src/transport/readiness.js";

const now = new Date("2026-07-16T12:00:00.000Z");
const timestamp = String(Math.floor(now.getTime() / 1_000));
const signingKey = randomBytes(32);

describe("Slack transport boundary", () => {
  test("persists before normalization and admits before returning an Events API acknowledgement", async () => {
    const order: string[] = [];
    const payloads = new MemoryPayloadStore(order);
    const request = eventsRequest(eventBody());

    const outcome = await handleEventsApiRequest(request, requestKey(), {
      admission: acceptingAdmission(order),
      clock: { now: () => now },
      normalizer: recordingNormalizer(order),
      payloads,
    });

    assert.deepEqual(order, ["persist", "normalize", "admit"]);
    assert.deepEqual(outcome, {
      command: { body: "", kind: "events_api_ack", status_code: 200 },
      kind: "acknowledge",
      run_id: "run-event-1",
    });
    assert.deepEqual(payloads.rawBodies, [request.raw_body]);
  });

  test("does not normalize, admit, or acknowledge when payload persistence fails", async () => {
    const order: string[] = [];
    const payloads = new MemoryPayloadStore(order);
    payloads.fail = true;

    const outcome = await handleEventsApiRequest(
      eventsRequest(eventBody()),
      requestKey(),
      {
        admission: acceptingAdmission(order),
        clock: { now: () => now },
        normalizer: recordingNormalizer(order),
        payloads,
      },
    );

    assert.deepEqual(order, ["persist"]);
    assert.deepEqual(outcome, {
      kind: "no_acknowledgement",
      reason_code: "payload_not_durable",
      retryable: true,
      stage: "persistence",
    });
  });

  test("does not acknowledge a malformed durable payload receipt", async () => {
    const order: string[] = [];
    const request = eventsRequest(eventBody());

    const outcome = await handleEventsApiRequest(request, requestKey(), {
      admission: acceptingAdmission(order),
      clock: { now: () => now },
      normalizer: recordingNormalizer(order),
      payloads: {
        persist: async () => {
          order.push("persist");
          return {
            digest: `sha256:${createHash("sha256")
              .update(request.raw_body)
              .digest("hex")}`,
          } as InboundPayloadReceipt;
        },
      },
    });

    assert.deepEqual(order, ["persist"]);
    assert.deepEqual(outcome, {
      kind: "no_acknowledgement",
      reason_code: "invalid_payload_receipt",
      retryable: true,
      stage: "persistence",
    });
  });

  test("does not acknowledge when durable admission rejects the event", async () => {
    const order: string[] = [];

    const outcome = await handleEventsApiRequest(
      eventsRequest(eventBody()),
      requestKey(),
      {
        admission: {
          admit: async () => {
            order.push("admit");
            return rejection(true);
          },
        },
        clock: { now: () => now },
        normalizer: recordingNormalizer(order),
        payloads: new MemoryPayloadStore(order),
      },
    );

    assert.deepEqual(order, ["persist", "normalize", "admit"]);
    assert.deepEqual(outcome, {
      kind: "no_acknowledgement",
      reason_code: "durable_admission_rejected",
      retryable: true,
      stage: "admission",
    });
  });

  test("reuses the durable payload and run when Slack retries an event", async () => {
    const order: string[] = [];
    const payloads = new MemoryPayloadStore(order);
    const admitted = new Map<string, string>();
    const request = eventsRequest(eventBody());
    const admission = {
      admit: async (envelope: SlackIngressEnvelope): Promise<SlackAdmissionResult> => {
        const runId = admitted.get(envelope.event_id) ?? `run-${envelope.event_id}`;
        const duplicate = admitted.has(envelope.event_id);
        admitted.set(envelope.event_id, runId);
        return accepted(runId, duplicate);
      },
    };
    const dependencies = {
      admission,
      clock: { now: () => now },
      normalizer: recordingNormalizer(order),
      payloads,
    };

    const first = await handleEventsApiRequest(request, requestKey(), dependencies);
    const second = await handleEventsApiRequest(request, requestKey(), dependencies);

    assert.equal(first.kind, "acknowledge");
    assert.equal(second.kind, "acknowledge");
    if (first.kind !== "acknowledge" || second.kind !== "acknowledge") {
      assert.fail("expected both retries to be acknowledged");
    }
    assert.equal(second.run_id, first.run_id);
    assert.equal(payloads.receiptCount, 1);
    assert.deepEqual(payloads.commitKeys, [
      "slack:app-1:team-1:event-1",
      "slack:app-1:team-1:event-1",
    ]);
  });

  test("rejects bad and stale signatures before payload persistence", async () => {
    const badOrder: string[] = [];
    const badRequest = eventsRequest(eventBody());
    badRequest.request_signature = `v0=${"0".repeat(64)}`;

    const bad = await handleEventsApiRequest(badRequest, requestKey(), {
      admission: acceptingAdmission(badOrder),
      clock: { now: () => now },
      normalizer: recordingNormalizer(badOrder),
      payloads: new MemoryPayloadStore(badOrder),
    });

    const staleOrder: string[] = [];
    const staleTimestamp = String(Number(timestamp) - 301);
    const staleRequest = eventsRequest(eventBody(), staleTimestamp);
    const stale = await handleEventsApiRequest(staleRequest, requestKey(), {
      admission: acceptingAdmission(staleOrder),
      clock: { now: () => now },
      normalizer: recordingNormalizer(staleOrder),
      payloads: new MemoryPayloadStore(staleOrder),
    });

    assert.deepEqual(badOrder, []);
    assert.deepEqual(staleOrder, []);
    assert.deepEqual(bad, {
      kind: "no_acknowledgement",
      reason_code: "invalid_signature",
      retryable: false,
      stage: "verification",
    });
    assert.deepEqual(stale, {
      kind: "no_acknowledgement",
      reason_code: "stale_timestamp",
      retryable: false,
      stage: "verification",
    });
  });

  test("verifies the signature against the exact raw request bytes", async () => {
    const order: string[] = [];
    const request = eventsRequest(eventBody());
    request.raw_body = Buffer.concat([request.raw_body, Buffer.from(" ")]);

    const outcome = await handleEventsApiRequest(request, requestKey(), {
      admission: acceptingAdmission(order),
      clock: { now: () => now },
      normalizer: recordingNormalizer(order),
      payloads: new MemoryPayloadStore(order),
    });

    assert.deepEqual(order, []);
    assert.equal(outcome.kind, "no_acknowledgement");
    if (outcome.kind !== "no_acknowledgement") {
      assert.fail("expected a signature failure");
    }
    assert.equal(outcome.reason_code, "invalid_signature");
  });

  test("authenticates a URL verification challenge without persisting or admitting it", async () => {
    const order: string[] = [];
    const request = eventsRequest(
      JSON.stringify({
        api_app_id: "app-1",
        challenge: "challenge-value",
        type: "url_verification",
      }),
    );

    const outcome = await handleEventsApiRequest(request, requestKey(), {
      admission: acceptingAdmission(order),
      clock: { now: () => now },
      normalizer: recordingNormalizer(order),
      payloads: new MemoryPayloadStore(order),
    });

    assert.deepEqual(order, []);
    assert.deepEqual(outcome, {
      command: {
        body: "challenge-value",
        kind: "url_verification",
        status_code: 200,
      },
      kind: "challenge",
    });
  });

  test("verifies durable Socket Mode presence before payload persistence", async () => {
    const order: string[] = [];
    const payload = JSON.parse(eventBody()) as Record<string, unknown>;
    const envelope: SlackSocketModeEnvelope = {
      envelope_id: "socket-envelope-1",
      payload,
      type: "events_api",
    };

    const outcome = await handleSocketModeRequest(
      {
        connection: { connection_ref: "connection-1", generation: 3 },
        raw_body: Buffer.from(JSON.stringify(envelope)),
        received_at: now.toISOString(),
        route: route(),
      },
      {
        admission: acceptingAdmission(order),
        normalizer: recordingNormalizer(order),
        payloads: new MemoryPayloadStore(order),
        presence: {
          isActive: async () => {
            order.push("verify");
            return true;
          },
        },
      },
    );

    assert.deepEqual(order, ["verify", "persist", "normalize", "admit"]);
    assert.deepEqual(outcome, {
      command: {
        envelope_id: "socket-envelope-1",
        kind: "socket_mode_ack",
      },
      kind: "acknowledge",
      run_id: "run-event-1",
    });
  });

  test("persists a signed slash command and durably admits it before acknowledgement", async () => {
    const order: string[] = [];
    const payloads = new MemoryPayloadStore(order);
    const request = signedInvocationRequest(slashCommandBody());

    const outcome = await handleSlashCommandRequest(request, requestKey(), {
      admission: acceptingAdmission(order),
      clock: { now: () => now },
      normalizer: recordingInvocationNormalizer(order),
      payloads,
    });

    assert.deepEqual(order, ["persist", "normalize", "admit"]);
    assert.deepEqual(payloads.commitKeys, [
      "slack:app-1:team-1:slash_command:trigger-command-1",
    ]);
    assert.deepEqual(outcome, {
      command: {
        body: "",
        invocation: "slash_command",
        kind: "signed_invocation_ack",
        status_code: 200,
      },
      kind: "acknowledge",
      run_id: "run-slash_command:trigger-command-1",
    });
  });

  test("persists a signed interaction without exposing response transport fields", async () => {
    const order: string[] = [];
    const payloads = new MemoryPayloadStore(order);
    const request = signedInvocationRequest(interactiveBody());
    let admitted: SlackIngressEnvelope | undefined;

    const outcome = await handleInteractiveRequest(request, requestKey(), {
      admission: {
        admit: async (envelope) => {
          order.push("admit");
          admitted = envelope;
          return accepted(`run-${envelope.event_id}`, false);
        },
      },
      clock: { now: () => now },
      normalizer: recordingInvocationNormalizer(order),
      payloads,
    });

    assert.deepEqual(order, ["persist", "normalize", "admit"]);
    assert.deepEqual(outcome, {
      command: {
        body: "",
        invocation: "interactive",
        kind: "signed_invocation_ack",
        status_code: 200,
      },
      kind: "acknowledge",
      run_id: "run-interactive:trigger-action-1",
    });
    assert.equal(admitted?.conversation_id, "conversation-1");
    assert.equal(admitted?.thread_id, "thread-1");
    assert.equal(admitted?.event_type, "interactive:block_actions:approve");
    assert.equal(JSON.stringify(admitted).includes("response_url"), false);
  });

  test("does not persist or acknowledge a malformed signed invocation", async () => {
    const order: string[] = [];
    const request = signedInvocationRequest("command=%2Fcerebro");

    const outcome = await handleSlashCommandRequest(request, requestKey(), {
      admission: acceptingAdmission(order),
      clock: { now: () => now },
      normalizer: recordingInvocationNormalizer(order),
      payloads: new MemoryPayloadStore(order),
    });

    assert.deepEqual(order, []);
    assert.deepEqual(outcome, {
      kind: "no_acknowledgement",
      reason_code: "invalid_envelope",
      retryable: false,
      stage: "parsing",
    });
  });

  test("normalizes a modal interaction through a durable thread route", async () => {
    const order: string[] = [];
    const rawBody = new URLSearchParams({
      payload: JSON.stringify({
        api_app_id: "app-1",
        callback_id: "schedule_review",
        team: { id: "team-1" },
        trigger_id: "trigger-modal-1",
        type: "view_submission",
        user: { id: "user-1" },
      }),
    }).toString();
    const request = signedInvocationRequest(rawBody);
    request.route = {
      ...request.route,
      conversation_id: "conversation-1",
      thread_id: "thread-1",
    };
    let admitted: SlackIngressEnvelope | undefined;

    const outcome = await handleInteractiveRequest(request, requestKey(), {
      admission: {
        admit: async (envelope) => {
          order.push("admit");
          admitted = envelope;
          return accepted(`run-${envelope.event_id}`, false);
        },
      },
      clock: { now: () => now },
      normalizer: recordingInvocationNormalizer(order),
      payloads: new MemoryPayloadStore(order),
    });

    assert.equal(outcome.kind, "acknowledge");
    assert.equal(admitted?.conversation_id, "conversation-1");
    assert.equal(admitted?.thread_id, "thread-1");
    assert.equal(
      admitted?.event_type,
      "interactive:view_submission:schedule_review",
    );
  });

  test("admits Socket Mode commands only after durable presence and payload storage", async () => {
    const order: string[] = [];
    const payload = Object.fromEntries(
      new URLSearchParams(slashCommandBody()).entries(),
    );
    const envelope: SlackSocketModeEnvelope = {
      envelope_id: "socket-command-1",
      payload,
      type: "slash_commands",
    };

    const outcome = await handleSocketModeRequest(
      {
        connection: { connection_ref: "connection-1", generation: 3 },
        raw_body: Buffer.from(JSON.stringify(envelope)),
        received_at: now.toISOString(),
        route: route(),
      },
      {
        admission: acceptingAdmission(order),
        invocation_normalizer: recordingInvocationNormalizer(order),
        normalizer: recordingNormalizer(order),
        payloads: new MemoryPayloadStore(order),
        presence: {
          isActive: async () => {
            order.push("verify");
            return true;
          },
        },
      },
    );

    assert.deepEqual(order, ["verify", "persist", "normalize", "admit"]);
    assert.deepEqual(outcome, {
      command: {
        envelope_id: "socket-command-1",
        kind: "socket_mode_ack",
      },
      kind: "acknowledge",
      run_id: "run-slash_command:trigger-command-1",
    });
  });
});

describe("Slack ingress readiness", () => {
  test("Events API requires public ingress capability", () => {
    assert.deepEqual(
      evaluateSlackIngressReadiness("events_api", {
        durable_presence_relay: true,
        public_ingress: false,
      }),
      { ready: false, reason_code: "public_ingress_required" },
    );
  });

  test("Socket Mode requires a durable presence relay", () => {
    assert.deepEqual(
      evaluateSlackIngressReadiness("socket_mode", {
        durable_presence_relay: false,
        public_ingress: true,
      }),
      { ready: false, reason_code: "durable_presence_relay_required" },
    );
  });
});

class MemoryPayloadStore implements DurableInboundPayloadPort {
  fail = false;
  readonly commitKeys: string[] = [];
  readonly rawBodies: Uint8Array[] = [];
  private readonly order: string[];
  private readonly receipts = new Map<string, InboundPayloadReceipt>();

  constructor(order: string[]) {
    this.order = order;
  }

  get receiptCount(): number {
    return this.receipts.size;
  }

  async persist(commit: InboundPayloadCommit): Promise<InboundPayloadReceipt> {
    this.order.push("persist");
    this.commitKeys.push(commit.idempotency_key);
    this.rawBodies.push(commit.raw_body);
    if (this.fail) {
      throw new Error("persistence unavailable");
    }
    const existing = this.receipts.get(commit.idempotency_key);
    if (existing !== undefined) {
      return existing;
    }
    const digest = createHash("sha256").update(commit.raw_body).digest("hex");
    const receipt = {
      digest: `sha256:${digest}`,
      payload_ref: `payload-ref:${commit.idempotency_key}`,
    };
    this.receipts.set(commit.idempotency_key, receipt);
    return receipt;
  }
}

function eventsRequest(
  rawBody: string,
  requestTimestamp = timestamp,
): SlackEventsApiRequest {
  const raw = Buffer.from(rawBody);
  const key = requestKey();
  return {
    raw_body: raw,
    received_at: now.toISOString(),
    request_signature: sign(raw, requestTimestamp, key),
    request_timestamp: requestTimestamp,
    route: route(),
  };
}

function eventBody(): string {
  return JSON.stringify({
    api_app_id: "app-1",
    event: {
      channel: "conversation-1",
      thread_ts: "thread-1",
      ts: "event-time-1",
      type: "app_mention",
    },
    event_id: "event-1",
    event_time: Math.floor(now.getTime() / 1_000),
    team_id: "team-1",
    type: "event_callback",
  });
}

function slashCommandBody(): string {
  return new URLSearchParams({
    api_app_id: "app-1",
    channel_id: "conversation-1",
    command: "/cerebro",
    response_url: "https://slack.invalid/opaque-response",
    team_id: "team-1",
    text: "inspect this thread",
    trigger_id: "trigger-command-1",
    user_id: "user-1",
  }).toString();
}

function interactiveBody(): string {
  return new URLSearchParams({
    payload: JSON.stringify({
      actions: [{ action_id: "approve", action_ts: "1" }],
      api_app_id: "app-1",
      container: {
        channel_id: "conversation-1",
        thread_ts: "thread-1",
      },
      response_url: "https://slack.invalid/opaque-response",
      team: { id: "team-1" },
      trigger_id: "trigger-action-1",
      type: "block_actions",
      user: { id: "user-1" },
    }),
  }).toString();
}

function signedInvocationRequest(rawBody: string): SlackSignedInvocationRequest {
  const raw = Buffer.from(rawBody);
  const key = requestKey();
  return {
    raw_body: raw,
    received_at: now.toISOString(),
    request_signature: sign(raw, timestamp, key),
    request_timestamp: timestamp,
    route: route(),
  };
}

function route() {
  return {
    binding_id: "binding-1",
    required_capabilities: [],
    retention_policy_ref: "retention-policy-1",
    run_kind: "interactive" as const,
    tenant_id: "tenant-1",
  };
}

function requestKey(): Uint8Array {
  return signingKey;
}

function sign(
  rawBody: Uint8Array,
  requestTimestamp: string,
  key: Uint8Array,
): string {
  return `v0=${createHmac("sha256", key)
    .update("v0:")
    .update(requestTimestamp)
    .update(":")
    .update(rawBody)
    .digest("hex")}`;
}

function recordingNormalizer(order: string[]) {
  const structural = new StructuralSlackEventNormalizer();
  return {
    normalize(input: SlackEventNormalizationInput): SlackIngressEnvelope {
      order.push("normalize");
      return structural.normalize(input);
    },
  };
}

function recordingInvocationNormalizer(order: string[]) {
  const structural = new StructuralSlackInvocationNormalizer();
  return {
    normalize(input: SlackInvocationNormalizationInput): SlackIngressEnvelope {
      order.push("normalize");
      return structural.normalize(input);
    },
  };
}

function acceptingAdmission(order: string[]) {
  return {
    admit: async (envelope: SlackIngressEnvelope): Promise<SlackAdmissionResult> => {
      order.push("admit");
      return accepted(`run-${envelope.event_id}`, false);
    },
  };
}

function accepted(runId: string, duplicate: boolean): SlackAdmissionResult {
  return {
    acknowledgement_permitted: true,
    duplicate,
    message: "Request saved and queued.",
    retryable: false,
    run_id: runId,
    status: "queued",
  };
}

function rejection(retryable: boolean): SlackAdmissionResult {
  return {
    acknowledgement_permitted: false,
    duplicate: false,
    message: "Request was not admitted.",
    retryable,
    status: "rejected",
  };
}
