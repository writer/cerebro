import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  SlackTransportV2Bridge,
  type TransportReceiptSignerV2,
  type TransportSequencePortV2,
  type TransportWakePortV2,
} from "../src/runtime/slack-transport-v2-bridge.js";
import type { OffSlackTransportAdapter, SlackTransportEnvelope } from "../src/runtime/off-slack-transport.js";

test("bridge projects an exact open-thread dispatch and signs the Rust receipt shape", async () => {
  let observed: SlackTransportEnvelope | undefined;
  const adapter = {
    async dispatch(envelope: SlackTransportEnvelope) {
      observed = envelope;
      return {
        attempt: 1,
        event_id: envelope.event_id,
        handled: true,
        messages: [],
        operations: [
          {
            method: "chat.update" as const,
            request: { channel: envelope.event.channel, text: "I checked it. The current path is healthy.", ts: "1785715200.000002" },
            response: { ts: "1785715200.000002" },
          },
        ],
        schema_version: "slack-transport-result/v1" as const,
        thread: { channel: envelope.event.channel, thread_ts: envelope.event.ts },
      };
    },
  };
  const body = dispatch("open_thread", "2026-08-03T00:00:00Z", "1785715200.000000");
  const requestDigest = digest(body);
  assert.equal(
    requestDigest,
    "sha256:bcb722ea3edb6476de801ad9886517bc39be0c62cf9158b2ae87c22aa3b82f0e",
    "pinned Rust sha256_json canonical digest",
  );
  const signer = fakeSigner();
  const sequencePort: TransportSequencePortV2 = {
    sequenceForRequest(actual) {
      assert.equal(actual, requestDigest);
      return 7;
    },
  };
  const bridge = new SlackTransportV2Bridge({
    adapter,
    botUserId: "U00000009",
    phaseBudgetMs: 20_000,
    sequencePort,
    signer,
  });

  const response = await bridge.handle(new Request("http://transport.test/v2", {
    body: JSON.stringify(body),
    method: "POST",
  }));
  const signed = await response.json() as Record<string, any>;

  assert.equal(response.status, 200);
  assert.deepEqual(observed, {
    authorizations: [{ user_id: "U00000009" }],
    event: {
      channel: "C00000001",
      text: "<@U00000009> Are you better now?",
      ts: "1785715200.000000",
      type: "app_mention",
      user: "U00000001",
    },
    event_id: "Ev00000001",
    schema_version: "slack-event-envelope/v1",
    team_id: "T00000001",
    type: "event_callback",
  });
  assert.equal(signed.schema_version, "slack-agent-signed-receipt-envelope/v2");
  assert.equal(signed.payload.schema_version, "slack-agent-trusted-event-receipt/v2");
  assert.equal(signed.payload.sequence, 7);
  assert.equal(signed.payload.request_digest, requestDigest);
  assert.deepEqual(signed.payload.transcript_delta, [{
    role: "assistant",
    message: "I checked it. The current path is healthy.",
  }]);
  assert.equal(signed.payload.telemetry.phases[0].phase, "route");
  assert.equal(signed.payload.telemetry.phases[0].budget_ms, 20_000);
  assert.equal(signed.payload_digest, digest(signed.payload));
  assert.equal(signed.signature_base64, Buffer.from(signed.payload_digest).toString("base64"));
});

test("bridge fails closed without signer or private sequence binding", async () => {
  const adapter = { dispatch: async () => { throw new Error("must not dispatch"); } } as unknown as OffSlackTransportAdapter;
  const unsigned = new SlackTransportV2Bridge({ adapter, botUserId: "U00000009", phaseBudgetMs: 20_000 });
  const unsignedResponse = await unsigned.handle(requestFor(dispatch(
    "open_thread",
    "2026-08-03T00:00:00Z",
    "1785715200.000000",
  )));
  assert.equal(unsignedResponse.status, 503);
  assert.deepEqual(await unsignedResponse.json(), { error: "receipt_signer_unavailable" });

  const unbound = new SlackTransportV2Bridge({
    adapter,
    botUserId: "U00000009",
    phaseBudgetMs: 20_000,
    signer: fakeSigner(),
  });
  const unboundResponse = await unbound.handle(requestFor(dispatch(
    "open_thread",
    "2026-08-03T00:00:00Z",
    "1785715200.000000",
  )));
  assert.equal(unboundResponse.status, 503);
  assert.deepEqual(await unboundResponse.json(), { error: "sequence_binding_unavailable" });
});

test("bridge rejects alias drift and unknown fields", async () => {
  const adapter = { dispatch: async () => { throw new Error("must not dispatch"); } } as unknown as OffSlackTransportAdapter;
  const bridge = new SlackTransportV2Bridge({
    adapter,
    botUserId: "U00000009",
    phaseBudgetMs: 20_000,
    sequencePort: { sequenceForRequest: () => 1 },
    signer: fakeSigner(),
  });
  const mismatched = dispatch("open_thread", "2026-08-03T00:00:00Z", "1785715200.000000");
  mismatched.candidate_event.aliases.context_scope_ref = "slack-context-scope://T00000001/C00000002";
  assert.equal((await bridge.handle(requestFor(mismatched))).status, 422);

  const extra = dispatch("open_thread", "2026-08-03T00:00:00Z", "1785715200.000000") as Record<string, unknown>;
  extra.private_manifest_ref = "must-not-cross";
  const extraResponse = await bridge.handle(requestFor(extra));
  assert.equal(extraResponse.status, 422);
  assert.deepEqual(await extraResponse.json(), { error: "dispatch_shape_invalid" });

});

test("bridge runs wake claim, validates its binding, posts, and acknowledges", async () => {
  const calls: string[] = [];
  const wakePort: TransportWakePortV2 = {
    async claim(input) {
      calls.push("claim");
      assert.equal(input.commitment_ref, "slack-commitment://one");
      return {
        claim_ref: "wake-claim://one",
        commitment_ref: input.commitment_ref,
        occurrence_ref: input.occurrence_ref,
        thread_ref: input.thread_ref,
        markdown: "I checked the scheduled condition. It now needs attention.",
        payload_digest: `sha256:${"a".repeat(64)}`,
      };
    },
    async post(input) {
      calls.push("post");
      assert.equal(input.channel_id, "C00000001");
      assert.equal(input.thread_ts, "1785715200.000000");
      return {
        attempt: 1,
        destination_receipt: "slack-message://receipt/one",
        message: input.claim.markdown,
      };
    },
    async acknowledge(input) {
      calls.push("acknowledge");
      assert.equal(input.destination_receipt, "slack-message://receipt/one");
    },
  };
  const bridge = new SlackTransportV2Bridge({
    adapter: { dispatch: async () => { throw new Error("wake must not become human speech"); } },
    botUserId: "U00000009",
    phaseBudgetMs: 20_000,
    sequencePort: { sequenceForRequest: () => 4 },
    signer: fakeSigner(),
    wakePort,
  });

  const response = await bridge.handle(requestFor(dispatch(
    "wake",
    "2026-08-03T00:00:01Z",
    "1785715200.000000",
  )));
  const signed = await response.json() as Record<string, any>;

  assert.equal(response.status, 200);
  assert.deepEqual(calls, ["claim", "post", "acknowledge"]);
  assert.deepEqual(signed.payload.transcript_delta, [{
    role: "assistant",
    message: "I checked the scheduled condition. It now needs attention.",
  }]);
  assert.deepEqual(signed.payload.deterministic_defects, []);
});

test("bridge refuses to post a wake whose trusted claim does not bind the event", async () => {
  let posted = false;
  const bridge = new SlackTransportV2Bridge({
    adapter: { dispatch: async () => { throw new Error("unused"); } },
    botUserId: "U00000009",
    phaseBudgetMs: 20_000,
    sequencePort: { sequenceForRequest: () => 4 },
    signer: fakeSigner(),
    wakePort: {
      async claim(input) {
        return {
          claim_ref: "wake-claim://one",
          commitment_ref: "slack-commitment://different",
          occurrence_ref: input.occurrence_ref,
          thread_ref: input.thread_ref,
          markdown: "This must not be posted.",
          payload_digest: `sha256:${"a".repeat(64)}`,
        };
      },
      async post() {
        posted = true;
        throw new Error("must not post");
      },
      async acknowledge() {
        throw new Error("must not acknowledge");
      },
    },
  });
  const response = await bridge.handle(requestFor(dispatch(
    "wake",
    "2026-08-03T00:00:01Z",
    "1785715200.000000",
  )));
  assert.equal(response.status, 502);
  assert.equal(posted, false);
});

function dispatch(event: "open_thread" | "wake", at: string, threadTs: string): any {
  const aliases = {
    actor_ref: "slack-user://U00000001",
    context_scope_ref: "slack-context-scope://T00000001/C00000001",
    delivery_ref: "slack-delivery://slack-event://Ev00000001",
    request_id: "slack-event://Ev00000001",
    tenant_id: "slack-workspace://T00000001",
    thread_ref: `slack-thread://T00000001/C00000001/${threadTs}`,
  };
  return event === "open_thread"
    ? {
      schema_version: "slack-agent-transport-dispatch/v2",
      candidate_event: { event, aliases, message: "Are you better now?", at },
    }
    : {
      schema_version: "slack-agent-transport-dispatch/v2",
      candidate_event: {
        event,
        aliases,
        commitment_ref: "slack-commitment://one",
        occurrence_ref: "slack-occurrence://one",
        at,
      },
    };
}

function fakeSigner(): TransportReceiptSignerV2 {
  return {
    signer: {
      algorithm: "ed25519",
      key_ref: "kms-key://transport-test",
      principal_ref: "principal:transport-test",
    },
    async signPayloadDigest(payloadDigest) {
      return Buffer.from(payloadDigest).toString("base64");
    },
  };
}

function requestFor(value: unknown): Request {
  return new Request("http://transport.test/v2", { body: JSON.stringify(value), method: "POST" });
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
