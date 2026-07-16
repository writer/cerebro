import { createHash } from "node:crypto";
import type {
  EventsApiHandlerDependencies,
  InboundPayloadReceipt,
  SlackEventCallbackEnvelope,
  SlackEventsApiRequest,
  SlackSocketModeRequest,
  SlackTransportOutcome,
  SlackTransportRoute,
  SocketModeHandlerDependencies,
} from "./contracts.js";
import {
  eventCallbackFromSocketMode,
  parseEventsApiEnvelope,
  parseSocketModeEnvelope,
} from "./normalization.js";
import { verifySlackRequestSignature } from "./signatures.js";

export async function handleEventsApiRequest(
  request: SlackEventsApiRequest,
  signingSecret: string | Uint8Array,
  dependencies: EventsApiHandlerDependencies,
): Promise<SlackTransportOutcome> {
  const verification = verifySlackRequestSignature(
    {
      now: dependencies.clock.now(),
      raw_body: request.raw_body,
      request_signature: request.request_signature,
      request_timestamp: request.request_timestamp,
    },
    signingSecret,
  );
  if (!verification.verified) {
    return noAcknowledgement("verification", verification.reason, false);
  }

  let parsed;
  try {
    parsed = parseEventsApiEnvelope(request.raw_body);
  } catch {
    return noAcknowledgement("parsing", "invalid_envelope", false);
  }

  if (parsed.type === "url_verification") {
    return {
      command: {
        body: parsed.challenge,
        kind: "url_verification",
        status_code: 200,
      },
      kind: "challenge",
    };
  }

  return persistNormalizeAdmit(
    "events_api",
    parsed,
    request.raw_body,
    request.received_at,
    request.route,
    dependencies,
    () => ({ body: "", kind: "events_api_ack", status_code: 200 }),
  );
}

export async function handleSocketModeRequest(
  request: SlackSocketModeRequest,
  dependencies: SocketModeHandlerDependencies,
): Promise<SlackTransportOutcome> {
  let active = false;
  try {
    active = await dependencies.presence.isActive(request.connection);
  } catch {
    return noAcknowledgement("verification", "presence_unavailable", true);
  }
  if (!active) {
    return noAcknowledgement("verification", "inactive_connection", false);
  }

  let envelope;
  let event;
  try {
    envelope = parseSocketModeEnvelope(request.raw_body);
    event = eventCallbackFromSocketMode(envelope);
  } catch {
    return noAcknowledgement("parsing", "invalid_envelope", false);
  }

  return persistNormalizeAdmit(
    "socket_mode",
    event,
    request.raw_body,
    request.received_at,
    request.route,
    dependencies,
    () => ({
      envelope_id: envelope.envelope_id,
      kind: "socket_mode_ack",
    }),
  );
}

async function persistNormalizeAdmit(
  transport: "events_api" | "socket_mode",
  event: SlackEventCallbackEnvelope,
  rawBody: Uint8Array,
  receivedAt: string,
  route: SlackTransportRoute,
  dependencies:
    | EventsApiHandlerDependencies
    | SocketModeHandlerDependencies,
  acknowledgement: () =>
    | { body: ""; kind: "events_api_ack"; status_code: 200 }
    | { envelope_id: string; kind: "socket_mode_ack" },
): Promise<SlackTransportOutcome> {
  let payload: InboundPayloadReceipt;
  try {
    payload = await dependencies.payloads.persist({
      idempotency_key: payloadIdempotencyKey(event),
      raw_body: rawBody,
      received_at: receivedAt,
      transport,
    });
  } catch {
    return noAcknowledgement("persistence", "payload_not_durable", true);
  }

  if (!validPayloadReceipt(payload, rawBody)) {
    return noAcknowledgement("persistence", "invalid_payload_receipt", true);
  }

  let normalized;
  try {
    normalized = dependencies.normalizer.normalize({
      envelope: event,
      payload,
      received_at: receivedAt,
      route,
    });
  } catch {
    return noAcknowledgement("normalization", "invalid_event", false);
  }

  try {
    const admission = await dependencies.admission.admit(normalized);
    if (!admission.acknowledgement_permitted) {
      return noAcknowledgement(
        "admission",
        "durable_admission_rejected",
        admission.retryable,
      );
    }
    return {
      command: acknowledgement(),
      kind: "acknowledge",
      run_id: admission.run_id,
    };
  } catch {
    return noAcknowledgement("admission", "durable_admission_failed", true);
  }
}

function payloadIdempotencyKey(event: SlackEventCallbackEnvelope): string {
  return `slack:${event.api_app_id}:${event.team_id}:${event.event_id}`;
}

function validPayloadReceipt(
  receipt: InboundPayloadReceipt,
  rawBody: Uint8Array,
): boolean {
  if (receipt.payload_ref.trim() === "") {
    return false;
  }
  const digest = createHash("sha256").update(rawBody).digest("hex");
  return receipt.digest === `sha256:${digest}`;
}

function noAcknowledgement(
  stage: "verification" | "parsing" | "persistence" | "normalization" | "admission",
  reasonCode: string,
  retryable: boolean,
): SlackTransportOutcome {
  return {
    kind: "no_acknowledgement",
    reason_code: reasonCode,
    retryable,
    stage,
  };
}
