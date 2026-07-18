import { createHash } from "node:crypto";
import type {
  EventsApiHandlerDependencies,
  InboundPayloadReceipt,
  SignedInvocationHandlerDependencies,
  SlackEventCallbackEnvelope,
  SlackEventsApiRequest,
  SlackInvocationEnvelope,
  SlackSignedInvocationRequest,
  SlackSocketModeRequest,
  SlackTransportOutcome,
  SocketModeHandlerDependencies,
} from "./contracts.js";
import {
  eventCallbackFromSocketMode,
  invocationFromSocketMode,
  parseInteractiveEnvelope,
  parseEventsApiEnvelope,
  parseSlashCommandEnvelope,
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
    payloadIdempotencyKey(parsed),
    request.raw_body,
    request.received_at,
    dependencies,
    (payload) => dependencies.normalizer.normalize({
      envelope: parsed,
      payload,
      received_at: request.received_at,
      route: request.route,
    }),
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
  let event: SlackEventCallbackEnvelope | SlackInvocationEnvelope;
  try {
    envelope = parseSocketModeEnvelope(request.raw_body);
    event = envelope.type === "events_api"
      ? eventCallbackFromSocketMode(envelope)
      : invocationFromSocketMode(envelope);
  } catch {
    return noAcknowledgement("parsing", "invalid_envelope", false);
  }

  return persistNormalizeAdmit(
    "socket_mode",
    socketPayloadIdempotencyKey(event),
    request.raw_body,
    request.received_at,
    dependencies,
    (payload) => event.type === "event_callback"
      ? dependencies.normalizer.normalize({
          envelope: event,
          payload,
          received_at: request.received_at,
          route: request.route,
        })
      : requireInvocationNormalizer(dependencies).normalize({
        envelope: event,
        payload,
        received_at: request.received_at,
        route: request.route,
      }),
    () => ({
      envelope_id: envelope.envelope_id,
      kind: "socket_mode_ack",
    }),
  );
}

export function handleSlashCommandRequest(
  request: SlackSignedInvocationRequest,
  signingSecret: string | Uint8Array,
  dependencies: SignedInvocationHandlerDependencies,
): Promise<SlackTransportOutcome> {
  return handleSignedInvocation(
    "slash_commands",
    request,
    signingSecret,
    dependencies,
    parseSlashCommandEnvelope,
  );
}

export function handleInteractiveRequest(
  request: SlackSignedInvocationRequest,
  signingSecret: string | Uint8Array,
  dependencies: SignedInvocationHandlerDependencies,
): Promise<SlackTransportOutcome> {
  return handleSignedInvocation(
    "interactive",
    request,
    signingSecret,
    dependencies,
    parseInteractiveEnvelope,
  );
}

async function handleSignedInvocation(
  transport: "interactive" | "slash_commands",
  request: SlackSignedInvocationRequest,
  signingSecret: string | Uint8Array,
  dependencies: SignedInvocationHandlerDependencies,
  parse: (rawBody: Uint8Array) => SlackInvocationEnvelope,
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

  let envelope;
  try {
    envelope = parse(request.raw_body);
  } catch {
    return noAcknowledgement("parsing", "invalid_envelope", false);
  }

  return persistNormalizeAdmit(
    transport,
    invocationPayloadIdempotencyKey(envelope),
    request.raw_body,
    request.received_at,
    dependencies,
    (payload) => dependencies.normalizer.normalize({
      envelope,
      payload,
      received_at: request.received_at,
      route: request.route,
    }),
    () => ({
      body: "",
      invocation: envelope.type,
      kind: "signed_invocation_ack",
      status_code: 200,
    }),
  );
}

async function persistNormalizeAdmit(
  transport: "events_api" | "interactive" | "slash_commands" | "socket_mode",
  idempotencyKey: string,
  rawBody: Uint8Array,
  receivedAt: string,
  dependencies:
    | EventsApiHandlerDependencies
    | SignedInvocationHandlerDependencies
    | SocketModeHandlerDependencies,
  normalize: (
    payload: InboundPayloadReceipt,
  ) => ReturnType<EventsApiHandlerDependencies["normalizer"]["normalize"]>,
  acknowledgement: () =>
    | { body: ""; kind: "events_api_ack"; status_code: 200 }
    | {
        body: "";
        invocation: "interactive" | "slash_command";
        kind: "signed_invocation_ack";
        status_code: 200;
      }
    | { envelope_id: string; kind: "socket_mode_ack" },
): Promise<SlackTransportOutcome> {
  let payload: InboundPayloadReceipt;
  try {
    payload = await dependencies.payloads.persist({
      idempotency_key: idempotencyKey,
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
    normalized = normalize(payload);
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

function invocationPayloadIdempotencyKey(
  envelope: SlackInvocationEnvelope,
): string {
  return `slack:${envelope.api_app_id}:${envelope.team_id}:${envelope.type}:${envelope.trigger_id}`;
}

function socketPayloadIdempotencyKey(
  envelope: SlackEventCallbackEnvelope | SlackInvocationEnvelope,
): string {
  return envelope.type === "event_callback"
    ? payloadIdempotencyKey(envelope)
    : invocationPayloadIdempotencyKey(envelope);
}

function requireInvocationNormalizer(
  dependencies: SocketModeHandlerDependencies,
) {
  if (dependencies.invocation_normalizer === undefined) {
    throw new Error("Socket Mode invocation normalizer is required");
  }
  return dependencies.invocation_normalizer;
}

function validPayloadReceipt(
  receipt: InboundPayloadReceipt,
  rawBody: Uint8Array,
): boolean {
  if (
    typeof receipt.payload_ref !== "string" ||
    receipt.payload_ref.trim() === ""
  ) {
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
