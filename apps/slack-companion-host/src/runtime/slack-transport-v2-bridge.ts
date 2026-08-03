import { createHash } from "node:crypto";
import { approvalCommandCode } from "./cerebro-ask-client.js";
import {
  type OffSlackTransportAdapter,
  type SlackTransportEnvelope,
  type SlackTransportResult,
} from "./off-slack-transport.js";

const DISPATCH_SCHEMA_VERSION = "slack-agent-transport-dispatch/v2";
const RECEIPT_SCHEMA_VERSION = "slack-agent-trusted-event-receipt/v2";
const SIGNED_ENVELOPE_SCHEMA_VERSION = "slack-agent-signed-receipt-envelope/v2";
const SLACK_ENVELOPE_SCHEMA_VERSION = "slack-event-envelope/v1";
const MAX_REQUEST_BYTES = 64 * 1024;

type CandidateEventName = "authorize" | "correction" | "message" | "open_thread" | "wake";
type SignatureAlgorithmV2 = "aws_kms_ecdsa_sha256" | "ed25519";

export interface TransportReceiptSignerV2 {
  readonly signer: {
    algorithm: SignatureAlgorithmV2;
    key_ref: string;
    principal_ref: string;
  };
  signPayloadDigest(payloadDigest: `sha256:${string}`): Promise<string>;
}

/**
 * The Rust dispatch deliberately excludes the private supervisor sequence.
 * The trusted host must bind the canonical request digest to that sequence out
 * of band; deriving a local counter is incorrect when world events intervene.
 */
export interface TransportSequencePortV2 {
  sequenceForRequest(requestDigest: `sha256:${string}`): Promise<number> | number;
}

export interface TransportWakeClaimV2 {
  claim_ref: string;
  commitment_ref: string;
  occurrence_ref: string;
  thread_ref: string;
  markdown: string;
  payload_digest: `sha256:${string}`;
}

export interface TransportWakePostReceiptV2 {
  attempt: number;
  destination_receipt: string;
  message: string;
}

/** Trusted-host boundary for the existing Rust claim -> Slack post -> Rust ack flow. */
export interface TransportWakePortV2 {
  claim(input: {
    at: string;
    commitment_ref: string;
    occurrence_ref: string;
    thread_ref: string;
  }): Promise<TransportWakeClaimV2>;
  post(input: {
    channel_id: string;
    claim: TransportWakeClaimV2;
    team_id: string;
    thread_ts: string;
  }): Promise<TransportWakePostReceiptV2>;
  acknowledge(input: {
    claim: TransportWakeClaimV2;
    destination_receipt: string;
  }): Promise<void>;
}

export interface SlackTransportV2BridgeOptions {
  adapter: Pick<OffSlackTransportAdapter, "dispatch">;
  botUserId: string;
  phaseBudgetMs: number;
  phase?: "deliver" | "route";
  sequencePort?: TransportSequencePortV2;
  signer?: TransportReceiptSignerV2;
  wakePort?: TransportWakePortV2;
}

interface CandidateAliasesV2 {
  actor_ref: string;
  context_scope_ref: string;
  delivery_ref: string;
  request_id: string;
  tenant_id: string;
  thread_ref: string;
}

interface CandidateTransportDispatchV2 {
  schema_version: typeof DISPATCH_SCHEMA_VERSION;
  candidate_event: {
    event: CandidateEventName;
    aliases: CandidateAliasesV2;
    at: string;
    message?: string;
    replaces_request_id?: string;
    approval_ref?: string;
    tool_id?: string;
    input_digest?: string;
    commitment_ref?: string;
    occurrence_ref?: string;
  };
}

interface SlackAliasBinding {
  channelId: string;
  eventId: string;
  eventTs: string;
  teamId: string;
  threadTs: string;
  userId: string;
}

interface TrustedEventReceiptV2 {
  schema_version: typeof RECEIPT_SCHEMA_VERSION;
  sequence: number;
  request_digest: `sha256:${string}`;
  transcript_delta: Array<{ role: "assistant"; message: string }>;
  telemetry: {
    exchange_sequence: number;
    end_to_end_ms: number;
    accounted_phase_ms: number;
    unaccounted_overhead_ms: number;
    phases: Array<{
      exchange_sequence: number;
      phase: "deliver" | "route";
      attempt: number;
      started_at: string;
      completed_at: string;
      duration_ms: number;
      budget_ms: number;
      input_digest: `sha256:${string}`;
      output_digest: `sha256:${string}`;
      outcome: "completed";
      model_call_count: number;
      tool_call_count: number;
      repair_count: number;
    }>;
  };
  fact_receipts: [];
  action_receipts: [];
  deterministic_defects: Array<{ code: string; detail: string; terminal: boolean }>;
}

export class SlackTransportV2Bridge {
  constructor(private readonly options: SlackTransportV2BridgeOptions) {
    requireSlackId(options.botUserId, "bot user");
    if (!Number.isSafeInteger(options.phaseBudgetMs) || options.phaseBudgetMs <= 0) {
      throw new Error("The transport phase budget must be a positive integer.");
    }
    if (options.phase !== undefined && options.phase !== "route" && options.phase !== "deliver") {
      throw new Error("The transport phase must match a sealed transport phase name.");
    }
  }

  async handle(request: Request): Promise<Response> {
    if (request.method !== "POST") return errorResponse(405, "method_not_allowed");
    if (!this.options.signer) return errorResponse(503, "receipt_signer_unavailable");
    if (!this.options.sequencePort) return errorResponse(503, "sequence_binding_unavailable");

    const body = new Uint8Array(await request.arrayBuffer());
    if (body.byteLength === 0 || body.byteLength > MAX_REQUEST_BYTES) {
      return errorResponse(413, "dispatch_size_invalid");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(Buffer.from(body).toString("utf8"));
    } catch {
      return errorResponse(400, "dispatch_json_invalid");
    }

    let dispatch: CandidateTransportDispatchV2;
    let aliases: SlackAliasBinding;
    try {
      dispatch = parseDispatch(parsed);
      aliases = parseAliases(dispatch.candidate_event.aliases, dispatch.candidate_event.at);
    } catch (error) {
      return errorResponse(422, errorCode(error));
    }
    const requestDigest = digestJson(dispatch);
    let sequence: number;
    try {
      sequence = await this.options.sequencePort.sequenceForRequest(requestDigest);
      if (!Number.isSafeInteger(sequence) || sequence <= 0) {
        throw new Error("invalid_sequence_binding");
      }
    } catch {
      return errorResponse(409, "sequence_binding_invalid");
    }

    const startedAt = new Date();
    const started = process.hrtime.bigint();
    let delivery: CandidateDeliveryV2;
    try {
      delivery = dispatch.candidate_event.event === "wake"
        ? await this.dispatchWake(dispatch, aliases)
        : await this.dispatchSlack(dispatch, aliases);
    } catch {
      return errorResponse(502, "candidate_transport_failed");
    }
    const completedAt = new Date();
    const durationMs = Number((process.hrtime.bigint() - started + 999_999n) / 1_000_000n);
    if (durationMs > this.options.phaseBudgetMs) {
      return errorResponse(504, "candidate_transport_timed_out");
    }

    const finalText = delivery.message;
    const outputDigest = digestJson(delivery.output);
    const receipt: TrustedEventReceiptV2 = {
      schema_version: RECEIPT_SCHEMA_VERSION,
      sequence,
      request_digest: requestDigest,
      transcript_delta: finalText === undefined ? [] : [{ role: "assistant", message: finalText }],
      telemetry: {
        exchange_sequence: sequence,
        end_to_end_ms: durationMs,
        accounted_phase_ms: durationMs,
        unaccounted_overhead_ms: 0,
        phases: [{
          exchange_sequence: sequence,
          phase: this.options.phase ?? "route",
          attempt: delivery.attempt,
          started_at: startedAt.toISOString(),
          completed_at: completedAt.toISOString(),
          duration_ms: durationMs,
          budget_ms: this.options.phaseBudgetMs,
          input_digest: requestDigest,
          output_digest: outputDigest,
          outcome: "completed",
          model_call_count: 0,
          tool_call_count: 0,
          repair_count: 0,
        }],
      },
      fact_receipts: [],
      action_receipts: [],
      deterministic_defects: delivery.handled && finalText !== undefined
        ? []
        : [{
          code: "candidate_delivery_missing",
          detail: "The candidate did not produce a terminal Slack delivery for this event.",
          terminal: true,
        }],
    };
    const payloadDigest = digestJson(receipt);
    let signatureBase64: string;
    try {
      validateSigner(this.options.signer.signer);
      signatureBase64 = await this.options.signer.signPayloadDigest(payloadDigest);
      requireCanonicalBase64(signatureBase64);
    } catch {
      return errorResponse(503, "receipt_signing_failed");
    }
    return Response.json({
      schema_version: SIGNED_ENVELOPE_SCHEMA_VERSION,
      payload: receipt,
      payload_digest: payloadDigest,
      signer: this.options.signer.signer,
      signature_base64: signatureBase64,
    });
  }

  private async dispatchSlack(
    dispatch: CandidateTransportDispatchV2,
    aliases: SlackAliasBinding,
  ): Promise<CandidateDeliveryV2> {
    const envelope = projectSlackEnvelope(dispatch, aliases, this.options.botUserId);
    const result = await this.options.adapter.dispatch(envelope);
    return {
      attempt: result.attempt,
      handled: result.handled,
      message: finalAssistantText(result),
      output: result,
    };
  }

  private async dispatchWake(
    dispatch: CandidateTransportDispatchV2,
    aliases: SlackAliasBinding,
  ): Promise<CandidateDeliveryV2> {
    const event = dispatch.candidate_event;
    if (event.event !== "wake") throw new Error("wake_dispatch_invalid");
    const port = this.options.wakePort;
    if (!port) throw new Error("wake_port_unavailable");
    const claim = await port.claim({
      at: event.at,
      commitment_ref: event.commitment_ref!,
      occurrence_ref: event.occurrence_ref!,
      thread_ref: event.aliases.thread_ref,
    });
    validateWakeClaim(claim, event);
    const posted = await port.post({
      channel_id: aliases.channelId,
      claim,
      team_id: aliases.teamId,
      thread_ts: aliases.threadTs,
    });
    validateWakePost(posted, claim);
    await port.acknowledge({ claim, destination_receipt: posted.destination_receipt });
    return {
      attempt: posted.attempt,
      handled: true,
      message: posted.message,
      output: { claim, posted },
    };
  }
}

interface CandidateDeliveryV2 {
  attempt: number;
  handled: boolean;
  message?: string;
  output: unknown;
}

function parseDispatch(input: unknown): CandidateTransportDispatchV2 {
  const dispatch = exactRecord(input, ["candidate_event", "schema_version"], "dispatch_shape_invalid");
  if (dispatch.schema_version !== DISPATCH_SCHEMA_VERSION) {
    throw new Error("dispatch_schema_unsupported");
  }
  const event = record(dispatch.candidate_event, "candidate_event_invalid");
  const eventName = event.event;
  if (!isEventName(eventName)) throw new Error("candidate_event_unsupported");
  const eventKeys: Record<CandidateEventName, readonly string[]> = {
    authorize: ["aliases", "approval_ref", "at", "event", "input_digest", "tool_id"],
    correction: ["aliases", "at", "event", "message", "replaces_request_id"],
    message: ["aliases", "at", "event", "message"],
    open_thread: ["aliases", "at", "event", "message"],
    wake: ["aliases", "at", "commitment_ref", "event", "occurrence_ref"],
  };
  exactKeys(event, eventKeys[eventName], "candidate_event_shape_invalid");
  const aliases = exactRecord(event.aliases, [
    "actor_ref",
    "context_scope_ref",
    "delivery_ref",
    "request_id",
    "tenant_id",
    "thread_ref",
  ], "candidate_aliases_invalid");
  const parsed = { ...event, aliases } as unknown as CandidateTransportDispatchV2["candidate_event"];
  requireRfc3339(parsed.at);
  if (eventName === "message" || eventName === "open_thread" || eventName === "correction") {
    requireText(parsed.message);
  }
  if (eventName === "correction") {
    matchAlias(
      parsed.replaces_request_id,
      /^slack-event:\/\/(Ev[A-Za-z0-9]{1,62})$/u,
      "replaced_request_alias_invalid",
    );
  }
  if (eventName === "authorize") {
    requireAliasText(parsed.approval_ref);
    requireAliasText(parsed.tool_id);
    requireSha256(parsed.input_digest);
  }
  if (eventName === "wake") {
    requireAliasText(parsed.commitment_ref);
    requireAliasText(parsed.occurrence_ref);
  }
  return {
    schema_version: DISPATCH_SCHEMA_VERSION,
    candidate_event: parsed,
  };
}

function parseAliases(aliases: CandidateAliasesV2, at: string): SlackAliasBinding {
  const teamId = matchAlias(aliases.tenant_id, /^slack-workspace:\/\/([A-Z][A-Z0-9]{1,31})$/u, "tenant_alias_invalid")[1]!;
  const eventId = matchAlias(aliases.request_id, /^slack-event:\/\/(Ev[A-Za-z0-9]{1,62})$/u, "request_alias_invalid")[1]!;
  const thread = matchAlias(
    aliases.thread_ref,
    /^slack-thread:\/\/([A-Z][A-Z0-9]{1,31})\/([A-Z][A-Z0-9]{1,31})\/(\d{1,12}\.\d{6})$/u,
    "thread_alias_invalid",
  );
  const userId = matchAlias(aliases.actor_ref, /^slack-user:\/\/([A-Z][A-Z0-9]{1,31})$/u, "actor_alias_invalid")[1]!;
  const context = matchAlias(
    aliases.context_scope_ref,
    /^slack-context-scope:\/\/([A-Z][A-Z0-9]{1,31})\/([A-Z][A-Z0-9]{1,31})$/u,
    "context_alias_invalid",
  );
  if (thread[1] !== teamId || context[1] !== teamId || context[2] !== thread[2]) {
    throw new Error("candidate_alias_binding_mismatch");
  }
  if (aliases.delivery_ref !== `slack-delivery://${aliases.request_id}`) {
    throw new Error("delivery_alias_invalid");
  }
  return {
    channelId: thread[2]!,
    eventId,
    eventTs: rfc3339ToSlackTimestamp(at),
    teamId,
    threadTs: thread[3]!,
    userId,
  };
}

function projectSlackEnvelope(
  dispatch: CandidateTransportDispatchV2,
  aliases: SlackAliasBinding,
  botUserId: string,
): SlackTransportEnvelope {
  const event = dispatch.candidate_event;
  if (event.event === "wake") throw new Error("wake_dispatch_requires_port");
  if (event.event === "open_thread") {
    if (aliases.eventTs !== aliases.threadTs) throw new Error("open_thread_timestamp_mismatch");
    return slackEnvelope(aliases, botUserId, {
      channel: aliases.channelId,
      text: `<@${botUserId}> ${event.message}`,
      ts: aliases.eventTs,
      type: "app_mention",
      user: aliases.userId,
    });
  }
  if (compareSlackTimestamps(aliases.eventTs, aliases.threadTs) <= 0) {
    throw new Error("thread_event_timestamp_invalid");
  }
  const text = event.event === "authorize"
    ? `approve ${approvalCommandCode(event.approval_ref!)}`
    : event.message!;
  return slackEnvelope(aliases, botUserId, {
    channel: aliases.channelId,
    text,
    thread_ts: aliases.threadTs,
    ts: aliases.eventTs,
    type: "message",
    user: aliases.userId,
  });
}

function slackEnvelope(
  aliases: SlackAliasBinding,
  botUserId: string,
  event: SlackTransportEnvelope["event"],
): SlackTransportEnvelope {
  return {
    authorizations: [{ user_id: botUserId }],
    event,
    event_id: aliases.eventId,
    schema_version: SLACK_ENVELOPE_SCHEMA_VERSION,
    team_id: aliases.teamId,
    type: "event_callback",
  };
}

function finalAssistantText(result: SlackTransportResult): string | undefined {
  const update = [...result.operations].reverse().find((operation) => operation.method === "chat.update");
  const text = update?.request.text.trim();
  return text ? text : undefined;
}

function validateWakeClaim(
  claim: TransportWakeClaimV2,
  event: CandidateTransportDispatchV2["candidate_event"],
): void {
  if (
    !claim.claim_ref.trim()
    || claim.commitment_ref !== event.commitment_ref
    || claim.occurrence_ref !== event.occurrence_ref
    || claim.thread_ref !== event.aliases.thread_ref
  ) throw new Error("wake_claim_binding_invalid");
  requireText(claim.markdown);
  requireSha256(claim.payload_digest);
}

function validateWakePost(
  posted: TransportWakePostReceiptV2,
  claim: TransportWakeClaimV2,
): void {
  if (
    !Number.isSafeInteger(posted.attempt)
    || posted.attempt <= 0
    || !posted.destination_receipt.trim()
    || posted.message !== claim.markdown
  ) throw new Error("wake_post_receipt_invalid");
}

function digestJson(value: unknown): `sha256:${string}` {
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
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new Error("canonical_json_invalid");
  return serialized;
}

function rfc3339ToSlackTimestamp(value: string): string {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/u.exec(value);
  if (!match) throw new Error("candidate_event_time_invalid");
  const seconds = Date.parse(`${match[1]}${match[3]}`) / 1_000;
  if (!Number.isSafeInteger(seconds)) throw new Error("candidate_event_time_invalid");
  const micros = (match[2] ?? "").padEnd(6, "0").slice(0, 6);
  return `${seconds}.${micros}`;
}

function compareSlackTimestamps(left: string, right: string): number {
  const value = (timestamp: string) => {
    const [seconds, micros] = timestamp.split(".");
    return BigInt(seconds!) * 1_000_000n + BigInt(micros!);
  };
  const difference = value(left) - value(right);
  return difference < 0n ? -1 : difference > 0n ? 1 : 0;
}

function requireRfc3339(value: unknown): asserts value is string {
  if (typeof value !== "string") throw new Error("candidate_event_time_invalid");
  rfc3339ToSlackTimestamp(value);
}

function requireText(value: unknown): asserts value is string {
  if (typeof value !== "string" || !value.trim() || Buffer.byteLength(value, "utf8") > 16 * 1024) {
    throw new Error("candidate_message_invalid");
  }
}

function requireAliasText(value: unknown): asserts value is string {
  if (typeof value !== "string" || !value.trim()) throw new Error("candidate_alias_invalid");
  if (/blackbox|eval|holdout|scenario|candidate/iu.test(value)) {
    throw new Error("candidate_alias_discloses_evaluator_state");
  }
}

function requireSha256(value: unknown): asserts value is `sha256:${string}` {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(value)) {
    throw new Error("candidate_input_digest_invalid");
  }
}

function matchAlias(value: unknown, pattern: RegExp, code: string): RegExpExecArray {
  requireAliasText(value);
  const match = pattern.exec(value);
  if (!match) throw new Error(code);
  return match;
}

function requireSlackId(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !/^[A-Z][A-Z0-9]{1,31}$/u.test(value)) {
    throw new Error(`The Slack ${label} ID is invalid.`);
  }
}

function validateSigner(signer: TransportReceiptSignerV2["signer"]): void {
  if (
    !signer.principal_ref.trim()
    || !signer.key_ref.trim()
    || !["aws_kms_ecdsa_sha256", "ed25519"].includes(signer.algorithm)
  ) throw new Error("receipt_signer_invalid");
}

function requireCanonicalBase64(value: string): void {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    throw new Error("receipt_signature_invalid");
  }
}

function isEventName(value: unknown): value is CandidateEventName {
  return ["authorize", "correction", "message", "open_thread", "wake"].includes(String(value));
}

function exactRecord(value: unknown, keys: readonly string[], code: string): Record<string, unknown> {
  const item = record(value, code);
  exactKeys(item, keys, code);
  return item;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], code: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(code);
  }
}

function record(value: unknown, code: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(code);
  return value as Record<string, unknown>;
}

function errorCode(error: unknown): string {
  return error instanceof Error && /^[a-z0-9_]+$/u.test(error.message)
    ? error.message
    : "dispatch_invalid";
}

function errorResponse(status: number, error: string): Response {
  return Response.json({ error }, { status });
}
