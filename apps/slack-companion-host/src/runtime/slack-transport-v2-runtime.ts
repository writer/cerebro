import {
  createHash,
  createPrivateKey,
  sign,
  type KeyObject,
} from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import type { CerebroAskClient, RustPendingWakeDelivery } from "./cerebro-ask-client.js";
import type { OffSlackTransportAdapter } from "./off-slack-transport.js";
import type { FileSlackThreadRouteStore } from "./slack-thread-route-store.js";
import {
  type TransportAuthorityTelemetryPortV2,
  type TransportAuthorityTelemetrySnapshotV2,
  type TransportReceiptSignerV2,
  type TransportSequencePortV2,
  type TransportWakeClaimV2,
  type TransportWakePortV2,
} from "./slack-transport-v2-bridge.js";

const PRIVATE_ATTESTATION_SCHEMA = "private-slack-candidate-attestation/v1";
const PRIVATE_BINDINGS_SCHEMA = "private-slack-transport-v2-bindings/v1";
const SHA256 = /^sha256:[a-f0-9]{64}$/u;

export interface PrivateCandidateAttestationV2 {
  artifact_digest: string;
  expected_status: {
    build_commit_sha: string;
    build_tree_clean: true;
    model_config_sha256: string;
    model_id: string;
    model_provider: "amazon-bedrock";
    session_schema_version: "agent-session/v2";
  };
  principal_ref: string;
  schema_version: typeof PRIVATE_ATTESTATION_SCHEMA;
}

export interface PrivateWakeBindingV2 {
  commitment_ref: string;
  occurrence_ref: string;
  rust_commitment_ref: string;
  rust_request_id: string;
  scratchpad_thread_ref: string;
  slack_thread_ref: string;
}

interface PrivateTransportBindingsV2 {
  schema_version: typeof PRIVATE_BINDINGS_SCHEMA;
  sequence_bindings: Array<{ request_digest: string; sequence: number }>;
  wake_bindings: PrivateWakeBindingV2[];
}

interface AuthorityStatusV2 {
  agent_ready: true;
  agent_tool_calls_total: number;
  agent_turn_failures_total: number;
  agent_turns_total: number;
  authority: "rust";
  build_commit_sha: string;
  build_tree_clean: boolean;
  component: "slack-answer-authority";
  grounded_total: number;
  model_config_sha256: string;
  model_id: string;
  model_provider: string;
  question_authorized_total: number;
  question_rejected_total: number;
  rejected_total: number;
  requests_total: number;
  runtime_instance_ref: string;
  safe_refusal_total: number;
  schema_version: "slack-answer-authority-status/v2";
  session_schema_version: string;
  status: "ready";
  uptime_ms: number;
  version: string;
}

export async function loadPrivateCandidateAttestation(
  path: string,
): Promise<PrivateCandidateAttestationV2> {
  return parsePrivateCandidateAttestation(JSON.parse(await readFile(path, "utf8")));
}

export async function loadPrivateTransportBindings(path: string): Promise<{
  sequencePort: TransportSequencePortV2;
  wakeBindings: ReadonlyMap<string, PrivateWakeBindingV2>;
}> {
  const bindings = parsePrivateTransportBindings(JSON.parse(await readFile(path, "utf8")));
  const sequences = new Map(bindings.sequence_bindings.map((binding) => [
    binding.request_digest,
    binding.sequence,
  ]));
  const wakes = new Map(bindings.wake_bindings.map((binding) => [
    wakeBindingKey(binding.slack_thread_ref, binding.commitment_ref, binding.occurrence_ref),
    binding,
  ]));
  return {
    sequencePort: {
      sequenceForRequest(requestDigest) {
        const sequence = sequences.get(requestDigest);
        if (sequence === undefined) throw new Error("The dispatch has no sealed sequence binding.");
        return sequence;
      },
    },
    wakeBindings: wakes,
  };
}

export async function loadEd25519TransportSigner(input: {
  candidatePrincipalRef: string;
  keyPath: string;
  keyRef: string;
  principalRef: string;
}): Promise<TransportReceiptSignerV2> {
  if (
    !input.principalRef.trim()
    || !input.keyRef.trim()
    || input.principalRef === input.candidatePrincipalRef
  ) throw new Error("The transport signer identity is not separate from the candidate runtime.");
  const metadata = await stat(input.keyPath);
  if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) {
    throw new Error("The transport signing key must be a private regular file.");
  }
  const key = createPrivateKey(await readFile(input.keyPath));
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("The transport signing key must be Ed25519.");
  }
  return new Ed25519TransportSigner(key, input.keyRef, input.principalRef);
}

class Ed25519TransportSigner implements TransportReceiptSignerV2 {
  readonly signer: TransportReceiptSignerV2["signer"];

  constructor(
    private readonly key: KeyObject,
    keyRef: string,
    principalRef: string,
  ) {
    this.signer = { algorithm: "ed25519", key_ref: keyRef, principal_ref: principalRef };
  }

  async signPayloadDigest(payloadDigest: `sha256:${string}`): Promise<string> {
    return sign(null, Buffer.from(payloadDigest, "utf8"), this.key).toString("base64");
  }
}

export class ChallengedAuthorityTelemetryPortV2 implements TransportAuthorityTelemetryPortV2 {
  private runtimeInstanceRef?: string;
  private priorUptimeMs?: number;

  constructor(
    private readonly authorityUrl: string,
    private readonly expected: PrivateCandidateAttestationV2,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async challenge(): Promise<AuthorityStatusV2> {
    const response = await this.fetchImpl(`${this.authorityUrl}/v1/status`, {
      headers: { Accept: "application/json", "Cache-Control": "no-store" },
      method: "GET",
    });
    if (!response.ok) throw new Error("The Rust authority status challenge failed.");
    const status = parseAuthorityStatus(await response.json());
    const expected = this.expected.expected_status;
    if (
      status.build_commit_sha !== expected.build_commit_sha
      || status.build_tree_clean !== expected.build_tree_clean
      || status.model_provider !== expected.model_provider
      || status.model_id !== expected.model_id
      || status.model_config_sha256 !== expected.model_config_sha256
      || status.session_schema_version !== expected.session_schema_version
    ) throw new Error("The live Rust authority does not match the sealed candidate attestation.");
    if (this.runtimeInstanceRef !== undefined && status.runtime_instance_ref !== this.runtimeInstanceRef) {
      throw new Error("The Rust authority instance changed during the sealed execution.");
    }
    if (this.priorUptimeMs !== undefined && status.uptime_ms < this.priorUptimeMs) {
      throw new Error("The Rust authority uptime moved backwards during the sealed execution.");
    }
    this.runtimeInstanceRef = status.runtime_instance_ref;
    this.priorUptimeMs = status.uptime_ms;
    return status;
  }

  async snapshot(): Promise<TransportAuthorityTelemetrySnapshotV2> {
    const status = await this.challenge();
    return {
      completed_turn_count: status.agent_turns_total,
      runtime_instance_ref: status.runtime_instance_ref,
      tool_call_count: status.agent_tool_calls_total,
    };
  }
}

export class BoundRustWakePortV2 implements TransportWakePortV2 {
  private readonly claimed = new Map<string, RustPendingWakeDelivery>();

  constructor(
    private readonly agent: CerebroAskClient,
    private readonly adapter: OffSlackTransportAdapter,
    private readonly routes: FileSlackThreadRouteStore,
    private readonly bindings: ReadonlyMap<string, PrivateWakeBindingV2>,
    private readonly workerRef: string,
    private readonly botUserId: string,
  ) {}

  async claim(input: {
    at: string;
    commitment_ref: string;
    occurrence_ref: string;
    thread_ref: string;
  }): Promise<TransportWakeClaimV2> {
    const binding = this.bindings.get(wakeBindingKey(
      input.thread_ref,
      input.commitment_ref,
      input.occurrence_ref,
    ));
    if (!binding) throw new Error("The wake has no private Slack-to-Rust binding.");
    const route = await this.routes.read(binding.scratchpad_thread_ref);
    if (!route || slackThreadRef(route.teamId, route.channelId, route.threadTs) !== input.thread_ref) {
      throw new Error("The wake's private Slack thread route is unavailable or changed.");
    }
    const execution = await this.agent.runDueWake({
      signal: AbortSignal.timeout(950_000),
      workerRef: this.workerRef,
    });
    if (
      !execution
      || execution.commitment_ref !== binding.rust_commitment_ref
      || execution.request_id !== binding.rust_request_id
    ) throw new Error("The Rust wake execution does not match its private binding.");
    const delivery = await this.agent.claimPendingWakeDelivery({
      signal: AbortSignal.timeout(20_000),
      workerRef: this.workerRef,
    });
    if (
      !delivery
      || delivery.lease.commitment_ref !== binding.rust_commitment_ref
      || delivery.lease.request_id !== binding.rust_request_id
      || delivery.thread_ref !== binding.scratchpad_thread_ref
      || delivery.mode !== "send"
      || !SHA256.test(delivery.lease.payload_digest)
    ) throw new Error("The Rust wake delivery does not match its private binding.");
    const claimRef = delivery.lease.delivery_attempt_ref;
    if (this.claimed.has(claimRef)) throw new Error("The Rust wake claim was reused.");
    this.claimed.set(claimRef, delivery);
    return {
      claim_ref: claimRef,
      commitment_ref: input.commitment_ref,
      markdown: delivery.markdown,
      occurrence_ref: input.occurrence_ref,
      payload_digest: delivery.lease.payload_digest as `sha256:${string}`,
      thread_ref: input.thread_ref,
    };
  }

  async post(input: {
    channel_id: string;
    claim: TransportWakeClaimV2;
    team_id: string;
    thread_ts: string;
  }): Promise<{ attempt: number; destination_receipt: string; message: string }> {
    const delivery = this.claimed.get(input.claim.claim_ref);
    if (!delivery) throw new Error("The wake claim is not held by this transport.");
    this.adapter.slack.bindBotUser(this.botUserId);
    const wakeClient = this.adapter.slack.client as unknown as {
      chat: { postMessage(input: {
        channel: string;
        metadata: { event_payload: Record<string, string>; event_type: string };
        text: string;
        thread_ts: string;
      }): Promise<{ ts?: string }> };
    };
    const posted = await wakeClient.chat.postMessage({
      channel: input.channel_id,
      metadata: {
        event_payload: {
          delivery_attempt_ref: delivery.lease.delivery_attempt_ref,
          delivery_ref: delivery.lease.delivery_ref,
          payload_digest: delivery.lease.payload_digest,
        },
        event_type: "cerebro_wake_delivery",
      },
      text: delivery.markdown,
      thread_ts: input.thread_ts,
    });
    if (!posted.ts) throw new Error("The off-Slack transport returned no wake destination receipt.");
    return {
      attempt: delivery.lease.fence,
      destination_receipt: `slack-message://sha256/${digest(`${input.channel_id}:${posted.ts}`)}`,
      message: delivery.markdown,
    };
  }

  async acknowledge(input: {
    claim: TransportWakeClaimV2;
    destination_receipt: string;
  }): Promise<void> {
    const delivery = this.claimed.get(input.claim.claim_ref);
    if (!delivery) throw new Error("The wake claim is not held by this transport.");
    await this.agent.recordWakeDelivery({
      deliveredAt: new Date().toISOString(),
      delivery,
      destinationReceipt: input.destination_receipt,
      signal: AbortSignal.timeout(20_000),
    });
    this.claimed.delete(input.claim.claim_ref);
  }
}

function parsePrivateCandidateAttestation(value: unknown): PrivateCandidateAttestationV2 {
  const record = exactRecord(value, ["artifact_digest", "expected_status", "principal_ref", "schema_version"]);
  const status = exactRecord(record.expected_status, [
    "build_commit_sha",
    "build_tree_clean",
    "model_config_sha256",
    "model_id",
    "model_provider",
    "session_schema_version",
  ]);
  if (
    record.schema_version !== PRIVATE_ATTESTATION_SCHEMA
    || !SHA256.test(requiredText(record.artifact_digest))
    || !requiredText(record.principal_ref)
    || !/^[a-f0-9]{40}$/u.test(requiredText(status.build_commit_sha))
    || status.build_tree_clean !== true
    || !SHA256.test(requiredText(status.model_config_sha256))
    || status.model_provider !== "amazon-bedrock"
    || !/^.+anthropic\.claude-opus-[A-Za-z0-9._:-]+$/u.test(requiredText(status.model_id))
    || status.session_schema_version !== "agent-session/v2"
  ) throw new Error("The private candidate attestation is invalid or is not exact Opus.");
  return record as unknown as PrivateCandidateAttestationV2;
}

function parsePrivateTransportBindings(value: unknown): PrivateTransportBindingsV2 {
  const record = exactRecord(value, ["schema_version", "sequence_bindings", "wake_bindings"]);
  if (
    record.schema_version !== PRIVATE_BINDINGS_SCHEMA
    || !Array.isArray(record.sequence_bindings)
    || !Array.isArray(record.wake_bindings)
    || record.sequence_bindings.length === 0
  ) throw new Error("The private transport bindings are invalid.");
  const sequences = record.sequence_bindings.map((value) => {
    const binding = exactRecord(value, ["request_digest", "sequence"]);
    if (!SHA256.test(requiredText(binding.request_digest)) || !positiveInteger(binding.sequence)) {
      throw new Error("A private sequence binding is invalid.");
    }
    return binding as unknown as PrivateTransportBindingsV2["sequence_bindings"][number];
  });
  const wakes = record.wake_bindings.map((value) => {
    const binding = exactRecord(value, [
      "commitment_ref",
      "occurrence_ref",
      "rust_commitment_ref",
      "rust_request_id",
      "scratchpad_thread_ref",
      "slack_thread_ref",
    ]);
    if (
      Object.values(binding).some((item) => !requiredText(item))
      || !/^slack-scratchpad:\/\/sha256\/[a-f0-9]{64}$/u.test(requiredText(binding.scratchpad_thread_ref))
      || !/^slack-thread:\/\/[A-Z][A-Z0-9]{1,31}\/[A-Z][A-Z0-9]{1,31}\/\d{1,12}\.\d{6}$/u.test(requiredText(binding.slack_thread_ref))
    ) throw new Error("A private wake binding is invalid.");
    return binding as unknown as PrivateWakeBindingV2;
  });
  if (
    new Set(sequences.map((binding) => binding.request_digest)).size !== sequences.length
    || new Set(sequences.map((binding) => binding.sequence)).size !== sequences.length
    || new Set(wakes.map((binding) => wakeBindingKey(
      binding.slack_thread_ref,
      binding.commitment_ref,
      binding.occurrence_ref,
    ))).size !== wakes.length
  ) throw new Error("The private transport bindings are not one-to-one.");
  return {
    schema_version: PRIVATE_BINDINGS_SCHEMA,
    sequence_bindings: sequences,
    wake_bindings: wakes,
  };
}

function parseAuthorityStatus(value: unknown): AuthorityStatusV2 {
  const status = exactRecord(value, [
    "agent_ready", "agent_tool_calls_total", "agent_turn_failures_total", "agent_turns_total",
    "authority", "build_commit_sha", "build_tree_clean", "component", "grounded_total",
    "model_config_sha256", "model_id", "model_provider", "question_authorized_total",
    "question_rejected_total", "rejected_total", "requests_total", "runtime_instance_ref",
    "safe_refusal_total", "schema_version", "session_schema_version", "status", "uptime_ms", "version",
  ]);
  if (
    status.schema_version !== "slack-answer-authority-status/v2"
    || status.agent_ready !== true
    || status.authority !== "rust"
    || status.component !== "slack-answer-authority"
    || status.status !== "ready"
    || !/^slack-authority-instance:\/\/sha256\/[a-f0-9]{64}$/u.test(requiredText(status.runtime_instance_ref))
    || [
      status.agent_tool_calls_total,
      status.agent_turn_failures_total,
      status.agent_turns_total,
      status.grounded_total,
      status.question_authorized_total,
      status.question_rejected_total,
      status.rejected_total,
      status.requests_total,
      status.safe_refusal_total,
      status.uptime_ms,
    ].some((counter) => !nonnegativeInteger(counter))
  ) throw new Error("The Rust authority status response is invalid.");
  return status as unknown as AuthorityStatusV2;
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("A private transport record is invalid.");
  }
  const record = value as Record<string, unknown>;
  if (JSON.stringify(Object.keys(record).sort()) !== JSON.stringify([...keys].sort())) {
    throw new Error("A private transport record has an unexpected shape.");
  }
  return record;
}

function wakeBindingKey(threadRef: string, commitmentRef: string, occurrenceRef: string): string {
  return JSON.stringify([threadRef, commitmentRef, occurrenceRef]);
}

function slackThreadRef(teamId: string, channelId: string, threadTs: string): string {
  return `slack-thread://${teamId}/${channelId}/${threadTs}`;
}

function requiredText(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function nonnegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
