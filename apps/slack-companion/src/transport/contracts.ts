import type { CapabilityRequirement, RunKind } from "@writer/cerebro-sdk";
import type {
  SlackAdmissionResult,
  SlackIngressEnvelope,
} from "../contracts.js";

export type SlackIngressMode =
  | "events_api"
  | "interactive"
  | "slash_commands"
  | "socket_mode";

export interface SlackTransportRoute {
  binding_id: string;
  conversation_id?: string;
  required_capabilities: CapabilityRequirement[];
  retention_policy_ref: string;
  run_kind: RunKind;
  tenant_id: string;
  thread_id?: string;
}

export interface SlackEventsApiRequest {
  raw_body: Uint8Array;
  received_at: string;
  request_signature: string;
  request_timestamp: string;
  route: SlackTransportRoute;
}

export interface SlackSignedInvocationRequest {
  raw_body: Uint8Array;
  received_at: string;
  request_signature: string;
  request_timestamp: string;
  route: SlackTransportRoute;
}

export interface SlackUrlVerificationEnvelope {
  challenge: string;
  type: "url_verification";
}

export interface SlackEventCallbackEnvelope {
  api_app_id: string;
  event: Record<string, unknown> & { type: string };
  event_id: string;
  event_time: number;
  team_id: string;
  type: "event_callback";
}

export type SlackEventsApiEnvelope =
  | SlackEventCallbackEnvelope
  | SlackUrlVerificationEnvelope;

export interface SlackSocketModeEnvelope {
  accepts_response_payload?: boolean;
  envelope_id: string;
  payload: unknown;
  retry_attempt?: number;
  retry_reason?: string;
  type: "events_api" | "interactive" | "slash_commands";
}

export interface SlackSlashCommandEnvelope {
  api_app_id: string;
  channel_id: string;
  command: string;
  team_id: string;
  text: string;
  trigger_id: string;
  type: "slash_command";
  user_id: string;
}

export interface SlackInteractiveEnvelope {
  action_id: string;
  api_app_id: string;
  conversation_id?: string;
  interaction_type: string;
  team_id: string;
  thread_id?: string;
  trigger_id: string;
  type: "interactive";
  user_id: string;
}

export type SlackInvocationEnvelope =
  | SlackInteractiveEnvelope
  | SlackSlashCommandEnvelope;

export interface SlackSocketConnectionProof {
  connection_ref: string;
  generation: number;
}

export interface SlackSocketModeRequest {
  connection: SlackSocketConnectionProof;
  raw_body: Uint8Array;
  received_at: string;
  route: SlackTransportRoute;
}

export interface InboundPayloadCommit {
  idempotency_key: string;
  raw_body: Uint8Array;
  received_at: string;
  transport: SlackIngressMode;
}

export interface InboundPayloadReceipt {
  digest: string;
  payload_ref: string;
}

/**
 * Stores the exact inbound bytes before normalization or durable admission.
 * Implementations must return the original receipt for an idempotent retry.
 */
export interface DurableInboundPayloadPort {
  persist(commit: InboundPayloadCommit): Promise<InboundPayloadReceipt>;
}

export interface DurableSocketPresencePort {
  /** Confirms that the connection generation is current in durable state. */
  isActive(proof: SlackSocketConnectionProof): Promise<boolean>;
}

export interface SlackAdmissionPort {
  admit(envelope: SlackIngressEnvelope): Promise<SlackAdmissionResult>;
}

export interface SlackEventNormalizationInput {
  envelope: SlackEventCallbackEnvelope;
  payload: InboundPayloadReceipt;
  received_at: string;
  route: SlackTransportRoute;
}

export interface SlackEventNormalizer {
  normalize(input: SlackEventNormalizationInput): SlackIngressEnvelope;
}

export interface SlackInvocationNormalizationInput {
  envelope: SlackInvocationEnvelope;
  payload: InboundPayloadReceipt;
  received_at: string;
  route: SlackTransportRoute;
}

export interface SlackInvocationNormalizer {
  normalize(input: SlackInvocationNormalizationInput): SlackIngressEnvelope;
}

export interface EventsApiAcknowledgementCommand {
  body: "";
  kind: "events_api_ack";
  status_code: 200;
}

export interface SocketModeAcknowledgementCommand {
  envelope_id: string;
  kind: "socket_mode_ack";
}

export interface SignedInvocationAcknowledgementCommand {
  body: "";
  invocation: "interactive" | "slash_command";
  kind: "signed_invocation_ack";
  status_code: 200;
}

export interface UrlVerificationCommand {
  body: string;
  kind: "url_verification";
  status_code: 200;
}

export type SlackAcknowledgementCommand =
  | EventsApiAcknowledgementCommand
  | SignedInvocationAcknowledgementCommand
  | SocketModeAcknowledgementCommand;

export type TransportFailureStage =
  | "verification"
  | "parsing"
  | "persistence"
  | "normalization"
  | "admission";

export type SlackTransportOutcome =
  | {
      command: SlackAcknowledgementCommand;
      kind: "acknowledge";
      run_id: string;
    }
  | {
      command: UrlVerificationCommand;
      kind: "challenge";
    }
  | {
      kind: "no_acknowledgement";
      reason_code: string;
      retryable: boolean;
      stage: TransportFailureStage;
    };

export interface EventsApiHandlerDependencies {
  admission: SlackAdmissionPort;
  clock: { now(): Date };
  normalizer: SlackEventNormalizer;
  payloads: DurableInboundPayloadPort;
}

export interface SocketModeHandlerDependencies {
  admission: SlackAdmissionPort;
  invocation_normalizer?: SlackInvocationNormalizer;
  normalizer: SlackEventNormalizer;
  payloads: DurableInboundPayloadPort;
  presence: DurableSocketPresencePort;
}

export interface SignedInvocationHandlerDependencies {
  admission: SlackAdmissionPort;
  clock: { now(): Date };
  normalizer: SlackInvocationNormalizer;
  payloads: DurableInboundPayloadPort;
}
