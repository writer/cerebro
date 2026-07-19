import type {
  AdmissionPolicy,
  RejectedSlackAcknowledgement,
  RunReceiptV1,
  SlackAdmissionResult,
  SlackIngressEnvelope,
} from "./contracts.js";
import { admissionStatus } from "./lifecycle.js";
import type {
  AdmissionContextPort,
  ClockPort,
  DurableAdmissionPort,
  IdentityPort,
} from "./ports.js";

export interface SlackAdmissionControllerOptions {
  clock: ClockPort;
  context: AdmissionContextPort;
  identities: IdentityPort;
  policy: AdmissionPolicy;
  store: DurableAdmissionPort;
}

export class SlackAdmissionController {
  private readonly clock: ClockPort;
  private readonly context: AdmissionContextPort;
  private readonly identities: IdentityPort;
  private readonly policy: AdmissionPolicy;
  private readonly store: DurableAdmissionPort;

  constructor(options: SlackAdmissionControllerOptions) {
    this.clock = options.clock;
    this.context = options.context;
    this.identities = options.identities;
    this.policy = options.policy;
    this.store = options.store;
  }

  async admit(envelope: SlackIngressEnvelope): Promise<SlackAdmissionResult> {
    assertEnvelope(envelope);

    const context = await this.context.read(envelope.binding_id);
    if (context.binding.binding_id !== envelope.binding_id) {
      throw new Error("admission context returned a different binding");
    }

    const status = admissionStatus(context, this.policy);
    if (!status.admit || status.accepted_status === undefined) {
      return rejection(status.message, status.retryable);
    }

    const admittedAt = this.clock.now().toISOString();
    const receipt: RunReceiptV1 = {
      admitted_at: admittedAt,
      binding_id: envelope.binding_id,
      idempotency_key: slackIdempotencyKey(envelope),
      input_digest: envelope.payload_digest,
      receipt_id: this.identities.nextReceiptId(),
      received_at: envelope.received_at,
      required_capabilities: envelope.required_capabilities,
      retention_policy_ref: envelope.retention_policy_ref,
      revision: 1,
      run_id: this.identities.nextRunId(),
      run_kind: envelope.run_kind,
      schema_version: "run-receipt/v1",
      state: "queued",
      subject_ref: envelope.subject_ref,
      tenant_id: envelope.tenant_id,
      updated_at: admittedAt,
    };

    try {
      const committed = await this.store.admitAndEnqueue({
        envelope,
        receipt,
        transitions: [
          { from: "received", to: "admitted" },
          { from: "admitted", to: "queued" },
        ],
      });
      return {
        acknowledgement_permitted: true,
        duplicate: !committed.created,
        message: status.message,
        retryable: false,
        run_id: committed.receipt.run_id,
        status: status.accepted_status,
      };
    } catch (error) {
      if (error instanceof IdempotencyConflictError) {
        return rejection(
          "This Slack event conflicts with an earlier accepted payload.",
          false,
        );
      }
      return rejection(
        "The request was not saved. Slack should retry this event.",
        true,
      );
    }
  }
}

export class IdempotencyConflictError extends Error {
  constructor() {
    super("idempotency key already belongs to a different payload");
  }
}

export function slackIdempotencyKey(envelope: SlackIngressEnvelope): string {
  return `slack:${envelope.app_id}:${envelope.tenant_id}:${envelope.event_id}`;
}

function rejection(
  message: string,
  retryable: boolean,
): RejectedSlackAcknowledgement {
  return {
    acknowledgement_permitted: false,
    duplicate: false,
    message,
    retryable,
    status: "rejected",
  };
}

function assertEnvelope(envelope: SlackIngressEnvelope): void {
  const required: Array<[string, string]> = [
    ["app_id", envelope.app_id],
    ["binding_id", envelope.binding_id],
    ["conversation_id", envelope.conversation_id],
    ["event_id", envelope.event_id],
    ["event_type", envelope.event_type],
    ["payload_digest", envelope.payload_digest],
    ["payload_ref", envelope.payload_ref],
    ["received_at", envelope.received_at],
    ["retention_policy_ref", envelope.retention_policy_ref],
    ["subject_ref", envelope.subject_ref],
    ["tenant_id", envelope.tenant_id],
    ["thread_id", envelope.thread_id],
  ];
  for (const [field, value] of required) {
    if (value.trim() === "") {
      throw new Error(`${field} is required`);
    }
  }
  if (Number.isNaN(Date.parse(envelope.received_at))) {
    throw new Error("received_at must be an ISO date-time");
  }
}
