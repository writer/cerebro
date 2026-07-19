import { createHash } from "node:crypto";
import type { RunReceiptV1 } from "@writer/cerebro-sdk";
import type { DeliveryCoordinator } from "../delivery/coordinator.js";
import { stableIdentity } from "../delivery/coordinator.js";
import type {
  BindSlackThreadRequest,
  SlackThreadBindingCoordinator,
} from "../thread-binding.js";
import type {
  AssistanceBindingResult,
  AssistanceOutcomeV1,
  AssistanceReplyResult,
  AssistanceRequestInput,
  AssistanceRequestResult,
  AssistanceRequestV1,
  BindAssistanceThreadInput,
  NormalizedAssistanceReply,
} from "./contracts.js";
import type {
  AssistanceClockPort,
  AssistanceRefinementPort,
  AssistanceRunReceiptPort,
  DurableAssistancePort,
} from "./ports.js";

export class AssistanceConflictError extends Error {}
export class AssistanceInputError extends Error {}
export class AssistanceReplyRejectedError extends Error {}

export interface AssistanceCoordinatorOptions {
  clock: AssistanceClockPort;
  delivery: Pick<DeliveryCoordinator, "plan">;
  max_outcome_bytes: number;
  refinements: AssistanceRefinementPort;
  runs: AssistanceRunReceiptPort;
  store: DurableAssistancePort;
  threads: Pick<SlackThreadBindingCoordinator, "bind" | "resume">;
}

export class AssistanceCoordinator {
  private readonly clock: AssistanceClockPort;
  private readonly delivery: Pick<DeliveryCoordinator, "plan">;
  private readonly maxOutcomeBytes: number;
  private readonly refinements: AssistanceRefinementPort;
  private readonly runs: AssistanceRunReceiptPort;
  private readonly store: DurableAssistancePort;
  private readonly threads: Pick<SlackThreadBindingCoordinator, "bind" | "resume">;

  constructor(options: AssistanceCoordinatorOptions) {
    if (!Number.isSafeInteger(options.max_outcome_bytes) || options.max_outcome_bytes < 1) {
      throw new AssistanceInputError("max_outcome_bytes must be a positive integer");
    }
    this.clock = options.clock;
    this.delivery = options.delivery;
    this.maxOutcomeBytes = options.max_outcome_bytes;
    this.refinements = options.refinements;
    this.runs = options.runs;
    this.store = options.store;
    this.threads = options.threads;
  }

  async request(input: AssistanceRequestInput): Promise<AssistanceRequestResult> {
    validateRequest(input, this.clock.now());
    const run = await this.requireAdmittedRun(input.request_run_id);
    if (
      run.binding_id !== input.binding_id ||
      run.subject_ref !== input.subject_ref ||
      run.tenant_id !== input.tenant_id
    ) {
      throw new AssistanceInputError("The assistance scope does not match the run.");
    }

    const now = this.clock.now().toISOString();
    const assistanceId = stableIdentity("assistance", [
      input.request_run_id,
      input.idempotency_key,
    ]);
    const request: AssistanceRequestV1 = {
      assistance_id: assistanceId,
      binding_id: input.binding_id,
      created_at: now,
      destination_ref: input.destination_ref,
      expires_at: input.expires_at,
      idempotency_key: stableIdentity("assistance-request", [
        input.request_run_id,
        input.idempotency_key,
      ]),
      installation_id: input.installation_id,
      intended_actor_ref: input.intended_actor_ref,
      payload_digest: input.payload_digest,
      payload_ref: input.payload_ref,
      request_run_id: input.request_run_id,
      revision: 1,
      schema_version: "assistance-request/v1",
      status: "requested",
      subject_ref: run.subject_ref,
      tenant_id: run.tenant_id,
      updated_at: now,
    };
    const committed = await this.store.putIfAbsent({
      payload_fingerprint: requestFingerprint(input),
      request,
    });

    const delivery = await this.delivery.plan({
      delivery_key: `assistance:${assistanceId}`,
      destination_ref: input.destination_ref,
      max_attempts: input.max_delivery_attempts,
      parts: [{ payload_digest: input.payload_digest, payload_ref: input.payload_ref }],
      run_id: input.request_run_id,
    });
    const attached = await this.store.attachDelivery({
      assistance_id: assistanceId,
      delivery_id: delivery.receipt.delivery_id,
      expected_revision: committed.request.revision,
      updated_at: this.clock.now().toISOString(),
    });
    return { delivery: delivery.receipt, request: attached };
  }

  async bindThread(
    assistanceId: string,
    input: BindAssistanceThreadInput,
  ): Promise<AssistanceBindingResult> {
    const request = await this.requireRequest(assistanceId);
    const now = this.clock.now().toISOString();
    if (Date.parse(request.expires_at) <= Date.parse(now)) {
      await this.store.expire(request.assistance_id, request.revision, now);
      throw new AssistanceInputError("The assistance request has expired.");
    }
    if (request.delivery_id === undefined) {
      throw new AssistanceInputError("Assistance delivery is not durable yet.");
    }
    validateBindRequest(request, input.bind);
    if (input.delivered.delivery_id !== request.delivery_id) {
      throw new AssistanceInputError("The delivered receipt does not match assistance.");
    }

    const binding = await this.threads.bind(input.bind, input.delivered);
    const attached = await this.store.attachThreadBinding({
      assistance_id: assistanceId,
      expected_revision: request.revision,
      thread_binding_id: binding.binding.thread_binding_id,
      thread_binding_updated_at: binding.binding.updated_at,
      updated_at: now,
    });
    return { binding: binding.binding, request: attached };
  }

  async acceptReply(
    reply: NormalizedAssistanceReply,
  ): Promise<AssistanceReplyResult> {
    validateReplyShape(reply, this.maxOutcomeBytes);
    const request = await this.requireRequest(reply.assistance_id);
    const now = this.clock.now().toISOString();
    if (Date.parse(request.expires_at) <= Date.parse(now)) {
      await this.store.expire(request.assistance_id, request.revision, now);
      throw new AssistanceReplyRejectedError("The assistance request has expired.");
    }
    if (
      request.status !== "awaiting_reply" &&
      request.status !== "outcome_recorded" &&
      request.status !== "refinement_admitted"
    ) {
      throw new AssistanceReplyRejectedError("The assistance request is not awaiting a reply.");
    }
    if (reply.actor_kind !== "human" || reply.subtype !== undefined) {
      throw new AssistanceReplyRejectedError("Only a direct human reply is accepted.");
    }
    if (reply.action_classification !== "informational") {
      throw new AssistanceReplyRejectedError("Action-like assistance replies are not accepted.");
    }
    if (reply.actor_ref !== request.intended_actor_ref) {
      throw new AssistanceReplyRejectedError("The reply actor does not match the request.");
    }
    if (reply.binding_id !== request.binding_id) {
      throw new AssistanceReplyRejectedError("The reply binding does not match the request.");
    }
    if (
      reply.installation_id !== request.installation_id ||
      reply.tenant_id !== request.tenant_id
    ) {
      throw new AssistanceReplyRejectedError("The reply installation scope does not match the request.");
    }

    const activeBinding = await this.threads.resume(threadIdentity(reply));
    if (
      activeBinding === undefined ||
      request.thread_binding_id === undefined ||
      activeBinding.thread_binding_id !== request.thread_binding_id ||
      activeBinding.updated_at !== request.thread_binding_updated_at ||
      activeBinding.installation_id !== request.installation_id ||
      activeBinding.subject_ref !== request.subject_ref ||
      activeBinding.tenant_id !== request.tenant_id
    ) {
      throw new AssistanceReplyRejectedError("The reply is not on the exact active thread.");
    }

    const replyRun = await this.requireAdmittedRun(reply.reply_run_id);
    if (
      replyRun.binding_id !== request.binding_id ||
      replyRun.input_digest !== reply.payload_digest ||
      replyRun.run_kind !== "interactive" ||
      replyRun.subject_ref !== request.subject_ref ||
      replyRun.tenant_id !== request.tenant_id
    ) {
      throw new AssistanceReplyRejectedError("The admitted reply receipt does not match the reply.");
    }

    const outcome = outcomeForReply(request, reply, now);
    const outcomeRecorded = await this.store.recordOutcome({
      assistance_id: request.assistance_id,
      expected_revision: request.revision,
      outcome,
      updated_at: now,
    });
    const refinement = await this.refinements.admit({
      assistance_id: request.assistance_id,
      idempotency_key: stableIdentity("assistance-refinement", [
        request.assistance_id,
        reply.reply_run_id,
      ]),
      outcome_digest: reply.outcome_digest,
      outcome_ref: reply.outcome_ref,
      reply_run_id: reply.reply_run_id,
    });
    const attached = await this.store.attachRefinement({
      assistance_id: request.assistance_id,
      expected_revision: outcomeRecorded.revision,
      refinement_ref: refinement.refinement_ref,
      updated_at: this.clock.now().toISOString(),
    });
    return { refinement, reply_run: replyRun, request: attached };
  }

  private async requireAdmittedRun(runId: string): Promise<RunReceiptV1> {
    const run = await this.runs.readRun(runId);
    if (
      run === undefined ||
      run.state === "cancelled" ||
      run.state === "completed" ||
      run.state === "delivering" ||
      run.state === "expired" ||
      run.state === "blocked"
    ) {
      throw new AssistanceReplyRejectedError("A durable admitted run is required.");
    }
    return run;
  }

  private async requireRequest(assistanceId: string): Promise<AssistanceRequestV1> {
    const request = await this.store.read(assistanceId);
    if (request === undefined) {
      throw new AssistanceInputError("The assistance request does not exist.");
    }
    return request;
  }
}

function validateRequest(input: AssistanceRequestInput, now: Date): void {
  for (const value of [
    input.binding_id,
    input.destination_ref,
    input.expires_at,
    input.idempotency_key,
    input.installation_id,
    input.intended_actor_ref,
    input.payload_digest,
    input.payload_ref,
    input.request_run_id,
    input.subject_ref,
    input.tenant_id,
  ]) {
    if (value.trim() === "") throw new AssistanceInputError("Assistance fields cannot be empty.");
  }
  if (
    !Number.isFinite(Date.parse(input.expires_at)) ||
    Date.parse(input.expires_at) <= now.getTime()
  ) {
    throw new AssistanceInputError("Assistance expiry must be in the future.");
  }
  if (!Number.isSafeInteger(input.max_delivery_attempts) || input.max_delivery_attempts < 1) {
    throw new AssistanceInputError("Delivery attempts must be a positive integer.");
  }
}

function validateBindRequest(
  request: AssistanceRequestV1,
  bind: BindSlackThreadRequest,
): void {
  if (
    bind.binding_id !== request.binding_id ||
    bind.delivery_id !== request.delivery_id ||
    bind.expires_at !== request.expires_at ||
    bind.installation_id !== request.installation_id ||
    bind.subject_ref !== request.subject_ref ||
    bind.tenant_id !== request.tenant_id
  ) {
    throw new AssistanceInputError("Thread binding does not match assistance intent.");
  }
}

function validateReplyShape(
  reply: NormalizedAssistanceReply,
  maxOutcomeBytes: number,
): void {
  for (const value of [
    reply.actor_ref,
    reply.app_id,
    reply.assistance_id,
    reply.binding_id,
    reply.conversation_id,
    reply.installation_id,
    reply.outcome_digest,
    reply.outcome_ref,
    reply.payload_digest,
    reply.reply_run_id,
    reply.tenant_id,
    reply.thread_id,
  ]) {
    if (value.trim() === "") throw new AssistanceReplyRejectedError("Reply fields cannot be empty.");
  }
  if (
    reply.redaction_state !== "redacted" ||
    !Number.isSafeInteger(reply.outcome_size_bytes) ||
    reply.outcome_size_bytes < 1 ||
    reply.outcome_size_bytes > maxOutcomeBytes
  ) {
    throw new AssistanceReplyRejectedError("The reply outcome is not bounded and redacted.");
  }
}

function threadIdentity(reply: NormalizedAssistanceReply) {
  return {
    app_id: reply.app_id,
    binding_id: reply.binding_id,
    conversation_id: reply.conversation_id,
    installation_id: reply.installation_id,
    tenant_id: reply.tenant_id,
    thread_id: reply.thread_id,
  };
}

function requestFingerprint(input: AssistanceRequestInput): string {
  return createHash("sha256")
    .update(JSON.stringify([
      input.binding_id,
      input.destination_ref,
      input.expires_at,
      input.idempotency_key,
      input.installation_id,
      input.intended_actor_ref,
      input.max_delivery_attempts,
      input.payload_digest,
      input.payload_ref,
      input.request_run_id,
      input.subject_ref,
      input.tenant_id,
    ]))
    .digest("hex");
}

function outcomeForReply(
  request: AssistanceRequestV1,
  reply: NormalizedAssistanceReply,
  recordedAt: string,
): AssistanceOutcomeV1 {
  if (request.outcome !== undefined) {
    if (
      request.outcome.outcome_digest !== reply.outcome_digest ||
      request.outcome.outcome_ref !== reply.outcome_ref ||
      request.outcome.reply_run_id !== reply.reply_run_id
    ) {
      throw new AssistanceConflictError("The reply outcome conflicts with the durable outcome.");
    }
    return request.outcome;
  }
  return {
    outcome_digest: reply.outcome_digest,
    outcome_ref: reply.outcome_ref,
    recorded_at: recordedAt,
    redaction_state: "redacted",
    reply_run_id: reply.reply_run_id,
  };
}
