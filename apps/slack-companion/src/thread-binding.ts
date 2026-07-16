import { createHash } from "node:crypto";
import type { DeliveryReceiptV1 } from "@writer/cerebro-sdk";

export type ThreadBindingState = "active" | "closed" | "expired";

export interface SlackThreadBindingV1 {
  app_id: string;
  binding_id: string;
  closed_at?: string;
  conversation_id: string;
  created_at: string;
  delivery_id: string;
  destination_receipt: string;
  destination_ref: string;
  expires_at: string;
  goal_ref: string;
  installation_id: string;
  schema_version: "slack-thread-binding/v1";
  state: ThreadBindingState;
  subject_ref: string;
  thread_binding_id: string;
  thread_id: string;
  updated_at: string;
}

export interface BindSlackThreadRequest {
  app_id: string;
  binding_id: string;
  conversation_id: string;
  delivery_id: string;
  destination_receipt: string;
  expires_at: string;
  goal_ref: string;
  installation_id: string;
  subject_ref: string;
  thread_id: string;
}

export interface ThreadBindingCommit {
  binding: SlackThreadBindingV1;
  payload_fingerprint: string;
}

export interface ThreadBindingCommitResult {
  binding: SlackThreadBindingV1;
  created: boolean;
}

export interface ThreadBindingStorePort {
  /** All writes are durable, idempotent, and compare the stored fingerprint. */
  close(threadBindingId: string, closedAt: string): Promise<SlackThreadBindingV1>;
  expire(threadBindingId: string, expiredAt: string): Promise<SlackThreadBindingV1>;
  putIfAbsent(commit: ThreadBindingCommit): Promise<ThreadBindingCommitResult>;
  read(threadBindingId: string): Promise<SlackThreadBindingV1 | undefined>;
}

export interface ThreadBindingClockPort {
  now(): Date;
}

export class ThreadBindingConflictError extends Error {}
export class ThreadBindingInputError extends Error {}

export class SlackThreadBindingCoordinator {
  constructor(
    private readonly clock: ThreadBindingClockPort,
    private readonly store: ThreadBindingStorePort,
  ) {}

  async bind(
    request: BindSlackThreadRequest,
    delivered: DeliveryReceiptV1,
  ): Promise<ThreadBindingCommitResult> {
    validateBindingRequest(request);
    if (delivered.delivery_id !== request.delivery_id) {
      throw new ThreadBindingInputError(
        "A thread can only bind to its own delivery.",
      );
    }
    const acceptedPart = delivered.parts.find(
      (part) =>
        part.state === "delivered" &&
        part.destination_receipt === request.destination_receipt,
    );
    if (acceptedPart === undefined) {
      throw new ThreadBindingInputError(
        "The destination receipt was not persisted on the delivery.",
      );
    }
    const now = this.clock.now().toISOString();
    if (Date.parse(request.expires_at) <= Date.parse(now)) {
      throw new ThreadBindingInputError("The thread binding expiry must be future.");
    }
    const threadBindingId = threadIdentity(request);
    const binding: SlackThreadBindingV1 = {
      app_id: request.app_id,
      binding_id: request.binding_id,
      conversation_id: request.conversation_id,
      created_at: now,
      delivery_id: request.delivery_id,
      destination_receipt: request.destination_receipt,
      destination_ref: delivered.destination_ref,
      expires_at: request.expires_at,
      goal_ref: request.goal_ref,
      installation_id: request.installation_id,
      schema_version: "slack-thread-binding/v1",
      state: "active",
      subject_ref: request.subject_ref,
      thread_binding_id: threadBindingId,
      thread_id: request.thread_id,
      updated_at: now,
    };
    return this.store.putIfAbsent({
      binding,
      payload_fingerprint: fingerprint(binding),
    });
  }

  async resume(
    request: Pick<
      BindSlackThreadRequest,
      "app_id" | "binding_id" | "conversation_id" | "installation_id" | "thread_id"
    >,
  ): Promise<SlackThreadBindingV1 | undefined> {
    if (Object.values(request).some((value) => value.length === 0)) {
      throw new ThreadBindingInputError("Thread identity fields cannot be empty.");
    }
    const id = threadIdentity(request);
    const binding = await this.store.read(id);
    if (binding === undefined || binding.state === "closed") {
      return undefined;
    }
    const now = this.clock.now().toISOString();
    if (binding.state === "expired" || Date.parse(binding.expires_at) <= Date.parse(now)) {
      await this.store.expire(id, now);
      return undefined;
    }
    return binding;
  }

  close(threadBindingId: string): Promise<SlackThreadBindingV1> {
    return this.store.close(threadBindingId, this.clock.now().toISOString());
  }
}

function validateBindingRequest(request: BindSlackThreadRequest): void {
  if (Object.values(request).some((value) => value.length === 0)) {
    throw new ThreadBindingInputError("Thread binding fields cannot be empty.");
  }
  if (!Number.isFinite(Date.parse(request.expires_at))) {
    throw new ThreadBindingInputError("Thread binding expiry must be a timestamp.");
  }
}

function threadIdentity(
  request: Pick<
    BindSlackThreadRequest,
    "app_id" | "binding_id" | "conversation_id" | "installation_id" | "thread_id"
  >,
): string {
  return `thread-${createHash("sha256")
    .update(
      JSON.stringify([
        request.app_id,
        request.installation_id,
        request.binding_id,
        request.conversation_id,
        request.thread_id,
      ]),
    )
    .digest("hex")
    .slice(0, 32)}`;
}

function fingerprint(binding: SlackThreadBindingV1): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        app_id: binding.app_id,
        binding_id: binding.binding_id,
        conversation_id: binding.conversation_id,
        delivery_id: binding.delivery_id,
        destination_receipt: binding.destination_receipt,
        destination_ref: binding.destination_ref,
        expires_at: binding.expires_at,
        goal_ref: binding.goal_ref,
        installation_id: binding.installation_id,
        subject_ref: binding.subject_ref,
        thread_id: binding.thread_id,
      }),
    )
    .digest("hex");
}
