import type {
  AdmitEvidenceRecheckResultV1,
  BindDeliveredAnswerEvidenceInputV1,
  DeliveredAnswerEvidenceBindingV1,
  EvidenceRecheckClockPort,
  EvidenceRecheckExecutionClaimV1,
  EvidenceRecheckExecutionLeaseV1,
  EvidenceRecheckExecutorPort,
  EvidenceRecheckStatusDeliveryPort,
  PortableEvidenceRecheckContract,
  SlackEvidenceRecheckStatusV1,
  VerifiedEvidenceRecheckInvocationPort,
  VerifiedEvidenceRecheckInvocationV1,
} from "./contracts.js";
import {
  AtomicEvidenceRecheckStore,
  EvidenceRecheckStoreConflictError,
} from "./persistence.js";

export interface EvidenceRecheckHostOptions {
  clock: EvidenceRecheckClockPort;
  contract: PortableEvidenceRecheckContract;
  executor: EvidenceRecheckExecutorPort;
  invocations: VerifiedEvidenceRecheckInvocationPort;
  status_delivery: EvidenceRecheckStatusDeliveryPort;
  store: AtomicEvidenceRecheckStore;
}

export interface EvidenceRecheckAdmissionOutcomeV1 {
  acknowledgement_permitted: boolean;
  duplicate: boolean;
  retryable: boolean;
  run_id?: string;
  schema_version: "private-evidence-recheck-admission-outcome/v1";
  status: SlackEvidenceRecheckStatusV1;
}

export type EvidenceRecheckExecutionOutcomeV1 =
  | {
      run_id: string;
      schema_version: "private-evidence-recheck-execution-outcome/v1";
      status: "completed";
    }
  | {
      run_id: string;
      schema_version: "private-evidence-recheck-execution-outcome/v1";
      status: "degraded";
    }
  | {
      schema_version: "private-evidence-recheck-execution-outcome/v1";
      status: "idle";
    };

export type EvidenceRecheckStatusDeliveryOutcomeV1 =
  | {
      outbox_id: string;
      schema_version: "private-evidence-recheck-status-outcome/v1";
      status: "delivered" | "requeued_after_inspection";
    }
  | {
      schema_version: "private-evidence-recheck-status-outcome/v1";
      status: "idle";
    };

/** Private composition around the verified portable recheck contract. */
export class EvidenceRecheckHost {
  private readonly clock: EvidenceRecheckClockPort;
  private readonly contract: PortableEvidenceRecheckContract;
  private readonly executor: EvidenceRecheckExecutorPort;
  private readonly invocations: VerifiedEvidenceRecheckInvocationPort;
  private readonly statusDelivery: EvidenceRecheckStatusDeliveryPort;
  private readonly store: AtomicEvidenceRecheckStore;

  constructor(options: EvidenceRecheckHostOptions) {
    this.clock = options.clock;
    this.contract = options.contract;
    this.executor = options.executor;
    this.invocations = options.invocations;
    this.statusDelivery = options.status_delivery;
    this.store = options.store;
  }

  async registerDeliveredAnswer(
    input: BindDeliveredAnswerEvidenceInputV1,
  ): Promise<{ binding: DeliveredAnswerEvidenceBindingV1; created: boolean }> {
    const binding = this.contract.bindDeliveredAnswerEvidence(input);
    return this.store.putBindingIfAbsent(binding);
  }

  async admitPersistedInvocation(
    payloadRef: string,
  ): Promise<EvidenceRecheckAdmissionOutcomeV1> {
    requireRef(payloadRef, "payload_ref");
    const invocation = await this.invocations.readVerified(payloadRef);
    validateInvocation(invocation, payloadRef);
    const bindingLookup = await this.store.bindingLookup(invocation.binding_ref);
    const contextualBindingLookup =
      bindingLookup.found &&
      bindingLookup.binding.conversation_ref === invocation.conversation_ref &&
      bindingLookup.binding.thread_ref === invocation.thread_ref
        ? bindingLookup
        : {
            binding_ref: invocation.binding_ref,
            found: false as const,
            schema_version: "delivered-answer-evidence-binding-lookup/v1" as const,
          };
    const recheckId = this.contract.evidenceRecheckIdentity(
      invocation.binding_ref,
      invocation.request_key,
    );
    const receiptId = this.contract.evidenceRecheckAdmissionReceiptIdentity(recheckId);
    const receiptLookup = await this.store.receiptLookup(receiptId);
    const result = await this.contract.admitEvidenceRecheck(
      {
        actor_ref: invocation.actor_ref,
        admitted_at: this.clock.now().toISOString(),
        binding_ref: invocation.binding_ref,
        received_at: invocation.received_at,
        request_key: invocation.request_key,
        run_context: invocation.run_context,
      },
      contextualBindingLookup,
      receiptLookup,
      this.store,
    );
    return admissionOutcome(
      result,
      this.contract.projectEvidenceRecheckStatus({
        kind: "admission",
        result,
        schema_version: "evidence-recheck-status-input/v1",
      }),
    );
  }

  async executeNext(
    claim: EvidenceRecheckExecutionClaimV1,
  ): Promise<EvidenceRecheckExecutionOutcomeV1> {
    const session = await this.store.claimNextExecution(claim);
    if (session === undefined) {
      return {
        schema_version: "private-evidence-recheck-execution-outcome/v1",
        status: "idle",
      };
    }
    let lease: EvidenceRecheckExecutionLeaseV1 = session.lease;
    try {
      const completion = await this.executor.execute(session, {
        checkpoint: (payloadRef, checkpointDigest) =>
          this.store.appendCheckpoint(
            lease,
            payloadRef,
            checkpointDigest,
            this.clock.now().toISOString(),
          ),
        renew: async () => {
          lease = await this.store.renewExecution(
            lease,
            this.clock.now().toISOString(),
            claim.lease_duration_ms,
          );
          return lease;
        },
      });
      const completedAt = this.clock.now().toISOString();
      await this.store.completeExecution(
        lease,
        { ...completion, completed_at: completedAt },
        completedAt,
      );
      return {
        run_id: lease.run_id,
        schema_version: "private-evidence-recheck-execution-outcome/v1",
        status: "completed",
      };
    } catch (error) {
      try {
        await this.store.releaseExecutionForRecovery(
          lease,
          this.clock.now().toISOString(),
          "execution_interrupted",
        );
      } catch (releaseError) {
        if (!(releaseError instanceof EvidenceRecheckStoreConflictError)) {
          throw releaseError;
        }
      }
      return {
        run_id: lease.run_id,
        schema_version: "private-evidence-recheck-execution-outcome/v1",
        status: "degraded",
      };
    }
  }

  recoverExpiredExecutions(): Promise<string[]> {
    return this.store.recoverExpiredExecutions(this.clock.now().toISOString());
  }

  async deliverNextStatus(
    claim: EvidenceRecheckExecutionClaimV1,
  ): Promise<EvidenceRecheckStatusDeliveryOutcomeV1> {
    const claimed = await this.store.claimNextOutbox(claim);
    if (claimed === undefined) {
      return {
        schema_version: "private-evidence-recheck-status-outcome/v1",
        status: "idle",
      };
    }
    if (claimed.lease.mode === "inspect") {
      const prior = await this.statusDelivery.inspect(claimed.lease.outbox_id);
      if (prior !== undefined) {
        await this.store.completeOutbox(claimed.lease, prior);
        return {
          outbox_id: claimed.lease.outbox_id,
          schema_version: "private-evidence-recheck-status-outcome/v1",
          status: "delivered",
        };
      }
      await this.store.resetOutboxAfterMissingInspection(claimed.lease);
      return {
        outbox_id: claimed.lease.outbox_id,
        schema_version: "private-evidence-recheck-status-outcome/v1",
        status: "requeued_after_inspection",
      };
    }
    const status = this.contract.projectEvidenceRecheckStatus({
      kind: "recheck",
      recheck: claimed.recheck,
      schema_version: "evidence-recheck-status-input/v1",
    });
    await this.store.beginOutboxSend(claimed.lease);
    const delivered = await this.statusDelivery.send({
      idempotency_key: claimed.lease.outbox_id,
      outbox_id: claimed.lease.outbox_id,
      status,
      thread_ref: claimed.thread_ref,
    });
    await this.store.completeOutbox(claimed.lease, delivered);
    return {
      outbox_id: claimed.lease.outbox_id,
      schema_version: "private-evidence-recheck-status-outcome/v1",
      status: "delivered",
    };
  }

  pendingCounts(): Promise<{ execution: number; outbox: number }> {
    return this.store.pendingCounts();
  }
}

function admissionOutcome(
  result: AdmitEvidenceRecheckResultV1,
  status: SlackEvidenceRecheckStatusV1,
): EvidenceRecheckAdmissionOutcomeV1 {
  return {
    acknowledgement_permitted: result.acknowledgement_permitted,
    duplicate: result.duplicate,
    retryable: result.retryable,
    ...(result.acknowledgement_permitted ? { run_id: result.receipt.run.run_id } : {}),
    schema_version: "private-evidence-recheck-admission-outcome/v1",
    status,
  };
}

function validateInvocation(
  invocation: VerifiedEvidenceRecheckInvocationV1,
  payloadRef: string,
): void {
  const expectedKeys = [
    "actor_ref",
    "binding_ref",
    "conversation_ref",
    "payload_ref",
    "received_at",
    "request_key",
    "run_context",
    "schema_version",
    "thread_ref",
  ];
  const actualKeys = Object.keys(invocation).sort();
  if (
    JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys) ||
    invocation.schema_version !== "verified-evidence-recheck-invocation/v1" ||
    invocation.payload_ref !== payloadRef
  ) {
    throw new Error("Verified evidence recheck invocation is invalid.");
  }
  for (const [value, field] of [
    [invocation.actor_ref, "actor_ref"],
    [invocation.binding_ref, "binding_ref"],
    [invocation.conversation_ref, "conversation_ref"],
    [invocation.request_key, "request_key"],
    [invocation.thread_ref, "thread_ref"],
  ] as const) {
    requireRef(value, field);
  }
  if (
    typeof invocation.received_at !== "string" ||
    !Number.isFinite(Date.parse(invocation.received_at)) ||
    new Date(Date.parse(invocation.received_at)).toISOString() !== invocation.received_at
  ) {
    throw new Error("Verified evidence recheck received_at must be canonical UTC.");
  }
  const expectedContextKeys = [
    "required_capabilities",
    "retention_policy_ref",
    "service_binding_id",
    "subject_ref",
    "tenant_id",
  ];
  if (
    invocation.run_context === null ||
    typeof invocation.run_context !== "object" ||
    JSON.stringify(Object.keys(invocation.run_context).sort()) !==
      JSON.stringify(expectedContextKeys) ||
    !Array.isArray(invocation.run_context.required_capabilities)
  ) {
    throw new Error("Verified evidence recheck run_context is invalid.");
  }
  for (const [value, field] of [
    [invocation.run_context.retention_policy_ref, "retention_policy_ref"],
    [invocation.run_context.service_binding_id, "service_binding_id"],
    [invocation.run_context.subject_ref, "subject_ref"],
    [invocation.run_context.tenant_id, "tenant_id"],
  ] as const) {
    requireRef(value, field);
  }
  for (const capability of invocation.run_context.required_capabilities) {
    if (
      capability === null ||
      typeof capability !== "object" ||
      !["optional", "required"].includes(capability.level)
    ) {
      throw new Error("Verified evidence recheck capability requirement is invalid.");
    }
    requireRef(capability.capability_id, "capability_id");
    requireRef(capability.version, "capability version");
  }
}

function requireRef(value: string, field: string): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2_048 ||
    value.trim() !== value ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new Error(`${field} must be a bounded opaque reference.`);
  }
}
