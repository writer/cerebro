import type { ExecutionCoordinator } from "./coordinator.js";
import { ExecutionInvariantError } from "./coordinator.js";
import {
  effectIntentDigest,
  normalizeEffectIntentValue,
} from "./effect-intent.js";
import type {
  EffectReceiptV1,
  ExecutionSession,
  ExternalEffectIntentDraft,
  ExternalEffectIntentV1,
  WorkLeaseV1,
} from "./model.js";
import type {
  DurableExecutionPort,
  ExecutionClockPort,
} from "./ports.js";

export interface ExternalEffectJob {
  candidate_version: string;
  fencing_token: number;
  generation: number;
  idempotency_key: string;
  lease_token: string;
  run_id: string;
}

export interface ExternalEffectDraft {
  approval_ref?: string;
  approval_required: boolean;
  candidate_version: string;
  effect_id: string;
  idempotency_key: string;
  request: unknown;
  rollback_plan_ref?: string;
  step_id: string;
  target_ref: string;
}

export interface ExternalEffectResult {
  candidate_version: string;
  result_digest: string;
  result_ref: string;
}

export interface ExternalEffectVerification {
  candidate_version: string;
  receipt_ref: string;
  state: "failed" | "verified";
}

export type RecoverableExternalEffectInspection =
  | {
      candidate_version: string;
      resume_token: string;
      state: "materialized" | "prepared";
    };

export type ExternalEffectInspection =
  | { state: "absent" }
  | RecoverableExternalEffectInspection
  | { result: ExternalEffectResult; state: "applied" }
  | {
      reason_code: string;
      state: "ambiguous" | "boundary_mismatch" | "target_moved";
    };

/** External I/O stays behind this port; credentials and placement are adapter-owned. */
export interface ExternalEffectPort {
  apply(
    intent: ExternalEffectIntentV1,
    lease: WorkLeaseV1,
  ): Promise<ExternalEffectResult>;

  inspect(
    intent: ExternalEffectIntentV1,
    lease: WorkLeaseV1,
  ): Promise<ExternalEffectInspection>;

  resume(
    intent: ExternalEffectIntentV1,
    inspection: RecoverableExternalEffectInspection,
    lease: WorkLeaseV1,
  ): Promise<ExternalEffectResult>;

  verify(
    intent: ExternalEffectIntentV1,
    result: ExternalEffectResult,
    lease: WorkLeaseV1,
  ): Promise<ExternalEffectVerification>;
}

export type StaleExternalEffectJobReason =
  | "candidate_version_mismatch"
  | "fencing_token_mismatch"
  | "generation_mismatch"
  | "idempotency_key_mismatch"
  | "lease_token_mismatch"
  | "run_mismatch";

export type ExternalEffectExecutionResult =
  | {
      effect: EffectReceiptV1;
      intent: ExternalEffectIntentV1;
      status: "applied" | "duplicate" | "recovered";
    }
  | { reason: StaleExternalEffectJobReason; status: "stale" };

export interface ExternalEffectReconcilerOptions {
  clock: ExecutionClockPort;
  execution: ExecutionCoordinator;
  external: ExternalEffectPort;
  store: Pick<
    DurableExecutionPort,
    "getEffectIntent" | "persistEffectIntent"
  >;
}

export class ExternalEffectReconciler {
  private readonly clock: ExecutionClockPort;
  private readonly execution: ExecutionCoordinator;
  private readonly external: ExternalEffectPort;
  private readonly store: ExternalEffectReconcilerOptions["store"];

  constructor(options: ExternalEffectReconcilerOptions) {
    this.clock = options.clock;
    this.execution = options.execution;
    this.external = options.external;
    this.store = options.store;
  }

  async execute(
    session: ExecutionSession,
    job: ExternalEffectJob,
    draft: ExternalEffectDraft,
  ): Promise<ExternalEffectExecutionResult> {
    validateDraft(draft);
    const staleReason = staleJobReason(session, job, draft);
    if (staleReason !== undefined) {
      return { reason: staleReason, status: "stale" };
    }

    const currentIntent = await this.store.getEffectIntent(
      session.run.run_id,
      draft.idempotency_key,
    );
    if (
      currentIntent !== undefined &&
      currentIntent.candidate_version !== draft.candidate_version
    ) {
      return { reason: "candidate_version_mismatch", status: "stale" };
    }

    const request = normalizeEffectIntentValue(draft.request);
    const intentFields = {
      approval_ref: draft.approval_ref,
      approval_required: draft.approval_required,
      candidate_version: draft.candidate_version,
      effect_id: draft.effect_id,
      idempotency_key: draft.idempotency_key,
      request,
      rollback_plan_ref: draft.rollback_plan_ref,
      step_id: draft.step_id,
      target_ref: draft.target_ref,
    };
    const intentDraft: ExternalEffectIntentDraft = {
      ...intentFields,
      request_digest: effectIntentDigest(intentFields),
    };
    const committed = await this.store.persistEffectIntent(
      session.lease,
      intentDraft,
      this.clock.now().toISOString(),
    );
    const effect = await this.execution.beginEffect(session, {
      approval_ref: committed.intent.approval_ref,
      approval_required: committed.intent.approval_required,
      effect_id: committed.intent.effect_id,
      idempotency_key: committed.intent.idempotency_key,
      request_digest: committed.intent.request_digest,
      rollback_plan_ref: committed.intent.rollback_plan_ref,
      step_id: committed.intent.step_id,
      target_ref: committed.intent.target_ref,
    });

    if (effect.state === "failed" || effect.state === "succeeded") {
      return { effect, intent: committed.intent, status: "duplicate" };
    }
    if (effect.state === "planned") {
      await this.execution.markEffectExecuting(
        session,
        committed.intent.idempotency_key,
      );
      const result = await this.external.apply(committed.intent, session.lease);
      return this.resolve(
        session,
        committed.intent,
        result,
        "applied",
      );
    }
    if (effect.state !== "executing" && effect.state !== "unknown") {
      throw new ExecutionInvariantError(
        `effect state ${effect.state} cannot be reconciled`,
      );
    }

    const inspection = await this.external.inspect(
      committed.intent,
      session.lease,
    );
    const result = await this.recoverResult(
      committed.intent,
      inspection,
      session.lease,
    );
    return this.resolve(
      session,
      committed.intent,
      result,
      "recovered",
    );
  }

  private recoverResult(
    intent: ExternalEffectIntentV1,
    inspection: ExternalEffectInspection,
    lease: WorkLeaseV1,
  ): Promise<ExternalEffectResult> {
    switch (inspection.state) {
      case "absent":
        return this.external.apply(intent, lease);
      case "applied":
        return Promise.resolve(inspection.result);
      case "materialized":
      case "prepared":
        assertCandidateVersion(intent, inspection.candidate_version);
        return this.external.resume(intent, inspection, lease);
      case "ambiguous":
      case "boundary_mismatch":
      case "target_moved":
        throw new EffectReconciliationBlockedError(inspection.state);
    }
  }

  private async resolve(
    session: ExecutionSession,
    intent: ExternalEffectIntentV1,
    result: ExternalEffectResult,
    status: "applied" | "recovered",
  ): Promise<ExternalEffectExecutionResult> {
    assertCandidateVersion(intent, result.candidate_version);
    const verification = await this.external.verify(
      intent,
      result,
      session.lease,
    );
    assertCandidateVersion(intent, verification.candidate_version);
    const effect = await this.execution.resolveEffect(
      session,
      intent.idempotency_key,
      {
        result_digest: result.result_digest,
        result_ref: result.result_ref,
        state: verification.state === "verified" ? "succeeded" : "failed",
        verification_receipt_ref: verification.receipt_ref,
        verification_state: verification.state,
      },
    );
    return { effect, intent, status };
  }
}

export class EffectReconciliationBlockedError extends Error {
  constructor(
    readonly code:
      | "ambiguous"
      | "boundary_mismatch"
      | "candidate_version_mismatch"
      | "target_moved",
  ) {
    super(`external effect reconciliation blocked: ${code}`);
    this.name = "EffectReconciliationBlockedError";
  }
}

function staleJobReason(
  session: ExecutionSession,
  job: ExternalEffectJob,
  draft: ExternalEffectDraft,
): StaleExternalEffectJobReason | undefined {
  if (job.run_id !== session.run.run_id) return "run_mismatch";
  if (job.generation !== session.lease.generation) return "generation_mismatch";
  if (job.fencing_token !== session.lease.fencing_token) {
    return "fencing_token_mismatch";
  }
  if (job.lease_token !== session.lease.lease_token) {
    return "lease_token_mismatch";
  }
  if (job.idempotency_key !== draft.idempotency_key) {
    return "idempotency_key_mismatch";
  }
  if (job.candidate_version !== draft.candidate_version) {
    return "candidate_version_mismatch";
  }
  return undefined;
}

function assertCandidateVersion(
  intent: ExternalEffectIntentV1,
  candidateVersion: string,
): void {
  if (intent.candidate_version !== candidateVersion) {
    throw new EffectReconciliationBlockedError("candidate_version_mismatch");
  }
}

function validateDraft(draft: ExternalEffectDraft): void {
  for (const [field, value] of [
    ["candidate_version", draft.candidate_version],
    ["effect_id", draft.effect_id],
    ["idempotency_key", draft.idempotency_key],
    ["step_id", draft.step_id],
    ["target_ref", draft.target_ref],
  ] as const) {
    if (value.trim() === "") {
      throw new ExecutionInvariantError(`${field} must not be empty`);
    }
  }
}
