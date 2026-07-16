import type {
  CheckpointDraft,
  ExecutionSession,
} from "../execution/model.js";
import {
  ExecutionCoordinator,
  ExecutionInvariantError,
} from "../execution/coordinator.js";
import type {
  EvidenceProofV1,
  MissionCapabilityBindingV1,
  MissionCheckpointProjectionV1,
  MissionClosureProjectionV1,
  MissionClosureResult,
  MissionDecisionProjectionV1,
  MissionEffectReceipt,
  MissionEffectResolutionV1,
  MissionPlanProjectionV1,
  MissionReadinessDecision,
  MissionReadinessInput,
  MissionStepProjectionV1,
  MissionVerificationProjectionV1,
  MissionWaitProjectionV1,
  MissionWaitResult,
  ReceiptProofV1,
} from "./model.js";
import {
  NATIVE_MISSION_CONTRACT_ID,
  NATIVE_MISSION_SCHEMA_VERSION,
} from "./model.js";

export class MissionBridgeCoordinator {
  constructor(private readonly execution: ExecutionCoordinator) {}

  readiness(
    plan: MissionPlanProjectionV1,
    input: MissionReadinessInput,
  ): MissionReadinessDecision {
    validatePlanShape(plan);
    validateDistinctRefs(input.missing_input_refs, "missing input");
    if (input.missing_input_refs.length > 0) {
      return {
        kind: "missing_input",
        status: "waiting",
        waiting_on_ref: input.missing_input_refs[0]!,
      };
    }

    const bindings = indexBindings(input.capability_bindings);
    for (const step of plan.steps) {
      const binding = bindings.get(step.capability_ref);
      if (
        binding === undefined ||
        binding.capability_version !== step.capability_version ||
        binding.state !== "bound"
      ) {
        return {
          kind: "missing_tool_binding",
          status: "waiting",
          waiting_on_ref: binding?.binding_ref ?? step.capability_ref,
        };
      }
    }
    return { status: "ready" };
  }

  wait(
    session: ExecutionSession,
    plan: MissionPlanProjectionV1,
    projection: MissionWaitProjectionV1,
  ): Promise<MissionWaitResult> {
    this.validateSessionPlan(session, plan);
    requireRef(projection.waiting_on_ref, "waiting_on_ref");
    return this.execution.waitForDependency(
      session,
      checkpointDraft(
        plan,
        projection,
        projection.waiting_on_ref,
        projection.kind,
      ),
    );
  }

  pauseForDrain(
    session: ExecutionSession,
    plan: MissionPlanProjectionV1,
    projection: MissionCheckpointProjectionV1,
  ): Promise<MissionWaitResult> {
    this.validateSessionPlan(session, plan);
    return this.execution.pauseForDrain(
      session,
      checkpointDraft(plan, projection, undefined, "drain"),
    );
  }

  beginEffect(
    session: ExecutionSession,
    plan: MissionPlanProjectionV1,
    stepId: string,
    decision?: MissionDecisionProjectionV1,
  ): Promise<MissionEffectReceipt> {
    this.validateSessionPlan(session, plan);
    const step = requireStep(plan, stepId);
    requireRef(step.rollback_plan_ref, "rollback_plan_ref");

    let approvalRef: string | undefined;
    if (step.approval_required) {
      if (decision === undefined) {
        return Promise.reject(
          new MissionBridgeInvariantError(
            "an approval decision is required before this effect",
          ),
        );
      }
      validateDecision(plan, decision);
      if (decision.decision !== "approved") {
        return Promise.reject(
          new MissionBridgeInvariantError(
            "a rejected decision cannot authorize an effect",
          ),
        );
      }
      approvalRef = decision.receipt.receipt_ref;
    }

    return this.execution.beginEffect(session, {
      approval_ref: approvalRef,
      approval_required: step.approval_required,
      effect_id: step.effect_id,
      idempotency_key: step.idempotency_key,
      request_digest: step.request_digest,
      rollback_plan_ref: step.rollback_plan_ref,
      step_id: step.step_id,
      target_ref: step.target_ref,
    });
  }

  markEffectExecuting(
    session: ExecutionSession,
    plan: MissionPlanProjectionV1,
    stepId: string,
  ): Promise<MissionEffectReceipt> {
    this.validateSessionPlan(session, plan);
    const step = requireStep(plan, stepId);
    return this.execution.markEffectExecuting(session, step.idempotency_key);
  }

  resolveEffect(
    session: ExecutionSession,
    plan: MissionPlanProjectionV1,
    stepId: string,
    resolution: MissionEffectResolutionV1,
  ): Promise<MissionEffectReceipt> {
    this.validateSessionPlan(session, plan);
    const step = requireStep(plan, stepId);
    validateReceipt(resolution.result, "effect result");
    validateVerification(resolution.executor_ref, resolution.verification);
    return this.execution.resolveEffect(session, step.idempotency_key, {
      result_digest: resolution.result.receipt_digest,
      result_ref: resolution.result.receipt_ref,
      state: resolution.state,
      verification_receipt_ref: resolution.verification.receipt.receipt_ref,
      verification_state:
        resolution.state === "succeeded" ? "verified" : "failed",
    });
  }

  async close(
    session: ExecutionSession,
    plan: MissionPlanProjectionV1,
    projection: MissionClosureProjectionV1,
  ): Promise<MissionClosureResult> {
    this.validateSessionPlan(session, plan);
    if (!projection.desired_condition_verified) {
      throw new MissionBridgeInvariantError(
        "mission closure requires a verified desired condition",
      );
    }
    if (projection.armed_wake_condition_refs.length > 0) {
      throw new MissionBridgeInvariantError(
        "mission closure cannot retain an armed wake condition",
      );
    }
    validateCompletedSteps(plan, projection.completed_step_ids);
    validateVerification(projection.executor_ref, projection.verification);

    const checkpoint = await this.execution.checkpoint(
      session,
      checkpointDraft(
        plan,
        {
          ...projection,
          state_receipt: projection.verification.receipt,
        },
        undefined,
        "verified_closure",
      ),
    );
    const run = await this.execution.finishExecution(session);
    return { checkpoint, run };
  }

  private validateSessionPlan(
    session: ExecutionSession,
    plan: MissionPlanProjectionV1,
  ): void {
    validatePlanShape(plan);
    if (
      session.run.run_id !== plan.run_id ||
      session.lease.run_id !== plan.run_id
    ) {
      throw new MissionBridgeInvariantError(
        "mission plan does not belong to the execution run",
      );
    }
    if (session.run.state !== "running") {
      throw new MissionBridgeInvariantError(
        "mission projection requires a running leased session",
      );
    }
  }
}

export class MissionBridgeInvariantError extends ExecutionInvariantError {
  constructor(message: string) {
    super(message);
    this.name = "MissionBridgeInvariantError";
  }
}

function validatePlanShape(plan: MissionPlanProjectionV1): void {
  if (plan.schema_version !== "mission-plan-projection/v1") {
    throw new MissionBridgeInvariantError(
      "mission plan projection schema version is unsupported",
    );
  }
  if (plan.mission_contract_id !== NATIVE_MISSION_CONTRACT_ID) {
    throw new MissionBridgeInvariantError("mission contract id is unsupported");
  }
  if (plan.mission_schema_version !== NATIVE_MISSION_SCHEMA_VERSION) {
    throw new MissionBridgeInvariantError(
      "mission contract schema version is unsupported",
    );
  }
  for (const [value, label] of [
    [plan.run_id, "run_id"],
    [plan.mission_ref, "mission_ref"],
    [plan.plan_ref, "plan_ref"],
    [plan.plan_digest, "plan_digest"],
  ] as const) {
    requireRef(value, label);
  }
  requirePositiveRevision(plan.mission_revision, "mission_revision");
  requirePositiveRevision(plan.plan_revision, "plan_revision");
  if (plan.steps.length === 0) {
    throw new MissionBridgeInvariantError("mission plan has no steps");
  }
  const stepIds = new Set<string>();
  const effectKeys = new Set<string>();
  for (const step of plan.steps) {
    validateStep(step);
    if (stepIds.has(step.step_id)) {
      throw new MissionBridgeInvariantError("mission plan repeats a step id");
    }
    if (effectKeys.has(step.idempotency_key)) {
      throw new MissionBridgeInvariantError(
        "mission plan repeats an effect idempotency key",
      );
    }
    stepIds.add(step.step_id);
    effectKeys.add(step.idempotency_key);
  }
}

function validateStep(step: MissionStepProjectionV1): void {
  for (const [value, label] of [
    [step.step_id, "step_id"],
    [step.capability_ref, "capability_ref"],
    [step.capability_version, "capability_version"],
    [step.effect_id, "effect_id"],
    [step.idempotency_key, "idempotency_key"],
    [step.request_digest, "request_digest"],
    [step.target_ref, "target_ref"],
  ] as const) {
    requireRef(value, label);
  }
}

function indexBindings(
  bindings: MissionCapabilityBindingV1[],
): Map<string, MissionCapabilityBindingV1> {
  const indexed = new Map<string, MissionCapabilityBindingV1>();
  for (const binding of bindings) {
    requireRef(binding.binding_ref, "binding_ref");
    requireRef(binding.capability_ref, "capability_ref");
    requireRef(binding.capability_version, "capability_version");
    if (indexed.has(binding.capability_ref)) {
      throw new MissionBridgeInvariantError(
        "capability readiness repeats a capability ref",
      );
    }
    indexed.set(binding.capability_ref, binding);
  }
  return indexed;
}

function checkpointDraft(
  plan: MissionPlanProjectionV1,
  projection: MissionCheckpointProjectionV1,
  waitingOnRef?: string,
  checkpointState = "checkpoint",
): CheckpointDraft {
  validateReceipt(projection.state_receipt, "mission state");
  validateCheckpointSequence(projection.sequence);
  validateCompletedStepSubset(plan, projection.completed_step_ids);
  validateDistinctRefs(projection.effect_receipt_ids, "effect receipt");
  requireRef(projection.checkpoint_id, "checkpoint_id");
  return {
    checkpoint_id: projection.checkpoint_id,
    completed_step_ids: [...projection.completed_step_ids],
    effect_receipt_ids: [...projection.effect_receipt_ids],
    payload_digest: projection.state_receipt.receipt_digest,
    payload_ref: projection.state_receipt.receipt_ref,
    resume_cursor: [
      plan.mission_ref,
      plan.mission_revision,
      plan.plan_ref,
      plan.plan_revision,
      checkpointState,
      projection.sequence,
    ].join(":"),
    sequence: projection.sequence,
    waiting_on_ref: waitingOnRef,
  };
}

function validateDecision(
  plan: MissionPlanProjectionV1,
  decision: MissionDecisionProjectionV1,
): void {
  if (decision.schema_version !== "mission-decision-projection/v1") {
    throw new MissionBridgeInvariantError(
      "mission decision projection schema version is unsupported",
    );
  }
  if (
    decision.mission_ref !== plan.mission_ref ||
    decision.mission_revision !== plan.mission_revision ||
    decision.plan_ref !== plan.plan_ref ||
    decision.plan_revision !== plan.plan_revision ||
    decision.plan_digest !== plan.plan_digest
  ) {
    throw new MissionBridgeInvariantError(
      "decision does not match the mission plan revision",
    );
  }
  validateReceipt(decision.receipt, "decision");
  validateEvidence(decision.evidence);
}

function validateVerification(
  executorRef: string,
  verification: MissionVerificationProjectionV1,
): void {
  requireRef(executorRef, "executor_ref");
  requireRef(verification.verifier_ref, "verifier_ref");
  if (executorRef === verification.verifier_ref) {
    throw new MissionBridgeInvariantError(
      "verification must be independent from execution",
    );
  }
  requireRef(
    verification.pre_action_source_revision,
    "pre_action_source_revision",
  );
  requireRef(
    verification.observed_source_revision,
    "observed_source_revision",
  );
  if (
    verification.pre_action_source_revision ===
    verification.observed_source_revision
  ) {
    throw new MissionBridgeInvariantError(
      "verification must observe a newer source revision",
    );
  }
  validateReceipt(verification.receipt, "verification");
  validateEvidence(verification.evidence);
  if (
    !verification.evidence.some(
      (proof) => proof.source_revision === verification.observed_source_revision,
    )
  ) {
    throw new MissionBridgeInvariantError(
      "verification evidence does not prove the observed source revision",
    );
  }
}

function validateEvidence(evidence: EvidenceProofV1[]): void {
  if (evidence.length === 0) {
    throw new MissionBridgeInvariantError(
      "a decision or verification requires evidence",
    );
  }
  const refs = new Set<string>();
  for (const proof of evidence) {
    requireRef(proof.evidence_ref, "evidence_ref");
    requireRef(proof.evidence_digest, "evidence_digest");
    requireRef(proof.source_revision, "source_revision");
    if (refs.has(proof.evidence_ref)) {
      throw new MissionBridgeInvariantError("evidence repeats a receipt ref");
    }
    refs.add(proof.evidence_ref);
  }
}

function validateReceipt(receipt: ReceiptProofV1, label: string): void {
  requireRef(receipt.receipt_ref, `${label} receipt_ref`);
  requireRef(receipt.receipt_digest, `${label} receipt_digest`);
}

function validateCompletedStepSubset(
  plan: MissionPlanProjectionV1,
  completedStepIds: string[],
): void {
  validateDistinctRefs(completedStepIds, "completed step");
  const known = new Set(plan.steps.map((step) => step.step_id));
  if (completedStepIds.some((stepId) => !known.has(stepId))) {
    throw new MissionBridgeInvariantError(
      "checkpoint contains a step outside the mission plan",
    );
  }
}

function validateCompletedSteps(
  plan: MissionPlanProjectionV1,
  completedStepIds: string[],
): void {
  validateCompletedStepSubset(plan, completedStepIds);
  const completed = new Set(completedStepIds);
  if (plan.steps.some((step) => !completed.has(step.step_id))) {
    throw new MissionBridgeInvariantError(
      "mission closure requires every plan step to be complete",
    );
  }
}

function requireStep(
  plan: MissionPlanProjectionV1,
  stepId: string,
): MissionStepProjectionV1 {
  const step = plan.steps.find((candidate) => candidate.step_id === stepId);
  if (step === undefined) {
    throw new MissionBridgeInvariantError("mission step does not exist");
  }
  return step;
}

function validateCheckpointSequence(sequence: number): void {
  requirePositiveRevision(sequence, "checkpoint sequence");
}

function requirePositiveRevision(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new MissionBridgeInvariantError(`${label} must be a positive integer`);
  }
}

function validateDistinctRefs(values: string[], label: string): void {
  const refs = new Set<string>();
  for (const value of values) {
    requireRef(value, `${label} ref`);
    if (refs.has(value)) {
      throw new MissionBridgeInvariantError(`${label} refs must be distinct`);
    }
    refs.add(value);
  }
}

function requireRef(value: string | undefined, label: string): asserts value is string {
  if (value === undefined || value.trim() === "") {
    throw new MissionBridgeInvariantError(`${label} must not be empty`);
  }
}
