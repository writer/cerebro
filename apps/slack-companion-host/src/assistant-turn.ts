export const ASSISTANT_EXECUTION_LANES = [
  "ignore",
  "converse",
  "continue",
  "lookup",
  "investigate",
  "act",
] as const;

export type AssistantExecutionLane = (typeof ASSISTANT_EXECUTION_LANES)[number];

export interface AssistantTurnBudget {
  execution_lane: AssistantExecutionLane;
  latency_budget_ms: number;
  max_selected_capabilities: number;
  max_tool_calls: number;
  schema_version: "assistant-turn-budget/v1";
}

export interface AssistantTurnProgress {
  capability_ref?: string;
  execution_lane?: AssistantExecutionLane;
  occurred_at: string;
  phase: "planning" | "checking" | "synthesizing" | "delivering" | "completed" | "blocked";
  schema_version: "assistant-turn-progress/v1";
  sequence: number;
  status: string;
}

export interface SlackStatusProjection {
  code: string;
  kind: "assistant_progress" | "run_status";
  observed_at: string;
  operation: "upsert";
  projection_id: string;
  run_id: string;
  schema_version: "slack-status-projection/v1";
  sequence?: number;
  text: string;
}

export interface SlackMultipartPartProjection {
  acceptance?: {
    accepted_at: string;
    destination_receipt: string;
  };
  client_message_id: string;
  part_id: string;
  payload_digest: string;
  payload_ref: string;
  schema_version: "slack-multipart-part-projection/v1";
  sequence: number;
  state: string;
}

export interface SlackMultipartProjection {
  accepted_part_count: number;
  delivery_id: string;
  destination_ref: string;
  part_count: number;
  parts: readonly SlackMultipartPartProjection[];
  projection_id: string;
  run_id: string;
  schema_version: "slack-multipart-projection/v1";
  state: string;
  undelivered_part_count: number;
  updated_at: string;
}

export interface AssistantTurnPlanPreflightInput {
  budget: AssistantTurnBudget;
  catalog: {
    list(): readonly AssistantTurnToolCatalogEntry[];
    resolve(toolId: string, toolVersion: string):
      | AssistantTurnToolCatalogEntry
      | undefined;
  };
  completed_tool_calls: number;
  elapsed_ms: number;
  invocation: {
    authority?: {
      authority_ref: string;
      decided_at: string;
      decision_id: string;
      expires_at?: string;
      invocation_id: string;
      outcome: "allowed" | "approval_required" | "denied";
      reason_code: string;
      request_digest: string;
      run_id: string;
      schema_version: "tool-authority-decision/v1";
      step_id: string;
      subject_ref: string;
      tool_id: string;
      tool_version: string;
    };
    invocation_id: string;
    request_digest: string;
    run_id: string;
    source_ref?: string;
    step_id: string;
    subject_ref: string;
    tool_id: string;
    tool_version: string;
  };
  observed_at: string;
  replan_count: number;
  selected_capability_refs: readonly string[];
  source_health: readonly AssistantTurnSourceHealthSnapshot[];
}

export interface AssistantTurnToolCatalogEntry {
  authority_class: "actuate" | "observe" | "propose";
  effect_class: "external_effect" | "read" | "write";
  input_schema_ref: string;
  replay_policy: "receipt_required" | "reconcile_before_retry" | "safe";
  required_capabilities: readonly string[];
  result_schema_ref: string;
  schema_version: "tool-catalog-entry/v1";
  summary: string;
  title: string;
  tool_id: string;
  tool_version: string;
}

export interface AssistantTurnSourceHealthSnapshot {
  allowed: boolean;
  attempts: number;
  average_latency_ms: number;
  consecutive_failures: number;
  retry_after_ms?: number;
  schema_version: "source-health-snapshot/v1";
  slow: boolean;
  source_ref: string;
  status: "cooldown" | "degraded" | "healthy";
  success_rate: number;
}

export interface AssistantTurnPlanPreflight {
  allowed: boolean;
  blockers: readonly string[];
  cutoff_ms: number;
  remaining_ms: number;
  schema_version: "assistant-turn-plan-preflight/v1";
  tool_calls_after_start: number;
}

export interface AssistantTurnEvidenceFallbackInput {
  evidence: readonly {
    evidence_id: string;
    observed_at: string;
    receipt_digest: string;
    receipt_ref: string;
    source_label: string;
    source_ref: string;
    statement: string;
  }[];
  gaps: readonly {
    scope: string;
    source_label: string;
    source_ref: string;
    state: "not_configured" | "not_found" | "timed_out" | "unauthorized" | "unavailable";
  }[];
  next_action: string;
}

export interface AssistantTurnOutput {
  answer?: string;
  content_digest: `sha256:${string}`;
  coverage_notice?: string;
  next_action?: string;
  question?: string;
  schema_version: "assistant-turn-output/v1";
  state: "answered" | "blocked" | "needs_input" | "partial";
}

export interface AssistantTurnOutcomeAssessmentInput {
  assessment_at: string;
  evaluation_blockers: readonly string[];
  execution_lane: AssistantExecutionLane;
  latency_budget_ms: number;
  negative_feedback_count: number;
  opened_at: string;
  outcome_state: "blocked" | "completed" | "needs_user" | "owned" | "unknown";
  request_id: string;
  request_kind: "human" | "machine_handoff";
  user_correction_count: number;
  useful_answer_at?: string;
  verified: boolean;
}

export interface AssistantTurnOutcomeAssessment
  extends AssistantTurnOutcomeAssessmentInput {
  assessment_digest: `sha256:${string}`;
  eligible: boolean;
  observation_window_complete: boolean;
  qualification: "eligible_failure" | "eligible_success" | "excluded" | "pending_observation";
  schema_version: "assistant-turn-outcome-assessment/v1";
  useful_answer_latency_ms?: number;
  verified_outcome_within_slo: boolean;
}

/** Exact public functions are injected by the composition root after source-lock verification. */
export interface PortableAssistantTurnContract {
  assistantTurnBudget(
    lane: AssistantExecutionLane,
    configured?: { max_tool_calls?: number; timeout_ms?: number },
  ): AssistantTurnBudget;
  projectAssistantTurnProgress(
    runId: string,
    progress: AssistantTurnProgress,
  ): SlackStatusProjection;
  projectSlackMultipartDelivery(receipt: unknown): SlackMultipartProjection;
  preflightAssistantTurnInvocation(
    input: AssistantTurnPlanPreflightInput,
  ): AssistantTurnPlanPreflight;
  buildAssistantTurnEvidenceFallback(
    input: AssistantTurnEvidenceFallbackInput,
  ): AssistantTurnOutput;
  assessAssistantTurnOutcome(
    input: AssistantTurnOutcomeAssessmentInput,
  ): AssistantTurnOutcomeAssessment;
}

export interface AssistantTurnReceiptPort {
  persistMultipartDelivery(
    projection: SlackMultipartProjection,
  ): Promise<{ receipt_ref: string }>;
  persistStatus(projection: SlackStatusProjection): Promise<{ receipt_ref: string }>;
  persistOutcome(
    assessment: AssistantTurnOutcomeAssessment,
  ): Promise<{ receipt_ref: string }>;
}

export type AssistantTurnHostTelemetryEvent =
  | {
      event_id: string;
      kind: "assistant_turn_progress_persisted";
      phase: string;
      receipt_ref: string;
      sequence?: number;
    }
  | {
      accepted_part_count: number;
      event_id: string;
      kind: "assistant_turn_delivery_persisted";
      part_count: number;
      receipt_ref: string;
      state: string;
      undelivered_part_count: number;
    }
  | {
      event_id: string;
      kind: "assistant_turn_outcome_persisted";
      observation_window_complete: boolean;
      qualification: AssistantTurnOutcomeAssessment["qualification"];
      receipt_ref: string;
      verified_outcome_within_slo: boolean;
    };

export interface AssistantTurnTelemetryPort {
  recordIdempotent(event: AssistantTurnHostTelemetryEvent): Promise<void>;
}

export interface AssistantTurnBudgetRequest {
  configured?: { max_tool_calls?: number; timeout_ms?: number };
  execution_lane: AssistantExecutionLane;
  planned_tool_call_count: number;
  selected_capability_count: number;
}

export class AssistantTurnHostPolicyError extends Error {}

export class AssistantTurnHostAdapter {
  constructor(
    private readonly contract: PortableAssistantTurnContract,
    private readonly receipts: AssistantTurnReceiptPort,
    private readonly telemetry: AssistantTurnTelemetryPort,
  ) {}

  enforceBudget(request: AssistantTurnBudgetRequest): AssistantTurnBudget {
    const selectedCapabilityCount = boundedCount(
      request.selected_capability_count,
      "selected capability count",
    );
    const plannedToolCallCount = boundedCount(
      request.planned_tool_call_count,
      "planned tool call count",
    );
    const budget = this.contract.assistantTurnBudget(
      request.execution_lane,
      request.configured,
    );
    if (selectedCapabilityCount > budget.max_selected_capabilities) {
      throw new AssistantTurnHostPolicyError(
        "The assistant turn selected more capabilities than its execution lane permits.",
      );
    }
    if (plannedToolCallCount > budget.max_tool_calls) {
      throw new AssistantTurnHostPolicyError(
        "The assistant turn planned more tool calls than its execution lane permits.",
      );
    }
    return budget;
  }

  preflightInvocation(
    input: AssistantTurnPlanPreflightInput,
  ): AssistantTurnPlanPreflight {
    return this.contract.preflightAssistantTurnInvocation(input);
  }

  buildEvidenceFallback(
    input: AssistantTurnEvidenceFallbackInput,
  ): AssistantTurnOutput {
    return this.contract.buildAssistantTurnEvidenceFallback(input);
  }

  async recordOutcome(
    input: AssistantTurnOutcomeAssessmentInput,
  ): Promise<AssistantTurnOutcomeAssessment> {
    const assessment = this.contract.assessAssistantTurnOutcome(input);
    const durable = await this.receipts.persistOutcome(assessment);
    await this.telemetry.recordIdempotent({
      event_id: `${assessment.assessment_digest}:persisted`,
      kind: "assistant_turn_outcome_persisted",
      observation_window_complete: assessment.observation_window_complete,
      qualification: assessment.qualification,
      receipt_ref: requiredReceiptRef(durable.receipt_ref),
      verified_outcome_within_slo: assessment.verified_outcome_within_slo,
    });
    return assessment;
  }

  async recordProgress(
    runId: string,
    progress: AssistantTurnProgress,
  ): Promise<SlackStatusProjection> {
    const projection = this.contract.projectAssistantTurnProgress(runId, progress);
    const durable = await this.receipts.persistStatus(projection);
    await this.telemetry.recordIdempotent({
      event_id: `${projection.projection_id}:persisted`,
      kind: "assistant_turn_progress_persisted",
      phase: projection.code,
      receipt_ref: requiredReceiptRef(durable.receipt_ref),
      ...(projection.sequence === undefined ? {} : { sequence: projection.sequence }),
    });
    return projection;
  }

  async recordDelivery(receipt: unknown): Promise<SlackMultipartProjection> {
    const projection = this.contract.projectSlackMultipartDelivery(receipt);
    const durable = await this.receipts.persistMultipartDelivery(projection);
    await this.telemetry.recordIdempotent({
      accepted_part_count: projection.accepted_part_count,
      event_id: `${projection.projection_id}:persisted`,
      kind: "assistant_turn_delivery_persisted",
      part_count: projection.part_count,
      receipt_ref: requiredReceiptRef(durable.receipt_ref),
      state: projection.state,
      undelivered_part_count: projection.undelivered_part_count,
    });
    return projection;
  }
}

function boundedCount(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new AssistantTurnHostPolicyError(`${field} must be a non-negative integer.`);
  }
  return value;
}

function requiredReceiptRef(value: string): string {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > 2_048
    || !/^[a-z][a-z0-9+.-]*:\/\/\S+$/.test(value)
  ) {
    throw new AssistantTurnHostPolicyError(
      "Assistant turn persistence must return an opaque receipt reference.",
    );
  }
  return value;
}
