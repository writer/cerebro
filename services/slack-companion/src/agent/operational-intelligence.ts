const MAX_ITEMS = 16;
const MAX_TEXT = 800;

export type AssistantExecutionLane = "ignore" | "converse" | "continue" | "lookup" | "investigate" | "act";
export type SecurityDomainLens = "identity" | "delivery" | "cloud" | "detection" | "compliance" | "incident" | "self" | "general";
export type WorldFactState = "observed" | "inferred" | "expected" | "desired";
export type HypothesisStatus = "open" | "supported" | "contradicted" | "eliminated";
export type WorkflowStepKind = "observe" | "compare" | "verify" | "decide" | "act" | "monitor" | "rollback";

export interface WorldFactInput {
  id?: string;
  statement?: string;
  state?: string;
  confidence?: number;
  source_tool?: string;
  evidence_receipt?: string;
  source_refs?: string[];
  observed_at?: string;
  freshness?: string;
  scope?: string;
  valid_until?: string;
}

export interface OperationalWorldFact {
  id: string;
  statement: string;
  state: WorldFactState;
  confidence: number;
  source_tool?: string;
  evidence_receipt?: string;
  source_refs: string[];
  observed_at?: string;
  freshness?: string;
  scope?: string;
  valid_until?: string;
  verified: boolean;
}

export interface HypothesisInput {
  id?: string;
  statement?: string;
  status?: string;
  confidence?: number;
  supporting_receipts?: string[];
  counterevidence_receipts?: string[];
  falsifier?: string;
  next_check?: string;
}

export interface InvestigationHypothesis {
  id: string;
  statement: string;
  status: HypothesisStatus;
  confidence: number;
  supporting_receipts: string[];
  counterevidence_receipts: string[];
  falsifier?: string;
  next_check?: string;
}

export interface DecisionInput {
  id?: string;
  decision?: string;
  rationale?: string;
  owner?: string;
  status?: string;
  review_at?: string;
  evidence_receipts?: string[];
  source_refs?: string[];
}

export interface OperationalDecision {
  id: string;
  decision: string;
  rationale: string;
  owner?: string;
  status: "proposed" | "approved" | "executed" | "superseded";
  review_at?: string;
  evidence_receipts: string[];
  source_refs: string[];
  verified: boolean;
}

export interface WorkflowStepInput {
  id?: string;
  kind?: string;
  title?: string;
  depends_on?: string[];
  tool?: string;
  tool_arguments?: Record<string, unknown>;
  approval_required?: boolean;
  idempotency_key?: string;
  verification?: string;
  verification_tool?: string;
  verification_arguments?: Record<string, unknown>;
  rollback?: string;
  max_attempts?: number;
  acceptance_criteria_ids?: string[];
}

export interface WorkflowCompileInput {
  objective?: string;
  owner?: string;
  steps?: WorkflowStepInput[];
  completion_condition?: string;
}

export interface OperationalWorkflowStep {
  id: string;
  kind: WorkflowStepKind;
  title: string;
  depends_on: string[];
  tool?: string;
  tool_arguments: Record<string, unknown>;
  approval_required: boolean;
  idempotency_key?: string;
  verification?: string;
  verification_tool?: string;
  verification_arguments: Record<string, unknown>;
  rollback?: string;
  max_attempts: number;
  acceptance_criteria_ids: string[];
}

export interface OperationalWorkflow {
  objective: string;
  owner?: string;
  steps: OperationalWorkflowStep[];
  completion_condition: string;
  valid: boolean;
  issues: string[];
}

export interface ActionSimulationInput {
  action?: string;
  target?: string;
  affected_resources?: string[];
  affected_owners?: string[];
  risks?: string[];
  evidence_receipts?: string[];
  approval_required?: boolean;
  rollback?: string;
  verification?: string;
}

export interface ActionSimulation {
  action: string;
  target: string;
  affected_resources: string[];
  affected_owners: string[];
  risks: string[];
  evidence_receipts: string[];
  approval_required: boolean;
  rollback?: string;
  verification?: string;
  ready: boolean;
  blockers: string[];
}

export interface AttentionDecisionInput {
  signal?: string;
  dedup_key?: string;
  novelty?: number;
  materiality?: number;
  urgency?: number;
  actionability?: number;
  confidence?: number;
  decision_needed?: boolean;
  reason?: string;
}

export interface AttentionDecision {
  signal: string;
  dedup_key: string;
  novelty: number;
  materiality: number;
  urgency: number;
  actionability: number;
  confidence: number;
  decision_needed: boolean;
  score: number;
  recommendation: "speak" | "suppress";
  reason: string;
}

export interface OperationalIntelligenceSnapshot {
  world_facts: OperationalWorldFact[];
  hypotheses: InvestigationHypothesis[];
  decisions: OperationalDecision[];
  workflow?: OperationalWorkflow;
  action_simulation?: ActionSimulation;
  attention?: AttentionDecision;
}

export class OperationalIntelligenceState {
  private worldFacts: OperationalWorldFact[] = [];
  private hypotheses: InvestigationHypothesis[] = [];
  private decisions: OperationalDecision[] = [];
  private workflow?: OperationalWorkflow;
  private actionSimulation?: ActionSimulation;
  private attention?: AttentionDecision;

  constructor(private readonly receiptIsValid: (receipt: string, sourceTool?: string) => boolean) {}

  updateWorld(input: { facts?: WorldFactInput[] }): OperationalIntelligenceSnapshot {
    const seen = new Set<string>();
    this.worldFacts = (input.facts ?? []).slice(0, MAX_ITEMS).flatMap((candidate, index) => {
      const statement = cleanText(candidate.statement);
      if (!statement) return [];
      const id = uniqueId(candidate.id, `fact-${index + 1}`, seen);
      const sourceTool = cleanText(candidate.source_tool) || undefined;
      const evidenceReceipt = cleanText(candidate.evidence_receipt) || undefined;
      const state = worldFactState(candidate.state);
      const verified = state === "observed" && Boolean(evidenceReceipt) && this.receiptIsValid(evidenceReceipt as string, sourceTool);
      return [{
        id,
        statement,
        state: state === "observed" && !verified ? "inferred" as const : state,
        confidence: verified ? bounded(candidate.confidence, 1) : Math.min(0.95, bounded(candidate.confidence, state === "desired" ? 1 : 0.6)),
        source_tool: verified ? sourceTool : undefined,
        evidence_receipt: verified ? evidenceReceipt : undefined,
        source_refs: cleanList(candidate.source_refs),
        observed_at: cleanIso(candidate.observed_at),
        freshness: cleanText(candidate.freshness) || undefined,
        scope: cleanText(candidate.scope) || undefined,
        valid_until: cleanIso(candidate.valid_until),
        verified,
      }];
    });
    return this.snapshot();
  }

  updateHypotheses(input: { hypotheses?: HypothesisInput[] }): OperationalIntelligenceSnapshot {
    const seen = new Set<string>();
    this.hypotheses = (input.hypotheses ?? []).slice(0, MAX_ITEMS).flatMap((candidate, index) => {
      const statement = cleanText(candidate.statement);
      if (!statement) return [];
      const supporting = validReceipts(candidate.supporting_receipts, this.receiptIsValid);
      const counterevidence = validReceipts(candidate.counterevidence_receipts, this.receiptIsValid);
      const requestedStatus = hypothesisStatus(candidate.status);
      const status = requestedStatus === "supported" && supporting.length === 0
        ? "open"
        : requestedStatus === "contradicted" && counterevidence.length === 0
          ? "open"
          : requestedStatus;
      return [{
        id: uniqueId(candidate.id, `hypothesis-${index + 1}`, seen),
        statement,
        status,
        confidence: bounded(candidate.confidence, 0.5),
        supporting_receipts: supporting,
        counterevidence_receipts: counterevidence,
        falsifier: cleanText(candidate.falsifier) || undefined,
        next_check: cleanText(candidate.next_check) || undefined,
      }];
    });
    return this.snapshot();
  }

  recordDecisions(input: { decisions?: DecisionInput[] }): OperationalIntelligenceSnapshot {
    const seen = new Set<string>();
    this.decisions = (input.decisions ?? []).slice(0, MAX_ITEMS).flatMap((candidate, index) => {
      const decision = cleanText(candidate.decision);
      const rationale = cleanText(candidate.rationale);
      if (!decision || !rationale) return [];
      const evidenceReceipts = validReceipts(candidate.evidence_receipts, this.receiptIsValid);
      return [{
        id: uniqueId(candidate.id, `decision-${index + 1}`, seen),
        decision,
        rationale,
        owner: cleanText(candidate.owner) || undefined,
        status: decisionStatus(candidate.status),
        review_at: cleanIso(candidate.review_at),
        evidence_receipts: evidenceReceipts,
        source_refs: cleanList(candidate.source_refs),
        verified: evidenceReceipts.length > 0,
      }];
    });
    return this.snapshot();
  }

  compileWorkflow(input: WorkflowCompileInput): OperationalIntelligenceSnapshot {
    const seen = new Set<string>();
    const steps = (input.steps ?? []).slice(0, MAX_ITEMS).flatMap((candidate, index) => {
      const title = cleanText(candidate.title);
      if (!title) return [];
      return [{
        id: uniqueId(candidate.id, `step-${index + 1}`, seen),
        kind: workflowStepKind(candidate.kind),
        title,
        depends_on: cleanList(candidate.depends_on),
        tool: cleanText(candidate.tool) || undefined,
        tool_arguments: boundedArguments(candidate.tool_arguments),
        approval_required: candidate.approval_required === true,
        idempotency_key: cleanText(candidate.idempotency_key) || undefined,
        verification: cleanText(candidate.verification) || undefined,
        verification_tool: cleanText(candidate.verification_tool) || undefined,
        verification_arguments: boundedArguments(candidate.verification_arguments),
        rollback: cleanText(candidate.rollback) || undefined,
        max_attempts: boundedAttempts(candidate.max_attempts),
        acceptance_criteria_ids: cleanList(candidate.acceptance_criteria_ids),
      }];
    });
    const ids = new Set(steps.map((step) => step.id));
    const issues: string[] = [];
    for (const step of steps) {
      const unknown = step.depends_on.filter((id) => !ids.has(id));
      if (unknown.length > 0) issues.push(`${step.id} has unknown dependencies: ${unknown.join(", ")}`);
      if (step.depends_on.includes(step.id)) issues.push(`${step.id} depends on itself.`);
      if (Object.keys(step.tool_arguments).length > 0 && !step.tool) issues.push(`${step.id} has tool arguments but no tool.`);
      if (step.kind === "act" && !step.approval_required) issues.push(`${step.id} action has no approval gate.`);
      if (step.kind === "act" && !step.tool) issues.push(`${step.id} action has no exact tool.`);
      if (step.kind === "act" && !step.idempotency_key) issues.push(`${step.id} action has no idempotency key.`);
      if (step.kind === "act" && !step.verification) issues.push(`${step.id} action has no verification condition.`);
      if (step.kind === "act" && !step.verification_tool) issues.push(`${step.id} action has no independent verification tool.`);
      if (step.kind === "act" && !step.rollback) issues.push(`${step.id} action has no rollback.`);
    }
    if (hasCycle(steps)) issues.push("Workflow dependencies contain a cycle.");
    this.workflow = {
      objective: cleanText(input.objective) || "Complete the requested security work.",
      owner: cleanText(input.owner) || undefined,
      steps,
      completion_condition: cleanText(input.completion_condition) || "The final verification step passes.",
      valid: steps.length > 0 && issues.length === 0,
      issues: issues.slice(0, MAX_ITEMS),
    };
    return this.snapshot();
  }

  simulateAction(input: ActionSimulationInput): OperationalIntelligenceSnapshot {
    const evidenceReceipts = validReceipts(input.evidence_receipts, this.receiptIsValid);
    const affectedResources = cleanList(input.affected_resources);
    const risks = cleanList(input.risks);
    const rollback = cleanText(input.rollback) || undefined;
    const verification = cleanText(input.verification) || undefined;
    const blockers = [
      affectedResources.length === 0 ? "Impact scope has no affected resources." : "",
      risks.length === 0 ? "No action risks were recorded." : "",
      evidenceReceipts.length === 0 ? "No verified evidence receipt supports the simulation." : "",
      input.approval_required !== true ? "Action has no approval requirement." : "",
      !rollback ? "Rollback is not defined." : "",
      !verification ? "Post-action verification is not defined." : "",
    ].filter(Boolean);
    this.actionSimulation = {
      action: cleanText(input.action) || "unspecified action",
      target: cleanText(input.target) || "unspecified target",
      affected_resources: affectedResources,
      affected_owners: cleanList(input.affected_owners),
      risks,
      evidence_receipts: evidenceReceipts,
      approval_required: input.approval_required === true,
      rollback,
      verification,
      ready: blockers.length === 0,
      blockers,
    };
    return this.snapshot();
  }

  decideAttention(input: AttentionDecisionInput): OperationalIntelligenceSnapshot {
    const novelty = bounded(input.novelty, 0);
    const materiality = bounded(input.materiality, 0);
    const urgency = bounded(input.urgency, 0);
    const actionability = bounded(input.actionability, 0);
    const confidence = bounded(input.confidence, 0);
    const decisionNeeded = input.decision_needed === true;
    const score = round((novelty * 0.25) + (materiality * 0.3) + (urgency * 0.15) + (actionability * 0.2) + (confidence * 0.1) + (decisionNeeded ? 0.1 : 0));
    this.attention = {
      signal: cleanText(input.signal) || "unspecified signal",
      dedup_key: cleanText(input.dedup_key) || "unspecified",
      novelty,
      materiality,
      urgency,
      actionability,
      confidence,
      decision_needed: decisionNeeded,
      score,
      recommendation: decisionNeeded || score >= 0.62 ? "speak" : "suppress",
      reason: cleanText(input.reason) || (decisionNeeded ? "A decision is required." : `Earned-attention score is ${score}.`),
    };
    return this.snapshot();
  }

  snapshot(): OperationalIntelligenceSnapshot {
    return {
      world_facts: [...this.worldFacts],
      hypotheses: [...this.hypotheses],
      decisions: [...this.decisions],
      workflow: this.workflow,
      action_simulation: this.actionSimulation,
      attention: this.attention,
    };
  }

  telemetryAttributes(): Record<string, number | boolean | string> {
    return {
      "assistant.intelligence.world_fact_count": this.worldFacts.length,
      "assistant.intelligence.verified_fact_count": this.worldFacts.filter((fact) => fact.verified).length,
      "assistant.intelligence.hypothesis_count": this.hypotheses.length,
      "assistant.intelligence.open_hypothesis_count": this.hypotheses.filter((hypothesis) => hypothesis.status === "open").length,
      "assistant.intelligence.decision_count": this.decisions.length,
      "assistant.intelligence.workflow_present": Boolean(this.workflow),
      "assistant.intelligence.workflow_valid": this.workflow?.valid ?? false,
      "assistant.intelligence.simulation_ready": this.actionSimulation?.ready ?? false,
      "assistant.intelligence.attention_recommendation": this.attention?.recommendation ?? "unset",
    };
  }
}

function validReceipts(values: string[] | undefined, isValid: (receipt: string) => boolean): string[] {
  return cleanList(values).filter((receipt) => isValid(receipt));
}

function cleanList(values: string[] | undefined): string[] {
  return [...new Set((values ?? []).map(cleanText).filter(Boolean))].slice(0, MAX_ITEMS);
}

function cleanText(value: unknown): string {
  return typeof value === "string" ? value.replace(/\s+/g, " ").trim().slice(0, MAX_TEXT) : "";
}

function cleanIso(value: unknown): string | undefined {
  const text = cleanText(value);
  if (!text || Number.isNaN(Date.parse(text))) return undefined;
  return new Date(text).toISOString();
}

function boundedArguments(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const bounded = Object.fromEntries(Object.entries(value as Record<string, unknown>).slice(0, 40));
  return JSON.stringify(bounded).length <= 20_000 ? bounded : {};
}

function boundedAttempts(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(1, Math.min(3, Math.floor(value))) : 1;
}

function bounded(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : fallback;
}

function round(value: number): number {
  return Math.round(Math.max(0, Math.min(1, value)) * 1000) / 1000;
}

function uniqueId(requested: unknown, fallback: string, seen: Set<string>): string {
  const base = (cleanText(requested) || fallback).toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || fallback;
  let candidate = base;
  let suffix = 2;
  while (seen.has(candidate)) candidate = `${base}-${suffix++}`;
  seen.add(candidate);
  return candidate;
}

function worldFactState(value: unknown): WorldFactState {
  return value === "observed" || value === "expected" || value === "desired" ? value : "inferred";
}

function hypothesisStatus(value: unknown): HypothesisStatus {
  return value === "supported" || value === "contradicted" || value === "eliminated" ? value : "open";
}

function decisionStatus(value: unknown): OperationalDecision["status"] {
  return value === "approved" || value === "executed" || value === "superseded" ? value : "proposed";
}

function workflowStepKind(value: unknown): WorkflowStepKind {
  return value === "compare" || value === "verify" || value === "decide" || value === "act" || value === "monitor" || value === "rollback" ? value : "observe";
}

function hasCycle(steps: OperationalWorkflowStep[]): boolean {
  const byId = new Map(steps.map((step) => [step.id, step]));
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (id: string): boolean => {
    if (visiting.has(id)) return true;
    if (visited.has(id)) return false;
    visiting.add(id);
    for (const dependency of byId.get(id)?.depends_on ?? []) {
      if (byId.has(dependency) && visit(dependency)) return true;
    }
    visiting.delete(id);
    visited.add(id);
    return false;
  };
  return steps.some((step) => visit(step.id));
}
