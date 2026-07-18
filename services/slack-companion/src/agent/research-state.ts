import { createHmac, randomBytes } from "node:crypto";
import {
  OperationalIntelligenceState,
  type ActionSimulationInput,
  type AssistantExecutionLane,
  type AttentionDecisionInput,
  type DecisionInput,
  type HypothesisInput,
  type OperationalIntelligenceSnapshot,
  type SecurityDomainLens,
  type WorkflowCompileInput,
  type WorldFactInput,
} from "./operational-intelligence.js";
import { SourceHealthRegistry, type SourceHealthSnapshot } from "./source-health.js";
import { evidenceCandidatesFromToolResult, reconcileClaimEvidence, type EvidenceLedgerClaim } from "./evidence.js";
import type { SecurityAssistantAnswer, SecurityAssistantEvidenceRef } from "./security-assistant-types.js";
import type { AssistantThreadIntelligenceUpdate } from "./thread-intelligence-store.js";
import { sourceEvidenceEnvelope, type SourceEvidenceEnvelope } from "./evidence-envelope.js";
import { hasUsablePartialToolEvidence } from "./tools/tool-result.js";

const MAX_PLAN_ITEMS = 12;
const MAX_TOOL_RUNS = 24;

export const RESEARCH_PLAN_TOOL = "operator_research_plan";
export const CLAIM_LEDGER_TOOL = "operator_claim_ledger";
export const WORLD_STATE_TOOL = "operator_world_state";
export const HYPOTHESIS_LEDGER_TOOL = "operator_hypothesis_ledger";
export const DECISION_LEDGER_TOOL = "operator_decision_ledger";
export const WORKFLOW_COMPILE_TOOL = "operator_workflow_compile";
export const ACTION_SIMULATION_TOOL = "operator_action_simulation";
export const ATTENTION_DECISION_TOOL = "operator_attention_decision";

export type ResearchClaimStatus = "supported" | "contradicted" | "unverified" | "blocked";
export type AssistantExecutionStyle = "direct" | "code";

export interface ResearchPlanClaimInput {
  id?: string;
  claim?: string;
  required?: boolean;
  source_candidates?: string[];
}

export interface ResearchPlanInput {
  decision?: string;
  execution_lane?: string;
  execution_style?: string;
  domain_lenses?: string[];
  entities?: string[];
  claims?: ResearchPlanClaimInput[];
  source_candidates?: string[];
  selected_tools?: string[];
  stop_conditions?: string[];
  user_visible_work?: string[];
  missing_context?: string[];
}

export interface ClaimLedgerEntryInput {
  id?: string;
  status?: string;
  source_tools?: string[];
  evidence_receipts?: string[];
  evidence_refs?: string[];
  freshness?: string;
  source_scope?: string;
  coverage?: string;
  absence_meaning?: string;
  notes?: string;
}

export interface ClaimLedgerInput {
  claims?: ClaimLedgerEntryInput[];
  remaining_gaps?: string[];
  answer_ready?: boolean;
}

interface ResearchPlanClaim {
  id: string;
  claim: string;
  required: boolean;
  source_candidates: string[];
}

interface ResearchPlan {
  decision: string;
  execution_lane: AssistantExecutionLane;
  execution_style: AssistantExecutionStyle;
  domain_lenses: SecurityDomainLens[];
  entities: string[];
  claims: ResearchPlanClaim[];
  source_candidates: string[];
  selected_tools: string[];
  unknown_source_candidates: string[];
  temporarily_unavailable_sources: string[];
  source_health: SourceHealthSnapshot[];
  stop_conditions: string[];
  user_visible_work: string[];
  missing_context: string[];
}

interface ResearchToolRun {
  tool: string;
  status: "completed" | "partial" | "failed";
  failure_kind?: "availability" | "scope" | "result";
  evidence_receipt?: string;
  evidence_envelope?: SourceEvidenceEnvelope;
}

interface ClaimLedgerEntry {
  id: string;
  claim: string;
  required: boolean;
  status: ResearchClaimStatus;
  source_tools: string[];
  evidence_receipts: string[];
  evidence_refs: string[];
  freshness?: string;
  source_scope?: string;
  coverage?: string;
  absence_meaning?: string;
  notes?: string;
  verified: boolean;
}

interface ClaimLedger {
  claims: ClaimLedgerEntry[];
  remaining_gaps: string[];
  required_claims: number;
  verified_required_claims: number;
  coverage: number;
  answer_ready: boolean;
}

export class SecurityResearchState {
  private readonly availableTools = new Set<string>();
  private readonly toolRuns: ResearchToolRun[] = [];
  private readonly receiptKey = randomBytes(32);
  private readonly operational = new OperationalIntelligenceState((receipt, sourceTool) => this.hasEvidenceReceipt(receipt, sourceTool));
  private plan?: ResearchPlan;
  private ledger?: ClaimLedger;
  private readonly createdGoalIds: string[] = [];
  private readonly evidenceById = new Map<string, SecurityAssistantEvidenceRef>();

  constructor(
    private readonly sourceHealth = new SourceHealthRegistry(),
    private readonly audienceChannelId?: string,
  ) {}

  setAvailableTools(toolNames: string[]): void {
    this.availableTools.clear();
    toolNames.filter((name) => !isResearchControlTool(name)).forEach((name) => this.availableTools.add(name));
  }

  hasPlan(): boolean {
    return Boolean(this.plan);
  }

  toolAllowedByPlan(toolName: string): boolean {
    if (!this.plan) return false;
    const selected = new Set([...this.plan.selected_tools, ...this.plan.source_candidates, ...this.plan.claims.flatMap((claim) => claim.source_candidates)]);
    return selected.size === 0 || selected.has(toolName);
  }

  completionIssue(): string | undefined {
    if (this.plan && this.toolRuns.length > 0 && this.plan.claims.length === 0) return "research_plan_has_no_claims";
    if (this.plan && this.toolRuns.length > 0 && !this.ledger) return "claim_ledger_not_closed";
    return undefined;
  }

  establishPlan(input: ResearchPlanInput): Record<string, unknown> {
    const sourceCandidates = strings(input.source_candidates);
    const knownSources = this.sourceHealth.rank(sourceCandidates.filter((name) => this.availableTools.has(name)));
    const unknownSources = sourceCandidates.filter((name) => !this.availableTools.has(name));
    const claimSourceCandidates = (input.claims ?? []).flatMap((claim) => strings(claim.source_candidates));
    const plannedSources = this.sourceHealth.rank([...new Set([...knownSources, ...claimSourceCandidates.filter((name) => this.availableTools.has(name))])]);
    const sourceHealth = plannedSources.map((name) => this.sourceHealth.snapshot(name));
    const temporarilyUnavailableSources = sourceHealth.filter((item) => !item.allowed).map((item) => item.source);
    const seenIds = new Set<string>();
    const claims = (input.claims ?? []).slice(0, MAX_PLAN_ITEMS).flatMap((item, index) => {
      const claim = text(item.claim);
      if (!claim) return [];
      const requestedId = text(item.id) || `claim-${index + 1}`;
      const id = uniqueId(requestedId, seenIds);
      const candidates = this.sourceHealth.rank(strings(item.source_candidates).filter((name) => this.availableTools.has(name)));
      return [{
        id,
        claim,
        required: item.required !== false,
        source_candidates: candidates,
      }];
    });
    this.plan = {
      decision: text(input.decision) || "Answer the Slack request with verified current state.",
      execution_lane: executionLane(input.execution_lane),
      execution_style: executionStyle(input.execution_style),
      domain_lenses: domainLenses(input.domain_lenses),
      entities: strings(input.entities),
      claims,
      source_candidates: knownSources,
      selected_tools: strings(input.selected_tools).filter((name) => this.availableTools.has(name)),
      unknown_source_candidates: unknownSources,
      temporarily_unavailable_sources: temporarilyUnavailableSources,
      source_health: sourceHealth,
      stop_conditions: strings(input.stop_conditions),
      user_visible_work: strings(input.user_visible_work),
      missing_context: strings(input.missing_context),
    };
    this.ledger = undefined;
    return this.snapshot();
  }

  seedStagedPlan(input: {
    user_intent: string;
    execution_lane?: string;
    execution_style?: string;
    domain_lenses?: string[];
    claims?: Array<{ id: string; claim: string; required?: boolean; source_candidates?: string[] }>;
    research_plan?: string[];
    user_visible_work?: string[];
    required_sources?: string[];
    selected_tools?: string[];
    missing_context_questions?: string[];
  }): Record<string, unknown> {
    const claims = input.claims && input.claims.length > 0
      ? input.claims
      : (input.research_plan ?? []).map((claim, index) => ({
          id: `claim-${index + 1}`,
          claim,
          required: true,
          source_candidates: input.required_sources,
        }));
    return this.establishPlan({
      decision: input.user_intent,
      execution_lane: input.execution_lane,
      execution_style: input.execution_style,
      domain_lenses: input.domain_lenses,
      claims,
      source_candidates: input.required_sources,
      selected_tools: input.selected_tools,
      stop_conditions: ["Required claims are supported, contradicted, or explicitly blocked by a named source."],
      user_visible_work: input.user_visible_work,
      missing_context: input.missing_context_questions,
    });
  }

  recordToolResult(toolName: string, result: unknown, latencyMs = 0): { evidenceReceipt?: string } | undefined {
    if (isResearchControlTool(toolName)) return undefined;
    const details = objectValue((result as { details?: unknown } | undefined)?.details);
    const failed = Boolean(details?.error) || details?.success === false;
    const partial = failed && hasUsablePartialToolEvidence(details);
    if (failed && !partial) {
      const failureKind = classifyFailure(details);
      if (failureKind === "availability") this.sourceHealth.recordFailure(toolName, latencyMs);
      else this.sourceHealth.recordSuccess(toolName, latencyMs);
      this.pushToolRun({ tool: toolName, status: "failed", failure_kind: failureKind });
      return {};
    }
    const evidenceReceipt = this.issueEvidenceReceipt(toolName, details ?? result);
    const envelope = sourceEvidenceEnvelope(toolName, evidenceReceipt, details ?? result);
    for (const evidence of [...evidenceCandidatesFromToolResult(toolName, details, this.audienceChannelId), ...envelope.subjects]) {
      this.evidenceById.set(evidence.id, evidence);
    }
    this.sourceHealth.recordSuccess(toolName, latencyMs);
    this.pushToolRun({
      tool: toolName,
      status: partial ? "partial" : "completed",
      ...(partial ? { failure_kind: classifyFailure(details) } : {}),
      evidence_receipt: evidenceReceipt,
      evidence_envelope: envelope,
    });
    return { evidenceReceipt };
  }

  recordToolFailure(toolName: string, latencyMs = 0): void {
    if (isResearchControlTool(toolName)) return;
    this.sourceHealth.recordFailure(toolName, latencyMs);
    this.pushToolRun({ tool: toolName, status: "failed" });
  }

  sourceHealthSnapshot(toolName: string): SourceHealthSnapshot {
    return this.sourceHealth.snapshot(toolName);
  }

  lastToolFailed(toolName: string): boolean {
    const run = [...this.toolRuns].reverse().find((item) => item.tool === toolName);
    return run?.status === "failed";
  }

  toolFailureCount(toolName: string): number {
    return this.toolRuns.filter((run) => run.tool === toolName && run.status === "failed").length;
  }

  hasCurrentEvidenceReceipt(receipt: string): boolean {
    return this.hasEvidenceReceipt(receipt);
  }

  recordCreatedGoal(goalId: string): void {
    const cleaned = goalId.replace(/[^A-Za-z0-9_.:-]/g, "").slice(0, 160);
    if (cleaned && !this.createdGoalIds.includes(cleaned)) this.createdGoalIds.push(cleaned);
  }

  createdGoals(): string[] {
    return this.createdGoalIds.slice(0, 16);
  }

  reconcileClaimEvidence(answer: SecurityAssistantAnswer): SecurityAssistantAnswer {
    return reconcileClaimEvidence(
      answer,
      [...this.evidenceById.values()],
      (this.ledger?.claims ?? []) as EvidenceLedgerClaim[],
    );
  }

  closeClaimLedger(input: ClaimLedgerInput): Record<string, unknown> {
    const planClaims = this.plan?.claims ?? [];
    const submitted = new Map(stringsById(input.claims));
    const evidencedRuns = this.toolRuns.filter((run) => run.evidence_receipt);
    const receiptTools = new Map(evidencedRuns.map((run) => [run.evidence_receipt as string, run.tool]));
    const claims = planClaims.map((planned): ClaimLedgerEntry => {
      const entry = submitted.get(planned.id);
      const plannedSources = new Set(planned.source_candidates);
      const evidenceReceipts = strings(entry?.evidence_receipts).filter((receipt) => {
        const receiptTool = receiptTools.get(receipt);
        return Boolean(receiptTool) && (plannedSources.size === 0 || plannedSources.has(receiptTool as string));
      });
      const receiptSourceTools = new Set(evidenceReceipts.map((receipt) => receiptTools.get(receipt) as string));
      const sourceTools = strings(entry?.source_tools).filter((name) => receiptSourceTools.has(name));
      const status = claimStatus(entry?.status);
      const absenceSemanticsReady = !claimNeedsAbsenceSemantics(planned.claim)
        || Boolean(text(entry?.source_scope) && text(entry?.coverage) && text(entry?.absence_meaning));
      const verified = (status === "supported" || status === "contradicted") && evidenceReceipts.length > 0 && sourceTools.length > 0 && absenceSemanticsReady;
      return {
        id: planned.id,
        claim: planned.claim,
        required: planned.required,
        status: verified ? status : status === "blocked" ? "blocked" : "unverified",
        source_tools: sourceTools,
        evidence_receipts: evidenceReceipts,
        evidence_refs: strings(entry?.evidence_refs),
        freshness: text(entry?.freshness) || undefined,
        source_scope: text(entry?.source_scope) || undefined,
        coverage: text(entry?.coverage) || undefined,
        absence_meaning: text(entry?.absence_meaning) || undefined,
        notes: text(entry?.notes) || undefined,
        verified,
      };
    });
    const required = claims.filter((claim) => claim.required);
    const verifiedRequired = required.filter((claim) => claim.verified);
    const remainingGaps = strings(input.remaining_gaps);
    const coverage = required.length === 0 ? 1 : verifiedRequired.length / required.length;
    this.ledger = {
      claims,
      remaining_gaps: remainingGaps,
      required_claims: required.length,
      verified_required_claims: verifiedRequired.length,
      coverage,
      answer_ready: input.answer_ready !== false && coverage === 1 && remainingGaps.length === 0,
    };
    return this.snapshot();
  }

  telemetryAttributes(): Record<string, boolean | number | string> {
    const completed = this.toolRuns.filter((run) => run.status === "completed").length;
    const partial = this.toolRuns.filter((run) => run.status === "partial").length;
    const failed = this.toolRuns.filter((run) => run.status === "failed").length;
    const receipts = this.toolRuns.filter((run) => Boolean(run.evidence_receipt)).length;
    const unavailableSources = this.plan?.source_health.filter((source) => !source.allowed).length ?? 0;
    const scopeFailures = this.toolRuns.filter((run) => run.failure_kind === "scope").length;
    return {
      "assistant.research.plan_present": Boolean(this.plan),
      "assistant.research.claim_ledger_closed": Boolean(this.ledger),
      "assistant.research.required_claim_count": this.ledger?.required_claims ?? this.plan?.claims.filter((claim) => claim.required).length ?? 0,
      "assistant.research.verified_claim_count": this.ledger?.verified_required_claims ?? 0,
      "assistant.research.claim_coverage": this.ledger?.coverage ?? 0,
      "assistant.research.answer_ready": this.ledger?.answer_ready ?? false,
      "assistant.research.evidence_tool_completed_count": completed,
      "assistant.research.evidence_tool_partial_count": partial,
      "assistant.research.evidence_tool_failed_count": failed,
      "assistant.research.evidence_receipt_count": receipts,
      "assistant.research.source_candidate_count": this.plan?.source_health.length ?? 0,
      "assistant.research.source_cooldown_count": unavailableSources,
      "assistant.research.scope_failure_count": scopeFailures,
      "assistant.research.selected_tool_count": this.plan?.selected_tools.length ?? 0,
      ...this.operational.telemetryAttributes(),
    };
  }

  adaptivePlan(): {
    executionLane: AssistantExecutionLane;
    executionStyle: AssistantExecutionStyle;
    domainLenses: SecurityDomainLens[];
    selectedTools: string[];
    sourceCandidates: string[];
  } {
    return {
      executionLane: this.plan?.execution_lane ?? "investigate",
      executionStyle: this.plan?.execution_style ?? "direct",
      domainLenses: [...(this.plan?.domain_lenses ?? ["general"])],
      selectedTools: [...(this.plan?.selected_tools ?? [])],
      sourceCandidates: [...(this.plan?.source_candidates ?? [])],
    };
  }

  updateWorldState(input: { facts?: WorldFactInput[] }): Record<string, unknown> {
    this.operational.updateWorld(input);
    return this.snapshot();
  }

  updateHypotheses(input: { hypotheses?: HypothesisInput[] }): Record<string, unknown> {
    this.operational.updateHypotheses(input);
    return this.snapshot();
  }

  recordDecisions(input: { decisions?: DecisionInput[] }): Record<string, unknown> {
    this.operational.recordDecisions(input);
    return this.snapshot();
  }

  compileWorkflow(input: WorkflowCompileInput): Record<string, unknown> {
    this.operational.compileWorkflow(input);
    return this.snapshot();
  }

  simulateAction(input: ActionSimulationInput): Record<string, unknown> {
    this.operational.simulateAction(input);
    return this.snapshot();
  }

  decideAttention(input: AttentionDecisionInput): Record<string, unknown> {
    this.operational.decideAttention(input);
    return this.snapshot();
  }

  operationalSnapshot(): OperationalIntelligenceSnapshot {
    return this.operational.snapshot();
  }

  threadIntelligenceUpdate(): AssistantThreadIntelligenceUpdate {
    const operational = this.operational.snapshot();
    return {
      decision: this.plan?.decision,
      executionLane: this.plan?.execution_lane,
      domainLenses: this.plan?.domain_lenses,
      entities: [...new Set([
        ...(this.plan?.entities ?? []),
        ...this.toolRuns.flatMap((run) => run.evidence_envelope?.subjects.map((subject) => subject.subjectId ?? subject.sourceRef ?? "") ?? []),
      ].filter(Boolean))].slice(0, 24),
      claimCoverage: this.ledger?.coverage,
      answerReady: this.ledger?.answer_ready,
      remainingGaps: this.ledger?.remaining_gaps,
      toolCount: this.toolRuns.length,
      worldFacts: operational.world_facts,
      hypotheses: operational.hypotheses,
      decisions: operational.decisions,
      workflow: operational.workflow,
      attention: operational.attention,
    };
  }

  snapshot(): Record<string, unknown> {
    return {
      plan: this.plan,
      tool_runs: [...this.toolRuns],
      claim_ledger: this.ledger,
      operational_intelligence: this.operational.snapshot(),
    };
  }

  private pushToolRun(run: ResearchToolRun): void {
    this.toolRuns.push(run);
    if (this.toolRuns.length > MAX_TOOL_RUNS) this.toolRuns.splice(0, this.toolRuns.length - MAX_TOOL_RUNS);
  }

  private issueEvidenceReceipt(toolName: string, evidence: unknown): string {
    const digest = createHmac("sha256", this.receiptKey)
      .update(toolName)
      .update("\0")
      .update(stableJson(evidence))
      .digest("hex")
      .slice(0, 20);
    return `evidence:${toolName}:${digest}`;
  }

  private hasEvidenceReceipt(receipt: string, sourceTool?: string): boolean {
    return this.toolRuns.some((run) => run.status !== "failed"
      && run.evidence_receipt === receipt
      && (!sourceTool || run.tool === sourceTool));
  }
}

export function isResearchControlTool(toolName: string): boolean {
  return toolName === "operator_tool_catalog_search"
    || toolName === RESEARCH_PLAN_TOOL
    || toolName === CLAIM_LEDGER_TOOL
    || toolName === WORLD_STATE_TOOL
    || toolName === HYPOTHESIS_LEDGER_TOOL
    || toolName === DECISION_LEDGER_TOOL
    || toolName === WORKFLOW_COMPILE_TOOL
    || toolName === ACTION_SIMULATION_TOOL
    || toolName === ATTENTION_DECISION_TOOL;
}

function stringsById(entries: ClaimLedgerEntryInput[] | undefined): Array<[string, ClaimLedgerEntryInput]> {
  return (entries ?? []).flatMap((entry) => {
    const id = text(entry.id);
    return id ? [[id, entry] as [string, ClaimLedgerEntryInput]] : [];
  });
}

function strings(values: string[] | undefined): string[] {
  return [...new Set((values ?? []).map(text).filter((value): value is string => Boolean(value)))].slice(0, MAX_PLAN_ITEMS);
}

function text(value: unknown): string {
  return typeof value === "string" ? value.replace(/\s+/g, " ").trim().slice(0, 800) : "";
}

function uniqueId(requested: string, seen: Set<string>): string {
  const base = requested.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "claim";
  let candidate = base;
  let suffix = 2;
  while (seen.has(candidate)) candidate = `${base}-${suffix++}`;
  seen.add(candidate);
  return candidate;
}

function claimStatus(value: unknown): ResearchClaimStatus {
  return value === "supported" || value === "contradicted" || value === "blocked" ? value : "unverified";
}

function claimNeedsAbsenceSemantics(claim: string): boolean {
  return /\b(no|none|zero|absent|missing|not found|does not|did not|never|nothing)\b/i.test(claim);
}

function executionLane(value: unknown): AssistantExecutionLane {
  return value === "ignore" || value === "converse" || value === "continue" || value === "lookup" || value === "act" ? value : "investigate";
}

function executionStyle(value: unknown): AssistantExecutionStyle {
  return value === "code" ? "code" : "direct";
}

function domainLenses(values: string[] | undefined): SecurityDomainLens[] {
  const lenses = strings(values).filter((value): value is SecurityDomainLens => value === "identity"
    || value === "delivery"
    || value === "cloud"
    || value === "detection"
    || value === "compliance"
    || value === "incident"
    || value === "self"
    || value === "general");
  return lenses.length > 0 ? lenses : ["general"];
}

function objectValue(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function classifyFailure(details: Record<string, unknown> | undefined): "availability" | "scope" | "result" {
  const text = JSON.stringify(details ?? {}).toLowerCase();
  if (/\b(timeout|timed out|abort|rate limit|429|5\d\d|unavailable|network|connection|temporar)/.test(text)) return "availability";
  if (/\b(401|403|404|not found|not configured|not allowed|permission|forbidden|scope|missing|required|validation)/.test(text)) return "scope";
  return "result";
}

function stableJson(value: unknown, seen = new WeakSet<object>()): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(Number.isFinite(value) ? value : String(value));
  if (typeof value === "bigint") return JSON.stringify(value.toString());
  if (value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(String(value));
  if (seen.has(value)) return JSON.stringify("[Circular]");
  seen.add(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableJson(item, seen)).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    .sort(([left], [right]) => left.localeCompare(right));
  return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item, seen)}`).join(",")}}`;
}
