import {
  agentAcceptanceCriterionSchema,
  agentResourceKindSchema,
  canonicalResourceRef,
  parseAgentStepExecution,
  type AgentAcceptanceCriterion,
  type AgentResourceRef,
} from "../../autonomy/agent-run.js";
import type { AutonomyPlanStep } from "../../autonomy/goals.js";

export interface OperatorAgentRunArgs {
  assumptions?: string[];
  resources?: OperatorGoalResourceArgs[];
  acceptance_criteria?: OperatorGoalCriterionArgs[];
  plan?: OperatorGoalStepArgs[];
}

interface OperatorGoalResourceArgs {
  kind?: string;
  id?: string;
  source?: string;
  label?: string;
  observed_at?: string;
  valid_until?: string;
  evidence_receipt?: string;
  confidence?: number;
  links?: Array<{ relation?: string; target_uri?: string }>;
}

interface OperatorGoalCriterionArgs {
  id?: string;
  description?: string;
  kind?: string;
  field?: string;
  expected?: string | number | boolean;
}

interface OperatorGoalStepArgs {
  id?: string;
  title?: string;
  depends_on?: string[];
  tool_name?: string;
  tool_arguments?: Record<string, unknown>;
  verification_tool_name?: string;
  verification_arguments?: Record<string, unknown>;
  approval_required?: boolean;
  idempotency_key?: string;
  rollback?: string;
  max_attempts?: number;
  acceptance_criteria_ids?: string[];
}

export function buildOperatorAgentRunContext(input: OperatorAgentRunArgs): {
  plan: AutonomyPlanStep[];
  resourceRefs: AgentResourceRef[];
  acceptanceCriteria: AgentAcceptanceCriterion[];
  assumptions?: string[];
} {
  const plan = agentPlan(input.plan);
  const resourceRefs = agentResources(input.resources);
  const acceptanceCriteria = agentCriteria(input.acceptance_criteria);
  validateAcceptance(plan, acceptanceCriteria);
  return { plan, resourceRefs, acceptanceCriteria, assumptions: stringList(input.assumptions) };
}

function agentPlan(input: OperatorGoalStepArgs[] | undefined): AutonomyPlanStep[] {
  const steps = (input ?? []).map((candidate, index) => {
    const id = stringValue(candidate.id) ?? `step-${index + 1}`;
    const title = stringValue(candidate.title);
    if (!title) throw new Error(`plan[${index}].title is required`);
    const toolName = stringValue(candidate.tool_name);
    const execution = toolName ? parseAgentStepExecution({
      toolName,
      arguments: candidate.tool_arguments ?? {},
      verificationToolName: stringValue(candidate.verification_tool_name),
      verificationArguments: candidate.verification_arguments ?? {},
      approvalRequired: candidate.approval_required === true,
      idempotencyKey: stringValue(candidate.idempotency_key),
      rollback: stringValue(candidate.rollback),
      maxAttempts: candidate.max_attempts ?? 1,
      attempts: 0,
    }) : undefined;
    if (toolName && !execution) throw new Error(`plan[${index}] has invalid or secret-like execution fields`);
    if (!toolName && (candidate.tool_arguments || candidate.verification_tool_name)) {
      throw new Error(`plan[${index}].tool_name is required for executable fields`);
    }
    return {
      id, title, status: "pending" as const, dependsOn: stringList(candidate.depends_on) ?? [], execution,
      acceptanceCriteriaIds: stringList(candidate.acceptance_criteria_ids),
    };
  });
  validatePlan(steps);
  return steps;
}

function validatePlan(steps: AutonomyPlanStep[]): void {
  const ids = new Set<string>();
  for (const step of steps) {
    if (ids.has(step.id)) throw new Error(`Duplicate plan step id ${step.id}`);
    ids.add(step.id);
  }
  for (const step of steps) {
    const unknown = step.dependsOn.filter((dependency) => !ids.has(dependency));
    if (unknown.length > 0) throw new Error(`${step.id} has unknown dependencies: ${unknown.join(", ")}`);
  }
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const byId = new Map(steps.map((step) => [step.id, step]));
  const visit = (id: string): void => {
    if (visiting.has(id)) throw new Error("Agent run plan contains a dependency cycle");
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of byId.get(id)?.dependsOn ?? []) visit(dependency);
    visiting.delete(id);
    visited.add(id);
  };
  for (const step of steps) visit(step.id);
}

function validateAcceptance(steps: AutonomyPlanStep[], criteria: AgentAcceptanceCriterion[]): void {
  const ids = new Set(criteria.map((criterion) => criterion.id));
  for (const step of steps) {
    const criterionIds = step.acceptanceCriteriaIds ?? [];
    if (step.execution && criterionIds.length === 0) throw new Error(`Executable plan step ${step.id} needs at least one acceptance criterion`);
    const unknown = criterionIds.filter((id) => !ids.has(id));
    if (unknown.length > 0) throw new Error(`${step.id} has unknown acceptance criteria: ${unknown.join(", ")}`);
  }
}

function agentResources(input: OperatorGoalResourceArgs[] | undefined): AgentResourceRef[] {
  return (input ?? []).map((candidate, index) => {
    const id = stringValue(candidate.id);
    if (!id) throw new Error(`resources[${index}].id is required`);
    return canonicalResourceRef({
      kind: agentResourceKindSchema.parse(candidate.kind), id, source: stringValue(candidate.source), label: stringValue(candidate.label),
      observedAt: stringValue(candidate.observed_at), validUntil: stringValue(candidate.valid_until), evidenceReceipt: stringValue(candidate.evidence_receipt),
      confidence: candidate.confidence,
      links: (candidate.links ?? []).flatMap((link) => {
        const relation = stringValue(link.relation);
        const targetUri = stringValue(link.target_uri);
        return relation && targetUri ? [{ relation, targetUri }] : [];
      }),
    });
  });
}

function agentCriteria(input: OperatorGoalCriterionArgs[] | undefined): AgentAcceptanceCriterion[] {
  return (input ?? []).map((candidate, index) => agentAcceptanceCriterionSchema.parse({
    id: stringValue(candidate.id) ?? `criterion-${index + 1}`, description: stringValue(candidate.description), kind: stringValue(candidate.kind),
    field: stringValue(candidate.field), expected: candidate.expected, status: "pending", evidenceRefs: [],
  }));
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function stringList(values: string[] | undefined): string[] | undefined {
  const cleaned = (values ?? []).map((value) => value.trim()).filter(Boolean);
  return cleaned.length > 0 ? [...new Set(cleaned)] : undefined;
}
