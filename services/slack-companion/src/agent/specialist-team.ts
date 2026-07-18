import * as v from "valibot";

export const SPECIALIST_ROLES = [
  "librarian",
  "researcher",
  "analyst",
  "coordinator",
  "triage",
  "qa",
  "developer",
  "compliance",
] as const;

export type SpecialistRole = typeof SPECIALIST_ROLES[number];

export const specialistRoleSchema = v.picklist(SPECIALIST_ROLES);

export const specialistAssignmentSchema = v.object({
  role: specialistRoleSchema,
  objective: v.pipe(v.string(), v.minLength(1)),
  deliverables: v.optional(v.array(v.pipe(v.string(), v.minLength(1))), []),
  depends_on: v.optional(v.array(specialistRoleSchema), []),
});

export const specialistWorkSchema = v.object({
  role: specialistRoleSchema,
  status: v.picklist(["completed", "blocked"]),
  findings: v.optional(v.array(v.pipe(v.string(), v.minLength(1))), []),
  recommendations: v.optional(v.array(v.pipe(v.string(), v.minLength(1))), []),
  actions: v.optional(v.array(v.pipe(v.string(), v.minLength(1))), []),
  checks: v.optional(v.array(v.pipe(v.string(), v.minLength(1))), []),
  blockers: v.optional(v.array(v.pipe(v.string(), v.minLength(1))), []),
  evidence_receipts: v.optional(v.array(v.pipe(v.string(), v.minLength(1))), []),
  handoff: v.optional(v.string()),
});

export type SpecialistAssignment = v.InferOutput<typeof specialistAssignmentSchema>;
export type SpecialistWork = v.InferOutput<typeof specialistWorkSchema>;

interface SpecialistContract {
  objective: string;
  deliverables: string[];
  completion: string;
}

const SPECIALIST_CONTRACTS: Record<SpecialistRole, SpecialistContract> = {
  librarian: {
    objective: "Find company precedent and preserve source-backed knowledge that will be useful again.",
    deliverables: ["relevant precedent", "source references", "conflicts or staleness", "durable learning candidate"],
    completion: "Cite the library or memory receipts used and distinguish historical precedent from current state.",
  },
  researcher: {
    objective: "Gather the smallest set of current first-party evidence needed to answer the request.",
    deliverables: ["source findings", "coverage and time window", "evidence receipts", "remaining uncertainty"],
    completion: "Attach each factual finding to the exact source subject and host-issued evidence receipt that covers it.",
  },
  analyst: {
    objective: "Compare the evidence, test competing explanations, and turn facts into a decision.",
    deliverables: ["comparison or drivers", "supported conclusion", "confidence and uncertainty", "recommendation"],
    completion: "Show which evidence separates the leading explanation from the alternatives.",
  },
  coordinator: {
    objective: "Turn the request into owned steps, dependencies, decisions, and a verified finish state.",
    deliverables: ["ordered actions", "owners and dependencies", "decision or approval needed", "completion check"],
    completion: "Persist unfinished Cerebro-owned work and leave each open loop with one owner and next action.",
  },
  triage: {
    objective: "Determine severity, affected scope, urgency, and the next containment or investigation action.",
    deliverables: ["severity and rationale", "affected scope", "priority", "immediate action"],
    completion: "Separate observed impact from possible impact and name the next check that changes priority.",
  },
  qa: {
    objective: "Test the answer, evidence coverage, and completed actions against the request and acceptance criteria.",
    deliverables: ["claim checks", "coverage and freshness checks", "action verification", "release blockers"],
    completion: "Record concrete checks; block completion when a required claim or acceptance check is open.",
  },
  developer: {
    objective: "Inspect, change, and verify code or runtime behavior within the available workspace and deployment tools.",
    deliverables: ["root cause or code finding", "implemented change", "validation output", "deployment or rollback state"],
    completion: "Name the changed artifact and exact validation performed; do not call work finished on an unverified write.",
  },
  compliance: {
    objective: "Map the request to controls, policy, evidence, exceptions, and audit-safe next actions.",
    deliverables: ["control or policy mapping", "evidence status", "gap or exception", "review action"],
    completion: "Cite the governing context and current evidence separately; state missing evidence without treating it as control failure.",
  },
};

export interface SpecialistPlanContext {
  user_intent: string;
  execution_lane: "ignore" | "converse" | "continue" | "lookup" | "investigate" | "act";
  domain_lenses: string[];
  selected_tools: string[];
  claims: unknown[];
  research_plan: string[];
  specialists?: SpecialistAssignment[];
}

const MAX_SPECIALISTS = SPECIALIST_ROLES.length;

export function resolveSpecialistAssignments(plan: SpecialistPlanContext): SpecialistAssignment[] {
  if (plan.execution_lane === "ignore") return [];
  const requested = plan.specialists ?? [];
  const selectedRoles = unique(requested.map((assignment) => assignment.role)).slice(0, MAX_SPECIALISTS);
  const selected = new Set(selectedRoles);
  const requestedByRole = new Map<SpecialistRole, SpecialistAssignment>();
  for (const assignment of requested) {
    if (!requestedByRole.has(assignment.role)) requestedByRole.set(assignment.role, assignment);
  }
  return selectedRoles.map((role) => {
    const explicit = requestedByRole.get(role);
    const contract = SPECIALIST_CONTRACTS[role];
    return {
      role,
      objective: explicit?.objective.trim() || contract.objective,
      deliverables: explicit?.deliverables.length ? unique(explicit.deliverables) : [...contract.deliverables],
      depends_on: dependenciesFor(role, explicit?.depends_on ?? [], selected),
    };
  });
}

export interface SpecialistCoverage {
  assignedCount: number;
  completedCount: number;
  blockedCount: number;
  incompleteCount: number;
  coverage: number;
  roles: SpecialistRole[];
  missingRoles: SpecialistRole[];
  incompleteRoles: SpecialistRole[];
}

export function assessSpecialistWork(assignments: SpecialistAssignment[], work: SpecialistWork[]): SpecialistCoverage {
  const byRole = new Map<SpecialistRole, SpecialistWork>();
  for (const receipt of work) {
    if (!byRole.has(receipt.role)) byRole.set(receipt.role, receipt);
  }
  const missingRoles: SpecialistRole[] = [];
  const incompleteRoles: SpecialistRole[] = [];
  let completedCount = 0;
  let blockedCount = 0;
  for (const assignment of assignments) {
    const receipt = byRole.get(assignment.role);
    if (!receipt) {
      missingRoles.push(assignment.role);
    } else if (receipt.status === "blocked") {
      if (receipt.blockers.length > 0) blockedCount += 1;
      else incompleteRoles.push(assignment.role);
    } else if (specialistWorkIsComplete(receipt)) {
      completedCount += 1;
    } else {
      incompleteRoles.push(assignment.role);
    }
  }
  const accepted = completedCount + blockedCount;
  return {
    assignedCount: assignments.length,
    completedCount,
    blockedCount,
    incompleteCount: missingRoles.length + incompleteRoles.length,
    coverage: assignments.length === 0 ? 1 : accepted / assignments.length,
    roles: assignments.map((assignment) => assignment.role),
    missingRoles,
    incompleteRoles,
  };
}

export function specialistExecutionFields(assignments: SpecialistAssignment[], work: SpecialistWork[]): {
  specialistRoles: SpecialistRole[];
  specialistCount: number;
  specialistCompletedCount: number;
  specialistBlockedCount: number;
  specialistIncompleteCount: number;
  specialistCoverage: number;
} {
  const coverage = assessSpecialistWork(assignments, work);
  return {
    specialistRoles: coverage.roles,
    specialistCount: coverage.assignedCount,
    specialistCompletedCount: coverage.completedCount,
    specialistBlockedCount: coverage.blockedCount,
    specialistIncompleteCount: coverage.incompleteCount,
    specialistCoverage: coverage.coverage,
  };
}

export function specialistTelemetryAttributes(execution: ReturnType<typeof specialistExecutionFields> | undefined): Record<string, number | string> {
  if (!execution) return {};
  return {
    "assistant.specialist.roles": execution.specialistRoles.join(","),
    "assistant.specialist.assigned_count": execution.specialistCount,
    "assistant.specialist.completed_count": execution.specialistCompletedCount,
    "assistant.specialist.blocked_count": execution.specialistBlockedCount,
    "assistant.specialist.incomplete_count": execution.specialistIncompleteCount,
    "assistant.specialist.coverage": execution.specialistCoverage,
  };
}

export function specialistOperatingStandard(): string[] {
  return [
    "Use one coordinated agent loop. In the research plan, assign only the specialist roles needed for this request; roles are private work contracts, not user-facing personas. The host preserves that bounded selection and does not infer extra roles from keywords, tools, lenses, claim counts, or plan length.",
    "Ask every assigned specialist for a completed work receipt or a concrete blocker. QA records the checks it performed. Evidence roles retain only exact host-issued source receipts. A partial receipt supports only returned facts and subjects, never the missing slice; never cite a failed-without-receipt or invented receipt.",
    "A missing or incomplete private specialist receipt is an internal coverage signal. Preserve the grounded answer, record aggregate incomplete coverage, and never expose the gap as a model, schema, prompt, contract, role, or retry error in Slack.",
    "Combine verified specialist work into one direct teammate response. Lead with the result, bind mutable facts to the exact subject and source, state failed or partial coverage that limits the conclusion, and never claim an action happened unless successful evidence says it happened.",
  ];
}

export function specialistAssignmentPrompt(assignments: SpecialistAssignment[]): string {
  if (assignments.length === 0) return "No specialist work is assigned for this turn.";
  const contracts = assignments.map((assignment) => ({
    ...assignment,
    completion: SPECIALIST_CONTRACTS[assignment.role].completion,
  }));
  return [
    "Complete these specialist assignments inside this research stage:",
    "Use only these assigned roles. Do not create or infer additional specialist roles.",
    "Use only exact host-issued evidence receipts. A partial receipt covers only returned facts and subjects, never the missing slice. A private receipt gap must not replace a grounded answer with an internal error.",
    JSON.stringify(contracts, null, 2),
  ].join("\n");
}

function dependenciesFor(role: SpecialistRole, explicit: SpecialistRole[], selected: Set<SpecialistRole>): SpecialistRole[] {
  const dependencies = [...explicit];
  if (role === "analyst" && selected.has("researcher")) dependencies.push("researcher");
  if (role === "qa") dependencies.push(...[...selected].filter((candidate) => candidate !== "qa" && candidate !== "coordinator"));
  return unique(dependencies).filter((candidate) => candidate !== role && selected.has(candidate));
}

function specialistWorkIsComplete(work: SpecialistWork): boolean {
  const hasFinding = work.findings.length > 0 || work.recommendations.length > 0;
  if (work.role === "researcher" || work.role === "librarian" || work.role === "compliance") {
    return hasFinding && work.evidence_receipts.length > 0;
  }
  if (work.role === "qa") return work.checks.length > 0;
  if (work.role === "developer") return (hasFinding || work.actions.length > 0) && work.checks.length > 0;
  if (work.role === "coordinator") return work.actions.length > 0 || work.recommendations.length > 0 || Boolean(work.handoff?.trim());
  return hasFinding;
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
