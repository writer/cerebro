import assert from "node:assert/strict";
import test from "node:test";
import {
  assessSpecialistWork,
  resolveSpecialistAssignments,
  specialistExecutionFields,
  specialistOperatingStandard,
  specialistTelemetryAttributes,
  type SpecialistAssignment,
  type SpecialistPlanContext,
  type SpecialistRole,
  type SpecialistWork,
} from "../src/agent/specialist-team.js";

function plan(overrides: Partial<SpecialistPlanContext> = {}): SpecialistPlanContext {
  return {
    user_intent: "Answer the request with current evidence.",
    execution_lane: "lookup",
    domain_lenses: ["general"],
    selected_tools: ["slack_ai_search"],
    claims: [{}],
    research_plan: ["Check the source."],
    ...overrides,
  };
}

function roles(overrides: Partial<SpecialistPlanContext> = {}): SpecialistRole[] {
  return resolveSpecialistAssignments(plan(overrides)).map((assignment) => assignment.role);
}

test("specialist routing preserves a bounded model-selected team", () => {
  const explicit: SpecialistAssignment[] = [
    { role: "researcher", objective: "Check current evidence.", deliverables: ["finding"], depends_on: [] },
    { role: "qa", objective: "Verify the result.", deliverables: ["checks"], depends_on: ["researcher"] },
  ];
  const assignments = resolveSpecialistAssignments(plan({ specialists: explicit }));
  assert.deepEqual(assignments.map((assignment) => assignment.role), ["researcher", "qa"]);
  assert.deepEqual(assignments.find((assignment) => assignment.role === "qa")?.depends_on, ["researcher"]);
});

test("specialist routing does not infer private roles from host-side work shape", () => {
  const assignments = resolveSpecialistAssignments(plan());
  assert.deepEqual(assignments, []);
  assert.deepEqual(roles({ execution_lane: "investigate", claims: [{}, {}] }), []);
  assert.deepEqual(roles({ execution_lane: "act", domain_lenses: ["incident", "compliance"], selected_tools: ["cerebro_code_workspace_patch", "company_library_search"], research_plan: ["one", "two", "three", "four"] }), []);
});

test("specialist routing preserves explicit assignments, removes duplicates, and stays bounded", () => {
  const assignments = resolveSpecialistAssignments(plan({
    execution_lane: "act",
    domain_lenses: ["incident", "compliance"],
    selected_tools: ["cerebro_code_workspace_patch", "company_library_search", "cerebro_compliance_context"],
    claims: [{}, {}],
    research_plan: ["one", "two", "three", "four"],
    specialists: [{
      role: "analyst",
      objective: "Decide which remediation path has the best evidence.",
      deliverables: ["decision table", "decision table"],
      depends_on: ["researcher"],
    }, {
      role: "analyst",
      objective: "This duplicate assignment must be removed.",
      deliverables: ["duplicate"],
      depends_on: [],
    }, {
      role: "researcher",
      objective: "Collect evidence.",
      deliverables: ["receipts"],
      depends_on: [],
    }],
  }));

  assert.equal(assignments.length, 2);
  assert.equal(new Set(assignments.map((assignment) => assignment.role)).size, 2);
  assert.equal(assignments[0]?.role, "analyst");
  assert.deepEqual(assignments[0]?.deliverables, ["decision table"]);
});

test("specialist routing does no private work for ignored input", () => {
  assert.deepEqual(roles({ execution_lane: "ignore" }), []);
});

test("specialist coverage requires evidence receipts and concrete QA checks", () => {
  const assignments: SpecialistAssignment[] = [
    { role: "researcher", objective: "Check current state.", deliverables: ["finding"], depends_on: [] },
    { role: "qa", objective: "Verify the answer.", deliverables: ["checks"], depends_on: ["researcher"] },
  ];
  const incomplete: SpecialistWork[] = [
    { role: "researcher", status: "completed", findings: ["The source is healthy."], recommendations: [], actions: [], checks: [], blockers: [], evidence_receipts: [], handoff: undefined },
    { role: "qa", status: "completed", findings: [], recommendations: [], actions: [], checks: [], blockers: [], evidence_receipts: [], handoff: undefined },
  ];
  const coverage = assessSpecialistWork(assignments, incomplete);

  assert.equal(coverage.coverage, 0);
  assert.deepEqual(coverage.incompleteRoles, ["researcher", "qa"]);
});

test("missing specialist receipts remain visible without blocking the answer", () => {
  const assignments: SpecialistAssignment[] = [
    { role: "researcher", objective: "Check current state.", deliverables: ["finding"], depends_on: [] },
    { role: "qa", objective: "Verify the answer.", deliverables: ["checks"], depends_on: ["researcher"] },
  ];

  assert.deepEqual(specialistExecutionFields(assignments, []), {
    specialistRoles: ["researcher", "qa"],
    specialistCount: 2,
    specialistCompletedCount: 0,
    specialistBlockedCount: 0,
    specialistIncompleteCount: 2,
    specialistCoverage: 0,
  });
});

test("specialist coverage accepts completed work and named blockers", () => {
  const assignments: SpecialistAssignment[] = [
    { role: "researcher", objective: "Check current state.", deliverables: ["finding"], depends_on: [] },
    { role: "qa", objective: "Verify the answer.", deliverables: ["checks"], depends_on: ["researcher"] },
  ];
  const work: SpecialistWork[] = [
    { role: "researcher", status: "completed", findings: ["The source is healthy."], recommendations: [], actions: [], checks: [], blockers: [], evidence_receipts: ["receipt-1"], handoff: undefined },
    { role: "qa", status: "blocked", findings: [], recommendations: [], actions: [], checks: [], blockers: ["The deployment has not finished."], evidence_receipts: [], handoff: undefined },
  ];
  const coverage = assessSpecialistWork(assignments, work);

  assert.equal(coverage.coverage, 1);
  assert.equal(coverage.completedCount, 1);
  assert.equal(coverage.blockedCount, 1);
});

test("specialist telemetry uses stable aggregate fields without work content", () => {
  const attributes = specialistTelemetryAttributes({
    specialistRoles: ["researcher", "qa"],
    specialistCount: 2,
    specialistCompletedCount: 2,
    specialistBlockedCount: 0,
    specialistIncompleteCount: 0,
    specialistCoverage: 1,
  });

  assert.deepEqual(attributes, {
    "assistant.specialist.roles": "researcher,qa",
    "assistant.specialist.assigned_count": 2,
    "assistant.specialist.completed_count": 2,
    "assistant.specialist.blocked_count": 0,
    "assistant.specialist.incomplete_count": 0,
    "assistant.specialist.coverage": 1,
  });
  assert.match(specialistOperatingStandard().join("\n"), /private work contracts/);
  assert.match(specialistOperatingStandard().join("\n"), /must not replace a grounded answer|Preserve the grounded answer/);
});
