import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  SPECIALIST_ROLES,
  resolveSpecialistAssignments,
  type SpecialistPlanContext,
  type SpecialistRole,
} from "../src/agent/specialist-team.js";

interface Scenario {
  name: string;
  plan: SpecialistPlanContext;
  required: SpecialistRole[];
  forbidden?: SpecialistRole[];
}

interface ScenarioResult {
  name: string;
  status: "pass" | "fail";
  assigned: SpecialistRole[];
  missing: SpecialistRole[];
  unexpected: SpecialistRole[];
}

const base: SpecialistPlanContext = {
  user_intent: "Resolve the request with current evidence.",
  execution_lane: "lookup",
  domain_lenses: ["general"],
  selected_tools: ["slack_ai_search"],
  claims: [{}],
  research_plan: ["Check the source."],
};

const scenarios: Scenario[] = [
  selectedScenario("company precedent", ["librarian", "researcher"]),
  selectedScenario("current fact lookup", ["researcher"]),
  selectedScenario("multi-source analysis", ["researcher", "analyst", "qa"], { execution_lane: "investigate", claims: [{}, {}] }),
  selectedScenario("coordinated action", ["coordinator", "developer", "qa"], { execution_lane: "act", research_plan: ["inspect", "change", "verify", "report"] }),
  selectedScenario("incident triage", ["triage", "researcher"], { domain_lenses: ["incident"] }),
  selectedScenario("code change", ["developer", "qa"], { selected_tools: ["cerebro_code_workspace_patch"] }),
  selectedScenario("control evidence", ["compliance", "researcher"], { domain_lenses: ["compliance"], selected_tools: ["cerebro_compliance_context"] }),
  scenario("host inference disabled", { execution_lane: "act", domain_lenses: ["incident", "compliance"], selected_tools: ["cerebro_code_workspace_patch", "company_library_search"], claims: [{}, {}], research_plan: ["inspect", "change", "verify", "report"] }, [], SPECIALIST_ROLES),
];

const results = scenarios.map(evaluate);
const pass = results.filter((result) => result.status === "pass").length;
const report = {
  generatedAt: new Date().toISOString(),
  summary: { scenarios: results.length, pass, fail: results.length - pass },
  results,
};
const outDir = path.join(process.cwd(), "tmp");
mkdirSync(outDir, { recursive: true });
const jsonPath = path.join(outDir, "specialist-routing-eval.json");
const markdownPath = path.join(outDir, "specialist-routing-eval.md");
writeFileSync(jsonPath, JSON.stringify(report, null, 2) + "\n", "utf8");
writeFileSync(markdownPath, renderMarkdown(report), "utf8");

console.log(`Specialist routing eval: ${pass}/${results.length} passed.`);
console.log(`JSON: ${jsonPath}`);
console.log(`Markdown: ${markdownPath}`);
if (pass !== results.length) process.exitCode = 1;

function scenario(name: string, overrides: Partial<SpecialistPlanContext>, required: SpecialistRole[], forbidden?: SpecialistRole[]): Scenario {
  return { name, plan: { ...base, ...overrides }, required, ...(forbidden ? { forbidden } : {}) };
}

function selectedScenario(name: string, selected: SpecialistRole[], overrides: Partial<SpecialistPlanContext> = {}): Scenario {
  const specialists = selected.map((role) => ({ role, objective: `Complete ${role} work for the request.`, deliverables: [], depends_on: [] }));
  return scenario(name, { ...overrides, specialists }, selected, SPECIALIST_ROLES.filter((role) => !selected.includes(role)));
}

function evaluate(input: Scenario): ScenarioResult {
  const assigned = resolveSpecialistAssignments(input.plan).map((assignment) => assignment.role);
  const missing = input.required.filter((role) => !assigned.includes(role));
  const unexpected = (input.forbidden ?? []).filter((role) => assigned.includes(role));
  return {
    name: input.name,
    status: missing.length === 0 && unexpected.length === 0 ? "pass" : "fail",
    assigned,
    missing,
    unexpected,
  };
}

function renderMarkdown(report: { generatedAt: string; summary: { scenarios: number; pass: number; fail: number }; results: ScenarioResult[] }): string {
  return [
    "# Specialist routing eval",
    "",
    `Generated: ${report.generatedAt}`,
    "",
    `Result: ${report.summary.pass}/${report.summary.scenarios} passed; ${report.summary.fail} failed.`,
    "",
    "| Scenario | Result | Assigned roles | Missing | Unexpected |",
    "| --- | --- | --- | --- | --- |",
    ...report.results.map((result) => `| ${result.name} | ${result.status} | ${result.assigned.join(", ") || "none"} | ${result.missing.join(", ") || "none"} | ${result.unexpected.join(", ") || "none"} |`),
    "",
  ].join("\n");
}
