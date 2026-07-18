import assert from "node:assert/strict";
import test from "node:test";
import { CLAIM_LEDGER_TOOL, RESEARCH_PLAN_TOOL, SecurityResearchState } from "../src/agent/research-state.js";
import { SecurityAssistantToolHooks } from "../src/agent/security-assistant-tool-hooks.js";
import { SourceHealthRegistry } from "../src/agent/source-health.js";

test("assistant tool hooks require a plan without charging control tools to the research budget", async () => {
  const researchState = new SecurityResearchState();
  const researchTrail: string[] = [];
  const evidenceTool = "cerebro_findings";
  researchState.setAvailableTools([RESEARCH_PLAN_TOOL, CLAIM_LEDGER_TOOL, evidenceTool]);
  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set([RESEARCH_PLAN_TOOL, CLAIM_LEDGER_TOOL, evidenceTool]),
    inferredIntent: "security_answer",
    maxResearchSteps: 1,
    researchState,
    researchTrail,
  });

  const blocked = await hooks.beforePi({ toolCall: { name: evidenceTool } });
  assert.match(blocked?.reason ?? "", /operator_research_plan/);
  assert.equal(hooks.count, 0);
  assert.equal(await hooks.beforePi({ toolCall: { name: RESEARCH_PLAN_TOOL } }), undefined);
  assert.equal(hooks.count, 0);

  researchState.establishPlan({
    decision: "Check the current finding state.",
    claims: [{ id: "finding-current", claim: "The finding is current.", source_candidates: [evidenceTool] }],
  });
  assert.equal(await hooks.beforePi({ toolCall: { name: evidenceTool } }), undefined);
  assert.equal(hooks.count, 1);

  researchState.recordToolResult(evidenceTool, { details: { error: "service unavailable" } });
  await hooks.afterPi({ toolCall: { name: evidenceTool }, isError: false });
  assert.deepEqual(researchTrail, [`${evidenceTool}: failed`]);
});

test("assistant tool hooks block cooled-down sources without spending research budget", async () => {
  const sourceHealth = new SourceHealthRegistry({ failureThreshold: 2, cooldownMs: 60_000 });
  sourceHealth.recordFailure("cerebro_findings");
  sourceHealth.recordFailure("cerebro_findings");
  const researchState = new SecurityResearchState(sourceHealth);
  researchState.setAvailableTools(["cerebro_findings"]);
  researchState.establishPlan({
    decision: "Check findings.",
    claims: [{ id: "finding-current", claim: "The finding is current.", source_candidates: ["cerebro_findings"] }],
    source_candidates: ["cerebro_findings"],
  });
  const plan = researchState.snapshot() as any;
  assert.deepEqual(plan.plan.temporarily_unavailable_sources, ["cerebro_findings"]);

  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set(["cerebro_findings"]),
    inferredIntent: "security_answer",
    maxResearchSteps: 3,
    researchState,
    researchTrail: [],
  });
  const blocked = await hooks.beforePi({ toolCall: { name: "cerebro_findings" } });
  assert.match(blocked?.reason ?? "", /temporarily unavailable/);
  assert.match(blocked?.reason ?? "", /Choose another planned source/);
  assert.equal(hooks.count, 0);
});

test("repeated scope failures open a per-answer circuit without disabling the shared source", async () => {
  const sourceHealth = new SourceHealthRegistry({ failureThreshold: 2, cooldownMs: 60_000 });
  const researchState = new SecurityResearchState(sourceHealth);
  researchState.setAvailableTools(["cerebro_code_github_pr_status"]);
  researchState.establishPlan({
    decision: "Check the PR.",
    claims: [{ id: "pr", claim: "The PR is ready.", source_candidates: ["cerebro_code_github_pr_status"] }],
    selected_tools: ["cerebro_code_github_pr_status"],
  });

  researchState.recordToolResult("cerebro_code_github_pr_status", { details: { success: false, error: "GitHub request failed with 404: repository not found" } });
  researchState.recordToolResult("cerebro_code_github_pr_status", { details: { success: false, error: "repo not allowed for this installation scope" } });

  assert.equal(researchState.sourceHealthSnapshot("cerebro_code_github_pr_status").allowed, true);
  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set(["cerebro_code_github_pr_status"]),
    inferredIntent: "security_answer",
    maxResearchSteps: 6,
    researchState,
    researchTrail: [],
  });
  const blocked = await hooks.beforePi({ toolCall: { name: "cerebro_code_github_pr_status" } });
  assert.match(blocked?.reason ?? "", /failed 2 times in this answer/i);
});

test("assistant tool hooks enforce the model-selected Pi tool pack", async () => {
  const researchState = new SecurityResearchState();
  researchState.setAvailableTools(["cerebro_findings", "cerebro_graph_reason"]);
  researchState.establishPlan({
    decision: "Read one current finding.",
    execution_lane: "lookup",
    selected_tools: ["cerebro_findings"],
    claims: [{ id: "finding", claim: "Finding f-1 is open.", source_candidates: ["cerebro_findings"] }],
  });
  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set(["cerebro_findings", "cerebro_graph_reason"]),
    inferredIntent: "security_answer",
    maxResearchSteps: 3,
    researchState,
    researchTrail: [],
  });

  assert.equal(await hooks.beforePi({ toolCall: { name: "cerebro_findings" } }), undefined);
  const blocked = await hooks.beforePi({ toolCall: { name: "cerebro_graph_reason" } });
  assert.match(blocked?.reason ?? "", /outside the current model-selected tool pack/);
});

test("a successful offboarding preflight blocks redundant source reads but preserves the claim ledger", async () => {
  const preflight = "cerebro_offboarding_preflight";
  const redundant = "cerebro_connector_activity";
  const researchState = new SecurityResearchState();
  researchState.setAvailableTools([RESEARCH_PLAN_TOOL, CLAIM_LEDGER_TOOL, preflight, redundant]);
  researchState.establishPlan({
    decision: "Attest Okta, GitHub, and AWS offboarding coverage.",
    selected_tools: [preflight, redundant],
    claims: [{ id: "coverage", claim: "Provider coverage is current.", source_candidates: [preflight, redundant] }],
  });
  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set([RESEARCH_PLAN_TOOL, CLAIM_LEDGER_TOOL, preflight, redundant]),
    inferredIntent: "security_answer",
    maxResearchSteps: 4,
    researchState,
    researchTrail: [],
  });

  assert.equal(await hooks.beforePi({ toolCall: { name: preflight } }), undefined);
  researchState.recordToolResult(preflight, { details: { answer_complete: true, provider_attestation_digest: "sha256:test" } });
  await hooks.afterPi({ toolCall: { name: preflight }, isError: false });

  const blocked = await hooks.beforePi({ toolCall: { name: redundant } });
  assert.match(blocked?.reason ?? "", /provider attestation as authoritative/);
  assert.equal(await hooks.beforePi({ toolCall: { name: CLAIM_LEDGER_TOOL } }), undefined);
  assert.equal(hooks.count, 1);
});

test("a failed offboarding preflight leaves planned fallback source reads available", async () => {
  const preflight = "cerebro_offboarding_preflight";
  const fallback = "cerebro_connector_detail";
  const researchState = new SecurityResearchState();
  researchState.setAvailableTools([preflight, fallback]);
  researchState.establishPlan({
    decision: "Attest provider coverage or use a bounded fallback.",
    selected_tools: [preflight, fallback],
    claims: [{ id: "coverage", claim: "Provider coverage is current.", source_candidates: [preflight, fallback] }],
  });
  const hooks = new SecurityAssistantToolHooks({
    allowedTools: new Set([preflight, fallback]),
    inferredIntent: "security_answer",
    maxResearchSteps: 4,
    researchState,
    researchTrail: [],
  });

  assert.equal(await hooks.beforePi({ toolCall: { name: preflight } }), undefined);
  researchState.recordToolResult(preflight, { details: { error: "provider API unavailable" } });
  await hooks.afterPi({ toolCall: { name: preflight }, isError: false });

  assert.equal(await hooks.beforePi({ toolCall: { name: fallback } }), undefined);
  assert.equal(hooks.count, 2);
});
