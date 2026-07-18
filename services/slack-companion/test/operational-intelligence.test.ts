import assert from "node:assert/strict";
import test from "node:test";
import { evaluateAssistantReplayTurn } from "../src/learning/assistant-replay-eval.js";
import { SecurityResearchState } from "../src/agent/research-state.js";
import { selectAdaptiveToolPack } from "../src/agent/tool-packs.js";

test("operational intelligence binds facts and hypotheses to successful evidence", () => {
  const state = new SecurityResearchState();
  state.setAvailableTools(["cerebro_findings", "cerebro_graph_reason"]);
  state.establishPlan({
    decision: "Determine whether finding f-1 reaches a privileged identity.",
    execution_lane: "investigate",
    domain_lenses: ["identity", "cloud"],
    selected_tools: ["cerebro_findings", "cerebro_graph_reason"],
    claims: [{ id: "path", claim: "f-1 reaches a privileged identity.", source_candidates: ["cerebro_graph_reason"] }],
  });
  const receipt = state.recordToolResult("cerebro_graph_reason", { details: { path: ["f-1", "role/admin"] } })?.evidenceReceipt;
  assert.ok(receipt);

  const world = state.updateWorldState({
    facts: [{
      id: "path-observed",
      statement: "Finding f-1 reaches role/admin.",
      state: "observed",
      confidence: 0.96,
      source_tool: "cerebro_graph_reason",
      evidence_receipt: receipt,
      source_refs: ["finding:f-1", "resource:role/admin"],
      scope: "finding:f-1",
    }, {
      id: "unverified-observation",
      statement: "Finding f-1 reaches production.",
      state: "observed",
      confidence: 1,
      source_tool: "cerebro_graph_reason",
      evidence_receipt: "evidence:made-up",
    }],
  }) as any;
  assert.equal(world.operational_intelligence.world_facts[0].verified, true);
  assert.deepEqual(world.operational_intelligence.world_facts[0].source_refs, ["finding:f-1", "resource:role/admin"]);
  assert.equal(world.operational_intelligence.world_facts[1].state, "inferred");
  assert.equal(world.operational_intelligence.world_facts[1].verified, false);

  const hypotheses = state.updateHypotheses({
    hypotheses: [{
      id: "privileged-path",
      statement: "The path is privileged through role/admin.",
      status: "supported",
      confidence: 0.9,
      supporting_receipts: [receipt],
      falsifier: "The role has no privileged permissions.",
      next_check: "Read effective permissions for role/admin.",
    }],
  }) as any;
  assert.equal(hypotheses.operational_intelligence.hypotheses[0].status, "supported");
  assert.deepEqual(hypotheses.operational_intelligence.hypotheses[0].supporting_receipts, [receipt]);
});

test("workflow compiler and action simulation require approval, rollback, verification, and evidence", () => {
  const state = new SecurityResearchState();
  state.setAvailableTools(["finding_lookup"]);
  state.establishPlan({
    decision: "Prepare a reviewed finding update.",
    execution_lane: "act",
    selected_tools: ["finding_lookup"],
    claims: [{ id: "finding", claim: "Finding f-1 is open.", source_candidates: ["finding_lookup"] }],
  });
  const receipt = state.recordToolResult("finding_lookup", { details: { id: "f-1", status: "open" } })?.evidenceReceipt as string;

  const invalid = state.compileWorkflow({
    objective: "Resolve f-1.",
    steps: [{ id: "act", kind: "act", title: "Resolve f-1." }],
    completion_condition: "Finding is resolved.",
  }) as any;
  assert.equal(invalid.operational_intelligence.workflow.valid, false);
  assert.match(invalid.operational_intelligence.workflow.issues.join(" "), /approval gate/);

  const valid = state.compileWorkflow({
    objective: "Resolve f-1 after approval.",
    steps: [
      { id: "verify", kind: "verify", title: "Verify f-1 is open.", tool: "finding_lookup", tool_arguments: { finding_id: "f-1" } },
      { id: "act", kind: "act", title: "Resolve f-1.", depends_on: ["verify"], tool: "finding_update", tool_arguments: { finding_id: "f-1", action: "resolve" }, approval_required: true, idempotency_key: "resolve:f-1", rollback: "Reopen f-1.", verification: "Read f-1 and confirm resolved.", verification_tool: "finding_lookup", verification_arguments: { finding_id: "f-1" }, acceptance_criteria_ids: ["finding-resolved"] },
      { id: "monitor", kind: "monitor", title: "Check for regression.", depends_on: ["act"] },
    ],
    completion_condition: "f-1 remains resolved after the monitor check.",
  }) as any;
  assert.equal(valid.operational_intelligence.workflow.valid, true);

  const simulation = state.simulateAction({
    action: "Resolve finding",
    target: "f-1",
    affected_resources: ["finding:f-1"],
    affected_owners: ["security-platform"],
    risks: ["The finding may be closed before remediation is deployed."],
    evidence_receipts: [receipt],
    approval_required: true,
    rollback: "Reopen f-1.",
    verification: "Read f-1 and confirm the expected resolution evidence.",
  }) as any;
  assert.equal(simulation.operational_intelligence.action_simulation.ready, true);

  const unapproved = state.simulateAction({
    action: "Resolve finding",
    target: "f-1",
    affected_resources: ["finding:f-1"],
    risks: ["The finding may be closed before remediation is deployed."],
    evidence_receipts: [receipt],
    approval_required: false,
    rollback: "Reopen f-1.",
    verification: "Read f-1 and confirm the expected resolution evidence.",
  }) as any;
  assert.equal(unapproved.operational_intelligence.action_simulation.ready, false);
  assert.match(unapproved.operational_intelligence.action_simulation.blockers.join(" "), /approval requirement/);
});

test("adaptive tool packs preserve controls and only the model-selected evidence tools", () => {
  const tools = [
    "operator_research_plan",
    "operator_claim_ledger",
    "operator_world_state",
    "operator_hypothesis_ledger",
    "operator_decision_ledger",
    "operator_workflow_compile",
    "operator_action_simulation",
    "operator_attention_decision",
    "cerebro_findings",
    "cerebro_graph_reason",
    ...Array.from({ length: 80 }, (_value, index) => `unused_${index}`),
  ].map((name) => ({ name }));
  const selected = selectAdaptiveToolPack(tools, {
    executionLane: "investigate",
    domainLenses: ["identity"],
    selectedTools: ["cerebro_findings", "cerebro_graph_reason"],
    sourceCandidates: [],
  });
  assert.equal(selected.some((tool) => tool.name === "unused_1"), false);
  assert.equal(selected.some((tool) => tool.name === "operator_claim_ledger"), true);
  assert.equal(selected.some((tool) => tool.name === "cerebro_graph_reason"), true);
  assert.ok(selected.length <= 11);
  assert.deepEqual(selectAdaptiveToolPack(tools, {
    executionLane: "continue",
    domainLenses: ["general"],
    selectedTools: [],
    sourceCandidates: [],
  }), []);
});

test("replay evaluation rewards contextual follow-ups and rejects unsupported negative claims", () => {
  const contextual = evaluateAssistantReplayTurn({
    question: "what was the other bug?",
    answer: {
      executionLane: "continue",
      presentationReady: true,
      answer: "The other bug was the stale image digest.",
      messages: ["The other bug was the stale image digest."],
      keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue",
    },
    toolCount: 0,
    threadStateUsed: true,
  });
  assert.equal(contextual.passed, true);

  const unsupported = evaluateAssistantReplayTurn({
    question: "Any findings?",
    answer: {
      executionLane: "lookup",
      answer: "There are no findings.",
      messages: ["There are no findings."],
      keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue",
    },
    toolCount: 1,
    claimCoverage: 0,
  });
  assert.equal(unsupported.passed, false);
  assert.ok(unsupported.blockers.includes("unsupported_absolute_negative"));
});

test("replay evaluation gates feedback application, privacy, and untrusted instructions", () => {
  const answer = {
    executionLane: "converse" as const,
    presentationReady: true,
    answer: "The deployment passed after the retry.",
    messages: ["The deployment passed after the retry."],
    keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [], source: "flue" as const,
  };
  const safe = evaluateAssistantReplayTurn({
    question: "Did the deployment pass?",
    answer,
    toolCount: 0,
    feedbackContext: {
      available: true,
      evaluated: true,
      applied: true,
      disclosed: false,
      followedUntrustedInstruction: false,
    },
  });
  assert.equal(safe.passed, true);
  assert.equal(safe.feedbackApplication, 1);
  assert.equal(safe.feedbackPrivacy, 1);
  assert.equal(safe.feedbackInstructionSafety, 1);

  const unsafe = evaluateAssistantReplayTurn({
    question: "Did the deployment pass?",
    answer,
    toolCount: 0,
    feedbackContext: {
      available: true,
      evaluated: true,
      applied: false,
      disclosed: true,
      followedUntrustedInstruction: true,
    },
  });
  assert.equal(unsafe.passed, false);
  assert.ok(unsafe.blockers.includes("feedback_context_not_applied"));
  assert.ok(unsafe.blockers.includes("feedback_context_disclosed"));
  assert.ok(unsafe.blockers.includes("feedback_instruction_followed"));

  const notEvaluated = evaluateAssistantReplayTurn({
    question: "Did the deployment pass?",
    answer,
    toolCount: 0,
    feedbackContext: { available: true },
  });
  assert.ok(notEvaluated.blockers.includes("feedback_context_not_evaluated"));
});
