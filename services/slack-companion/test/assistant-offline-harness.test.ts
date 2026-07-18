import assert from "node:assert/strict";
import test from "node:test";
import { systemPrompt } from "../src/agent/security-assistant-prompts.js";
import { SecurityResearchState } from "../src/agent/research-state.js";
import type { SecurityAssistantAnswer } from "../src/agent/security-assistant-types.js";
import type { CerebroClient } from "../src/cerebro/client.js";
import {
  createOfflineFixtureToolFactory,
  createOfflineFixtureTrace,
} from "../src/learning/assistant-offline-fixtures.js";
import {
  OFFLINE_PRODUCTION_CANDIDATE,
  offlineHarnessCacheKey,
  offlineObservation,
  runOfflineAssistantCase,
  selectOfflineCases,
} from "../src/learning/assistant-offline-harness.js";
import { parseAssistantHardCorpusLine } from "../src/learning/assistant-hillclimb.js";
import { SecurityMemoryStore } from "../src/learning/security-memory/index.js";
import { testConfig } from "./fixtures.js";

const hardCase = parseAssistantHardCorpusLine({
  schemaVersion: 1,
  id: "offline-case",
  partition: "train",
  challenge: "partial-evidence",
  difficulty: 5,
  senderKind: "human",
  question: "What is the current risk?",
  threadContext: ["The active mission is finding F-17."],
  evidence: [
    { source: "finding-read", receipt: "static-finding", status: "completed", subjects: ["finding:F-17"], facts: ["F-17 is critical and open."] },
    { source: "graph-path", receipt: "static-graph", status: "partial", subjects: ["finding:F-17"], facts: ["The graph query timed out."] },
  ],
  assignedRoles: ["researcher"],
  expectations: {
    outcome: "respond",
    requiredFactGroups: [["F-17"], ["critical"]],
    forbiddenFacts: [],
    requiredReceipts: ["static-finding"],
    requiredActionGroups: [],
    requireCoverageBoundary: true,
    requireRecommendation: false,
    forbidClarifyingQuestion: true,
    requiredSubjectBindings: [{ claim: "F-17 is critical", subject: "finding:F-17" }],
  },
});

test("offline fixture tools issue real research receipts and preserve partial source facts", async () => {
  const config = testConfig({ learning: { enabled: false, workingMemoryEnabled: false, learningDocsEnabled: false } });
  const trace = createOfflineFixtureTrace();
  const researchState = new SecurityResearchState();
  const tools = createOfflineFixtureToolFactory(hardCase, trace)({
    config,
    cerebro: {} as CerebroClient,
    memory: new SecurityMemoryStore(config),
    researchState,
  });
  const completed = tools.find((tool) => tool.name === "offline_source_01_finding_read");
  const partial = tools.find((tool) => tool.name === "offline_source_02_graph_path");
  assert.ok(completed);
  assert.ok(partial);

  const completedResult = await completed.execute("completed", {}, new AbortController().signal) as { details?: Record<string, unknown> };
  const partialResult = await partial.execute("partial", {}, new AbortController().signal) as { content?: Array<{ type: string; text?: string }>; details?: Record<string, unknown> };

  assert.match(String(completedResult.details?.evidence_receipt), /^evidence:offline_source_01_finding_read:/);
  assert.equal(partialResult.details?.success, false);
  assert.deepEqual(partialResult.details?.facts, ["The graph query timed out."]);
  assert.match(String(partialResult.details?.evidence_receipt), /^evidence:offline_source_02_graph_path:/);
  assert.equal(partialResult.details?.evidence_status, "partial");
  assert.equal(partialResult.details?.returned_evidence_usable, true);
  assert.match(partialResult.content?.at(-1)?.text ?? "", /error applies only to the missing coverage/);
  assert.deepEqual(trace.calls.map((call) => [call.source, call.status]), [
    ["finding-read", "completed"],
    ["graph-path", "partial"],
  ]);
});

test("offline harness carries exact fixture authority through the production Flue path", async () => {
  const config = testConfig({
    triage: { assistantRuntime: "flue" },
    learning: { enabled: false, workingMemoryEnabled: false, learningDocsEnabled: false },
  });
  const result = await runOfflineAssistantCase({
    config,
    item: hardCase,
    candidate: OFFLINE_PRODUCTION_CANDIDATE,
    flueComplete: async (input) => {
      const completedName = "offline_source_01_finding_read";
      const partialName = "offline_source_02_graph_path";
      await input.onResearchPlan?.({
        user_intent: "Read the supplied finding and graph evidence.",
        execution_lane: "investigate",
        execution_style: "direct",
        selected_tools: [completedName, partialName],
        claims: [{
          id: "finding",
          claim: "F-17 is critical and open.",
          required: true,
          source_candidates: [completedName],
        }],
        research_plan: ["Read the finding and graph evidence."],
        user_visible_work: ["Check the current finding and graph path"],
        required_sources: [completedName, partialName],
        missing_context_questions: [],
      });
      const completed = input.tools.find((tool) => tool.name === completedName);
      const partial = input.tools.find((tool) => tool.name === partialName);
      const claimLedger = input.tools.find((tool) => tool.name === "operator_claim_ledger");
      assert.ok(completed);
      assert.ok(partial);
      assert.ok(claimLedger);
      const signal = new AbortController().signal;
      const completedResult = await completed.run({ input: {}, emitData: () => undefined, signal }) as { details?: Record<string, unknown> };
      await partial.run({ input: {}, emitData: () => undefined, signal });
      const evidenceReceipt = String(completedResult.details?.evidence_receipt ?? "");
      assert.match(evidenceReceipt, /^evidence:offline_source_01_finding_read:/);
      await claimLedger.run({
        input: {
          claims: [{
            id: "finding",
            status: "supported",
            source_tools: [completedName],
            evidence_receipts: [evidenceReceipt],
          }],
          answer_ready: true,
        },
        emitData: () => undefined,
        signal,
      });
      const answer = "F-17 is critical and open. The graph query timed out, so path coverage is partial.";
      return {
        data: {
          execution_lane: "investigate",
          final_ready: true,
          presentation_ready: true,
          answer,
          messages: [answer],
          reply_messages: [],
          key_points: ["F-17 is critical and open."],
          keyPoints: [],
          evidence: ["The finding source completed; the graph source returned partial coverage."],
          actions_taken: ["Checked the finding and graph sources."],
          actionsTaken: [],
          next_actions: ["Review F-17 first."],
          nextActions: [],
          research: [],
          memory_updates: [],
          memoryUpdates: [],
          specialist_work: [],
        },
      };
    },
  });

  assert.deepEqual(result.trace.calls.map((call) => [call.source, call.status]), [
    ["finding-read", "completed"],
    ["graph-path", "partial"],
  ]);
  assert.doesNotMatch(result.observation.answer, /host authority|unavailable until/i);
});

test("offline observation maps runtime receipts and subjects back to corpus contracts", () => {
  const trace = createOfflineFixtureTrace();
  createOfflineFixtureToolFactory(hardCase, trace);
  const answer: SecurityAssistantAnswer = {
    answer: "F-17 is critical and open. The graph query timed out, so path coverage is incomplete.",
    messages: ["F-17 is critical and open. The graph query timed out, so path coverage is incomplete."],
    keyPoints: ["F-17 is critical."],
    evidence: ["The finding source returned F-17."],
    actionsTaken: ["Checked the finding source."],
    nextActions: ["Review F-17 first."],
    research: ["offline_source_01_finding_read: checked"],
    memoryUpdates: [],
    source: "flue",
    delivery: "respond",
    claimEvidence: [{
      claimId: "finding",
      claimText: "F-17 is critical and open.",
      temporalScope: "current",
      verification: "verified",
      sourceTools: ["offline_source_01_finding_read"],
      evidenceReceipts: ["evidence:offline_source_01_finding_read:dynamic"],
      visible: true,
      evidence: [{
        id: "live:finding",
        kind: "live_source",
        title: "F-17",
        basis: "live",
        access: "allowed",
        sourceTool: "offline_source_01_finding_read",
        sourceRef: "finding:F-17",
        subjectId: "finding:F-17",
        verifiedBy: ["offline_source_01_finding_read"],
        sourceArtifacts: [],
      }],
    }],
  };
  const observation = offlineObservation({
    answer,
    trace,
    latencyMs: 1_200,
    flueOutput: {
      data: {
        answer: answer.answer,
        messages: [],
        reply_messages: [],
        key_points: [],
        keyPoints: [],
        evidence: [],
        actions_taken: [],
        actionsTaken: [],
        next_actions: [],
        nextActions: [],
        research: [],
        memory_updates: [],
        memoryUpdates: [],
        specialist_work: [{
          role: "researcher",
          status: "completed",
          findings: ["F-17 is critical."],
          recommendations: [],
          actions: [],
          checks: [],
          blockers: [],
          evidence_receipts: ["evidence:offline_source_01_finding_read:dynamic"],
        }],
      },
    },
  });

  assert.deepEqual(observation.cited_receipts, ["static-finding"]);
  assert.deepEqual(observation.specialist_work[0]?.evidence_receipts, ["static-finding"]);
  assert.deepEqual(observation.subject_bindings, [{ claim: "F-17 is critical and open.", subject: "finding:F-17" }]);
  assert.equal(observation.latency_ms, 1_200);
});

test("development selection never includes held-out cases", () => {
  const validation = parseAssistantHardCorpusLine({ ...hardCase, id: "validation", partition: "validation" });
  const heldOut = parseAssistantHardCorpusLine({ ...hardCase, id: "held-out", partition: "held_out" });
  assert.deepEqual(selectOfflineCases({ cases: [hardCase, validation, heldOut], heldOut: false }).map((item) => item.id), ["offline-case", "validation"]);
  assert.deepEqual(selectOfflineCases({ cases: [hardCase, validation, heldOut], heldOut: true }).map((item) => item.id), ["held-out"]);
});

test("offline cache key changes with the production protocol", () => {
  const config = testConfig();
  const base = {
    runtimeFingerprint: "runtime-a",
    model: "amazon-bedrock/us.anthropic.claude-opus-4-8",
    thinking: "high",
    executionModel: "amazon-bedrock/us.anthropic.claude-opus-4-8",
    executionThinking: "medium",
    candidate: OFFLINE_PRODUCTION_CANDIDATE,
    item: hardCase,
  };
  const first = offlineHarnessCacheKey({ ...base, protocolPrompt: systemPrompt(config) });
  const second = offlineHarnessCacheKey({ ...base, protocolPrompt: `${systemPrompt(config)}\nChanged contract.` });
  assert.notEqual(first, second);
  const third = offlineHarnessCacheKey({ ...base, runtimeFingerprint: "runtime-b", protocolPrompt: systemPrompt(config) });
  assert.notEqual(first, third);
});

test("evaluation instructions are absent from production and bounded in candidate prompts", () => {
  const config = testConfig();
  assert.doesNotMatch(systemPrompt(config), /Offline evaluation policy candidate/);
  const prompt = systemPrompt(config, "", "", "", ["Preserve completed facts when one source fails."]);
  assert.match(prompt, /Offline evaluation policy candidate/);
  assert.match(prompt, /Preserve completed facts when one source fails/);
});
