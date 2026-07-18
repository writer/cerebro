import assert from "node:assert/strict";
import test from "node:test";
import { CerebroEnsembleService, ENSEMBLE_CHAIR_POLICY, ENSEMBLE_REVIEW_POLICY } from "../src/agent/cerebro-ensemble.js";
import type { SecurityAssistantAnswer, SecurityAssistantInput } from "../src/agent/security-assistant-types.js";
import type { A2AMessage } from "../src/a2a/index.js";
import { testConfig } from "./fixtures.js";

const question: SecurityAssistantInput = {
  interactionId: "interaction-1",
  channelId: "CSECURITY",
  userId: "U1",
  senderKind: "human",
  question: "Is the production finding legitimate, and what should we do next?",
  ts: "1700000000.000001",
};

const candidate: SecurityAssistantAnswer = {
  answer: "The production finding is likely legitimate.",
  messages: ["The production finding is likely legitimate."],
  keyPoints: ["The detector matched."],
  evidence: ["Production detector match at 09:00 UTC."],
  actionsTaken: ["No action taken."],
  nextActions: ["Review the finding."],
  research: ["finding:get completed"],
  memoryUpdates: [],
  source: "flue",
  executionLane: "investigate",
  delivery: "respond",
  presentationReady: true,
};

test("ensemble asks active security peers and uses the Opus chair's materially better answer", async () => {
  const requests: Array<Record<string, unknown>> = [];
  const config = testConfig({ a2a: { instanceId: "primary-1", ensembleMaxPeers: 2, ensembleTimeoutMs: 2_000 } });
  const peerReview = {
    recommendation: "revise",
    material_issues: ["The answer does not distinguish detector evidence from exploit confirmation."],
    preserve: ["The detector matched in production."],
    replacement_answer: "The detector match is real, but exploitability is not confirmed.",
    replacement_key_points: ["Production matched."],
    replacement_next_actions: ["Validate exploitability against the affected runtime."],
    confidence: 0.92,
  };
  const fleet = {
    async listInstances() {
      return [
        instance("primary-1", ["security"]),
        instance("peer-analyst", ["security", "research"]),
        instance("peer-goals", ["goals"]),
      ];
    },
    async request(input: Record<string, unknown>) {
      requests.push(input);
      return reply("peer-analyst", peerReview);
    },
  };
  const ensemble = new CerebroEnsembleService(config, fleet as any, {
    complete: async ({ stage, systemPrompt }) => {
      assert.equal(stage, "chair");
      assert.match(systemPrompt, /independent Opus chair/);
      return JSON.stringify({
        use_ensemble: true,
        answer: "The production detector match is legitimate. I’m not sure it is exploitable yet because runtime validation has not completed.",
        key_points: ["The production detector match is confirmed.", "Exploitability remains unverified."],
        next_actions: ["Validate exploitability against the affected runtime, then close or escalate the finding."],
      });
    },
  });

  const result = await ensemble.refine(question, candidate);

  assert.equal(requests.length, 1);
  assert.equal(requests[0]?.to, "peer-analyst");
  assert.match(result.answer, /I’m not sure it is exploitable yet/);
  assert.deepEqual(result.actionsTaken, candidate.actionsTaken);
  assert.deepEqual(result.evidence, candidate.evidence);
  assert.deepEqual(result.messages, []);
  assert.equal(result.presentationReady, false);
});

test("ensemble failure returns the original human answer unchanged", async () => {
  const config = testConfig({ a2a: { instanceId: "primary-1", ensembleTimeoutMs: 1_000 } });
  const fleet = {
    async listInstances() { return [instance("peer-1", ["security"])]; },
    async request() { return undefined; },
  };
  const ensemble = new CerebroEnsembleService(config, fleet as any, {
    complete: async () => { throw new Error("must not run"); },
  });

  assert.equal(await ensemble.refine(question, candidate), candidate);
});

test("local evaluation cannot turn malformed peer output into a human non-answer", async () => {
  const ensemble = new CerebroEnsembleService(testConfig(), undefined, {
    complete: async () => "not valid review json",
  });

  assert.equal(await ensemble.refineWithLocalReviews(question, candidate, 2), candidate);
});

test("ensemble never runs on bot traffic, conversational lanes, or non-Opus configuration", async () => {
  let listed = 0;
  const fleet = { async listInstances() { listed += 1; return []; }, async request() { return undefined; } };
  const config = testConfig({ a2a: { instanceId: "primary-1" } });
  const ensemble = new CerebroEnsembleService(config, fleet as any);

  assert.equal(await ensemble.refine({ ...question, senderKind: "bot" }, candidate), candidate);
  const conversational = { ...candidate, executionLane: "converse" as const };
  assert.equal(await ensemble.refine(question, conversational), conversational);
  const nonOpus = new CerebroEnsembleService(testConfig({ triage: { pi: { model: "amazon.nova-pro-v1:0" } } }), fleet as any);
  assert.equal(await nonOpus.refine(question, candidate), candidate);
  assert.equal(listed, 0);
});

test("a peer returns a bounded read-only review packet", async () => {
  const stages: string[] = [];
  const ensemble = new CerebroEnsembleService(testConfig(), undefined, {
    complete: async ({ stage, systemPrompt }) => {
      stages.push(stage);
      assert.match(systemPrompt, /read-only peer/);
      return JSON.stringify({
        recommendation: "keep",
        material_issues: [],
        preserve: ["The subject and time are exact."],
        replacement_answer: candidate.answer,
        replacement_key_points: candidate.keyPoints,
        replacement_next_actions: candidate.nextActions,
        confidence: 0.8,
      });
    },
  });
  const response = await ensemble.handleMessage({
    messageId: "message-1",
    contextId: "ensemble:test",
    taskId: "task-1",
    kind: "task",
    from: "primary-1",
    to: "peer-1",
    parts: [{ kind: "data", data: { protocol: "cerebro-ensemble-review-v1", lens: "Evidence challenger", question: question.question, candidate: { answer: candidate.answer } } }],
    createdAt: new Date().toISOString(),
    expiresAt: Math.floor(Date.now() / 1_000) + 30,
  });

  assert.deepEqual(stages, ["peer_review"]);
  assert.equal(response?.[0]?.data?.protocol, "cerebro-ensemble-review-v1");
  assert.equal((response?.[0]?.data?.review as { recommendation?: string })?.recommendation, "keep");
});

test("production ensemble prompts preserve useful answers and qualified uncertainty", () => {
  assert.match(ENSEMBLE_REVIEW_POLICY.join("\n"), /internal failure message or silence/);
  assert.match(ENSEMBLE_CHAIR_POLICY.join("\n"), /exactly what you are not sure about and why/);
  assert.match(ENSEMBLE_CHAIR_POLICY.join("\n"), /Do not turn an internal coverage gap into a human non-answer/);
});

function instance(instanceId: string, capabilities: string[]) {
  return {
    instanceId,
    label: instanceId,
    role: "analyst",
    commit: "sha-test",
    capabilities,
    state: "active" as const,
    startedAt: "2026-07-16T00:00:00.000Z",
    heartbeatAt: "2026-07-16T00:00:01.000Z",
    expiresAt: 2_000_000_000,
  };
}

function reply(from: string, review: Record<string, unknown>): A2AMessage {
  return {
    messageId: "reply-1",
    contextId: "ensemble:test",
    taskId: "task-1",
    kind: "status",
    from,
    to: "primary-1",
    parts: [{ kind: "data", data: { protocol: "cerebro-ensemble-review-v1", review } }],
    createdAt: new Date().toISOString(),
    expiresAt: Math.floor(Date.now() / 1_000) + 30,
  };
}
