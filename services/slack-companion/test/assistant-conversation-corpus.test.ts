import assert from "node:assert/strict";
import test from "node:test";
import { buildConversationCorpusCase, buildInteractionReplayCase, loadConversationCorpusCases } from "../src/learning/assistant-conversation-corpus.js";

test("blocked human interactions become private train-only response replays", () => {
  const item = buildInteractionReplayCase({
    interaction: {
      interactionId: "0123456789abcdef",
      answerHash: "1111111111111111",
      channelHash: "2222222222222222",
      threadHash: "3333333333333333",
      occurredAt: "2026-07-15T16:37:00.000Z",
      question: "dawg :cry:",
      answer: "LLM error: citation_claim_not_visible",
      answerSource: "blocked",
      toolNames: ["cerebro_code_status"],
      evidenceCount: 4,
      actionCount: 3,
      commitmentStates: [],
      deliveryComplete: true,
      followsInteractionId: "fedcba9876543210",
    },
    prior: {
      interactionId: "fedcba9876543210",
      answerHash: "4444444444444444",
      channelHash: "2222222222222222",
      threadHash: "3333333333333333",
      occurredAt: "2026-07-15T16:36:00.000Z",
      question: "Tell the team your updates.",
      answer: "I could not complete this check.",
      answerSource: "blocked",
      toolNames: [], evidenceCount: 0, actionCount: 0, commitmentStates: [], deliveryComplete: true,
    },
  });

  assert.equal(item?.id, "traffic-0123456789abcdef");
  assert.equal(item?.partition, "train");
  assert.equal(item?.expectations.outcome, "respond");
  assert.equal(item?.expectations.forbidClarifyingQuestion, true);
  assert.deepEqual(item?.threadContext, ["Human: Tell the team your updates.", "Cerebro: I could not complete this check."]);
  assert.ok(item?.expectations.forbiddenFacts.includes("citation_claim_not_visible"));
});

test("verified live conversations become train-only subject-bound corpus cases after presentation paraphrases", () => {
  const item = buildConversationCorpusCase({
    interactionId: "0123456789abcdef",
    question: "again, ask <@U123ABC> to use staging",
    prior: { question: "Which runtime failed in <#C123ABC|security>?", answer: "Production failed. https://writer.slack.com/archives/C123ABC/p1234567890" },
    answer: {
      answer: "staging-eu is unhealthy.",
      messages: ["staging-eu is unhealthy."],
      keyPoints: [],
      evidence: ["Runtime health returned staging-eu."],
      actionsTaken: ["Checked runtime health."],
      nextActions: [],
      research: ["cerebro_runtime_health: checked"],
      memoryUpdates: [],
      claimEvidence: [{
        claimId: "runtime-health",
        claimText: "staging-eu is unhealthy.",
        temporalScope: "current",
        verification: "verified",
        sourceTools: ["cerebro_runtime_health"],
        evidenceReceipts: ["runtime-receipt-1"],
        visible: false,
        evidence: [{
          id: "live:runtime:staging-eu",
          kind: "live_source",
          title: "staging-eu",
          basis: "live",
          access: "allowed",
          sourceTool: "cerebro_runtime_health",
          sourceRef: "runtime:staging-eu",
          subjectId: "runtime:staging-eu",
          verifiedBy: ["cerebro_runtime_health"],
          sourceArtifacts: [],
        }],
      }],
      source: "flue",
    },
  });

  assert.equal(item?.partition, "train");
  assert.equal(item?.question, "again, ask [person] to use staging");
  assert.deepEqual(item?.threadContext, ["Human: Which runtime failed in [channel]?", "Cerebro: Production failed. [slack_message]"]);
  assert.deepEqual(item?.expectations.requiredReceipts, ["runtime-receipt-1"]);
  assert.deepEqual(item?.expectations.requiredSubjectBindings, [{ claim: "staging-eu is unhealthy.", subject: "runtime:staging-eu" }]);
  assert.equal(item?.expectations.forbidClarifyingQuestion, true);
});

test("blocked and memory-only answers do not teach the development corpus", () => {
  const base = {
    answer: "No useful result.", messages: ["No useful result."], keyPoints: [], evidence: [], actionsTaken: [], nextActions: [], research: [], memoryUpdates: [],
  };
  assert.equal(buildConversationCorpusCase({ interactionId: "one", question: "check", answer: { ...base, source: "blocked" } }), undefined);
  assert.equal(buildConversationCorpusCase({ interactionId: "two", question: "check", answer: {
    ...base,
    source: "pi",
    claimEvidence: [{
      claimId: "memory", claimText: "Old owner is Payments.", temporalScope: "historical", verification: "verified", sourceTools: ["security_memory_search"], evidenceReceipts: ["memory-1"], visible: true,
      evidence: [{ id: "memory-1", kind: "memory", title: "Owner", basis: "historical", access: "allowed", verifiedBy: [], sourceArtifacts: [] }],
    }],
  } }), undefined);
  assert.equal(buildConversationCorpusCase({ interactionId: "three", question: "check", answer: {
    ...base,
    source: "flue",
    claimEvidence: [{
      claimId: "private-live", claimText: "Private source fact.", temporalScope: "current", verification: "verified", sourceTools: ["private-source"], evidenceReceipts: ["private-1"], visible: false,
      evidence: [{ id: "private-1", kind: "live_source", title: "Private source", basis: "live", access: "restricted", sourceRef: "private:1", verifiedBy: ["private-source"], sourceArtifacts: [] }],
    }],
  } }), undefined);
});

test("conversation corpus loader excludes held-out artifacts and prefers recent objects", async () => {
  const trainCase = buildConversationCorpusCase({
    interactionId: "train-case",
    question: "Which finding is open?",
    answer: {
      answer: "F-1 is open.", messages: ["F-1 is open."], keyPoints: [], evidence: ["F-1"], actionsTaken: [], nextActions: [], research: ["finding: checked"], memoryUpdates: [], source: "flue",
      claimEvidence: [{ claimId: "f-1", claimText: "F-1 is open.", temporalScope: "current", verification: "verified", sourceTools: ["finding-read"], evidenceReceipts: ["finding-1"], visible: true,
        evidence: [{ id: "live:finding:F-1", kind: "live_source", title: "F-1", basis: "live", access: "allowed", sourceRef: "finding:F-1", subjectId: "finding:F-1", verifiedBy: ["finding-read"], sourceArtifacts: [] }] }],
    },
  });
  assert.ok(trainCase);
  const heldCase = { ...trainCase, id: "held", partition: "held_out" };
  const bodies = new Map([
    ["runs/conversation-2026-07-15-new/corpus/new.json", JSON.stringify(trainCase)],
    ["runs/conversation-2026-07-14-old/corpus/old.json", JSON.stringify(heldCase)],
    ["runs/conversation-2026-07-15-broken/corpus/broken.json", "{not-json"],
  ]);
  const client = {
    async send(command: any) {
      if (command.constructor.name === "ListObjectsV2Command") {
        if (command.input.Prefix === "runs/conversation-2026-07-15-") return { Contents: [
          { Key: "runs/conversation-2026-07-15-new/corpus/new.json", LastModified: new Date("2026-07-15T00:00:00Z") },
          { Key: "runs/conversation-2026-07-15-broken/corpus/broken.json", LastModified: new Date("2026-07-15T01:00:00Z") },
        ] };
        if (command.input.Prefix === "runs/conversation-2026-07-14-") return { Contents: [
          { Key: "runs/conversation-2026-07-14-old/corpus/old.json", LastModified: new Date("2026-07-14T00:00:00Z") },
        ] };
        return { Contents: [] };
      }
      const body = bodies.get(command.input.Key);
      return { Body: body ? { transformToString: async () => body } : undefined };
    },
  };

  const loaded = await loadConversationCorpusCases({ bucket: "private-corpus", client, limit: 10, now: new Date("2026-07-15T12:00:00Z") });
  assert.deepEqual(loaded.map((item) => item.id), ["live-train-case"]);
});

test("conversation corpus loader reconstructs restart-broken follow-ups from the thread hash", async () => {
  const prior = {
    interactionId: "1111111111111111", answerHash: "aaaaaaaaaaaaaaaa", channelHash: "bbbbbbbbbbbbbbbb", threadHash: "cccccccccccccccc",
    occurredAt: "2026-07-15T16:30:00.000Z", question: "Show me a useful finding.", answer: "I found one identity issue.", answerSource: "flue",
    toolNames: ["cerebro_findings"], evidenceCount: 1, actionCount: 0, commitmentStates: [], deliveryComplete: true,
  };
  const followUp = {
    interactionId: "2222222222222222", answerHash: "dddddddddddddddd", channelHash: "bbbbbbbbbbbbbbbb", threadHash: "cccccccccccccccc",
    occurredAt: "2026-07-15T16:31:00.000Z", question: "yawn. Something cooler pls", answer: "I could not complete this check.", answerSource: "blocked",
    toolNames: [], evidenceCount: 0, actionCount: 0, commitmentStates: [], deliveryComplete: true,
  };
  const bodies = new Map([
    ["runs/interaction-1111111111111111/interaction/prior.json", JSON.stringify(prior)],
    ["runs/interaction-2222222222222222/interaction/follow-up.json", JSON.stringify(followUp)],
  ]);
  const client = {
    async send(command: any) {
      if (command.constructor.name === "ListObjectsV2Command") {
        if (command.input.Prefix === "runs/interaction-") return { Contents: [...bodies.keys()].map((Key) => ({ Key, LastModified: new Date("2026-07-15T16:32:00.000Z") })) };
        return { Contents: [] };
      }
      const body = bodies.get(command.input.Key);
      return { Body: body ? { transformToString: async () => body } : undefined };
    },
  };

  const loaded = await loadConversationCorpusCases({ bucket: "private-corpus", client, limit: 10, now: new Date("2026-07-15T17:00:00Z") });
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0]?.id, "traffic-2222222222222222");
  assert.deepEqual(loaded[0]?.threadContext, ["Human: Show me a useful finding.", "Cerebro: I found one identity issue."]);
});
