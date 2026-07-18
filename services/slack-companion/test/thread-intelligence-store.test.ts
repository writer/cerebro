import assert from "node:assert/strict";
import test from "node:test";
import { assistantThreadStatePromptBlock, AssistantThreadStateStore } from "../src/agent/thread-intelligence-store.js";
import { testConfig } from "./fixtures.js";

test("assistant thread intelligence persists bounded world state and recent turns", async () => {
  let now = new Date("2026-07-14T12:00:00.000Z");
  const store = new AssistantThreadStateStore(testConfig({ triage: { threadStateTableName: undefined } }), { now: () => now });
  const question = { channelId: "CSEC", threadTs: "100.1", ts: "100.2", question: "Which deployment broke?" };
  const answer = {
    executionLane: "lookup" as const,
    domainLenses: ["delivery" as const],
    answer: "The API deployment still uses the previous image digest.",
    messages: ["The API deployment still uses the previous image digest."],
    keyPoints: ["API deployment uses the previous image digest."],
    evidence: ["ECS task definition returned digest sha-old."],
    actionsTaken: ["Checked the running task definition."],
    nextActions: ["Deploy the merged image and verify the digest."],
    research: ["cerebro_runtime: checked"],
    memoryUpdates: [],
    source: "flue" as const,
    teammate: {
      objective: "Identify and repair the broken deployment.",
      desiredOutcome: "The merged image is running and its digest is verified.",
      resolvedScope: ["service:api", "deployment:api"],
      scopeAssumptions: ["The API deployment named in this thread is the affected service."],
      commitments: [{
        id: "verify-api-deploy",
        summary: "Verify the API deployment after the merged image is released.",
        status: "in_progress" as const,
        nextAction: "Check the running task digest after deployment.",
        artifactRefs: ["task-definition:api:42"],
      }],
      openLoops: [{
        id: "verify-api-deploy",
        summary: "The running digest still needs verification.",
        owner: "cerebro" as const,
        nextAction: "Check the running task digest after deployment.",
      }],
      userDecision: { required: false },
    },
  };
  await store.recordTurn({
    question,
    answer,
    intelligence: {
      decision: "Identify the broken deployment.",
      executionLane: "lookup",
      domainLenses: ["delivery"],
      entities: ["service:api"],
      claimCoverage: 1,
      answerReady: true,
      toolCount: 1,
      worldFacts: [{
        id: "api-digest",
        statement: "API deployment uses sha-old.",
        state: "observed",
        confidence: 1,
        source_tool: "cerebro_runtime",
        evidence_receipt: "evidence:cerebro_runtime:abc",
        source_refs: ["task-definition:api:42"],
        verified: true,
      }],
    },
  });
  now = new Date("2026-07-14T12:01:00.000Z");
  await store.recordTurn({
    question: { ...question, ts: "100.3", question: "anything else?" },
    answer: {
      ...answer,
      executionLane: "continue",
      answer: "No other material deployment delta was reported.",
      messages: ["No other material deployment delta was reported."],
      teammate: {
        ...answer.teammate,
        commitments: [{ ...answer.teammate.commitments[0]!, status: "completed" as const }],
        openLoops: [],
      },
    },
    intelligence: { executionLane: "continue", toolCount: 0 },
  });

  const state = await store.get("CSEC", "100.1");
  assert.equal(state?.turns.length, 2);
  assert.equal(state?.turns[0]?.question, "anything else?");
  assert.deepEqual(state?.entities, ["service:api"]);
  assert.equal(state?.worldFacts[0]?.id, "api-digest");
  assert.equal(state?.teammate.objective, "Identify and repair the broken deployment.");
  assert.equal(state?.teammate.commitments[0]?.id, "verify-api-deploy");
  assert.equal(state?.teammate.commitments[0]?.status, "completed");
  assert.deepEqual(state?.teammate.openLoops, []);
  const prompt = assistantThreadStatePromptBlock(state);
  assert.match(prompt, /already_reported_facts/);
  assert.match(prompt, /API deployment uses the previous image digest/);
  assert.match(prompt, /anything else/);
  assert.match(prompt, /continuity context, not proof/);
  assert.match(prompt, /desired_outcome/);
  assert.match(prompt, /verify-api-deploy/);
});

test("assistant mission continuity follows one human across referential root messages", async () => {
  const store = new AssistantThreadStateStore(testConfig({ triage: { threadStateTableName: undefined } }));
  const firstAnswer = {
    answer: "Finding f-17 affects the production login runtime.",
    messages: ["Finding f-17 affects the production login runtime."],
    keyPoints: [], evidence: ["finding:f-17"], actionsTaken: ["Checked the finding."], nextActions: [], research: ["cerebro_findings: checked"], memoryUpdates: [], source: "flue" as const,
    teammate: {
      objective: "Determine whether finding f-17 is a legitimate production risk.",
      desiredOutcome: "The finding has a source-bound risk decision and owner action.",
      resolvedScope: ["finding:f-17", "runtime:login-production"],
      scopeAssumptions: [],
      commitments: [],
      openLoops: [],
      userDecision: { required: false },
    },
  };
  await store.recordTurn({
    question: { channelId: "DSEC", userId: "UJON", ts: "200.1", question: "Check finding f-17." },
    answer: firstAnswer,
    intelligence: { executionLane: "lookup", entities: ["finding:f-17", "runtime:login-production"], toolCount: 1 },
  });

  const resumed = await store.getForQuestion({ channelId: "DSEC", userId: "UJON", ts: "200.2", question: "do a better query then" });
  assert.equal(resumed?.mission?.objective, "Determine whether finding f-17 is a legitimate production risk.");
  assert.equal(resumed?.mission?.subjects.some((subject) => subject.id === "finding:f-17"), true);

  const unrelated = await store.getForQuestion({ channelId: "DSEC", userId: "UJON", ts: "200.3", question: "Summarize the security program for the board next quarter." });
  assert.equal(unrelated, undefined);
  const otherHuman = await store.getForQuestion({ channelId: "DSEC", userId: "UOTHER", ts: "200.4", question: "show me the detailed link" });
  assert.equal(otherHuman, undefined);
});
