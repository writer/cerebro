import assert from "node:assert/strict";
import test from "node:test";
import { SelfImprovementService } from "../src/learning/self-improvement.js";
import { SecurityMemoryStore } from "../src/learning/security-memory/index.js";
import type { RuntimeCodePrInput } from "../src/code/runtime-code.js";
import type { SecurityAssistantAnswer } from "../src/agent/security-assistant.js";
import { testConfig } from "./fixtures.js";

test("self-improvement opens a draft repair PR after repeated matching answer gaps", async () => {
  const config = testConfig({
    selfRepair: { threshold: 2 },
    learning: { maxSearchResults: 10 },
  });
  const memory = new SecurityMemoryStore(config);
  const createdPrs: RuntimeCodePrInput[] = [];
  const service = new SelfImprovementService(config, memory, {
    repairPrCreator: {
      status: () => ({ github_pr_enabled: true }),
      createGithubPullRequest: async (input) => {
        createdPrs.push(input);
        return { ok: true, pull_request: { number: 17, url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/17" } };
      },
    },
  });

  await service.observeSlackAnswer({
    channelId: "CSEC",
    userId: "UUSER",
    question: "do you know what you are?",
    ts: "1782514645.298069",
  }, blockedAnswer("Pi assistant is unavailable: model validation failed."));
  assert.equal(createdPrs.length, 0);

  await service.observeSlackAnswer({
    channelId: "CSEC",
    userId: "UUSER",
    question: "do you know who you are?",
    ts: "1782514646.298069",
  }, blockedAnswer("Pi assistant is unavailable: model validation failed again."));

  assert.equal(createdPrs.length, 1);
  assert.equal(createdPrs[0]?.draft, true);
  assert.match(createdPrs[0]?.title ?? "", /Self-repair: Self improvement Assistant Blocked/);
  assert.match(createdPrs[0]?.files[0]?.path ?? "", /^docs\/self-repair\/\d{4}-\d{2}-\d{2}-self-improvement-assistant-blocked-[a-f0-9]{8}\.md$/);
  assert.match(createdPrs[0]?.files[0]?.content ?? "", /Review Boundary/);
  assert.match(createdPrs[0]?.files[0]?.content ?? "", /do you know what you are\?/);
  assert.match(createdPrs[0]?.files[0]?.content ?? "", /do you know who you are\?/);

  const markers = await memory.recall({ kinds: ["runbook_note"], query: "self repair", limit: 10 });
  assert.equal(markers.some((record) => record.tags.includes("self-repair") && record.tags.includes("opened")), true);
});

test("self-improvement does not open duplicate repair PRs during cooldown", async () => {
  const config = testConfig({
    selfRepair: { threshold: 2, cooldownHours: 168 },
    learning: { maxSearchResults: 10 },
  });
  const memory = new SecurityMemoryStore(config);
  const createdPrs: RuntimeCodePrInput[] = [];
  const service = new SelfImprovementService(config, memory, {
    repairPrCreator: {
      status: () => ({ github_pr_enabled: true }),
      createGithubPullRequest: async (input) => {
        createdPrs.push(input);
        return { ok: true, pull_request: { number: 18, url: "https://github.com/WriterInternal/cerebro-slack-companion/pull/18" } };
      },
    },
  });

  for (const [index, question] of ["what are you?", "who are you?", "what tools do you have?"].entries()) {
    await service.observeSlackAnswer({
      channelId: "CSEC",
      userId: "UUSER",
      question,
      ts: `17825146${index}.000000`,
    }, blockedAnswer(`Pi assistant is unavailable: attempt ${index}.`));
  }

  assert.equal(createdPrs.length, 1);
});

test("self-improvement records a pending repair marker when PR creation is unavailable", async () => {
  const config = testConfig({
    selfRepair: { threshold: 2 },
    learning: { maxSearchResults: 10 },
  });
  const memory = new SecurityMemoryStore(config);
  const service = new SelfImprovementService(config, memory, {
    repairPrCreator: {
      status: () => ({ github_pr_enabled: false }),
      createGithubPullRequest: async () => {
        throw new Error("should not create PR");
      },
    },
  });

  await service.observeSlackAnswer({
    channelId: "CSEC",
    userId: "UUSER",
    question: "do you know what you are?",
    ts: "1782514645.298069",
  }, blockedAnswer("Pi assistant is unavailable."));
  await service.observeSlackAnswer({
    channelId: "CSEC",
    userId: "UUSER",
    question: "what are your tools?",
    ts: "1782514646.298069",
  }, blockedAnswer("Pi assistant is unavailable."));

  const markers = await memory.recall({ kinds: ["runbook_note"], query: "self repair", limit: 10 });
  assert.equal(markers.some((record) => record.tags.includes("self-repair") && record.tags.includes("pending")), true);
});

test("self-improvement ignores bot-authored machine handoffs", async () => {
  const config = testConfig({ selfRepair: { threshold: 1 } });
  const memory = new SecurityMemoryStore(config);
  const createdPrs: RuntimeCodePrInput[] = [];
  const service = new SelfImprovementService(config, memory, {
    repairPrCreator: {
      status: () => ({ github_pr_enabled: true }),
      createGithubPullRequest: async (input) => {
        createdPrs.push(input);
        return { ok: true };
      },
    },
  });

  await service.observeSlackAnswer({
    channelId: "CSEC",
    userId: "UBOT",
    senderKind: "bot",
    question: "Automated digest with no human request.",
    ts: "1782514647.000000",
  }, blockedAnswer("A machine handoff failed."));

  assert.equal(createdPrs.length, 0);
  assert.equal((await memory.recall({ kinds: ["skill_improvement"], limit: 10 })).length, 0);
});

test("recursive self-improvement keeps Slack assistance routing separate from candidate metadata", async () => {
  const config = testConfig();
  const observations: any[] = [];
  const service = new SelfImprovementService(config, new SecurityMemoryStore(config), {
    improvement: {
      observe: async (signal, candidate, options) => {
        observations.push({ signal, candidate, options });
        return undefined;
      },
    },
  });

  await service.observeSlackAnswer({
    channelId: "CSEC",
    userId: "UUSER",
    question: "Can you finish the repair?",
    ts: "1782514648.000000",
  }, blockedAnswer("The repair did not finish."));
  await service.observeSlackAnswer({
    channelId: "CSEC",
    question: "Can you finish the repair without a known requester?",
    ts: "1782514649.000000",
  }, blockedAnswer("The repair did not finish."));

  assert.deepEqual(observations[0]?.options, {
    humanAssistance: { channelId: "CSEC", intendedUserId: "UUSER" },
  });
  assert.equal(observations[1]?.options, undefined);
  assert.doesNotMatch(JSON.stringify(observations[0]?.candidate), /CSEC|UUSER|Can you finish/);
});

test("self-improvement records an unresolved partial research failure even when the answer has evidence", async () => {
  const config = testConfig();
  const memory = new SecurityMemoryStore(config);
  const observations: any[] = [];
  const service = new SelfImprovementService(config, memory, {
    improvement: {
      observe: async (signal, candidate, options) => {
        observations.push({ signal, candidate, options });
        return undefined;
      },
    },
  });
  const input = {
    channelId: "CSEC",
    userId: "UUSER",
    question: "Improve yourself from this answer.",
    ts: "1782514650.000000",
  };
  const answer: SecurityAssistantAnswer = {
    answer: "Prod reads returned five medium identity findings and current runtime details.",
    messages: ["Prod reads returned five medium identity findings and current runtime details."],
    reaction: "white_check_mark",
    keyPoints: [],
    evidence: ["Cerebro prod returned five medium identity findings."],
    actionsTaken: [],
    nextActions: ["Retry the graph evaluation after the stream recovers."],
    research: ["cerebro_findings_read: checked", "security_memory_search: failed", "cerebro_graph_reason: failed"],
    memoryUpdates: [],
    source: "pi",
  };

  await service.observeSlackAnswer(input, answer);
  await service.observeSlackAnswer(
    { ...input, ts: "1782514651.000000" },
    { ...answer, research: ["cerebro_findings_read: checked", "cerebro_graph_reason: checked"] },
  );

  assert.equal(observations.length, 1);
  assert.equal(observations[0]?.signal.issueKind, "partial-tool-failure");
  assert.deepEqual(observations[0]?.signal.toolNames, ["cerebro_graph_reason", "security_memory_search"]);
  assert.match(observations[0]?.signal.signature ?? "", /^self-repair:self-improvement:partial-tool-failure:[a-f0-9]{8}$/);
  assert.equal((await memory.recall({ kinds: ["skill_improvement"], limit: 10 })).length, 1);

  await service.observeSlackAnswer(
    { ...input, ts: "1782514652.000000" },
    { ...answer, research: ["cerebro_findings_read: checked", "writer_github_audit: failed"] },
  );
  await service.observeSlackAnswer(
    { ...input, ts: "1782514653.000000" },
    { ...answer, research: ["cerebro_graph_reason: failed", "security_memory_search: failed", "cerebro_findings_read: checked"] },
  );

  assert.equal(observations.length, 3);
  assert.deepEqual(observations[1]?.signal.toolNames, ["writer_github_audit"]);
  assert.notEqual(observations[0]?.signal.signature, observations[1]?.signal.signature);
  assert.equal(observations[0]?.signal.signature, observations[2]?.signal.signature);
});

test("self-improvement ignores an auxiliary research failure when the answer has no open loop", async () => {
  const config = testConfig();
  const memory = new SecurityMemoryStore(config);
  const observations: any[] = [];
  const service = new SelfImprovementService(config, memory, {
    improvement: {
      observe: async (signal) => {
        observations.push(signal);
        return undefined;
      },
    },
  });

  await service.observeSlackAnswer({
    channelId: "CSEC",
    userId: "UUSER",
    question: "Improve yourself from this answer.",
    ts: "1782514654.000000",
  }, {
    answer: "The source was healthy when checked, and the current identity findings are confirmed.",
    messages: ["The source was healthy when checked, and the current identity findings are confirmed."],
    reaction: "white_check_mark",
    keyPoints: [],
    evidence: ["Cerebro prod returned the current identity findings."],
    actionsTaken: [],
    nextActions: ["No follow-up is needed."],
    research: ["cerebro_findings_read: checked", "security_memory_search: failed"],
    memoryUpdates: [],
    source: "pi",
  });

  assert.deepEqual(observations, []);
  assert.deepEqual(await memory.recall({ kinds: ["skill_improvement"], limit: 10 }), []);
});

function blockedAnswer(message: string): SecurityAssistantAnswer {
  return {
    answer: `I could not complete this check. ${message} No memory, Slack, or graph substitute ran.`,
    messages: [`I could not complete this check. ${message} No memory, Slack, or graph substitute ran.`],
    reaction: "warning",
    keyPoints: [],
    evidence: [],
    actionsTaken: [],
    nextActions: ["Try again after the runtime is healthy."],
    research: [],
    memoryUpdates: [],
    source: "blocked",
  };
}
