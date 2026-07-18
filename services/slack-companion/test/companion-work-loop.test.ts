import assert from "node:assert/strict";
import test from "node:test";
import { SLACK_REPLY_PART_MAX_CHARS } from "../src/slack/blocks/conversation.js";
import { configureTelemetry, renderMetrics, resetTelemetryForTests } from "../src/telemetry.js";
import { CompanionWorkLoop } from "../src/work/companion-work-loop.js";
import { testConfig } from "./fixtures.js";

test("companion work loop posts answers and writes encounter stories", async () => {
  const posts: any[] = [];
  const reactions: any[] = [];
  const apiCalls: any[] = [];
  const notes: any[] = [];
  const memories: any[] = [];
  const feedbackAnswers: any[] = [];
  const improvementInteractions: any[] = [];
  const improvementOutcomes: any[] = [];
  const assistantInputs: any[] = [];
  const config = testConfig({ triage: { maxConcurrent: 1 } });
  const loop = new CompanionWorkLoop({
    config,
    assistant: {
      answer: async (input: any) => {
        assistantInputs.push(input);
        return ({
        answer: "One GitHub identity finding needs owner review.",
        messages: ["One GitHub identity finding needs owner review."],
        reaction: "mag",
        keyPoints: ["GitHub identity finding is open"],
        evidence: ["Cerebro finding f-1"],
        actionsTaken: ["Checked Cerebro graph"],
        nextActions: ["Confirm owner"],
        research: ["cerebro_graph_reason: checked"],
        memoryUpdates: [],
        source: "pi",
        });
      },
    } as any,
    memory: {
      remember: async (input: any) => {
        memories.push(input);
        return { id: "story-1", ...input, tags: input.tags ?? [], createdAt: new Date().toISOString() };
      },
      recall: async () => [],
    } as any,
    notes: {
      record: async (input: any) => {
        notes.push(input);
      },
    } as any,
    feedback: { registerAnswer: async (input: any) => { feedbackAnswers.push(input); return input; } } as any,
    improvement: {
      observe: async () => undefined,
      recordInteraction: async (input: any) => {
        improvementInteractions.push(input);
        return { kind: "interaction", uri: "memory://interaction.json", sha256: "a".repeat(64), createdAt: input.occurredAt };
      },
      recordOutcomeEvent: async (input: any) => {
        improvementOutcomes.push(input);
        return { kind: "outcome", uri: "memory://outcome.json", sha256: "b".repeat(64), createdAt: input.occurredAt };
      },
    },
  });

  loop.enqueueSlackQuestion(fakeClient(posts, reactions, apiCalls), {
    channelId: "CSEC",
    userId: "UUSER",
    question: "what are the newest scariest findings today?",
    ts: "1782510000.000000",
    replyThreadTs: "1782510000.000000",
  });
  await loop.onIdle();

  assert.equal(posts.some((post) => post.text === "One GitHub identity finding needs owner review."), true);
  assert.equal(posts.some((post) => post.text === "Rate this Cerebro response"), true);
  assert.equal(feedbackAnswers[0].answerId, "CSEC:answer-1");
  assert.equal(feedbackAnswers[0].interactionId, assistantInputs[0].interactionId);
  assert.equal(feedbackAnswers[0].trafficKind, "human_request");
  assert.deepEqual(feedbackAnswers[0].toolNames, ["cerebro_graph_reason"]);
  assert.deepEqual(feedbackAnswers[0].actionsTaken, ["Checked Cerebro graph"]);
  assert.deepEqual(feedbackAnswers[0].delivery, { plannedMessages: 1, postedMessages: 1, complete: true });
  assert.equal(improvementInteractions[0].answerHash, "52f5f3f4e7203592");
  assert.equal(improvementInteractions[0].interactionId, assistantInputs[0].interactionId);
  assert.deepEqual(improvementInteractions[0].requester, { slackUserId: "UUSER" });
  assert.equal(improvementInteractions[0].threadHash, "1e13fdd23759f7b4");
  assert.equal(improvementInteractions[0].question, "what are the newest scariest findings today?");
  assert.equal(improvementInteractions[0].deliveryComplete, true);
  assert.equal(improvementOutcomes[0].interactionId, assistantInputs[0].interactionId);
  assert.equal(improvementOutcomes[0].result, "complete");
  assert.equal(reactions.some((reaction) => reaction.name === "mag"), true);
  assert.equal(apiCalls.some((call) => call.method === "assistant.threads.setStatus" && call.args.status === ""), true);
  assert.equal(notes.some((note) => note.kind === "encounter_story" && note.outcome === "answered"), true);
  assert.equal(notes.every((note) => note.trafficKind === "human_request"), true);
  assert.equal(memories.some((memory) => memory.kind === "encounter_story" && /newest scariest findings/i.test(memory.topic)), true);
});

test("companion work loop posts claim-bound evidence with Slack permalinks", async () => {
  const posts: any[] = [];
  const permalinkCalls: any[] = [];
  const evidenceReceipts: any[] = [];
  const client = fakeClient(posts, [], []);
  client.chat.getPermalink = async (input: any) => {
    permalinkCalls.push(input);
    return { permalink: "https://writer.slack.com/archives/CSEC/p1782501562693279" };
  };
  const loop = new CompanionWorkLoop({
    config: testConfig({ triage: { maxConcurrent: 1 } }),
    assistant: {
      answer: async () => ({
        answer: "Checkout belongs to the payments team.",
        messages: ["Checkout belongs to the payments team."],
        reaction: "mag",
        keyPoints: [],
        evidence: ["Memory record memory-1 supplied the historical owner context."],
        actionsTaken: ["Checked security memory."],
        nextActions: [],
        research: ["security_memory_intelligence: checked"],
        memoryUpdates: [],
        claimEvidence: [{
          claimId: "checkout-owner",
          claimText: "Checkout belongs to the payments team.",
          temporalScope: "historical",
          verification: "verified",
          sourceTools: ["security_memory_intelligence"],
          evidenceReceipts: ["evidence:security_memory_intelligence:one"],
          visible: true,
          evidence: [{
            id: "memory-1",
            kind: "memory",
            title: "Checkout service owner",
            basis: "historical",
            access: "allowed",
            channelId: "CSEC",
            sourceTs: "1782501562.693279",
            createdAt: "2026-07-12T10:30:00.000Z",
            verifiedBy: ["slack_message_context"],
            sourceArtifacts: ["service-catalog:checkout"],
            quality: "source_verified",
            freshness: "current",
          }],
        }],
        source: "pi",
      }),
    } as any,
    memory: memorySink(),
    notes: { record: async () => undefined } as any,
    evidenceGovernance: {
      recordAnswer: async (input: any) => {
        evidenceReceipts.push(input);
      },
    },
  });

  loop.enqueueSlackQuestion(client, {
    channelId: "CSEC",
    userId: "UUSER",
    question: "Who owns checkout?",
    ts: "1782510000.000005",
    replyThreadTs: "1782510000.000005",
  });
  await loop.onIdle();

  assert.deepEqual(permalinkCalls, [{ channel: "CSEC", message_ts: "1782501562.693279" }]);
  assert.match(posts[0]?.text ?? "", /payments team\. \[1\]/);
  assert.match(posts[0]?.text ?? "", /\*Sources\*/);
  assert.match(posts[0]?.text ?? "", /<https:\/\/writer\.slack\.com\/archives\/CSEC\/p1782501562693279\|Checkout service owner>/);
  assert.match(posts[0]?.text ?? "", /memory `memory-1`/);
  assert.match(posts[0]?.text ?? "", /source verified · current/);
  assert.equal(evidenceReceipts.length, 1);
  assert.equal(evidenceReceipts[0].answerId, "CSEC:answer-1");
  assert.equal(evidenceReceipts[0].threadTs, "1782510000.000005");
  assert.equal(evidenceReceipts[0].answer.claimEvidence[0].claimId, "checkout-owner");
});

test("companion work loop records ignored bot handoffs without sending Slack content", async () => {
  const posts: any[] = [];
  const reactions: any[] = [];
  const apiCalls: any[] = [];
  const notes: any[] = [];
  const memories: any[] = [];
  const improvementInteractions: any[] = [];
  const loop = new CompanionWorkLoop({
    config: testConfig({ triage: { maxConcurrent: 1 } }),
    assistant: {
      answer: async () => ({
        answer: "Automated handoff ignored.",
        messages: [],
        keyPoints: ["Routine digest had no explicit request or new verified value."],
        evidence: [],
        actionsTaken: [],
        nextActions: [],
        research: ["delivery_disposition: ignored_bot_handoff"],
        memoryUpdates: [],
        source: "flue",
        delivery: "suppress",
        dispositionReason: "Routine digest had no explicit request or new verified value.",
      }),
    } as any,
    memory: {
      remember: async (input: any) => { memories.push(input); return { id: "memory", ...input }; },
      recall: async () => [],
    } as any,
    notes: { record: async (input: any) => { notes.push(input); } } as any,
    improvement: {
      observe: async () => undefined,
      recordInteraction: async (input: any) => {
        improvementInteractions.push(input);
        return { kind: "interaction", uri: "memory://interaction.json", sha256: "a".repeat(64), createdAt: input.occurredAt };
      },
    },
  });

  loop.enqueueSlackQuestion(fakeClient(posts, reactions, apiCalls), {
    channelId: "CSEC",
    userId: "UBOT",
    senderKind: "bot",
    question: "Routine security digest with assigned owners.",
    ts: "1782510000.000003",
    replyThreadTs: "1782510000.000003",
  });
  await loop.onIdle();

  assert.deepEqual(posts, []);
  assert.deepEqual(reactions, []);
  assert.equal(apiCalls.some((call) => call.method === "assistant.threads.setSuggestedPrompts"), false);
  assert.equal(notes.some((note) => note.outcome === "ignored" && note.tags.includes("automated-handoff")), true);
  assert.equal(notes.some((note) => note.outcome === "ignored" && note.trafficKind === "machine_handoff"), true);
  assert.deepEqual(memories, []);
  assert.deepEqual(improvementInteractions, []);
});

test("companion work loop reports a partial Slack delivery receipt", async () => {
  const posts: any[] = [];
  const notes: any[] = [];
  let postAttempt = 0;
  const client = fakeClient(posts, [], []);
  client.chat.postMessage = async (message: any) => {
    postAttempt += 1;
    if (postAttempt === 2) throw new Error("Slack write failed");
    posts.push(message);
    return { ok: true, ts: `answer-${postAttempt}` };
  };
  const loop = new CompanionWorkLoop({
    config: testConfig({ triage: { maxConcurrent: 1 } }),
    assistant: {
      answer: async () => ({
        answer: "The result has two parts.",
        messages: [
          `The first result. ${"A".repeat(SLACK_REPLY_PART_MAX_CHARS - 80)}`,
          `The second result. ${"B".repeat(SLACK_REPLY_PART_MAX_CHARS - 80)}`,
        ],
        reaction: "mag",
        keyPoints: [], evidence: ["run:1"], actionsTaken: [], nextActions: [], research: ["run_status: checked"], memoryUpdates: [], source: "pi",
      }),
    } as any,
    memory: memorySink(),
    notes: { record: async (input: any) => { notes.push(input); } } as any,
  });

  loop.enqueueSlackQuestion(client, {
    channelId: "CSEC",
    userId: "UUSER",
    senderKind: "human",
    question: "Give me both parts.",
    ts: "1782510000.000004",
    replyThreadTs: "1782510000.000004",
  });
  await loop.onIdle();

  assert.match(posts[0].text, /^\(1\/2\) The first result\./);
  assert.match(posts[1].text, /posted 1 of 2 reply parts/i);
  assert.equal(notes.some((note) => note.outcome === "failed" && note.trafficKind === "human_request"), true);
});

test("companion work loop retries one transient Slack part without duplicating earlier parts", async () => {
  const posts: any[] = [];
  const client = fakeClient(posts, [], []);
  const secondIds: string[] = [];
  let secondAttempts = 0;
  client.chat.postMessage = async (message: any) => {
    if (message.text.includes("Second verified result")) {
      secondAttempts += 1;
      secondIds.push(message.client_msg_id);
      if (secondAttempts === 1) throw new Error("timeout while writing Slack message");
    }
    posts.push(message);
    return { ok: true, ts: `answer-${posts.length}` };
  };
  const loop = new CompanionWorkLoop({
    config: testConfig({ triage: { maxConcurrent: 1 } }),
    assistant: { answer: async () => ({
      answer: "Two verified results.",
      messages: ["First verified result.", "Second verified result."],
      keyPoints: [], evidence: ["source:1"], actionsTaken: [], nextActions: [], research: ["source: checked"], memoryUpdates: [], source: "flue",
    }) } as any,
    memory: memorySink(),
    notes: { record: async () => undefined } as any,
  });

  loop.enqueueSlackQuestion(client, { channelId: "CSEC", userId: "UUSER", question: "Give me both verified results.", ts: "1782510000.000006", replyThreadTs: "1782510000.000006" });
  await loop.onIdle();

  assert.equal(secondAttempts, 2);
  assert.equal(secondIds[0], secondIds[1]);
  assert.equal(posts.filter((post) => /First verified result/.test(post.text)).length, 1);
  assert.equal(posts.filter((post) => /Second verified result/.test(post.text)).length, 1);
  assert.equal(posts.some((post) => /Slack rejected/.test(post.text)), false);
});

test("companion work loop records a human correction against the prior interaction", async () => {
  const outcomes: any[] = [];
  const interactions: any[] = [];
  const loop = new CompanionWorkLoop({
    config: testConfig({ triage: { maxConcurrent: 1, duplicateQuestionCooldownMs: 0 } }),
    assistant: { answer: async (input: any) => answer(`done: ${input.question}`) } as any,
    memory: memorySink(),
    notes: { record: async () => undefined } as any,
    improvement: {
      observe: async () => undefined,
      recordInteraction: async (input: any) => {
        interactions.push(input);
        return { kind: "interaction", uri: "memory://interaction.json", sha256: "a".repeat(64), createdAt: input.occurredAt };
      },
      recordOutcomeEvent: async (input: any) => {
        outcomes.push(input);
        return { kind: "outcome", uri: "memory://outcome.json", sha256: "b".repeat(64), createdAt: input.occurredAt };
      },
    },
  });
  const client = fakeClient([], [], []);
  loop.enqueueSlackQuestion(client, { channelId: "DSEC", userId: "UJON", question: "Check the production runtime.", ts: "1782510000.000007", replyThreadTs: "1782510000.000007" });
  await loop.onIdle();
  loop.enqueueSlackQuestion(client, { channelId: "DSEC", userId: "UJON", question: "again, that was staging", ts: "1782510001.000007", replyThreadTs: "1782510001.000007" });
  await loop.onIdle();

  assert.equal(outcomes.some((outcome) => outcome.type === "implicit_correction" && outcome.result === "human_requested_rework"), true);
  assert.equal(interactions[1].followsInteractionId, interactions[0].interactionId);
});

test("companion work loop writes skill improvement notes for weak answers", async () => {
  const posts: any[] = [];
  const reactions: any[] = [];
  const apiCalls: any[] = [];
  const memories: any[] = [];
  const feedbackAnswers: any[] = [];
  const loop = new CompanionWorkLoop({
    config: testConfig({ triage: { maxConcurrent: 1 } }),
    assistant: {
      answer: async () => ({
        answer: "I could not complete the graph-backed answer yet.",
        messages: ["I could not get the graph answer back yet."],
        reaction: "thinking_face",
        keyPoints: [],
        evidence: ["Cerebro graph reasoning did not return an answer."],
        actionsTaken: ["Used fallback path"],
        nextActions: ["Try again later."],
        research: ["cerebro_graph_reason: failed"],
        memoryUpdates: [],
        source: "blocked",
      }),
    } as any,
    memory: {
      remember: async (input: any) => {
        memories.push(input);
        return { id: `memory-${memories.length}`, ...input, tags: input.tags ?? [], createdAt: new Date().toISOString() };
      },
      recall: async () => [],
    } as any,
    notes: { record: async () => undefined } as any,
    feedback: { registerAnswer: async (input: any) => { feedbackAnswers.push(input); return input; } } as any,
  });

  loop.enqueueSlackQuestion(fakeClient(posts, reactions, apiCalls), {
    channelId: "CSEC",
    userId: "UUSER",
    question: "what are the newest scariest findings today?",
    ts: "1782510000.000001",
    replyThreadTs: "1782510000.000001",
  });
  await loop.onIdle();

  assert.equal(memories.some((memory) => memory.kind === "skill_improvement" && memory.tags.includes("scary-findings")), true);
  assert.equal(feedbackAnswers.length, 0);
  assert.equal(posts.some((post) => post.text === "Rate this Cerebro response"), false);
});

test("companion work loop posts every Slack chunk for long assistant replies", async () => {
  const posts: any[] = [];
  const reactions: any[] = [];
  const apiCalls: any[] = [];
  const longAnswer = "Hermes found more context, and this sentence should make it all the way into Slack. ".repeat(500);
  const loop = new CompanionWorkLoop({
    config: testConfig({ triage: { maxConcurrent: 1 } }),
    assistant: {
      answer: async () => ({
        answer: longAnswer,
        messages: [longAnswer],
        reaction: "mag",
        keyPoints: [],
        evidence: ["Compliance context was checked."],
        actionsTaken: ["Checked compliance source context."],
        nextActions: [],
        research: ["cerebro_compliance_context: checked"],
        memoryUpdates: [],
        source: "pi",
      }),
    } as any,
    memory: {
      remember: async (input: any) => ({ id: "story-1", ...input, tags: input.tags ?? [], createdAt: new Date().toISOString() }),
      recall: async () => [],
    } as any,
    notes: { record: async () => undefined } as any,
  });

  loop.enqueueSlackQuestion(fakeClient(posts, reactions, apiCalls), {
    channelId: "CSEC",
    userId: "UUSER",
    question: "Hermes, give me the detailed version.",
    ts: "1782510000.000002",
    replyThreadTs: "1782510000.000002",
  });
  await loop.onIdle();

  assert.ok(posts.length > 10, "expected the complete answer to exceed the old ten-message cap");
  assert.ok(posts.every((post) => post.text.length <= SLACK_REPLY_PART_MAX_CHARS));
  assert.match(posts[0]?.text ?? "", /^\(1\/\d+\) /);
  assert.equal(posts.map((post) => stripReplyPartNumber(post.text)).join(" ").replace(/\s+/g, " ").trim(), longAnswer.replace(/\s+/g, " ").trim());
});

test("companion work loop drops repeated questions in the duplicate cooldown", async () => {
  const posts: any[] = [];
  const reactions: any[] = [];
  const apiCalls: any[] = [];
  let answerCount = 0;
  const loop = new CompanionWorkLoop({
    config: testConfig({ triage: { maxConcurrent: 1, duplicateQuestionCooldownMs: 600_000 } }),
    assistant: {
      answer: async () => {
        answerCount += 1;
        return answer("Checked once.");
      },
    } as any,
    memory: memorySink(),
    notes: { record: async () => undefined } as any,
  });

  const first = await loop.enqueueSlackQuestion(fakeClient(posts, reactions, apiCalls), {
    channelId: "CSEC",
    userId: "UUSER",
    question: "Check this finding",
    ts: "1782510000.000010",
    replyThreadTs: "1782510000.000010",
  });
  const duplicate = await loop.enqueueSlackQuestion(fakeClient(posts, reactions, apiCalls), {
    channelId: "CSEC",
    userId: "UUSER",
    question: "  check   this finding  ",
    ts: "1782510001.000010",
    replyThreadTs: "1782510000.000010",
  });
  await loop.onIdle();

  assert.equal(first.accepted, true);
  assert.equal(duplicate.accepted, false);
  assert.equal(duplicate.reason, "duplicate_question");
  assert.equal(answerCount, 1);
  assert.equal(posts.length, 1);
});

test("companion work loop does not run two jobs from the same Slack thread at once", async () => {
  const posts: any[] = [];
  const reactions: any[] = [];
  const apiCalls: any[] = [];
  const started: string[] = [];
  let releaseFirst!: () => void;
  const firstStarted = deferred<void>();
  const firstRelease = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  const loop = new CompanionWorkLoop({
    config: testConfig({ triage: { maxConcurrent: 2, duplicateQuestionCooldownMs: 0 } }),
    assistant: {
      answer: async (input: any) => {
        started.push(input.question);
        if (input.question === "first") {
          firstStarted.resolve();
          await firstRelease;
        }
        return answer(`done ${input.question}`);
      },
    } as any,
    memory: memorySink(),
    notes: { record: async () => undefined } as any,
  });

  loop.enqueueSlackQuestion(fakeClient(posts, reactions, apiCalls), {
    channelId: "CSEC",
    userId: "UUSER",
    question: "first",
    ts: "1782510000.000020",
    replyThreadTs: "1782510000.000020",
  });
  await firstStarted.promise;
  loop.enqueueSlackQuestion(fakeClient(posts, reactions, apiCalls), {
    channelId: "CSEC",
    userId: "UUSER",
    question: "second same thread",
    ts: "1782510001.000020",
    replyThreadTs: "1782510000.000020",
  });
  loop.enqueueSlackQuestion(fakeClient(posts, reactions, apiCalls), {
    channelId: "COPS",
    userId: "UUSER",
    question: "third different thread",
    ts: "1782510002.000020",
    replyThreadTs: "1782510002.000020",
  });
  await waitFor(() => started.includes("third different thread"));

  assert.deepEqual(started, ["first", "third different thread"]);
  releaseFirst();
  await loop.onIdle();
  assert.deepEqual(started, ["first", "third different thread", "second same thread"]);
});

test("companion work loop records queue gauges and latency metrics", async () => {
  resetTelemetryForTests();
  configureTelemetry({
    enabled: false,
    metricsEnabled: true,
    serviceName: "test",
    serviceVersion: "test",
    deploymentEnvironment: "test",
  });
  const posts: any[] = [];
  const reactions: any[] = [];
  const apiCalls: any[] = [];
  const started: string[] = [];
  let releaseFirst!: () => void;
  const firstStarted = deferred<void>();
  const firstRelease = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  const loop = new CompanionWorkLoop({
    config: testConfig({ triage: { maxConcurrent: 1, duplicateQuestionCooldownMs: 0 }, telemetry: { metricsEnabled: true } }),
    assistant: {
      answer: async (input: any) => {
        started.push(input.question);
        if (input.question === "first") {
          firstStarted.resolve();
          await firstRelease;
        }
        return answer(`done ${input.question}`);
      },
    } as any,
    memory: memorySink(),
    notes: { record: async () => undefined } as any,
  });

  try {
    loop.enqueueSlackQuestion(fakeClient(posts, reactions, apiCalls), {
      channelId: "CSEC",
      userId: "UUSER",
      question: "first",
      ts: "1782510000.000030",
      replyThreadTs: "1782510000.000030",
    });
    await firstStarted.promise;
    loop.enqueueSlackQuestion(fakeClient(posts, reactions, apiCalls), {
      channelId: "COPS",
      userId: "UUSER",
      question: "second",
      ts: "1782510001.000030",
      replyThreadTs: "1782510001.000030",
    });

    assert.match(renderMetrics(), /cerebro_slack_companion_work_queue_depth\{kind="slack_question"\} 1/);
    releaseFirst();
    await loop.onIdle();
    const metrics = renderMetrics();
    assert.match(metrics, /cerebro_slack_companion_work_queue_latency_seconds_count\{kind="slack_question"\} 2/);
    assert.match(metrics, /cerebro_slack_companion_work_active_threads\{kind="slack_question"\} 0/);
  } finally {
    resetTelemetryForTests();
  }
});

function stripReplyPartNumber(value: string): string {
  return value.replace(/^\(\d+\/\d+\)\s+/, "");
}

function answer(message: string): any {
  return {
    answer: message,
    messages: [message],
    reaction: "mag",
    keyPoints: [],
    evidence: ["test evidence"],
    actionsTaken: ["Checked test fixture"],
    nextActions: [],
    research: ["test_tool: checked"],
    memoryUpdates: [],
    source: "pi",
  };
}

function memorySink(): any {
  return {
    remember: async (input: any) => ({ id: "story-1", ...input, tags: input.tags ?? [], createdAt: new Date().toISOString() }),
    recall: async () => [],
  };
}

function deferred<T>(): { promise: Promise<T>; resolve: (value: T | PromiseLike<T>) => void } {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((innerResolve) => {
    resolve = innerResolve;
  });
  return { promise, resolve };
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 1000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("condition was not met");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function fakeClient(posts: any[], reactions: any[], apiCalls: any[]): any {
  return {
    chat: {
      postMessage: async (message: any) => {
        posts.push(message);
        return { ok: true, ts: `answer-${posts.length}` };
      },
    },
    reactions: {
      add: async (reaction: any) => {
        reactions.push(reaction);
        return { ok: true };
      },
    },
    apiCall: async (method: string, args: any) => {
      apiCalls.push({ method, args });
      return { ok: true };
    },
  };
}
