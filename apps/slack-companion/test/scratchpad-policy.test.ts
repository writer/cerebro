import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";
import {
  formatSlackThreadScratchpadContext,
  normalizeScratchpadContent,
  parseSlackThreadScratchpadCommand,
  recordSlackThreadWorkingTurn,
  slackScratchpadAuthorRef,
  slackThreadScratchpadRef,
  validateSlackThreadScratchpad,
  verifiedTurnScratchpadContent,
} from "../src/index.js";

test("scratchpad commands require explicit add, show, or clear actions", () => {
  assert.deepEqual(parseSlackThreadScratchpadCommand("scratchpad"), {
    action: "show",
    schema_version: "slack-thread-scratchpad-command/v1",
  });
  assert.deepEqual(parseSlackThreadScratchpadCommand("scratchpad add: use the current finding owner"), {
    action: "add",
    content: "use the current finding owner",
    schema_version: "slack-thread-scratchpad-command/v1",
  });
  assert.deepEqual(parseSlackThreadScratchpadCommand("scratchpad add : keep the incident timeline"), {
    action: "add",
    content: "keep the incident timeline",
    schema_version: "slack-thread-scratchpad-command/v1",
  });
  assert.equal(
    parseSlackThreadScratchpadCommand(`scratchpad add${" ".repeat(100_000)}`),
    undefined,
  );
  assert.equal(parseSlackThreadScratchpadCommand("scratchpad additional context"), undefined);
  assert.equal(parseSlackThreadScratchpadCommand("this belongs in a scratchpad"), undefined);
  assert.deepEqual(parseSlackThreadScratchpadCommand("clear scratchpad"), {
    action: "clear",
    schema_version: "slack-thread-scratchpad-command/v1",
  });
});

test("scratchpad identities do not expose Slack workspace, channel, or user ids", () => {
  assert.match(
    slackThreadScratchpadRef("T-ONE", "C-ONE", "1710000000.000001"),
    /^slack-scratchpad:\/\/sha256\/[a-f0-9]{64}$/u,
  );
  assert.match(
    slackScratchpadAuthorRef("T-ONE", "U-ONE"),
    /^slack-user:\/\/sha256\/[a-f0-9]{64}$/u,
  );
});

test("scratchpad content is bounded and rendered without authority", () => {
  const credential = ["xoxb", "fixture", "value"].join("-");
  assert.equal(normalizeScratchpadContent(" use   the finding owner "), "use the finding owner");
  assert.throws(() => normalizeScratchpadContent("x".repeat(901)), /invalid or too long/u);
  assert.equal(
    normalizeScratchpadContent(`token=${credential}`),
    "token=[redacted_secret]",
  );
  const scratchpad = validateSlackThreadScratchpad({
    notes: [{
      author_ref: "slack-user://sha256/author",
      content: "Use the incident timeline from this thread.",
      created_at: "2026-07-29T10:00:00.000Z",
      expires_at: "2026-08-05T10:00:00.000Z",
      note_id: "slack-note://sha256/note",
      schema_version: "slack-thread-scratchpad-note/v1",
      source: "human",
      thread_ref: "slack-scratchpad://sha256/thread",
    }],
    schema_version: "slack-thread-scratchpad/v1",
    thread_ref: "slack-scratchpad://sha256/thread",
  }, new Date("2026-07-30T10:00:00.000Z"));

  assert.equal(
    formatSlackThreadScratchpadContext(scratchpad),
    "1. [thread note] Use the incident timeline from this thread.",
  );
});

test("verified turns become bounded autonomous working memory", () => {
  const content = verifiedTurnScratchpadContent(
    "Who owns the checkout finding?",
    `Security Operations owns ${"the current finding. ".repeat(100)}`,
  );

  assert.match(content, /^Question: Who owns the checkout finding\? Verified answer:/u);
  assert.ok(Buffer.byteLength(content, "utf8") <= 900);
  assert.match(content, /\.\.\.$/u);
});

test("working state preserves recent requests and the last bounded outcome", () => {
  const threadRef = "slack-scratchpad://sha256/thread";
  const first = recordSlackThreadWorkingTurn(undefined, {
    currentRequest: "What is the most material risk this week?",
    now: new Date("2026-07-29T10:00:00.000Z"),
    outcome: "completed",
    threadRef,
  });
  const second = recordSlackThreadWorkingTurn(first, {
    blocker: "Graph evidence was timed out.",
    currentRequest: "Give me another.",
    now: new Date("2026-07-29T10:01:00.000Z"),
    outcome: "blocked",
    threadRef,
  });

  assert.deepEqual(second.recent_requests, [
    "Give me another.",
    "What is the most material risk this week?",
  ]);
  assert.equal(second.last_outcome, "blocked");
  assert.equal(second.blocker, "Graph evidence was timed out.");
  assert.match(
    formatSlackThreadScratchpadContext({
      notes: [],
      schema_version: "slack-thread-scratchpad/v1",
      thread_ref: threadRef,
      working_state: second,
    }) ?? "",
    /Current working state \(unverified; context only\):[\s\S]*Give me another\.[\s\S]*most material risk[\s\S]*Last outcome: blocked\.[\s\S]*Last blocker: Graph evidence was timed out\./u,
  );
});

test("working state redacts secrets and retains only three distinct requests", () => {
  const threadRef = "slack-scratchpad://sha256/thread";
  let state = recordSlackThreadWorkingTurn(undefined, {
    currentRequest: "first request",
    now: new Date("2026-07-29T10:00:00.000Z"),
    outcome: "completed",
    threadRef,
  });
  for (const [index, request] of ["second request", "third request", "fourth request"].entries()) {
    state = recordSlackThreadWorkingTurn(state, {
      currentRequest: request,
      now: new Date(`2026-07-29T10:0${index + 1}:00.000Z`),
      outcome: "completed",
      threadRef,
    });
  }
  const credential = ["xoxb", "fixture", "value"].join("-");
  state = recordSlackThreadWorkingTurn(state, {
    currentRequest: `inspect token=${credential}`,
    now: new Date("2026-07-29T10:04:00.000Z"),
    outcome: "needs_user",
    threadRef,
  });

  assert.deepEqual(state.recent_requests, [
    "inspect token=[redacted_secret]",
    "fourth request",
    "third request",
  ]);
  assert.doesNotMatch(JSON.stringify(state), new RegExp(credential, "u"));
});
