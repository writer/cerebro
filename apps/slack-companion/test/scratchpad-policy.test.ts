import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";
import {
  formatSlackThreadScratchpadContext,
  normalizeScratchpadContent,
  parseSlackThreadScratchpadCommand,
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
