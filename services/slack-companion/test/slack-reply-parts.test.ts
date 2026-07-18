import assert from "node:assert/strict";
import test from "node:test";
import {
  SLACK_REPLY_PART_MAX_CHARS,
  composeReplyParts,
  splitReplyForSlack,
} from "../src/slack/blocks/conversation.js";
import { securityAnswerMessages } from "../src/slack/blocks/index.js";

test("splitReplyForSlack returns one part for short content", () => {
  const parts = splitReplyForSlack("Login posture is healthy.");
  assert.equal(parts.length, 1);
  assert.equal(parts[0], "Login posture is healthy.");
});

test("splitReplyForSlack splits long content on paragraph and sentence boundaries", () => {
  const block = "Sentence one. Sentence two. Sentence three.".repeat(120);
  const parts = splitReplyForSlack(block);
  assert.ok(parts.length > 1);
  for (const part of parts) {
    assert.ok(part.length <= SLACK_REPLY_PART_MAX_CHARS);
    assert.ok(part.length > 0);
  }
  assert.equal(parts.join(" ").replace(/\s+/g, " ").trim().slice(0, 200), block.replace(/\s+/g, " ").trim().slice(0, 200));
});

test("composeReplyParts packs short lines together", () => {
  const parts = composeReplyParts(["one", "two", "three"]);
  assert.equal(parts.length, 1);
  assert.equal(parts[0], "one\ntwo\nthree");
});

test("composeReplyParts splits when total exceeds the per-part cap", () => {
  const long = "x".repeat(SLACK_REPLY_PART_MAX_CHARS);
  const parts = composeReplyParts([long, "trailer"]);
  assert.ok(parts.length >= 2);
  assert.match(parts[0] ?? "", /^\(1\/\d+\) /);
  for (const part of parts) {
    assert.ok(part.length <= SLACK_REPLY_PART_MAX_CHARS);
  }
});

test("composeReplyParts preserves content beyond ten emitted parts", () => {
  const lines = Array.from({ length: 14 }, (_, index) => `Part ${index}: ${`token${index} `.repeat(450)}`.trim());
  const parts = composeReplyParts(lines);
  assert.ok(parts.length > 10);
  assert.ok(parts.every((part) => part.length <= SLACK_REPLY_PART_MAX_CHARS));
  assert.equal(
    parts.map(stripReplyPartNumber).join(" ").replace(/\s+/g, " ").trim(),
    lines.join(" ").replace(/\s+/g, " ").trim(),
  );
});

test("securityAnswerMessages splits a long answer into multiple short parts", () => {
  const longAnswer = "Three levers to make the GitHub-Okta linkage fire fast. ".repeat(160);
  const messages = securityAnswerMessages("be more detailed", {
    answer: longAnswer,
    messages: [longAnswer],
    reaction: "white_check_mark",
    keyPoints: [],
    evidence: [],
    actionsTaken: [],
    nextActions: [],
    research: [],
    memoryUpdates: [],
    source: "pi",
  });
  assert.ok(messages.length > 1, "expected multi-part Slack reply for long content");
  for (const message of messages) {
    assert.ok(message.length <= SLACK_REPLY_PART_MAX_CHARS);
    assert.ok(message.trim().length > 0);
  }
  assert.match(messages[0] ?? "", /^\(1\/\d+\) /);
  assert.equal(messages.map(stripReplyPartNumber).join(" ").replace(/\s+/g, " ").trim(), longAnswer.replace(/\s+/g, " ").trim());
});

test("securityAnswerMessages keeps answer lines with snake_case configuration names", () => {
  const answer = [
    "A couple more, and I re-checked these live:",
    "- The task runs with `NODE_ENV=production` while the deployment environment is development.",
    "- Pull request creation is enabled even though `github_pr_enabled=false` is stale.",
    "cerebro_graph_reason: checked",
  ].join("\n");
  const messages = securityAnswerMessages("what else?", {
    answer,
    messages: [answer],
    reaction: "white_check_mark",
    keyPoints: [],
    evidence: [],
    actionsTaken: [],
    nextActions: [],
    research: ["cerebro_graph_reason: checked"],
    memoryUpdates: [],
    source: "pi",
  });

  assert.equal(messages.length, 1);
  assert.match(messages[0] ?? "", /NODE_ENV=production/);
  assert.match(messages[0] ?? "", /github_pr_enabled=false/);
  assert.doesNotMatch(messages[0] ?? "", /cerebro_graph_reason/);
});

function stripReplyPartNumber(value: string): string {
  return value.replace(/^\(\d+\/\d+\)\s+/, "");
}
