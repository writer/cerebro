import assert from "node:assert/strict";
import test from "node:test";

import {
  containsSlackMention,
  parseSlackRememberCommand,
  SlackRememberCommandError,
} from "../src/index.js";

test("parses direct, greeting, and mention remember forms", () => {
  const direct = parseSlackRememberCommand("Cerebro remember that Rowan prefers short updates");
  assert.equal(direct?.content, "Rowan prefers short updates");
  assert.equal(direct?.topic, "Slack context: Rowan");
  assert.equal(direct?.summary, "Rowan prefers short updates");
  assert.equal(direct?.working_memory_target, "team");
  assert.deepEqual(direct?.tags, ["slack-remember", "team-context"]);

  const mention = parseSlackRememberCommand(
    "<@U0BOT> hi Cerebro, please remember: I prefer concise replies",
    { author_name: "Avery", expected_mention: "<@U0BOT>" },
  );
  assert.equal(mention?.summary, "Avery: I prefer concise replies");
  assert.equal(mention?.working_memory_target, "team");
  assert.equal(containsSlackMention("<@U0BOT> remember this"), true);
  assert.equal(Object.isFrozen(mention), true);
  assert.equal(Object.isFrozen(mention?.tags), true);
});

test("distinguishes operator notes and team context", () => {
  const personal = parseSlackRememberCommand("remember review this tomorrow");
  assert.equal(personal?.working_memory_target, "memory");
  assert.deepEqual(personal?.tags, ["slack-remember", "operator-note"]);

  const team = parseSlackRememberCommand("remember the team prefers status in the thread");
  assert.equal(team?.working_memory_target, "team");
  assert.deepEqual(team?.tags, ["slack-remember", "team-context", "slack"]);

  assert.throws(() => parseSlackRememberCommand("remember"), /Add content/);
});

test("requires the host-verified companion mention before removing a mention", () => {
  assert.equal(
    parseSlackRememberCommand("<@U999> remember keep this note"),
    undefined,
  );
  assert.equal(
    parseSlackRememberCommand("<@U999> remember keep this note", {
      expected_mention: "<@U0BOT>",
    }),
    undefined,
  );
  assert.equal(
    parseSlackRememberCommand("<@U0BOT> remember keep this note", {
      expected_mention: "<@U0BOT>",
    })?.content,
    "keep this note",
  );
});

test("does not treat quoted prose as a remember command", () => {
  assert.equal(
    parseSlackRememberCommand('Actually that is useful. "Cerebro remember"'),
    undefined,
  );
});

test("normalizes bounded content and rejects ambiguous truncation or controls", () => {
  const normalized = parseSlackRememberCommand("remember  a   concise\n note  ");
  assert.equal(normalized?.content, "a concise note");
  assert.throws(
    () => parseSlackRememberCommand(`remember ${"x".repeat(901)}`),
    /content is too long/,
  );
  assert.equal(
    parseSlackRememberCommand(`remember ${"é".repeat(450)}`)?.content,
    "é".repeat(450),
  );
  assert.throws(
    () => parseSlackRememberCommand(`remember ${"é".repeat(451)}`),
    /content is too long/,
  );
  assert.throws(
    () => parseSlackRememberCommand("remember unsafe\u0000content"),
    SlackRememberCommandError,
  );
  assert.throws(
    () => parseSlackRememberCommand("remember hello", { author_name: "x".repeat(61) }),
    /author name is invalid/,
  );
});
