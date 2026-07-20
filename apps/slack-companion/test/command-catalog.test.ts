import assert from "node:assert/strict";
import test from "node:test";

import {
  parseSlackCommand,
  SLACK_COMMAND_CATALOG_V1,
  SlackCommandParseError,
} from "../src/index.js";

test("exposes stable immutable operator command identities", () => {
  assert.deepEqual(
    SLACK_COMMAND_CATALOG_V1.commands.map((command) => command.command_id),
    ["help", "ask", "remember", "status", "triage", "watch", "recheck"],
  );
  assert.equal(SLACK_COMMAND_CATALOG_V1.schema_version, "slack-command-catalog/v1");
  assert.equal(Object.isFrozen(SLACK_COMMAND_CATALOG_V1), true);
  assert.equal(Object.isFrozen(SLACK_COMMAND_CATALOG_V1.commands), true);
  assert.equal(Object.isFrozen(SLACK_COMMAND_CATALOG_V1.commands[0]), true);
  assert.equal(Object.isFrozen(SLACK_COMMAND_CATALOG_V1.commands[0]?.aliases), true);
});

test("parses explicit commands and keeps unknown text as an implicit question", () => {
  assert.deepEqual(parseSlackCommand("   "), {
    command_id: "help",
    name: "help",
    schema_version: "slack-command-intent/v1",
  });
  assert.deepEqual(parseSlackCommand("ASK   what changed?"), {
    command_id: "ask",
    invocation: "explicit",
    name: "ask",
    question: "what changed?",
    schema_version: "slack-command-intent/v1",
  });
  assert.deepEqual(parseSlackCommand("why is this queued?"), {
    command_id: "ask",
    invocation: "implicit",
    name: "ask",
    question: "why is this queued?",
    schema_version: "slack-command-intent/v1",
  });
});

test("parses remember through the shared registry and portable remember behavior", () => {
  const parsed = parseSlackCommand("remember that I prefer concise replies", {
    author_name: "Avery",
  });
  assert.equal(parsed.name, "remember");
  if (parsed.name !== "remember") assert.fail("expected remember command");
  assert.equal(parsed.command_id, "remember");
  assert.equal(parsed.remember.content, "I prefer concise replies");
  assert.equal(parsed.remember.summary, "Avery: I prefer concise replies");
  assert.equal(parsed.remember.working_memory_target, "team");
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.remember), true);
});

test("parses deterministic operator commands with host-resolved targets", () => {
  assert.deepEqual(parseSlackCommand("status"), {
    command_id: "status",
    name: "status",
    schema_version: "slack-command-intent/v1",
    status_scope: "workspace",
  });
  assert.deepEqual(parseSlackCommand("status incident://case/123"), {
    command_id: "status",
    name: "status",
    schema_version: "slack-command-intent/v1",
    status_scope: "target",
    target_hint: "incident://case/123",
  });
  assert.deepEqual(parseSlackCommand("triage <https://example.invalid/alert/123>"), {
    command_id: "triage",
    name: "triage",
    schema_version: "slack-command-intent/v1",
    target_hint: "<https://example.invalid/alert/123>",
  });
  assert.deepEqual(parseSlackCommand("watch the delivered answer above"), {
    command_id: "watch",
    name: "watch",
    schema_version: "slack-command-intent/v1",
    target_hint: "the delivered answer above",
  });
  assert.deepEqual(parseSlackCommand("recheck evidence://binding/abc"), {
    command_id: "recheck",
    name: "recheck",
    schema_version: "slack-command-intent/v1",
    target_hint: "evidence://binding/abc",
  });
});

test("requires targets for target-bound operator commands", () => {
  assert.throws(() => parseSlackCommand("triage"), /Add a target/);
  assert.throws(() => parseSlackCommand("watch"), /Add a target/);
  assert.throws(() => parseSlackCommand("recheck"), /Add a target/);
});

test("rejects empty explicit questions and command input outside fixed bounds", () => {
  assert.throws(() => parseSlackCommand("ask"), /Add a question/);
  assert.throws(() => parseSlackCommand("remember"), /Add content/);
  assert.throws(
    () => parseSlackCommand("x".repeat(2_001)),
    SlackCommandParseError,
  );
  assert.throws(
    () => parseSlackCommand(`triage ${Array.from({ length: 33 }, () => "word").join(" ")}`),
    /arguments exceed supported bounds/,
  );
  assert.throws(
    () => parseSlackCommand(`watch ${"x".repeat(257)}`),
    /arguments exceed supported bounds/,
  );
  assert.throws(
    () => parseSlackCommand(`recheck ${"é".repeat(129)}`),
    /arguments exceed supported bounds/,
  );
  assert.throws(
    () => parseSlackCommand("é".repeat(1_001)),
    /input is invalid/,
  );
  assert.throws(() => parseSlackCommand("ask unsafe\u0000text"), /input is invalid/);
});

test("allows long free-form ask and remember text within byte bounds", () => {
  const question = Array.from({ length: 80 }, (_, index) => `word${index}`).join(" ");
  assert.deepEqual(parseSlackCommand(`ask ${question}`), {
    command_id: "ask",
    invocation: "explicit",
    name: "ask",
    question,
    schema_version: "slack-command-intent/v1",
  });

  const remembered = Array.from({ length: 60 }, (_, index) => `note${index}`).join(" ");
  const parsed = parseSlackCommand(`remember ${remembered}`);
  assert.equal(parsed.name, "remember");
  if (parsed.name !== "remember") assert.fail("expected remember command");
  assert.equal(parsed.remember.content, remembered);
});
