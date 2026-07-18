import assert from "node:assert/strict";
import test from "node:test";

import {
  createSlackCommandRegistry,
  type SlackCommandDefinition,
} from "../src/commands/registry.js";

type ParsedCommand =
  | { name: "help" }
  | { name: "ask"; question: string }
  | { name: "status"; target?: string }
  | { name: "run"; subject: string; details: string };

function registry(
  definitions: readonly SlackCommandDefinition<ParsedCommand>[] = definitionsFixture(),
) {
  return createSlackCommandRegistry(definitions, {
    empty: () => ({ name: "help" }),
    unknown: (question) => ({ name: "ask", question }),
  });
}

test("parses canonical names and aliases through caller-owned definitions", () => {
  const commands = registry();

  assert.deepEqual(commands.parse("status runtime-a"), {
    name: "status",
    target: "runtime-a",
  });
  assert.deepEqual(commands.parse("S runtime-b"), {
    name: "status",
    target: "runtime-b",
  });
});

test("provides exact raw remainder and normalized words to pure parsers", () => {
  const commands = registry();

  assert.deepEqual(commands.parse("run control-a  include   history"), {
    name: "run",
    subject: "control-a",
    details: "include history",
  });
});

test("delegates empty and unknown text to explicit fallbacks", () => {
  const commands = registry();

  assert.deepEqual(commands.parse("   "), { name: "help" });
  assert.deepEqual(commands.parse("why is this queued?"), {
    name: "ask",
    question: "why is this queued?",
  });
});

test("snapshots immutable help metadata independently of caller mutation", () => {
  const aliases = ["s"];
  const definitions = definitionsFixture(aliases);
  const commands = registry(definitions);
  aliases.push("changed");

  const help = commands.helpEntries();
  assert.deepEqual(help[0], {
    command: "status",
    aliases: ["s"],
    usage: "/assistant status [target]",
    summary: "Show current status.",
  });
  assert.equal(Object.isFrozen(help), true);
  assert.equal(Object.isFrozen(help[0]), true);
  assert.equal(Object.isFrozen(help[0]?.aliases), true);
});

test("rejects ambiguous or malformed caller definitions", () => {
  const parse = (): ParsedCommand => ({ name: "help" });
  const definition = (command: string, aliases: readonly string[] = []) => ({
    command,
    aliases,
    usage: `/assistant ${command}`,
    summary: "Summary.",
    parse,
  });

  assert.throws(
    () => registry([definition("one", ["shared"]), definition("two", ["shared"])]),
    /registered more than once/,
  );
  assert.throws(() => registry([definition("Upper")]), /lowercase single words/);
  assert.throws(() => registry([definition("two words")]), /lowercase single words/);
  assert.throws(
    () => registry([{ ...definition("empty"), summary: "" }]),
    /usage and summary must be non-empty/,
  );
});

function definitionsFixture(
  statusAliases: string[] = ["s"],
): SlackCommandDefinition<ParsedCommand>[] {
  return [
    {
      command: "status",
      aliases: statusAliases,
      usage: "/assistant status [target]",
      summary: "Show current status.",
      parse: ({ words }) => ({ name: "status", target: words[0] }),
    },
    {
      command: "run",
      usage: "/assistant run <subject> [details]",
      summary: "Run one registered action.",
      parse: ({ words }) => {
        const subject = words[0];
        if (!subject) throw new Error("run requires a subject");
        return {
          name: "run",
          subject,
          details: words.slice(1).join(" "),
        };
      },
    },
  ];
}
