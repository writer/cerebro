import { Buffer } from "node:buffer";

import {
  createSlackCommandRegistry,
  type SlackCommandDefinition,
} from "./registry.js";
import {
  parseSlackRememberCommand,
  type SlackRememberCommandOptions,
  type SlackRememberCommandV1,
} from "./remember.js";

const MAX_COMMAND_INPUT_LENGTH = 2_000;
const MAX_COMMAND_WORDS = 32;
const MAX_COMMAND_WORD_LENGTH = 256;
const UNSAFE_CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

export type ParsedSlackCommandV1 =
  | {
      readonly command_id: "help";
      readonly name: "help";
      readonly schema_version: "slack-command-intent/v1";
    }
  | {
      readonly command_id: "ask";
      readonly invocation: "explicit" | "implicit";
      readonly name: "ask";
      readonly question: string;
      readonly schema_version: "slack-command-intent/v1";
    }
  | {
      readonly command_id: "remember";
      readonly name: "remember";
      readonly remember: SlackRememberCommandV1;
      readonly schema_version: "slack-command-intent/v1";
    }
  | {
      readonly command_id: "status";
      readonly name: "status";
      readonly schema_version: "slack-command-intent/v1";
      readonly status_scope: "workspace" | "target";
      readonly target_hint?: string;
    }
  | {
      readonly command_id: "triage";
      readonly name: "triage";
      readonly schema_version: "slack-command-intent/v1";
      readonly target_hint: string;
    }
  | {
      readonly command_id: "watch";
      readonly name: "watch";
      readonly schema_version: "slack-command-intent/v1";
      readonly target_hint: string;
    }
  | {
      readonly command_id: "recheck";
      readonly name: "recheck";
      readonly schema_version: "slack-command-intent/v1";
      readonly target_hint: string;
    };

export interface SlackCommandCatalogEntryV1 {
  readonly aliases: readonly string[];
  readonly command_id: ParsedSlackCommandV1["command_id"];
  readonly summary: string;
  readonly token: string;
  readonly usage: string;
}

export interface SlackCommandCatalogV1 {
  readonly commands: readonly SlackCommandCatalogEntryV1[];
  readonly schema_version: "slack-command-catalog/v1";
}

export class SlackCommandParseError extends Error {}

const definitions: readonly SlackCommandDefinition<ParsedSlackCommandV1>[] = [
  {
    command: "help",
    usage: "/cerebro help",
    summary: "Show available commands.",
    parse: () => helpCommand(),
  },
  {
    command: "ask",
    usage: "/cerebro ask <question>",
    summary: "Ask Cerebro a question.",
    parse: ({ rawRest }) => askCommand(rawRest, "explicit"),
  },
  {
    command: "remember",
    usage: "/cerebro remember <note>",
    summary: "Record an explicit note after the host accepts it.",
    parse: ({ rawRest }) => rememberCommand(rawRest),
  },
  {
    command: "status",
    usage: "/cerebro status [target]",
    summary: "Show companion and work status.",
    parse: ({ rawRest }) => statusCommand(rawRest),
  },
  {
    command: "triage",
    usage: "/cerebro triage <alert-or-thread>",
    summary: "Start portable alert triage for a host-resolved target.",
    parse: ({ rawRest }) => targetCommand("triage", rawRest),
  },
  {
    command: "watch",
    usage: "/cerebro watch <answer-or-evidence>",
    summary: "Watch a delivered answer or evidence binding for changes.",
    parse: ({ rawRest }) => targetCommand("watch", rawRest),
  },
  {
    command: "recheck",
    usage: "/cerebro recheck <answer-or-evidence>",
    summary: "Request a fresh check of a delivered evidence binding.",
    parse: ({ rawRest }) => targetCommand("recheck", rawRest),
  },
];

const commandRegistry = createSlackCommandRegistry(definitions, {
  empty: helpCommand,
  unknown: (text) => askCommand(text, "implicit"),
});

export const SLACK_COMMAND_CATALOG_V1: SlackCommandCatalogV1 = Object.freeze({
  commands: Object.freeze(
    commandRegistry.helpEntries().map((entry) =>
      Object.freeze({
        aliases: entry.aliases,
        command_id: entry.command as ParsedSlackCommandV1["command_id"],
        summary: entry.summary,
        token: entry.command,
        usage: entry.usage,
      }),
    ),
  ),
  schema_version: "slack-command-catalog/v1",
});

/** Parses the portable command catalog. Unknown text remains an implicit question. */
export function parseSlackCommand(
  text: string,
  options: SlackRememberCommandOptions = {},
): ParsedSlackCommandV1 {
  const normalized = normalizeCommandText(text);
  const parsed = commandRegistry.parse(normalized);
  validateParsedCommand(parsed);
  if (parsed.name !== "remember" || options.author_name === undefined) return parsed;
  const remember = parseSlackRememberCommand(
    `remember ${parsed.remember.content}`,
    options,
  );
  if (!remember) throw new SlackCommandParseError("The remember command is invalid.");
  return Object.freeze({
    command_id: "remember",
    name: "remember",
    remember,
    schema_version: "slack-command-intent/v1",
  });
}

function helpCommand(): ParsedSlackCommandV1 {
  return Object.freeze({
    command_id: "help",
    name: "help",
    schema_version: "slack-command-intent/v1",
  });
}

function askCommand(
  question: string,
  invocation: "explicit" | "implicit",
): ParsedSlackCommandV1 {
  if (!question) throw new SlackCommandParseError("Add a question after /cerebro ask.");
  return Object.freeze({
    command_id: "ask",
    invocation,
    name: "ask",
    question,
    schema_version: "slack-command-intent/v1",
  });
}

function rememberCommand(content: string): ParsedSlackCommandV1 {
  const remember = parseSlackRememberCommand(`remember ${content}`);
  if (!remember) throw new SlackCommandParseError("The remember command is invalid.");
  return Object.freeze({
    command_id: "remember",
    name: "remember",
    remember,
    schema_version: "slack-command-intent/v1",
  });
}

function statusCommand(targetHint: string): ParsedSlackCommandV1 {
  if (!targetHint) {
    return Object.freeze({
      command_id: "status",
      name: "status",
      schema_version: "slack-command-intent/v1",
      status_scope: "workspace",
    });
  }
  return Object.freeze({
    command_id: "status",
    name: "status",
    schema_version: "slack-command-intent/v1",
    status_scope: "target",
    target_hint: targetHint,
  });
}

function targetCommand(
  name: "triage" | "watch" | "recheck",
  targetHint: string,
): ParsedSlackCommandV1 {
  if (!targetHint) {
    throw new SlackCommandParseError(`Add a target after /cerebro ${name}.`);
  }
  switch (name) {
    case "triage":
      return Object.freeze({
        command_id: "triage",
        name: "triage",
        schema_version: "slack-command-intent/v1",
        target_hint: targetHint,
      });
    case "watch":
      return Object.freeze({
        command_id: "watch",
        name: "watch",
        schema_version: "slack-command-intent/v1",
        target_hint: targetHint,
      });
    case "recheck":
      return Object.freeze({
        command_id: "recheck",
        name: "recheck",
        schema_version: "slack-command-intent/v1",
        target_hint: targetHint,
      });
  }
}

function normalizeCommandText(text: string): string {
  if (
    typeof text !== "string"
    || Buffer.byteLength(text, "utf8") > MAX_COMMAND_INPUT_LENGTH
    || UNSAFE_CONTROL_CHARACTERS.test(text)
  ) {
    throw new SlackCommandParseError("The Slack command input is invalid.");
  }
  return text.replace(/\s+/g, " ").trim();
}

function validateWords(text: string): void {
  const words = text ? text.split(" ") : [];
  if (
    words.length > MAX_COMMAND_WORDS
    || words.some((word) => Buffer.byteLength(word, "utf8") > MAX_COMMAND_WORD_LENGTH)
  ) {
    throw new SlackCommandParseError("The Slack command arguments exceed supported bounds.");
  }
}

function validateParsedCommand(command: ParsedSlackCommandV1): void {
  switch (command.name) {
    case "status":
      if (command.status_scope === "target") validateWords(command.target_hint ?? "");
      return;
    case "triage":
    case "watch":
    case "recheck":
      validateWords(command.target_hint);
      return;
    case "ask":
    case "help":
    case "remember":
      return;
  }
}
