export interface SlackCommandParseInput {
  readonly rawRest: string;
  readonly words: readonly string[];
}

export interface SlackCommandDefinition<Result> {
  readonly command: string;
  readonly aliases?: readonly string[];
  readonly usage: string;
  readonly summary: string;
  readonly parse: (input: SlackCommandParseInput) => Result;
}

export interface SlackCommandHelpEntry {
  readonly command: string;
  readonly aliases: readonly string[];
  readonly usage: string;
  readonly summary: string;
}

export interface SlackCommandFallbacks<Result> {
  readonly empty: () => Result;
  readonly unknown: (text: string) => Result;
}

export interface SlackCommandRegistry<Result> {
  readonly parse: (text: string) => Result;
  readonly helpEntries: () => readonly SlackCommandHelpEntry[];
}

interface RegisteredCommand<Result> extends SlackCommandHelpEntry {
  readonly parse: (input: SlackCommandParseInput) => Result;
}

const COMMAND_NAME_PATTERN = /^[a-z][a-z0-9_-]*$/;

/**
 * Creates a portable command parser from caller-owned command definitions.
 *
 * The registry performs no I/O and does not own command handlers. Parse
 * callbacks must also be pure so transport admission and execution remain
 * separate durability boundaries.
 */
export function createSlackCommandRegistry<Result>(
  definitions: readonly SlackCommandDefinition<Result>[],
  fallbacks: SlackCommandFallbacks<Result>,
): SlackCommandRegistry<Result> {
  const registered = definitions.map(snapshotDefinition);
  const lookup = buildLookup(registered);
  const help = Object.freeze(
    registered.map((definition) =>
      Object.freeze({
        command: definition.command,
        aliases: definition.aliases,
        usage: definition.usage,
        summary: definition.summary,
      }),
    ),
  );

  return Object.freeze({
    parse(text: string): Result {
      const trimmed = text.trim();
      if (!trimmed) return fallbacks.empty();

      const { head, tail } = splitHead(trimmed);
      const definition = lookup.get(head.toLowerCase());
      if (!definition) return fallbacks.unknown(trimmed);

      return definition.parse(
        Object.freeze({
          rawRest: tail,
          words: Object.freeze(tail ? tail.split(/\s+/) : []),
        }),
      );
    },
    helpEntries(): readonly SlackCommandHelpEntry[] {
      return help;
    },
  });
}

function snapshotDefinition<Result>(
  definition: SlackCommandDefinition<Result>,
): RegisteredCommand<Result> {
  validateName(definition.command);
  for (const alias of definition.aliases ?? []) validateName(alias);
  if (!definition.usage.trim() || !definition.summary.trim()) {
    throw new Error("command registry usage and summary must be non-empty");
  }

  return Object.freeze({
    command: definition.command,
    aliases: Object.freeze([...(definition.aliases ?? [])]),
    usage: definition.usage,
    summary: definition.summary,
    parse: definition.parse,
  });
}

function buildLookup<Result>(
  definitions: readonly RegisteredCommand<Result>[],
): ReadonlyMap<string, RegisteredCommand<Result>> {
  const lookup = new Map<string, RegisteredCommand<Result>>();
  for (const definition of definitions) {
    for (const name of [definition.command, ...definition.aliases]) {
      const normalized = name.toLowerCase();
      if (lookup.has(normalized)) {
        throw new Error("command registry name is registered more than once");
      }
      lookup.set(normalized, definition);
    }
  }
  return lookup;
}

function validateName(name: string): void {
  if (!COMMAND_NAME_PATTERN.test(name)) {
    throw new Error("command registry names must be lowercase single words");
  }
}

function splitHead(text: string): { head: string; tail: string } {
  const splitAt = text.search(/\s/);
  if (splitAt === -1) return { head: text, tail: "" };
  return {
    head: text.slice(0, splitAt),
    tail: text.slice(splitAt).trimStart(),
  };
}
