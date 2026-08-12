import { AgentGymContractError, CEREBRO_AGENT_GYM } from "./index.js";

export interface AgentGymCliCommandV1 {
  readonly command: "compare" | "replay" | "validate" | "version";
  readonly input_paths: readonly string[];
  readonly output: "json" | "ndjson";
  readonly schema_version: "agent-gym-cli-command/v1";
}

/** Parses the stable, intentionally narrow repository CLI surface. */
export function parseAgentGymCliCommand(args: readonly string[]): AgentGymCliCommandV1 {
  if (args.length === 1 && args[0] === "--version") {
    return Object.freeze({
      command: "version",
      input_paths: Object.freeze([]),
      output: "json",
      schema_version: "agent-gym-cli-command/v1",
    });
  }
  const [command, ...rest] = args;
  if (command !== "compare" && command !== "replay" && command !== "validate") invalid();
  const formatIndex = rest.indexOf("--output");
  let output: "json" | "ndjson" = "json";
  const paths = [...rest];
  if (formatIndex >= 0) {
    const selected = paths[formatIndex + 1];
    if ((selected !== "json" && selected !== "ndjson") || formatIndex + 2 !== paths.length) invalid();
    output = selected;
    paths.splice(formatIndex, 2);
  }
  if (paths.length === 0 || paths.length > 256) invalid();
  for (const path of paths) {
    if (!path.trim() || path.length > 1_024 || path.startsWith("-")
      || /[\u0000-\u001f\u007f]/u.test(path)) invalid();
  }
  return Object.freeze({
    command,
    input_paths: Object.freeze(paths),
    output,
    schema_version: "agent-gym-cli-command/v1",
  });
}

export function agentGymVersionOutput(): string {
  return `${JSON.stringify(CEREBRO_AGENT_GYM)}\n`;
}

function invalid(): never { throw new AgentGymContractError("Agent gym CLI command is invalid."); }
