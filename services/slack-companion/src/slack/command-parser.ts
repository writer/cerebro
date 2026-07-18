import { isAutonomyGoalStatus, type AutonomyGoalStatus } from "../autonomy/goals.js";

export type ParsedCommand =
  | { name: "help" }
  | { name: "home" }
  | { name: "health"; runtimeId?: string }
  | { name: "findings"; runtimeId?: string }
  | { name: "ask"; question: string; scopeUrn?: string }
  | { name: "evidence"; runtimeId: string; findingId: string }
  | { name: "skills" }
  | { name: "skill"; skillId: string; details?: string }
  | { name: "schedule_create"; text: string }
  | { name: "schedules" }
  | { name: "schedule_run"; jobId: string }
  | { name: "schedule_pause"; jobId: string }
  | { name: "schedule_resume"; jobId: string }
  | { name: "goal_create"; text: string }
  | { name: "goals"; status?: AutonomyGoalStatus }
  | { name: "goal_show"; goalId: string }
  | { name: "goal_pause"; goalId: string }
  | { name: "goal_resume"; goalId: string }
  | { name: "goal_cancel"; goalId: string }
  | { name: "goal_complete"; goalId: string; summary?: string }
  | { name: "operator"; action: "whoami" | "deploy" | "health" }
  | { name: "sync"; runtimeId: string }
  | { name: "ingest"; runtimeId: string }
  | { name: "evaluate"; runtimeId: string };

export interface CommandHelpEntry {
  command: string;
  aliases: string[];
  usage: string;
  summary: string;
}

export interface CommandDefinition {
  command: string;
  aliases?: string[];
  usage: string;
  summary: string;
  parse(input: CommandParseInput): ParsedCommand;
}

export interface CommandParseInput {
  rest: string[];
  rawRest: string;
}

export const COMMAND_REGISTRY: readonly CommandDefinition[] = [
  {
    command: "help",
    usage: "/cerebro help",
    summary: "Show available commands.",
    parse: () => ({ name: "help" }),
  },
  {
    command: "home",
    usage: "/cerebro home",
    summary: "Refresh the Cerebro app home tab.",
    parse: () => ({ name: "home" }),
  },
  {
    command: "health",
    usage: "/cerebro health [runtime-id]",
    summary: "Show source runtime health.",
    parse: ({ rest }) => ({ name: "health", runtimeId: rest[0] }),
  },
  {
    command: "findings",
    aliases: ["finding"],
    usage: "/cerebro findings [runtime-id]",
    summary: "List open findings by runtime.",
    parse: ({ rest }) => ({ name: "findings", runtimeId: rest[0] }),
  },
  {
    command: "ask",
    usage: "/cerebro ask <question>",
    summary: "Ask a graph-backed Cerebro question.",
    parse: ({ rawRest }) => {
      if (!rawRest) throw new Error("Add a question after /cerebro ask");
      return { name: "ask", question: rawRest };
    },
  },
  {
    command: "evidence",
    usage: "/cerebro evidence <runtime-id> <finding-id>",
    summary: "Show finding evidence rows.",
    parse: ({ rest }) => {
      if (!rest[0] || !rest[1]) {
        throw new Error("Use /cerebro evidence <runtime-id> <finding-id>");
      }
      return { name: "evidence", runtimeId: rest[0], findingId: rest[1] };
    },
  },
  {
    command: "skills",
    aliases: ["runbooks"],
    usage: "/cerebro skills",
    summary: "List reusable security checks.",
    parse: () => ({ name: "skills" }),
  },
  {
    command: "skill",
    aliases: ["runbook"],
    usage: "/cerebro skill <skill-id> [details]",
    summary: "Run a reusable security check now.",
    parse: ({ rawRest }) => {
      const { head, tail } = splitHead(rawRest);
      if (!head) return { name: "skills" };
      return { name: "skill", skillId: head, details: tail || undefined };
    },
  },
  {
    command: "schedule",
    aliases: ["cron"],
    usage: "/cerebro schedule <plain language>",
    summary: "Create or manage a scheduled check.",
    parse: parseScheduleCommand,
  },
  {
    command: "schedules",
    aliases: ["jobs"],
    usage: "/cerebro schedules",
    summary: "List scheduled checks.",
    parse: () => ({ name: "schedules" }),
  },
  {
    command: "goal",
    usage: "/cerebro goal <objective>",
    summary: "Create or manage an autonomous goal.",
    parse: parseGoalCommand,
  },
  {
    command: "goals",
    usage: "/cerebro goals [status]",
    summary: "List autonomous goals.",
    parse: ({ rest }) => ({ name: "goals", status: parseGoalStatus(rest[0]) }),
  },
  {
    command: "operator",
    aliases: ["ops"],
    usage: "/cerebro operator [whoami|deploy|health]",
    summary: "Show operator identity, deploy policy, or runtime health.",
    parse: parseOperatorCommand,
  },
  {
    command: "sync",
    usage: "/cerebro sync <runtime-id>",
    summary: "Start a source runtime sync.",
    parse: ({ rest }) => runtimeAction("sync", rest[0]),
  },
  {
    command: "ingest",
    usage: "/cerebro ingest <runtime-id>",
    summary: "Start graph ingest for a runtime.",
    parse: ({ rest }) => runtimeAction("ingest", rest[0]),
  },
  {
    command: "evaluate",
    usage: "/cerebro evaluate <runtime-id>",
    summary: "Start finding evaluation for a runtime.",
    parse: ({ rest }) => runtimeAction("evaluate", rest[0]),
  },
];

validateCommandRegistry(COMMAND_REGISTRY);

const commandLookup = new Map(COMMAND_REGISTRY.flatMap((definition) => [
  [definition.command, definition],
  ...(definition.aliases ?? []).map((alias) => [alias, definition] as const),
] as const));

export function commandHelpEntries(): CommandHelpEntry[] {
  return COMMAND_REGISTRY.map((definition) => ({
    command: definition.command,
    aliases: definition.aliases ?? [],
    usage: definition.usage,
    summary: definition.summary,
  }));
}

export function parseCommand(text: string): ParsedCommand {
  const trimmed = text.trim();
  if (!trimmed) return { name: "help" };

  const { head, tail } = splitHead(trimmed);
  const command = head.toLowerCase();
  const definition = commandLookup.get(command);
  if (!definition) {
    return { name: "ask", question: trimmed };
  }
  return definition.parse({
    rawRest: tail,
    rest: words(tail),
  });
}

export function validateCommandRegistry(registry: readonly CommandDefinition[]): void {
  const seen = new Map<string, string>();
  for (const definition of registry) {
    const names = [definition.command, ...(definition.aliases ?? [])];
    for (const name of names) {
      const normalized = name.toLowerCase();
      const owner = seen.get(normalized);
      if (owner) {
        throw new Error(`Command name ${normalized} is registered by both ${owner} and ${definition.command}.`);
      }
      seen.set(normalized, definition.command);
    }
  }
}

function parseScheduleCommand({ rest, rawRest }: CommandParseInput): ParsedCommand {
  if (!rest[0]) return { name: "schedules" };

  const subcommand = rest[0].toLowerCase();
  if (subcommand === "list" || subcommand === "ls") {
    return { name: "schedules" };
  }
  if (subcommand === "run") {
    if (!rest[1]) throw new Error("Use /cerebro schedule run <schedule-id>");
    return { name: "schedule_run", jobId: rest[1] };
  }
  if (subcommand === "pause") {
    if (!rest[1]) throw new Error("Use /cerebro schedule pause <schedule-id>");
    return { name: "schedule_pause", jobId: rest[1] };
  }
  if (subcommand === "resume") {
    if (!rest[1]) throw new Error("Use /cerebro schedule resume <schedule-id>");
    return { name: "schedule_resume", jobId: rest[1] };
  }
  return { name: "schedule_create", text: rawRest };
}

function parseGoalCommand({ rest, rawRest }: CommandParseInput): ParsedCommand {
  if (!rest[0]) return { name: "goals" };

  const subcommand = rest[0].toLowerCase();
  if (subcommand === "list" || subcommand === "ls") {
    return { name: "goals", status: parseGoalStatus(rest[1]) };
  }
  if (subcommand === "show" || subcommand === "status") {
    if (!rest[1]) throw new Error("Use /cerebro goal show <goal-id>");
    return { name: "goal_show", goalId: rest[1] };
  }
  if (subcommand === "pause") {
    if (!rest[1]) throw new Error("Use /cerebro goal pause <goal-id>");
    return { name: "goal_pause", goalId: rest[1] };
  }
  if (subcommand === "resume") {
    if (!rest[1]) throw new Error("Use /cerebro goal resume <goal-id>");
    return { name: "goal_resume", goalId: rest[1] };
  }
  if (subcommand === "cancel") {
    if (!rest[1]) throw new Error("Use /cerebro goal cancel <goal-id>");
    return { name: "goal_cancel", goalId: rest[1] };
  }
  if (subcommand === "complete" || subcommand === "done") {
    if (!rest[1]) throw new Error("Use /cerebro goal complete <goal-id> [summary]");
    return { name: "goal_complete", goalId: rest[1], summary: rest.slice(2).join(" ") || undefined };
  }
  return { name: "goal_create", text: rawRest };
}

function parseGoalStatus(value: string | undefined): AutonomyGoalStatus | undefined {
  if (!value) return undefined;
  const normalized = value.toLowerCase();
  if (!isAutonomyGoalStatus(normalized)) {
    throw new Error("Goal status must be active, waiting, approval_needed, blocked, paused, completed, or cancelled.");
  }
  return normalized;
}

function parseOperatorCommand({ rest }: CommandParseInput): ParsedCommand {
  const subcommand = rest[0]?.toLowerCase();
  if (!subcommand || subcommand === "whoami" || subcommand === "me") {
    return { name: "operator", action: "whoami" };
  }
  if (subcommand === "deploy" || subcommand === "deployment" || subcommand === "autodeploy") {
    return { name: "operator", action: "deploy" };
  }
  if (subcommand === "health" || subcommand === "status") {
    return { name: "operator", action: "health" };
  }
  throw new Error("Use /cerebro operator whoami, /cerebro operator deploy, or /cerebro operator health.");
}

function runtimeAction(name: "sync" | "ingest" | "evaluate", runtimeId: string | undefined): ParsedCommand {
  if (!runtimeId) {
    throw new Error(`Use /cerebro ${name} <runtime-id>`);
  }
  return { name, runtimeId };
}

function splitHead(value: string): { head: string; tail: string } {
  const match = /^(\S+)(?:\s+([\s\S]*))?$/.exec(value.trim());
  return {
    head: match?.[1] ?? "",
    tail: match?.[2]?.trim() ?? "",
  };
}

function words(value: string): string[] {
  return value ? value.split(/\s+/).filter(Boolean) : [];
}
