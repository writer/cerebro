import type { Authorization, SlackActor } from "../../auth.js";
import type { AutonomyGoalService } from "../../autonomy/goal-service.js";
import type { CerebroClient } from "../../cerebro/client.js";
import type { AppConfig } from "../../config/index.js";
import type { DailyNotesService } from "../../learning/daily-notes.js";
import type { ScheduledJobService } from "../../schedules/scheduled-jobs/index.js";
import type { SecuritySkillService } from "../../skills/security-skill-service.js";
import type { CompanionWorkLoop } from "../../work/companion-work-loop.js";
import type { SlackEventCoordinator } from "../coordination.js";
import type { ParsedCommand } from "../command-parser.js";
import type { A2AFleetService } from "../../a2a/index.js";

export interface CommandDeps {
  config: AppConfig;
  auth: Authorization;
  cerebro: CerebroClient;
  notes: DailyNotesService;
  skills: SecuritySkillService;
  scheduler: ScheduledJobService;
  goals: AutonomyGoalService;
  coordinator?: SlackEventCoordinator;
  workLoop?: CompanionWorkLoop;
  a2a?: A2AFleetService;
}

export interface CommandContext<TCommand extends ParsedCommand = ParsedCommand> {
  deps: CommandDeps;
  command: any;
  respond: (message: any) => Promise<unknown>;
  client: any;
  actor: SlackActor;
  parsed: TCommand;
}

export type CommandByName<Name extends ParsedCommand["name"]> = Extract<ParsedCommand, { name: Name }>;
export type CommandHandler<TCommand extends ParsedCommand = ParsedCommand> = (context: CommandContext<TCommand>) => Promise<void>;
export type CommandHandlers = {
  [Name in ParsedCommand["name"]]: CommandHandler<CommandByName<Name>>;
};
