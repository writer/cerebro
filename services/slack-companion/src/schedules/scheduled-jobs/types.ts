import type { SlackActor } from "../../auth.js";
import type { CerebroClient } from "../../cerebro/client.js";
import type { AppConfig } from "../../config/index.js";
import type { DailyNotesService } from "../../learning/daily-notes.js";
import type { SecuritySkillService } from "../../skills/security-skill-service.js";
import type {
  ScheduledContextProviderId,
  ScheduledJobDraft,
  ScheduledJobStatus,
} from "../schedule-parser.js";
import type { SchedulePlanner } from "../schedule-planner.js";

export interface CommandSender {
  send(command: unknown): Promise<unknown>;
}

export interface ScheduledJobRecord extends Omit<ScheduledJobDraft, "warnings"> {
  id: string;
  status: ScheduledJobStatus;
  createdAt: string;
  updatedAt: string;
  createdBy: SlackActor;
  warnings: string[];
  lastRunAt?: string;
  lastStatus?: "completed" | "failed";
  lastSummary?: string;
  consecutiveFailures?: number;
  lastFailureAt?: string;
  lastError?: string;
}

export interface ScheduledJobServiceStats {
  enabled: boolean;
  store: "dynamodb" | "memory";
  total: number;
  active: number;
  paused: number;
  completed: number;
  blocked: number;
  dueCount: number;
  oldestDueAgeMs: number;
  triggerOnlyCount: number;
  activeRuns: number;
  maxConcurrent: number;
  lastTickAt?: string;
  lastTickStatus?: "completed" | "failed";
  lastTickError?: string;
}

export interface ScheduledJobContextResult {
  providerId: ScheduledContextProviderId;
  title: string;
  status: "completed" | "failed";
  summary: string;
  details?: unknown;
}

export interface ScheduledJobRunResult {
  job: ScheduledJobRecord;
  status: "completed" | "failed";
  summary: string;
  contextResults: ScheduledJobContextResult[];
  stepResults: Array<{ stepId: string; title: string; status: "completed" | "failed"; summary: string }>;
}

export interface ScheduledJobServiceOptions {
  dynamo?: CommandSender;
  now?: () => Date;
  planner?: SchedulePlanner;
}

export interface ScheduledJobServiceDeps {
  config: AppConfig;
  cerebro: CerebroClient;
  notes: DailyNotesService;
  skills: SecuritySkillService;
}
