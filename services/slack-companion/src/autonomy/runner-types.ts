import type { CerebroClient } from "../cerebro/client.js";
import type { SecurityMemoryStore } from "../learning/security-memory/index.js";
import type { AutonomyGithubMonitorClient } from "./github-monitor-runner.js";
import type { AutonomyToolDispatcher } from "./tool-dispatcher.js";

export interface AutonomyRunnerOptions {
  workerId?: string;
  now?: () => Date;
  cerebro?: CerebroClient;
  memory?: SecurityMemoryStore;
  code?: AutonomyGithubMonitorClient;
  dispatcher?: AutonomyToolDispatcher;
}

export interface AutonomyRunnerAdvanceResult {
  goalId: string;
  status: "advanced" | "claimed_elsewhere" | "stale" | "skipped" | "failed";
  summary: string;
}
