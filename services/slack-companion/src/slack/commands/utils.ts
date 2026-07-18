import type { AppConfig } from "../../config/index.js";

export function assertAllowedTeam(config: AppConfig, teamId: string | undefined): void {
  if (config.slack.allowedTeamIds.size === 0) {
    return;
  }
  if (!teamId || !config.slack.allowedTeamIds.has(teamId)) {
    throw new Error("This Slack workspace is not allowed for Cerebro commands.");
  }
}

export function runtimeIdsFor(config: AppConfig, requested?: string): string[] {
  if (requested) {
    return [requested];
  }
  if (config.cerebro.defaultRuntimeIds.length === 0) {
    throw new Error("Set CEREBRO_DEFAULT_RUNTIME_IDS or pass a runtime id.");
  }
  return config.cerebro.defaultRuntimeIds;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function questionTitle(question: string): string {
  return `/cerebro ask: ${question.replace(/\s+/g, " ").trim().slice(0, 120) || "question"}`;
}
