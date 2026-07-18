import type { ParsedEnv } from "./env.js";
import { parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildSchedulesConfig(parsed: ParsedEnv): AppConfig["schedules"] {
  return {
    enabled: parseBoolean(parsed.CEREBRO_SCHEDULES_ENABLED),
    tableName: parsed.CEREBRO_SCHEDULES_TABLE_NAME ?? parsed.SECURITY_LEARNING_TABLE_NAME,
    pollIntervalMs: parsed.CEREBRO_SCHEDULES_POLL_INTERVAL_MS,
    maxConcurrent: parsed.CEREBRO_SCHEDULES_MAX_CONCURRENT,
    defaultChannelId: parsed.CEREBRO_SCHEDULES_DEFAULT_CHANNEL_ID ?? parsed.SLACK_DEFAULT_CHANNEL_ID,
    defaultTimeZone: parsed.CEREBRO_SCHEDULES_DEFAULT_TIME_ZONE || parsed.CEREBRO_DAILY_NOTES_TIME_ZONE,
  };
}
