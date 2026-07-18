import type { ParsedEnv } from "./env.js";
import { csvSet, parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildLearningConfig(parsed: ParsedEnv): AppConfig["learning"] {
  return {
    enabled: parseBoolean(parsed.SECURITY_LEARNING_ENABLED),
    tableName: parsed.SECURITY_LEARNING_TABLE_NAME,
    maxSearchResults: parsed.SECURITY_LEARNING_MAX_SEARCH_RESULTS,
    channelLearningEnabled: parseBoolean(parsed.CEREBRO_SLACK_CHANNEL_LEARNING_ENABLED),
    channelLearningExcludedChannelIds: csvSet(parsed.CEREBRO_SLACK_CHANNEL_LEARNING_EXCLUDED_CHANNEL_IDS),
    channelLearningBatchSize: parsed.CEREBRO_SLACK_CHANNEL_LEARNING_BATCH_SIZE,
    channelLearningFlushIntervalMs: parsed.CEREBRO_SLACK_CHANNEL_LEARNING_FLUSH_INTERVAL_MS,
    dailyNotesEnabled: parseBoolean(parsed.CEREBRO_DAILY_NOTES_ENABLED),
    dailyNotesTimeZone: parsed.CEREBRO_DAILY_NOTES_TIME_ZONE,
    dailyNotesConsolidationHour: parsed.CEREBRO_DAILY_NOTES_CONSOLIDATION_HOUR,
    dailyNotesConsolidationMinute: parsed.CEREBRO_DAILY_NOTES_CONSOLIDATION_MINUTE,
    dailyNotesNightStartHour: parsed.CEREBRO_DAILY_NOTES_NIGHT_START_HOUR,
    dailyNotesNightEndHour: parsed.CEREBRO_DAILY_NOTES_NIGHT_END_HOUR,
    dailyNotesCheckIntervalMs: parsed.CEREBRO_DAILY_NOTES_CHECK_INTERVAL_MS,
    dailyNotesRetentionDays: parsed.CEREBRO_DAILY_NOTES_RETENTION_DAYS,
    workingMemoryEnabled: parseBoolean(parsed.SECURITY_WORKING_MEMORY_ENABLED),
    workingMemoryDir: parsed.SECURITY_WORKING_MEMORY_DIR,
    workingMemoryCharLimit: parsed.SECURITY_WORKING_MEMORY_CHAR_LIMIT,
    teamMemoryCharLimit: parsed.SECURITY_TEAM_MEMORY_CHAR_LIMIT,
    learningDocsEnabled: parseBoolean(parsed.SECURITY_LEARNING_DOCS_ENABLED),
    learningDocsDir: parsed.SECURITY_LEARNING_DOCS_DIR,
    learningDocsCharLimit: parsed.SECURITY_LEARNING_DOCS_CHAR_LIMIT,
  };
}
