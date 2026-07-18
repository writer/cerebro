import type { ParsedEnv } from "./env.js";
import { parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildAutonomyConfig(parsed: ParsedEnv): AppConfig["autonomy"] {
  return {
    goalsEnabled: parseBoolean(parsed.CEREBRO_AUTONOMY_GOALS_ENABLED),
    goalsTableName: parsed.CEREBRO_AUTONOMY_GOALS_TABLE_NAME ?? parsed.CEREBRO_SCHEDULES_TABLE_NAME ?? parsed.SECURITY_LEARNING_TABLE_NAME,
    legacyGoalsTableName: parsed.CEREBRO_AUTONOMY_GOALS_LEGACY_TABLE_NAME,
    maxListedGoals: parsed.CEREBRO_AUTONOMY_GOALS_MAX_LIST,
    runnerEnabled: parseBoolean(parsed.CEREBRO_AUTONOMY_RUNNER_ENABLED),
    runnerPollIntervalMs: parsed.CEREBRO_AUTONOMY_RUNNER_POLL_INTERVAL_MS,
    runnerLeaseMs: parsed.CEREBRO_AUTONOMY_RUNNER_LEASE_MS,
    runnerMaxGoalsPerTick: parsed.CEREBRO_AUTONOMY_RUNNER_MAX_GOALS_PER_TICK,
    queueEnabled: parseBoolean(parsed.CEREBRO_AUTONOMY_QUEUE_ENABLED),
    queueUrl: parsed.CEREBRO_AUTONOMY_QUEUE_URL,
    queuePublisherIntervalMs: parsed.CEREBRO_AUTONOMY_QUEUE_PUBLISHER_INTERVAL_MS,
    queuePublisherBatchSize: parsed.CEREBRO_AUTONOMY_QUEUE_PUBLISHER_BATCH_SIZE,
    queueReconcileIntervalMs: parsed.CEREBRO_AUTONOMY_QUEUE_RECONCILE_INTERVAL_MS,
    queueConsumerCount: parsed.CEREBRO_AUTONOMY_QUEUE_CONSUMER_COUNT,
    queueVisibilityTimeoutSeconds: parsed.CEREBRO_AUTONOMY_QUEUE_VISIBILITY_TIMEOUT_SECONDS,
  };
}
