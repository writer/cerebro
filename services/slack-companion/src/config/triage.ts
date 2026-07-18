import type { ParsedEnv } from "./env.js";
import { parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildTriageConfig(parsed: ParsedEnv): AppConfig["triage"] {
  const workQueueEnabled = parseBoolean(parsed.CEREBRO_WORK_QUEUE_ENABLED);
  if (workQueueEnabled && !parsed.CEREBRO_WORK_QUEUE_URL) {
    throw new Error("CEREBRO_WORK_QUEUE_URL is required when CEREBRO_WORK_QUEUE_ENABLED is true.");
  }
  return {
    enabled: parseBoolean(parsed.CEREBRO_TRIAGE_ENABLED),
    threadStateTableName: parsed.CEREBRO_TRIAGE_THREAD_STATE_TABLE_NAME ?? parsed.SECURITY_LEARNING_TABLE_NAME ?? parsed.CEREBRO_SCHEDULES_TABLE_NAME,
    minConfidence: parsed.CEREBRO_TRIAGE_MIN_CONFIDENCE,
    maxResearchSteps: parsed.CEREBRO_TRIAGE_MAX_RESEARCH_STEPS,
    timeoutMs: parsed.CEREBRO_TRIAGE_TIMEOUT_MS,
    maxConcurrent: parsed.CEREBRO_TRIAGE_MAX_CONCURRENT,
    promptMaxChars: parsed.CEREBRO_TRIAGE_PROMPT_MAX_CHARS,
    promptCompactionTargetChars: Math.max(4_000, Math.min(parsed.CEREBRO_TRIAGE_PROMPT_COMPACTION_TARGET_CHARS, Math.max(8_000, parsed.CEREBRO_TRIAGE_PROMPT_MAX_CHARS) - 1_000)),
    duplicateQuestionCooldownMs: parsed.CEREBRO_WORK_LOOP_DUPLICATE_COOLDOWN_MS,
    workQueueEnabled,
    workQueueUrl: parsed.CEREBRO_WORK_QUEUE_URL,
    workQueuePublisherIntervalMs: parsed.CEREBRO_WORK_QUEUE_PUBLISHER_INTERVAL_MS,
    workQueuePublisherBatchSize: parsed.CEREBRO_WORK_QUEUE_PUBLISHER_BATCH_SIZE,
    workQueueConsumerCount: parsed.CEREBRO_WORK_QUEUE_CONSUMER_COUNT,
    workQueueVisibilityTimeoutSeconds: parsed.CEREBRO_WORK_QUEUE_VISIBILITY_TIMEOUT_SECONDS,
    assistantRuntime: parsed.CEREBRO_ASSISTANT_RUNTIME,
    pi: {
      enabled: parseBoolean(parsed.PI_ENABLED),
      provider: parsed.PI_PROVIDER,
      model: parsed.PI_MODEL,
      thinkingLevel: parsed.PI_THINKING_LEVEL,
      executionModel: parsed.PI_EXECUTION_MODEL ?? parsed.PI_MODEL,
      executionThinkingLevel: parsed.PI_EXECUTION_THINKING_LEVEL ?? parsed.PI_THINKING_LEVEL,
    },
  };
}
