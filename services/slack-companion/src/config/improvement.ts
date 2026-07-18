import type { ParsedEnv } from "./env.js";
import { parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildImprovementConfig(parsed: ParsedEnv): AppConfig["improvement"] {
  return {
    enabled: parseBoolean(parsed.CEREBRO_IMPROVEMENT_ENABLED),
    tableName: parsed.CEREBRO_IMPROVEMENT_TABLE_NAME,
    artifactBucket: parsed.CEREBRO_IMPROVEMENT_ARTIFACT_BUCKET,
    queueUrl: parsed.CEREBRO_IMPROVEMENT_QUEUE_URL,
    promotionKeyId: parsed.CEREBRO_IMPROVEMENT_PROMOTION_KEY_ID,
    delegationKeyId: parsed.CEREBRO_IMPROVEMENT_DELEGATION_KEY_ID,
    delegationRolloutMode: parsed.CEREBRO_IMPROVEMENT_DELEGATION_ROLLOUT_MODE,
    delegationCanaryBasisPoints: parsed.CEREBRO_IMPROVEMENT_DELEGATION_CANARY_BASIS_POINTS,
    delegationTtlSeconds: parsed.CEREBRO_IMPROVEMENT_DELEGATION_TTL_SECONDS,
    delegationPolicyVersion: parsed.CEREBRO_IMPROVEMENT_DELEGATION_POLICY_VERSION,
    delegationToolsetVersion: parsed.CEREBRO_IMPROVEMENT_DELEGATION_TOOLSET_VERSION,
    delegationMaxSourceCalls: parsed.CEREBRO_IMPROVEMENT_DELEGATION_MAX_SOURCE_CALLS,
    delegationMaxRuntimeMs: parsed.CEREBRO_IMPROVEMENT_DELEGATION_MAX_RUNTIME_MS,
    signalThreshold: parsed.CEREBRO_IMPROVEMENT_SIGNAL_THRESHOLD,
    pollIntervalMs: parsed.CEREBRO_IMPROVEMENT_POLL_INTERVAL_MS,
    staleRunHours: parsed.CEREBRO_IMPROVEMENT_STALE_RUN_HOURS,
  };
}
