import type { ParsedEnv } from "./env.js";
import { parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildCoordinationConfig(parsed: ParsedEnv): AppConfig["coordination"] {
  return {
    version: parsed.CEREBRO_COMPANION_VERSION,
    commitSubject: parsed.CEREBRO_COMPANION_COMMIT_SUBJECT?.trim() || undefined,
    eventDedupeEnabled: parseBoolean(parsed.CEREBRO_HA_EVENT_DEDUPE_ENABLED),
    eventDedupeTtlSeconds: parsed.CEREBRO_HA_EVENT_DEDUPE_TTL_SECONDS,
    lifecycleNoticeTtlSeconds: parsed.CEREBRO_LIFECYCLE_NOTICE_TTL_SECONDS,
    deploymentFenceEnabled: parseBoolean(parsed.CEREBRO_DEPLOYMENT_FENCE_ENABLED),
    deploymentFenceCacheMs: parsed.CEREBRO_DEPLOYMENT_FENCE_CACHE_MS,
    ecsClusterName: parsed.ECS_CLUSTER_NAME,
    ecsServiceName: parsed.ECS_SERVICE_NAME,
  };
}
