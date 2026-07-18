import { hostname } from "node:os";
import type { ParsedEnv } from "./env.js";
import { csv, parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildA2AConfig(parsed: ParsedEnv): AppConfig["a2a"] {
  const label = cleanIdentityPart(parsed.CEREBRO_A2A_LABEL, "primary");
  return {
    enabled: parseBoolean(parsed.CEREBRO_A2A_ENABLED),
    instanceId: parsed.CEREBRO_A2A_INSTANCE_ID?.trim()
      || `${label}-${cleanIdentityPart(hostname(), "local")}-${process.pid}`,
    label,
    role: cleanIdentityPart(parsed.CEREBRO_A2A_ROLE, "generalist"),
    capabilities: csv(parsed.CEREBRO_A2A_CAPABILITIES).slice(0, 24),
    heartbeatIntervalMs: parsed.CEREBRO_A2A_HEARTBEAT_INTERVAL_MS,
    instanceTtlSeconds: parsed.CEREBRO_A2A_INSTANCE_TTL_SECONDS,
    inboxPollIntervalMs: parsed.CEREBRO_A2A_INBOX_POLL_INTERVAL_MS,
    drainTimeoutMs: parsed.CEREBRO_A2A_DRAIN_TIMEOUT_MS,
    ensembleEnabled: parseBoolean(parsed.CEREBRO_ENSEMBLE_ENABLED),
    ensembleMaxPeers: parsed.CEREBRO_ENSEMBLE_MAX_PEERS,
    ensembleTimeoutMs: parsed.CEREBRO_ENSEMBLE_TIMEOUT_MS,
    workFleetEnabled: parseBoolean(parsed.CEREBRO_WORK_FLEET_ENABLED),
    workFleetMaxPeers: parsed.CEREBRO_WORK_FLEET_MAX_PEERS,
    workFleetTimeoutMs: parsed.CEREBRO_WORK_FLEET_TIMEOUT_MS,
    modelMaxConcurrent: parsed.CEREBRO_FLEET_MODEL_MAX_CONCURRENT,
    sourceMaxConcurrent: parsed.CEREBRO_FLEET_SOURCE_MAX_CONCURRENT,
    rateLeaseMs: parsed.CEREBRO_FLEET_RATE_LEASE_MS,
    rateWaitMs: parsed.CEREBRO_FLEET_RATE_WAIT_MS,
  };
}

function cleanIdentityPart(value: string, fallback: string): string {
  const cleaned = value.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80);
  return cleaned || fallback;
}
