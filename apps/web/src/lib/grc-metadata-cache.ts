import type { GRCDashboard } from "@/lib/grc";

const GRC_METADATA_CACHE_TTL_MS = 5 * 60_000;
const grcMetadata = new Map<string, { value: string; expiresAt: number }>();

const writeMetadata = (key: string, value: unknown, now: number) => {
  const normalized = String(value ?? "").trim();
  if (!normalized) return;
  grcMetadata.set(key, { value: normalized, expiresAt: now + GRC_METADATA_CACHE_TTL_MS });
};

export const cacheGRCMetadata = (payload: unknown) => {
  const dashboard = payload as Partial<GRCDashboard> | null;
  if (!dashboard || typeof dashboard !== "object") return;
  const now = Date.now();
  dashboard.controls?.forEach((control) => {
    writeMetadata(`control:${control.framework_name}:${control.control_id}`, `${control.framework_name} ${control.control_id}`, now);
  });
  dashboard.connectors?.forEach((connector) => {
    writeMetadata(`runtime:${connector.runtime_id}`, connector.source_id || connector.runtime_id, now);
  });
  dashboard.findings?.forEach((finding) => {
    writeMetadata(`rule:${finding.rule_id}`, finding.rule_id, now);
    writeMetadata(`policy:${finding.policy_id}`, finding.policy_name || finding.policy_id, now);
  });
};

export const readGRCMetadata = (key: string) => {
  const cached = grcMetadata.get(key);
  if (!cached) return null;
  if (cached.expiresAt <= Date.now()) {
    grcMetadata.delete(key);
    return null;
  }
  return cached.value;
};
