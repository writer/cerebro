import type { GRCDashboard } from "@/lib/grc";

const GRC_METADATA_CACHE_TTL_MS = 5 * 60_000;
const grcMetadata = new Map<string, { value: string; expiresAt: number }>();

export type GRCMetadataScope = {
  actor: string;
  apiKey?: string;
  tenantID?: string;
  workspaceID?: string;
};

const metadataCacheKey = (key: string, scope: GRCMetadataScope) => {
  const actor = scope.actor.trim();
  if (!actor) return null;
  return [
    scope.apiKey?.trim() ?? "",
    actor,
    scope.tenantID?.trim() ?? "",
    scope.workspaceID?.trim() ?? "",
    key,
  ].join("\n");
};

const writeMetadata = (key: string, value: unknown, now: number, scope: GRCMetadataScope) => {
  const normalized = String(value ?? "").trim();
  if (!normalized) return;
  const scopedKey = metadataCacheKey(key, scope);
  if (!scopedKey) return;
  grcMetadata.set(scopedKey, { value: normalized, expiresAt: now + GRC_METADATA_CACHE_TTL_MS });
};

export const cacheGRCMetadata = (payload: unknown, scope: GRCMetadataScope) => {
  const dashboard = payload as Partial<GRCDashboard> | null;
  if (!dashboard || typeof dashboard !== "object" || !scope.actor.trim()) return;
  const now = Date.now();
  dashboard.controls?.forEach((control) => {
    writeMetadata(
      `control:${control.framework_name}:${control.control_id}`,
      `${control.framework_name} ${control.control_id}`,
      now,
      scope,
    );
  });
  dashboard.connectors?.forEach((connector) => {
    writeMetadata(`runtime:${connector.runtime_id}`, connector.source_id || connector.runtime_id, now, scope);
  });
  dashboard.findings?.forEach((finding) => {
    writeMetadata(`rule:${finding.rule_id}`, finding.rule_id, now, scope);
    writeMetadata(`policy:${finding.policy_id}`, finding.policy_name || finding.policy_id, now, scope);
  });
};

export const readGRCMetadata = (key: string, scope: GRCMetadataScope) => {
  const scopedKey = metadataCacheKey(key, scope);
  if (!scopedKey) return null;
  const cached = grcMetadata.get(scopedKey);
  if (!cached) return null;
  if (cached.expiresAt <= Date.now()) {
    grcMetadata.delete(scopedKey);
    return null;
  }
  return cached.value;
};
