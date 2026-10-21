import { DEFAULT_ASSET_RISK_MODEL, type AssetRiskModel, type AssetRiskModelResponse } from "@/lib/asset-risk-model";

// Fixture-mode stand-in for GET/PUT/DELETE /grc/asset-risk-model. Sections
// present in a PUT body replace the default section, as on the server.

export type AssetRiskFixtureResult = { payload: unknown; status: number };

const fixtureTimestamp = "2026-01-15T12:00:00Z";
const sectionKeys = ["asset_value", "vulnerability", "exposure", "countermeasures", "relations", "traversal", "thresholds"] as const;

let saved: AssetRiskModel | null = null;

const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

const response = (): AssetRiskModelResponse => ({
  model: saved ? clone(saved) : { ...clone(DEFAULT_ASSET_RISK_MODEL), tenant_id: "local" },
  persisted: Boolean(saved),
});

export const assetRiskFixtureResponse = (method: string, path: string, body?: string): AssetRiskFixtureResult | null => {
  if (path !== "grc/asset-risk-model") return null;
  if (method === "GET") return { payload: response(), status: 200 };
  if (method === "DELETE") {
    saved = null;
    return { payload: response(), status: 200 };
  }
  if (method !== "PUT") return { payload: { error: "method not allowed" }, status: 405 };
  let parsed: Record<string, unknown>;
  try {
    parsed = body ? JSON.parse(body) as Record<string, unknown> : {};
  } catch {
    return { payload: { error: "invalid asset risk model: malformed JSON" }, status: 400 };
  }
  const next = { ...clone(DEFAULT_ASSET_RISK_MODEL), tenant_id: "local" } as Record<string, unknown>;
  for (const key of sectionKeys) {
    if (parsed[key] !== undefined && parsed[key] !== null) next[key] = clone(parsed[key]);
  }
  saved = {
    ...(next as AssetRiskModel),
    model_version: "asset-risk-v1+config:fixture",
    created_at: saved?.created_at ?? fixtureTimestamp,
    updated_at: fixtureTimestamp,
  };
  return { payload: response(), status: 200 };
};

export const resetAssetRiskFixturesForTests = () => {
  saved = null;
};
