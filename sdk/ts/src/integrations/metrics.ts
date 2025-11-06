import { IntegrationCoverageRecord, IntegrationCoverageHealth } from "../types.js";

function toRatio(value: number, total: number): number {
  if (!Number.isFinite(total) || total <= 0) {
    return 0;
  }
  return value / total;
}

export function computeCoverageHealth(record: IntegrationCoverageRecord): IntegrationCoverageHealth {
  const { scopes } = record;
  const totalScopes = scopes.total ?? 0;
  const healthyPercentage = toRatio(scopes.healthy ?? 0, totalScopes);
  const warningPercentage = toRatio(scopes.warning ?? 0, totalScopes);
  const criticalPercentage = toRatio(scopes.critical ?? 0, totalScopes);
  const overallScore = healthyPercentage - warningPercentage * 0.5 - criticalPercentage;

  return {
    ...record,
    healthyPercentage,
    warningPercentage,
    criticalPercentage,
    overallScore,
  };
}

export function computeCoverageHealthMap(records: IntegrationCoverageRecord[]): Record<string, IntegrationCoverageHealth> {
  return records.reduce<Record<string, IntegrationCoverageHealth>>((acc, record) => {
    const health = computeCoverageHealth(record);
    acc[health.integration] = health;
    return acc;
  }, {});
}
