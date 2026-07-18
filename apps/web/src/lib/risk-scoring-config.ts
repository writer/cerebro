export type RiskScoringLevelThresholds = {
  critical: number;
  high: number;
  medium: number;
};

export type RiskScoringSignalThresholds = {
  epss_high: number;
  epss_elevated: number;
  cvss_critical: number;
  cvss_high: number;
  private_network_likelihood_cap: number;
};

export type RiskScoringFactorWeight = {
  likelihood?: number;
  impact?: number;
  confidence?: number;
  likelihood_cap?: number;
};

export type RiskScoringConfig = {
  tenant_id: string;
  thresholds: RiskScoringLevelThresholds;
  signals: RiskScoringSignalThresholds;
  relation_weights: Record<string, number>;
  factor_weights: Record<string, RiskScoringFactorWeight>;
  model_version: string;
  created_at?: string;
  updated_at?: string;
};

export type RiskScoringConfigResponse = {
  config: RiskScoringConfig;
  persisted: boolean;
};

export type RiskScoringConfigFormState = {
  tenantID: string;
  thresholds: RiskScoringLevelThresholds;
  signals: RiskScoringSignalThresholds;
  relationWeightsJSON: string;
  factorWeightsJSON: string;
};

export const DEFAULT_RISK_SCORING_CONFIG: RiskScoringConfig = {
  tenant_id: "local",
  thresholds: { critical: 85, high: 70, medium: 40 },
  signals: {
    epss_high: 0.7,
    epss_elevated: 0.2,
    cvss_critical: 9,
    cvss_high: 7,
    private_network_likelihood_cap: 35,
  },
  relation_weights: {
    can_admin: 10,
    can_assume: 8,
    can_impersonate: 8,
    can_perform: 8,
    can_reach: 7,
    acted_on: 5,
    has_evidence: 5,
    supports: 5,
    assigned_to: 4,
    member_of: 4,
    runs_as: 4,
    has_finding: 3,
    has_identifier: 1,
    has_classification: 1,
    tagged_as: 1,
    default: 2,
  },
  factor_weights: {
    external_exposure: { likelihood: 35 },
    critical_asset: { impact: 35 },
    privileged_actor: { likelihood: 10, impact: 15 },
    known_exploited: { likelihood: 35 },
    epss_high: { likelihood: 25 },
    limited_evidence: { confidence: -15 },
  },
  model_version: "likelihood-impact-v2",
};

export const riskScoringConfigPath = (tenantID: string) =>
  `/grc/risk-scoring-config?tenant_id=${encodeURIComponent(tenantID.trim() || "local")}`;

export const prettyJSON = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

export const riskScoringFormFromConfig = (config: RiskScoringConfig): RiskScoringConfigFormState => ({
  tenantID: config.tenant_id || "local",
  thresholds: { ...config.thresholds },
  signals: { ...config.signals },
  relationWeightsJSON: prettyJSON(config.relation_weights),
  factorWeightsJSON: prettyJSON(config.factor_weights),
});

export type RiskScoringPayloadResult =
  | { ok: true; payload: Record<string, unknown> }
  | { ok: false; error: string };

export const riskScoringPayloadFromForm = (form: RiskScoringConfigFormState): RiskScoringPayloadResult => {
  const tenantID = form.tenantID.trim();
  if (tenantID === "") {
    return { ok: false, error: "Tenant ID is required." };
  }
  const thresholdError = validateThresholds(form.thresholds);
  if (thresholdError) return { ok: false, error: thresholdError };
  const signalError = validateSignals(form.signals);
  if (signalError) return { ok: false, error: signalError };
  const relationWeights = parseJSONRecord<number>(form.relationWeightsJSON, "Relation weights");
  if (!relationWeights.ok) return relationWeights;
  const factorWeights = parseJSONRecord<RiskScoringFactorWeight>(form.factorWeightsJSON, "Factor weights");
  if (!factorWeights.ok) return factorWeights;
  return {
    ok: true,
    payload: {
      tenant_id: tenantID,
      thresholds: form.thresholds,
      signals: form.signals,
      relation_weights: relationWeights.value,
      factor_weights: factorWeights.value,
    },
  };
};

export const validateThresholds = (thresholds: RiskScoringLevelThresholds): string | null => {
  if (!scoreInRange(thresholds.critical) || !scoreInRange(thresholds.high) || !scoreInRange(thresholds.medium)) {
    return "Risk thresholds must be between 1 and 100.";
  }
  if (!(thresholds.critical > thresholds.high && thresholds.high > thresholds.medium)) {
    return "Risk thresholds must satisfy critical > high > medium.";
  }
  return null;
};

export const validateSignals = (signals: RiskScoringSignalThresholds): string | null => {
  if (!between(signals.epss_high, 0, 1) || !between(signals.epss_elevated, 0, 1) || signals.epss_high < signals.epss_elevated) {
    return "EPSS thresholds must satisfy 1 >= high >= elevated >= 0.";
  }
  if (!between(signals.cvss_critical, 0, 10) || !between(signals.cvss_high, 0, 10) || signals.cvss_critical <= signals.cvss_high) {
    return "CVSS thresholds must satisfy 10 >= critical > high >= 0.";
  }
  if (!scoreInRange(signals.private_network_likelihood_cap, true)) {
    return "Private network likelihood cap must be between 0 and 100.";
  }
  return null;
};

const parseJSONRecord = <T>(value: string, label: string): { ok: true; value: Record<string, T> } | { ok: false; error: string } => {
  try {
    const parsed = JSON.parse(value || "{}") as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: `${label} must be a JSON object.` };
    }
    return { ok: true, value: parsed as Record<string, T> };
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid JSON";
    return { ok: false, error: `${label} JSON is invalid: ${message}` };
  }
};

const scoreInRange = (value: number, allowZero = false) =>
  Number.isFinite(value) && value >= (allowZero ? 0 : 1) && value <= 100;

const between = (value: number, min: number, max: number) =>
  Number.isFinite(value) && value >= min && value <= max;
