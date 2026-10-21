import type { RiskScoringLevelThresholds } from "@/lib/risk-scoring-config";

// Mirrors internal/assetrisk. The server stores fractions (0-1); the editor
// shows percentages because they read more naturally next to each other.

export const ASSET_RISK_MODEL_PATH = "/grc/asset-risk-model";

export type AssetRiskRelationDirection = "outgoing" | "incoming" | "both";

export type AssetRiskValueModel = {
  default: number;
  crown_jewel: number;
  production_boost: number;
  classification_attributes: string[];
  classifications: Record<string, number>;
  kind_values: Record<string, number>;
};

export type AssetRiskVulnerabilityModel = {
  relations: string[];
  base: number;
  no_known_vulnerability: number;
  epss_weight: number;
  known_exploited: number;
  ransomware_use: number;
  cvss_critical: number;
  cvss_high: number;
  cvss_critical_probability: number;
  cvss_high_probability: number;
  max_per_asset: number;
};

export type AssetRiskExposureModel = {
  entry_probability: number;
  internet: number;
  internal: number;
  internet_attributes: string[];
};

export type AssetRiskCountermeasure = {
  key: string;
  label: string;
  attributes: string[];
  values?: string[];
  applies_to?: string[];
  reduction: number;
};

export type AssetRiskRelation = {
  probability: number;
  direction: AssetRiskRelationDirection;
  requires_exploit?: boolean;
};

export type AssetRiskTraversal = {
  max_depth: number;
  max_paths: number;
  max_expansions: number;
  min_probability: number;
};

export type AssetRiskModel = {
  tenant_id: string;
  asset_value: AssetRiskValueModel;
  vulnerability: AssetRiskVulnerabilityModel;
  exposure: AssetRiskExposureModel;
  countermeasures: AssetRiskCountermeasure[];
  relations: Record<string, AssetRiskRelation>;
  traversal: AssetRiskTraversal;
  thresholds: RiskScoringLevelThresholds;
  model_version: string;
  created_at?: string;
  updated_at?: string;
};

export type AssetRiskModelResponse = {
  model: AssetRiskModel;
  persisted: boolean;
};

export type AssetRiskModelPayload = Omit<AssetRiskModel, "model_version" | "created_at" | "updated_at" | "tenant_id"> & {
  tenant_id?: string;
};

export const DEFAULT_ASSET_RISK_MODEL: AssetRiskModel = {
  tenant_id: "",
  model_version: "asset-risk-v1",
  asset_value: {
    default: 0.2,
    crown_jewel: 1,
    production_boost: 0.15,
    classification_attributes: ["data_classification", "classification", "data_sensitivity", "sensitivity"],
    classifications: {
      restricted: 1,
      secret: 1,
      confidential: 0.85,
      pii: 0.85,
      phi: 0.9,
      pci: 0.9,
      sensitive: 0.8,
      internal: 0.4,
      public: 0.05,
    },
    kind_values: {
      secret: 0.9,
      database: 0.8,
      cluster: 0.7,
      repository: 0.6,
      bucket: 0.6,
      application: 0.6,
      role: 0.5,
      host: 0.5,
      instance: 0.5,
      device: 0.4,
      identity: 0.4,
      user: 0.4,
      person: 0.3,
      group: 0.3,
      entitlement: 0.4,
      capability: 0.5,
      vulnerability: 0,
    },
  },
  vulnerability: {
    relations: ["affected_by"],
    base: 0.05,
    no_known_vulnerability: 0.02,
    epss_weight: 1,
    known_exploited: 0.85,
    ransomware_use: 0.95,
    cvss_critical: 9,
    cvss_high: 7,
    cvss_critical_probability: 0.3,
    cvss_high_probability: 0.15,
    max_per_asset: 50,
  },
  exposure: {
    entry_probability: 0.2,
    internet: 1,
    internal: 0.4,
    internet_attributes: ["internet_exposed", "publicly_accessible", "public", "public_ip", "external_exposure"],
  },
  countermeasures: [
    { key: "mfa", label: "MFA enforced", attributes: ["mfa_enabled", "mfa_enforced", "mfa_active"], applies_to: ["identity", "user", "person", "account"], reduction: 0.6 },
    { key: "edr", label: "EDR agent active", attributes: ["edr_active", "edr_installed", "agent_active"], applies_to: ["device", "host", "instance", "endpoint"], reduction: 0.5 },
    { key: "network_segmentation", label: "Network segmented", attributes: ["network_segmented", "private_network"], reduction: 0.4 },
    { key: "waf", label: "WAF in front", attributes: ["waf_enabled", "waf_protected"], reduction: 0.3 },
    { key: "encryption", label: "Encrypted at rest", attributes: ["encrypted", "encryption_enabled", "disk_encrypted"], reduction: 0.2 },
  ],
  relations: {
    same_actor: { probability: 0.95, direction: "both" },
    represents_identity: { probability: 0.95, direction: "both" },
    owned_by: { probability: 0.7, direction: "both" },
    member_of: { probability: 1, direction: "outgoing" },
    assigned_to: { probability: 0.9, direction: "outgoing" },
    grants_entitlement: { probability: 0.9, direction: "outgoing" },
    confers_capability: { probability: 0.9, direction: "outgoing" },
    can_admin: { probability: 0.9, direction: "outgoing" },
    can_assume: { probability: 0.8, direction: "outgoing" },
    can_impersonate: { probability: 0.8, direction: "outgoing" },
    runs_as: { probability: 0.8, direction: "outgoing" },
    has_access: { probability: 0.7, direction: "outgoing" },
    can_perform: { probability: 0.6, direction: "outgoing" },
    can_reach: { probability: 0.5, direction: "outgoing", requires_exploit: true },
  },
  traversal: { max_depth: 4, max_paths: 50, max_expansions: 150, min_probability: 0.01 },
  thresholds: { critical: 40, high: 20, medium: 8 },
};

export type NamedPercent = { id: string; name: string; percent: number };

export type CountermeasureForm = {
  id: string;
  key: string;
  label: string;
  attributes: string;
  values: string;
  appliesTo: string;
  reductionPercent: number;
};

export type RelationForm = {
  id: string;
  name: string;
  percent: number;
  direction: AssetRiskRelationDirection;
  requiresExploit: boolean;
};

export type AssetRiskForm = {
  value: {
    defaultPercent: number;
    crownJewelPercent: number;
    productionBoostPercent: number;
    classificationAttributes: string;
    classifications: NamedPercent[];
    kinds: NamedPercent[];
  };
  vulnerability: {
    relations: string;
    basePercent: number;
    noKnownPercent: number;
    epssWeightPercent: number;
    knownExploitedPercent: number;
    ransomwarePercent: number;
    cvssCritical: number;
    cvssHigh: number;
    cvssCriticalPercent: number;
    cvssHighPercent: number;
    maxPerAsset: number;
  };
  exposure: {
    entryPercent: number;
    internetPercent: number;
    internalPercent: number;
    internetAttributes: string;
  };
  countermeasures: CountermeasureForm[];
  relations: RelationForm[];
  traversal: {
    maxDepth: number;
    maxPaths: number;
    maxExpansions: number;
    minProbabilityPercent: number;
  };
  thresholds: RiskScoringLevelThresholds;
};

let rowCounter = 0;
export const newRowID = () => {
  rowCounter += 1;
  return `row-${rowCounter}`;
};

export const toPercent = (fraction: number) => Math.round(fraction * 1000) / 10;
const toFraction = (percent: number) => Math.round(percent * 10) / 1000;

export const joinList = (values: readonly string[] | undefined) => (values ?? []).join(", ");

export const splitList = (value: string) => {
  const seen = new Set<string>();
  return value
    .split(",")
    .map((part) => part.trim().toLowerCase())
    .filter((part) => {
      if (!part || seen.has(part)) return false;
      seen.add(part);
      return true;
    });
};

const keyFromLabel = (label: string) =>
  label.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");

const namedPercents = (values: Record<string, number>): NamedPercent[] =>
  Object.entries(values)
    .sort(([leftName, left], [rightName, right]) => right - left || leftName.localeCompare(rightName))
    .map(([name, value]) => ({ id: newRowID(), name, percent: toPercent(value) }));

export const assetRiskFormFromModel = (model: AssetRiskModel): AssetRiskForm => ({
  value: {
    defaultPercent: toPercent(model.asset_value.default),
    crownJewelPercent: toPercent(model.asset_value.crown_jewel),
    productionBoostPercent: toPercent(model.asset_value.production_boost),
    classificationAttributes: joinList(model.asset_value.classification_attributes),
    classifications: namedPercents(model.asset_value.classifications),
    kinds: namedPercents(model.asset_value.kind_values),
  },
  vulnerability: {
    relations: joinList(model.vulnerability.relations),
    basePercent: toPercent(model.vulnerability.base),
    noKnownPercent: toPercent(model.vulnerability.no_known_vulnerability),
    epssWeightPercent: toPercent(model.vulnerability.epss_weight),
    knownExploitedPercent: toPercent(model.vulnerability.known_exploited),
    ransomwarePercent: toPercent(model.vulnerability.ransomware_use),
    cvssCritical: model.vulnerability.cvss_critical,
    cvssHigh: model.vulnerability.cvss_high,
    cvssCriticalPercent: toPercent(model.vulnerability.cvss_critical_probability),
    cvssHighPercent: toPercent(model.vulnerability.cvss_high_probability),
    maxPerAsset: model.vulnerability.max_per_asset,
  },
  exposure: {
    entryPercent: toPercent(model.exposure.entry_probability),
    internetPercent: toPercent(model.exposure.internet),
    internalPercent: toPercent(model.exposure.internal),
    internetAttributes: joinList(model.exposure.internet_attributes),
  },
  countermeasures: model.countermeasures.map((countermeasure) => ({
    id: newRowID(),
    key: countermeasure.key,
    label: countermeasure.label,
    attributes: joinList(countermeasure.attributes),
    values: joinList(countermeasure.values),
    appliesTo: joinList(countermeasure.applies_to),
    reductionPercent: toPercent(countermeasure.reduction),
  })),
  relations: Object.entries(model.relations)
    .sort(([leftName, left], [rightName, right]) => right.probability - left.probability || leftName.localeCompare(rightName))
    .map(([name, relation]) => ({
      id: newRowID(),
      name,
      percent: toPercent(relation.probability),
      direction: relation.direction,
      requiresExploit: Boolean(relation.requires_exploit),
    })),
  traversal: {
    maxDepth: model.traversal.max_depth,
    maxPaths: model.traversal.max_paths,
    maxExpansions: model.traversal.max_expansions,
    minProbabilityPercent: toPercent(model.traversal.min_probability),
  },
  thresholds: { ...model.thresholds },
});

type PayloadResult = { ok: true; payload: AssetRiskModelPayload } | { ok: false; error: string };

const isPercent = (value: number) => Number.isFinite(value) && value >= 0 && value <= 100;
const isIntegerIn = (value: number, min: number, max: number) => Number.isInteger(value) && value >= min && value <= max;

const namedMap = (rows: NamedPercent[], label: string): Record<string, number> | string => {
  const out: Record<string, number> = {};
  for (const row of rows) {
    const name = row.name.trim().toLowerCase();
    if (!name) return `Every ${label} needs a name.`;
    if (name in out) return `${label[0].toUpperCase()}${label.slice(1)} "${name}" is listed twice.`;
    if (!isPercent(row.percent)) return `${label[0].toUpperCase()}${label.slice(1)} "${name}" must be between 0% and 100%.`;
    out[name] = toFraction(row.percent);
  }
  return out;
};

// Validates with the same bounds as internal/assetrisk so most mistakes are
// caught before the request; the server remains the authority.
export const assetRiskPayloadFromForm = (form: AssetRiskForm, tenantID = ""): PayloadResult => {
  const fail = (error: string): PayloadResult => ({ ok: false, error });
  const percents: [string, number][] = [
    ["Default asset value", form.value.defaultPercent],
    ["Crown jewel value", form.value.crownJewelPercent],
    ["Production boost", form.value.productionBoostPercent],
    ["Vulnerability base probability", form.vulnerability.basePercent],
    ["No known vulnerability probability", form.vulnerability.noKnownPercent],
    ["EPSS weight", form.vulnerability.epssWeightPercent],
    ["Known exploited probability", form.vulnerability.knownExploitedPercent],
    ["Ransomware use probability", form.vulnerability.ransomwarePercent],
    ["Critical CVSS probability", form.vulnerability.cvssCriticalPercent],
    ["High CVSS probability", form.vulnerability.cvssHighPercent],
    ["Direct compromise probability", form.exposure.entryPercent],
    ["Internet exposure factor", form.exposure.internetPercent],
    ["Internal exposure factor", form.exposure.internalPercent],
    ["Minimum path probability", form.traversal.minProbabilityPercent],
  ];
  for (const [label, value] of percents) {
    if (!isPercent(value)) return fail(`${label} must be between 0% and 100%.`);
  }
  if (form.traversal.minProbabilityPercent >= 100) return fail("Minimum path probability must be below 100%.");

  const classifications = namedMap(form.value.classifications, "classification");
  if (typeof classifications === "string") return fail(classifications);
  const kinds = namedMap(form.value.kinds, "asset kind");
  if (typeof kinds === "string") return fail(kinds);

  const { cvssCritical, cvssHigh } = form.vulnerability;
  if (!(Number.isFinite(cvssCritical) && Number.isFinite(cvssHigh) && cvssCritical <= 10 && cvssHigh >= 0 && cvssCritical > cvssHigh)) {
    return fail("CVSS thresholds must satisfy 10 ≥ critical > high ≥ 0.");
  }
  if (!isIntegerIn(form.vulnerability.maxPerAsset, 1, 200)) return fail("Vulnerabilities counted per asset must be a whole number from 1 to 200.");
  const vulnerabilityRelations = splitList(form.vulnerability.relations);
  if (vulnerabilityRelations.length === 0 || vulnerabilityRelations.length > 8) return fail("List between 1 and 8 vulnerability relations.");

  const countermeasures: AssetRiskCountermeasure[] = [];
  const countermeasureKeys = new Set<string>();
  for (const row of form.countermeasures) {
    const key = (row.key.trim() || keyFromLabel(row.label)).toLowerCase();
    const label = row.label.trim() || key;
    if (!key) return fail("Every countermeasure needs a name.");
    if (countermeasureKeys.has(key)) return fail(`Countermeasure "${label}" is listed twice.`);
    countermeasureKeys.add(key);
    const attributes = splitList(row.attributes);
    if (attributes.length === 0) return fail(`Countermeasure "${label}" needs at least one attribute to look for.`);
    if (!isPercent(row.reductionPercent)) return fail(`Countermeasure "${label}" reduction must be between 0% and 100%.`);
    const values = splitList(row.values);
    const appliesTo = splitList(row.appliesTo);
    countermeasures.push({
      key,
      label,
      attributes,
      ...(values.length > 0 ? { values } : {}),
      ...(appliesTo.length > 0 ? { applies_to: appliesTo } : {}),
      reduction: toFraction(row.reductionPercent),
    });
  }

  const relations: Record<string, AssetRiskRelation> = {};
  for (const row of form.relations) {
    const name = row.name.trim().toLowerCase();
    if (!name) return fail("Every attack step needs a relation name.");
    if (name in relations) return fail(`Attack step "${name}" is listed twice.`);
    if (vulnerabilityRelations.includes(name)) return fail(`"${name}" is a vulnerability relation and cannot also be an attack step.`);
    if (!isPercent(row.percent)) return fail(`Attack step "${name}" must be between 0% and 100%.`);
    relations[name] = {
      probability: toFraction(row.percent),
      direction: row.direction,
      ...(row.requiresExploit ? { requires_exploit: true } : {}),
    };
  }
  if (Object.keys(relations).length === 0) return fail("Add at least one attack step.");

  const { traversal, thresholds } = form;
  if (!isIntegerIn(traversal.maxDepth, 1, 6)) return fail("Maximum path length must be a whole number from 1 to 6.");
  if (!isIntegerIn(traversal.maxPaths, 1, 200)) return fail("Paths returned must be a whole number from 1 to 200.");
  if (!isIntegerIn(traversal.maxExpansions, 1, 1000)) return fail("Exploration budget must be a whole number from 1 to 1000.");
  if (!(thresholds.critical <= 100 && thresholds.critical > thresholds.high && thresholds.high > thresholds.medium && thresholds.medium > 0)) {
    return fail("Risk levels must satisfy 100 ≥ critical > high > medium > 0.");
  }

  return {
    ok: true,
    payload: {
      ...(tenantID.trim() ? { tenant_id: tenantID.trim() } : {}),
      asset_value: {
        default: toFraction(form.value.defaultPercent),
        crown_jewel: toFraction(form.value.crownJewelPercent),
        production_boost: toFraction(form.value.productionBoostPercent),
        classification_attributes: splitList(form.value.classificationAttributes),
        classifications,
        kind_values: kinds,
      },
      vulnerability: {
        relations: vulnerabilityRelations,
        base: toFraction(form.vulnerability.basePercent),
        no_known_vulnerability: toFraction(form.vulnerability.noKnownPercent),
        epss_weight: toFraction(form.vulnerability.epssWeightPercent),
        known_exploited: toFraction(form.vulnerability.knownExploitedPercent),
        ransomware_use: toFraction(form.vulnerability.ransomwarePercent),
        cvss_critical: cvssCritical,
        cvss_high: cvssHigh,
        cvss_critical_probability: toFraction(form.vulnerability.cvssCriticalPercent),
        cvss_high_probability: toFraction(form.vulnerability.cvssHighPercent),
        max_per_asset: form.vulnerability.maxPerAsset,
      },
      exposure: {
        entry_probability: toFraction(form.exposure.entryPercent),
        internet: toFraction(form.exposure.internetPercent),
        internal: toFraction(form.exposure.internalPercent),
        internet_attributes: splitList(form.exposure.internetAttributes),
      },
      countermeasures,
      relations,
      traversal: {
        max_depth: traversal.maxDepth,
        max_paths: traversal.maxPaths,
        max_expansions: traversal.maxExpansions,
        min_probability: toFraction(traversal.minProbabilityPercent),
      },
      thresholds: { ...thresholds },
    },
  };
};

export const assetRiskModelPath = (tenantID = "") => {
  const tenant = tenantID.trim();
  return tenant ? `${ASSET_RISK_MODEL_PATH}?tenant_id=${encodeURIComponent(tenant)}` : ASSET_RISK_MODEL_PATH;
};

export type ExampleStep = { label: string; detail: string; probability: number; cumulative: number };

export type ExamplePath = {
  steps: ExampleStep[];
  targetValue: number;
  probability: number;
  score: number;
  level: "critical" | "high" | "medium" | "low";
};

const levelFor = (score: number, thresholds: RiskScoringLevelThresholds): ExamplePath["level"] => {
  if (score >= thresholds.critical) return "critical";
  if (score >= thresholds.high) return "high";
  if (score >= thresholds.medium) return "medium";
  return "low";
};

const clamp = (value: number) => (Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : 0);

// A worked example of the server's math, recomputed as the model is edited:
// an internal workstation with one known-exploited CVE, owned by an admin
// whose identity administers a database holding restricted data.
export const exampleAttackPath = (form: AssetRiskForm): ExamplePath => {
  const pct = (value: number) => clamp(value / 100);
  const relation = (name: string) => form.relations.find((row) => row.name.trim().toLowerCase() === name);
  const step = (name: string) => {
    const row = relation(name);
    return row?.requiresExploit ? 0 : pct(row?.percent ?? 0);
  };
  const exploit = Math.max(pct(form.vulnerability.basePercent), pct(form.vulnerability.knownExploitedPercent));
  const entry = clamp(1 - (1 - pct(form.exposure.entryPercent)) * (1 - exploit * pct(form.exposure.internalPercent)));
  const hops = [
    { label: "Workstation", detail: "Internal laptop with a known-exploited CVE", probability: entry },
    { label: "Admin", detail: "owned_by", probability: step("owned_by") },
    { label: "Admin's identity", detail: "same_actor", probability: step("same_actor") },
    { label: "Customer database", detail: "can_admin · restricted data", probability: step("can_admin") },
  ];
  let cumulative = 1;
  const steps = hops.map((hop) => {
    cumulative *= hop.probability;
    return { ...hop, cumulative };
  });
  const named = (rows: NamedPercent[], name: string) => rows.find((row) => row.name.trim().toLowerCase() === name);
  const kindValue = named(form.value.kinds, "database")?.percent ?? form.value.defaultPercent;
  const targetValue = Math.max(pct(named(form.value.classifications, "restricted")?.percent ?? 0), pct(kindValue));
  const score = Math.round(100 * cumulative * targetValue);
  return { steps, targetValue, probability: cumulative, score, level: levelFor(score, form.thresholds) };
};
