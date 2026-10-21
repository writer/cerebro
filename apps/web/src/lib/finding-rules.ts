import { parse as parseYAML, stringify as stringifyYAML } from "yaml";

// Mirrors internal/rulecatalog: every built-in policy rule, Go detection, and
// correlation pattern plus the tenant's custom rules, classified for the
// /rules catalog.

export const RULE_CATALOG_PATH = "/finding-rules/catalog";
export const RULE_VALIDATE_PATH = "/finding-rules/validate";
export const RULE_TEST_PATH = "/finding-rules/test";

export type RuleDomain = "paas" | "saas" | "identity" | "correlation";
export type RulePosture = "cspm" | "sspm" | "ispm" | "correlation";
export type RuleOrigin = "builtin_policy" | "builtin_detection" | "correlation_pattern" | "custom";
export type RuleFormat = "yaml" | "json";

export type RuleCatalogEntry = {
  id: string;
  name: string;
  summary: string;
  severity: string;
  origin: RuleOrigin | string;
  domain: RuleDomain | string;
  posture: RulePosture | string;
  provider: string;
  category?: string;
  resource_type?: string;
  evaluation: string;
  detection: string;
  enabled: boolean;
  maturity?: string;
  tags?: string[];
  frameworks?: string[];
  mitre_techniques?: string[];
  updated_at?: string;
};

export type RuleCatalogDetail = RuleCatalogEntry & {
  description: string;
  attack_description: string;
  remediation: string;
  remediation_steps?: string[];
  runbook?: string;
  false_positives?: string[];
  references?: string[];
  control_refs?: { framework: string; control: string }[];
  mitre_attack?: { tactic: string; technique: string }[];
  conditions?: string[];
  query?: string;
  graph_query?: string;
  graph_source_kinds?: string[];
  correlated_rule_ids?: string[];
  correlation_dimensions?: string[];
  correlation_window?: string;
  fingerprint_fields?: string[];
  lifecycle?: string;
  source_path?: string;
  document?: string;
  editable: boolean;
  testable: boolean;
  created_by?: string;
  updated_by?: string;
  created_at?: string;
};

export type RuleCatalogResponse = {
  rules: RuleCatalogEntry[];
  total: number;
  custom_rules_ready: boolean;
};

export type RuleAuthoringIssue = { severity: "error" | "warning" | string; message: string };

export type RuleValidationResult = {
  valid: boolean;
  issues: RuleAuthoringIssue[];
  yaml?: string;
  json?: string;
  preview?: RuleCatalogDetail;
};

export type RuleTestResult = {
  valid: boolean;
  issues: RuleAuthoringIssue[];
  evaluated: boolean;
  matched: boolean;
  message: string;
};

export const ruleDomains: { id: RuleDomain; label: string; description: string }[] = [
  { id: "paas", label: "PaaS", description: "Cloud and platform posture (CSPM)" },
  { id: "saas", label: "SaaS", description: "SaaS application posture (SSPM)" },
  { id: "identity", label: "Identity", description: "Identity provider posture (ISPM)" },
  { id: "correlation", label: "Correlation", description: "Cross-source graph and event correlation" },
];

export const rulePostureLabels: Record<string, string> = {
  cspm: "CSPM",
  sspm: "SSPM",
  ispm: "ISPM",
  correlation: "Correlation",
};

export const ruleOriginLabels: Record<string, string> = {
  builtin_policy: "Built-in policy",
  builtin_detection: "Built-in detection",
  correlation_pattern: "Correlation pattern",
  custom: "Custom",
};

export const ruleEvaluationLabels: Record<string, string> = {
  cel: "Condition (CEL)",
  sql: "SQL query",
  graph: "Graph query",
  event: "Event detection",
  correlation: "Correlation",
};

export const ruleDetectionLabels: Record<string, string> = {
  posture: "Probing (current state)",
  event: "Event stream",
  correlation: "Correlation",
};

const severityOrder = ["critical", "high", "medium", "low", "info"];

export const severityRank = (severity: string) => {
  const index = severityOrder.indexOf(severity.trim().toLowerCase());
  return index === -1 ? severityOrder.length : index;
};

export const ruleSeverities = severityOrder;

export type RuleCatalogFilters = {
  domain: RuleDomain | "all";
  query: string;
  severity: string;
  origin: string;
  provider: string;
};

export const defaultRuleCatalogFilters: RuleCatalogFilters = {
  domain: "all",
  query: "",
  severity: "all",
  origin: "all",
  provider: "all",
};

const matchesQuery = (rule: RuleCatalogEntry, needle: string) =>
  [
    rule.id,
    rule.name,
    rule.summary,
    rule.provider,
    rule.resource_type,
    rule.category,
    ...(rule.tags ?? []),
    ...(rule.frameworks ?? []),
    ...(rule.mitre_techniques ?? []),
  ]
    .filter(Boolean)
    .some((field) => String(field).toLowerCase().includes(needle));

// Custom rules first, then by severity, then by name, so new authoring work and
// the most severe built-ins sit at the top of every tab.
export const filterRuleCatalog = (rules: RuleCatalogEntry[], filters: RuleCatalogFilters) => {
  const needle = filters.query.trim().toLowerCase();
  return rules
    .filter((rule) => {
      if (filters.domain !== "all" && rule.domain !== filters.domain) return false;
      if (filters.severity !== "all" && rule.severity.toLowerCase() !== filters.severity) return false;
      if (filters.origin !== "all" && rule.origin !== filters.origin) return false;
      if (filters.provider !== "all" && rule.provider !== filters.provider) return false;
      return !needle || matchesQuery(rule, needle);
    })
    .sort((left, right) => {
      const customDelta = Number(right.origin === "custom") - Number(left.origin === "custom");
      if (customDelta !== 0) return customDelta;
      const severityDelta = severityRank(left.severity) - severityRank(right.severity);
      if (severityDelta !== 0) return severityDelta;
      return (left.name || left.id).localeCompare(right.name || right.id);
    });
};

export type RuleCatalogSummary = {
  total: number;
  custom: number;
  byDomain: Record<string, number>;
  bySeverity: Record<string, number>;
  providers: { provider: string; count: number }[];
};

export const summarizeRuleCatalog = (rules: RuleCatalogEntry[], domain: RuleDomain | "all" = "all"): RuleCatalogSummary => {
  const byDomain: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  const providers = new Map<string, number>();
  let custom = 0;
  for (const rule of rules) {
    byDomain[rule.domain] = (byDomain[rule.domain] ?? 0) + 1;
    if (domain !== "all" && rule.domain !== domain) continue;
    bySeverity[rule.severity] = (bySeverity[rule.severity] ?? 0) + 1;
    if (rule.provider) providers.set(rule.provider, (providers.get(rule.provider) ?? 0) + 1);
    if (rule.origin === "custom") custom += 1;
  }
  return {
    total: rules.length,
    custom,
    byDomain,
    bySeverity,
    providers: [...providers.entries()]
      .map(([provider, count]) => ({ provider, count }))
      .sort((left, right) => right.count - left.count || left.provider.localeCompare(right.provider)),
  };
};

const withTenant = (path: string, tenantID: string) =>
  tenantID ? `${path}${path.includes("?") ? "&" : "?"}tenant_id=${encodeURIComponent(tenantID)}` : path;

export const ruleCatalogPath = (tenantID = "") => withTenant(RULE_CATALOG_PATH, tenantID);

export const ruleDetailPath = (ruleID: string, tenantID = "") =>
  withTenant(`${RULE_CATALOG_PATH}/${encodeURIComponent(ruleID)}`, tenantID);

export const customRulePath = (ruleID: string, tenantID = "") =>
  withTenant(`/finding-rules/custom/${encodeURIComponent(ruleID)}`, tenantID);

export type RuleDocumentConversion = { ok: true; content: string } | { ok: false; error: string };

// Local conversion keeps the YAML/JSON toggle usable on drafts the server would
// reject; the server still owns validation and canonical formatting.
export const convertRuleDocument = (content: string, from: RuleFormat, to: RuleFormat): RuleDocumentConversion => {
  if (from === to) return { ok: true, content };
  if (!content.trim()) return { ok: true, content: "" };
  try {
    const parsed: unknown = from === "json" ? JSON.parse(content) : parseYAML(content);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: "The document must be an object with apiVersion, kind, metadata, and spec." };
    }
    return {
      ok: true,
      content: to === "json" ? `${JSON.stringify(parsed, null, 2)}\n` : stringifyYAML(parsed, { lineWidth: 0 }),
    };
  } catch (error) {
    return { ok: false, error: `Could not convert ${from.toUpperCase()}: ${error instanceof Error ? error.message : String(error)}` };
  }
};

export const ruleIDFromDocument = (content: string, format: RuleFormat): string => {
  try {
    const parsed = (format === "json" ? JSON.parse(content) : parseYAML(content)) as { metadata?: { id?: unknown } } | null;
    const id = parsed?.metadata?.id;
    return typeof id === "string" ? id.trim() : "";
  } catch {
    return "";
  }
};

// Built-in IDs are reserved server-side, so a duplicate gets a custom- prefixed
// id and name suffix that the author can then rename.
export const duplicateRuleDocument = (document: string, sourceID: string): string | null => {
  try {
    const parsed = parseYAML(document) as { metadata?: Record<string, unknown> } | null;
    if (!parsed || typeof parsed !== "object" || !parsed.metadata) return null;
    const baseID = sourceID.startsWith("custom-") ? sourceID : `custom-${sourceID}`;
    parsed.metadata.id = baseID === sourceID ? `${sourceID}-copy` : baseID;
    if (typeof parsed.metadata.name === "string") parsed.metadata.name = `${parsed.metadata.name} (custom)`;
    delete parsed.metadata.lastModified;
    return stringifyYAML(parsed, { lineWidth: 0 });
  } catch {
    return null;
  }
};

export const hasBlockingIssues = (issues: RuleAuthoringIssue[] | undefined) =>
  (issues ?? []).some((issue) => issue.severity === "error");

export type RuleTemplate = {
  id: string;
  label: string;
  domain: RuleDomain;
  description: string;
  document: string;
  sampleResource: Record<string, unknown>;
};

export const ruleTemplates: RuleTemplate[] = [
  {
    id: "cspm",
    label: "Cloud posture (CSPM)",
    domain: "paas",
    description: "Probe a cloud resource's current configuration.",
    document: `apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: custom-s3-bucket-public-unencrypted
  name: Public S3 bucket without default encryption
  description: An S3 bucket is publicly readable and has no default encryption.
  tags: [aws, s3, exposure]
spec:
  severity: high
  effect: forbid
  resource: aws::s3::bucket
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "public_access"), true)
      - cmp_eq(path(resource, "default_encryption_enabled"), false)
  remediation:
    summary: Block public access and enable default SSE-KMS encryption.
    steps:
      - Enable S3 Block Public Access on the bucket.
      - Configure default encryption with a customer managed KMS key.
  frameworks:
    - name: SOC 2
      controls: [CC6.1]
  mitreAttack:
    - tactic: Collection
      technique: T1530
`,
    sampleResource: { public_access: true, default_encryption_enabled: false },
  },
  {
    id: "sspm",
    label: "SaaS posture (SSPM)",
    domain: "saas",
    description: "Check a SaaS application setting.",
    document: `apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: custom-github-public-repo-unprotected
  name: Public GitHub repository without branch protection
  description: A public repository allows direct pushes to its default branch.
  tags: [github, repository, change-management]
spec:
  severity: medium
  effect: forbid
  resource: github::repository
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "visibility"), "public")
      - cmp_eq(path(resource, "default_branch_protected"), false)
  remediation:
    summary: Protect the default branch and require reviews before merge.
    steps:
      - Add a branch protection rule or ruleset for the default branch.
      - Require pull request reviews and status checks.
  frameworks:
    - name: SOC 2
      controls: [CC8.1]
  mitreAttack:
    - tactic: Persistence
      technique: T1195.002
`,
    sampleResource: { visibility: "public", default_branch_protected: false },
  },
  {
    id: "ispm",
    label: "Identity posture (ISPM)",
    domain: "identity",
    description: "Check an identity provider account or policy.",
    document: `apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: custom-okta-admin-without-mfa
  name: Okta administrator without MFA
  description: An Okta administrator account has no enrolled MFA factor.
  tags: [okta, identity, privileged-access]
spec:
  severity: critical
  effect: forbid
  resource: okta::user
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "is_admin"), true)
      - cmp_eq(path(resource, "mfa_enrolled"), false)
  remediation:
    summary: Enroll a phishing-resistant MFA factor or remove admin rights.
    steps:
      - Require MFA enrollment for the administrator.
      - Remove admin roles until enrollment completes.
  frameworks:
    - name: SOC 2
      controls: [CC6.1]
  mitreAttack:
    - tactic: Initial Access
      technique: T1078.004
`,
    sampleResource: { is_admin: true, mfa_enrolled: false },
  },
  {
    id: "correlation",
    label: "Graph correlation",
    domain: "correlation",
    description: "Correlate graph facts across sources with a read-only query.",
    document: `apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: custom-public-resource-reaches-admin
  name: Public resource reaches an administrator identity
  description: An internet-exposed resource can assume or act as a privileged identity.
  tags: [correlation, exposure, privileged-access]
spec:
  severity: critical
  graph:
    query: >-
      MATCH (r:Resource {internet_exposed: true})-[:CAN_ASSUME]->(i:Identity {privileged: true})
      RETURN r.urn AS primary_urn, r.name AS primary_label, 'resource' AS primary_type,
      r.urn + '|' + i.urn AS fingerprint_key, 'Public resource reaches ' + i.urn AS summary,
      'critical' AS severity, 'restrict_exposure' AS action, [r.urn, i.urn] AS resource_urns,
      [i.urn] AS evidence
      ORDER BY primary_urn LIMIT 100
  remediation:
    summary: Remove public exposure or the trust path to the privileged identity.
    steps:
      - Restrict inbound access to the resource.
      - Scope down the role or remove the trust relationship.
  frameworks:
    - name: SOC 2
      controls: [CC6.6]
  mitreAttack:
    - tactic: Privilege Escalation
      technique: T1078
`,
    sampleResource: {},
  },
];
