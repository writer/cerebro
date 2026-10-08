import type { GRCFinding } from "@/lib/grc";

export const RISK_DOMAIN_IDS = ["cloud", "saas", "identity", "endpoint", "other"] as const;

export type RiskDomainID = typeof RISK_DOMAIN_IDS[number];

export const RISK_DOMAIN_LABELS: Record<RiskDomainID, string> = {
  cloud: "Cloud Posture",
  saas: "SaaS Posture",
  identity: "Identity",
  endpoint: "Endpoint",
  other: "Other",
};

export const RISK_DOMAIN_DETAIL: Record<RiskDomainID, string> = {
  cloud: "AWS, GCP, Azure, Kubernetes",
  saas: "GitHub, Microsoft 365, Slack, Salesforce",
  identity: "Directories, accounts, secrets, certificates",
  endpoint: "Managed devices and agents",
  other: "Not attributable to a posture domain",
};

// A finding's rule ID leads with its catalog category, and the list API returns
// rule_id on every item. It is the only cloud/SaaS dimension available here:
// cloud account, region and resource type are not returned by this endpoint.
// Unmapped prefixes stay in "other" rather than inflating a posture domain on a guess.
const DOMAIN_BY_RULE_PREFIX: Record<string, RiskDomainID> = {
  aws: "cloud",
  azure: "cloud",
  backup: "cloud",
  bucket: "cloud",
  cloud: "cloud",
  container: "cloud",
  db: "cloud",
  gcp: "cloud",
  gke: "cloud",
  k8s: "cloud",
  network: "cloud",
  serverless: "cloud",
  storage: "cloud",
  vpc: "cloud",
  github: "saas",
  hubspot: "saas",
  m365: "saas",
  repo: "saas",
  salesforce: "saas",
  slack: "saas",
  stripe: "saas",
  zendesk: "saas",
  admin: "identity",
  cert: "identity",
  consent: "identity",
  group: "identity",
  identity: "identity",
  okta: "identity",
  sa: "identity",
  secrets: "identity",
  user: "identity",
  endpoint: "endpoint",
  sentinelone: "endpoint",
  vm: "endpoint",
};

// Shipped rules are hyphen-delimited, but persisted and seeded records also use a
// dot-delimited form, so both separators have to yield the same leading segment.
export const riskDomainForRuleID = (ruleID?: string): RiskDomainID => {
  const prefix = (ruleID ?? "").trim().toLowerCase().split(/[-.]/)[0];
  return DOMAIN_BY_RULE_PREFIX[prefix] ?? "other";
};

export const riskDomainForFinding = (finding: GRCFinding): RiskDomainID =>
  riskDomainForRuleID(finding.rule_id);

export type RiskGroup = {
  critical: number;
  findings: GRCFinding[];
  high: number;
  id: string;
  label: string;
  topRisk: number;
  unowned: number;
};

const isUnowned = (finding: GRCFinding) => !finding.owner || finding.owner === "Unassigned";

const emptyGroup = (id: string, label: string): RiskGroup => ({
  critical: 0,
  findings: [],
  high: 0,
  id,
  label,
  topRisk: 0,
  unowned: 0,
});

const accumulate = (group: RiskGroup, finding: GRCFinding) => {
  group.findings.push(finding);
  if (finding.severity === "CRITICAL") group.critical += 1;
  if (finding.severity === "HIGH") group.high += 1;
  if (isUnowned(finding)) group.unowned += 1;
  group.topRisk = Math.max(group.topRisk, finding.risk_score ?? 0);
};

export const groupFindings = (
  findings: GRCFinding[],
  key: (finding: GRCFinding) => { id: string; label: string },
): RiskGroup[] => {
  const groups = new Map<string, RiskGroup>();
  for (const finding of findings) {
    const { id, label } = key(finding);
    const group = groups.get(id) ?? emptyGroup(id, label);
    accumulate(group, finding);
    groups.set(id, group);
  }
  return [...groups.values()].sort((left, right) =>
    right.critical - left.critical
    || right.high - left.high
    || right.topRisk - left.topRisk
    || right.findings.length - left.findings.length
    || left.label.localeCompare(right.label));
};

export const groupFindingsByRule = (findings: GRCFinding[]) =>
  groupFindings(findings, (finding) => ({
    id: finding.rule_id?.trim() || "unclassified",
    label: finding.policy_name?.trim() || finding.rule_id?.trim() || "Unclassified rule",
  }));

export const groupFindingsBySource = (findings: GRCFinding[]) =>
  groupFindings(findings, (finding) => ({
    id: finding.source_id?.trim() || "unknown",
    label: finding.source_id?.trim() || "Unattributed source",
  }));

export const riskDomainSummary = (findings: GRCFinding[]) => {
  const summary = RISK_DOMAIN_IDS.reduce((all, domain) => {
    all[domain] = emptyGroup(domain, RISK_DOMAIN_LABELS[domain]);
    return all;
  }, {} as Record<RiskDomainID, RiskGroup>);
  for (const finding of findings) {
    accumulate(summary[riskDomainForFinding(finding)], finding);
  }
  return summary;
};
