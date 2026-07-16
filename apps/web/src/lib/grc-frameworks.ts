import { connectorCoverageControlRefLabel } from "@/lib/connectors";
import type { ConnectorCoverageControlRef, ConnectorScopeOption } from "@/lib/connectors";
import type { GRCControl, GRCControlRef, GRCFinding, GRCFramework, GRCInventoryAsset, GRCInventoryTest } from "@/lib/grc";

export type SupportedGRCFramework = {
  name: string;
  aliases?: string[];
  lifecycle?: "active" | "upcoming";
};

export type GRCFrameworkSegment = {
  framework: SupportedGRCFramework;
  alertTerms: string[];
  assetTerms: string[];
  connectorFamilies: string[];
  sourceIDs: string[];
};

// Mirrored from writer/cerebro internal/compliance/control_families.yaml version 2026-06-17.
export const supportedGRCFrameworks: SupportedGRCFramework[] = [
  { name: "SOC 2", aliases: ["soc2"] },
  { name: "ISO 27001:2022", aliases: ["iso27001", "iso 27001", "iso 27001 2022"] },
  { name: "ISO 27701", aliases: ["iso27701"] },
  { name: "ISO 27701:2025", aliases: ["iso27701 2025", "iso 27701 2025"] },
  { name: "ISO 42001", aliases: ["iso42001", "ai management system"] },
  { name: "NIST 800-53 r5", aliases: ["nist 800 53", "nist sp 800 53", "nist 800-53 rev 5"] },
  { name: "CIS Controls v8", aliases: ["cis controls", "cis v8"] },
  { name: "CIS AWS Foundations Benchmark v2.0", aliases: ["cis aws", "aws foundations benchmark"] },
  { name: "CIS Kubernetes Benchmark", aliases: ["cis kubernetes", "cis k8s"] },
  { name: "CIS GKE Benchmark v1.4", aliases: ["cis gke", "gke benchmark"] },
  { name: "CIS EKS Benchmark v1.3", aliases: ["cis eks", "eks benchmark"] },
  { name: "CIS Benchmarks", aliases: ["cis benchmark"] },
  { name: "PCI DSS v4.0.1", aliases: ["pci dss", "pci"] },
  { name: "PCI DSS v4.0", aliases: ["pci dss 4"] },
  { name: "PCI SAQ D-SP", aliases: ["pci saq", "saq d-sp"] },
  { name: "HIPAA" },
  { name: "GDPR" },
  { name: "CCPA" },
  { name: "US Data Privacy", aliases: ["us privacy"] },
  { name: "EU AI Act", aliases: ["eu ai"] },
  { name: "HITRUST e1", aliases: ["hitrust"] },
  { name: "CISA" },
  { name: "DORA", aliases: ["digital operational resilience act"] },
  { name: "FedRAMP Rev. 5", aliases: ["fedramp", "fedramp rev5", "fedramp rev 5"] },
  { name: "NIS2", aliases: ["nis 2"] },
  { name: "CMMC 2.0", aliases: ["cmmc"] },
  { name: "CJIS Security Policy", aliases: ["cjis"] },
  { name: "NIST CSF 2.0", aliases: ["nist csf", "cybersecurity framework"] },
  { name: "Cerebro AI Governance", aliases: ["ai governance"] },
  { name: "Cerebro Financial Controls", aliases: ["financial controls"] },
  { name: "Cerebro Operational Resilience", aliases: ["operational resilience"] },
  { name: "Cerebro Organizational Resilience", aliases: ["organizational resilience"] },
  { name: "Cerebro Revenue Operations", aliases: ["revenue operations"] },
  { name: "CIS GitHub Benchmark", aliases: ["cis github"] },
  { name: "CIS Google Workspace Benchmark", aliases: ["cis google workspace"] },
  { name: "NIST SP 800-177", aliases: ["nist 800 177", "nist email"] },
  { name: "NIST AI RMF 1.0", aliases: ["nist ai rmf", "ai risk management framework"], lifecycle: "upcoming" },
  { name: "CSA CCM v4.0", aliases: ["csa ccm", "cloud controls matrix"], lifecycle: "upcoming" },
];

export const supportedGRCFrameworkNames = supportedGRCFrameworks.map((framework) => framework.name);
export const activeGRCFrameworkNames = supportedGRCFrameworks
  .filter((framework) => framework.lifecycle !== "upcoming")
  .map((framework) => framework.name);
export const upcomingGRCFrameworkNames = supportedGRCFrameworks
  .filter((framework) => framework.lifecycle === "upcoming")
  .map((framework) => framework.name);

const normalizeFrameworkText = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();

const compactFrameworkText = (value: string) => normalizeFrameworkText(value).replace(/\s+/g, "");

export const frameworkRouteSegment = (framework: { id?: string; name: string }) =>
  encodeURIComponent(
    (framework.id?.trim() || framework.name.trim())
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, ""),
  );

export const frameworkMatchesRouteSegment = (framework: { id?: string; name: string }, segment: string) => {
  const decoded = decodeURIComponent(segment).trim().toLowerCase();
  return decoded === framework.id?.trim().toLowerCase() || decoded === decodeURIComponent(frameworkRouteSegment(framework));
};

export const staticGRCFrameworkCatalog: GRCFramework[] = supportedGRCFrameworks.map((framework) => {
  const upcoming = framework.lifecycle === "upcoming";
  return {
    id: frameworkRouteSegment(framework),
    name: framework.name,
    lifecycle: framework.lifecycle ?? "active",
    family_count: 0,
    control_count: 0,
    maturity: {
      status: upcoming ? "planning" : "not_configured",
      score: 0,
      summary: upcoming
        ? "Framework is discoverable for scoping, but controls are not measured yet."
        : "Live framework metadata is not available yet.",
    },
    coverage: {
      selected_controls: 0,
      mapped_controls: 0,
      unmapped_controls: 0,
      mapped_rules: 0,
    },
    readiness: {
      auditor_ready_controls: 0,
      needs_enrichment_controls: 0,
      placeholder_controls: 0,
    },
    gap_actions: [{
      code: upcoming ? "plan_framework_scope" : "select_controls",
      label: upcoming
        ? "Define applicability, owners, and initial control scope."
        : "Connect the backend framework catalog to populate live maturity.",
      priority: 1,
    }],
  };
});

export const frameworkSearchTerms = (framework: SupportedGRCFramework) => [
  framework.name,
  ...(framework.aliases ?? []),
];

export const findSupportedGRCFramework = (query: string) => {
  const normalizedQuery = normalizeFrameworkText(query);
  if (!normalizedQuery) {
    return null;
  }
  const compactQuery = compactFrameworkText(query);

  const exact = supportedGRCFrameworks.find((framework) =>
    frameworkSearchTerms(framework).some((term) =>
      normalizeFrameworkText(term) === normalizedQuery || compactFrameworkText(term) === compactQuery,
    ),
  );
  if (exact) {
    return exact;
  }

  if (normalizedQuery.length < 3) {
    return null;
  }
  return supportedGRCFrameworks.find((framework) =>
    frameworkSearchTerms(framework).some((term) =>
      normalizeFrameworkText(term).startsWith(normalizedQuery) || compactFrameworkText(term).startsWith(compactQuery),
    ),
  ) ?? null;
};

export const isUpcomingGRCFramework = (query: string) =>
  findSupportedGRCFramework(query)?.lifecycle === "upcoming";

export const frameworkOptionLabel = (framework: string) =>
  isUpcomingGRCFramework(framework) ? `${framework} (Upcoming)` : framework;

const identityTerms = ["identity", "access", "user", "users", "group", "groups", "role", "roles", "mfa", "sso", "iam", "okta", "entra", "duo", "workspace"];
const cloudTerms = ["aws", "gcp", "azure", "cloud", "compute", "storage", "bucket", "database", "network", "container", "kubernetes", "kms", "key", "logging"];
const resilienceTerms = ["backup", "recovery", "availability", "resilience", "incident", "monitoring", "vendor", "third party", "continuity", "sla"];
const privacyTerms = ["privacy", "pii", "personal", "customer", "data", "subject", "consent", "ccpa", "gdpr"];
const aiTerms = ["ai", "ml", "model", "bedrock", "sagemaker", "openai", "agent", "aiplatform"];
const financialTerms = ["pci", "payment", "card", "cde", "billing", "refund", "revenue", "invoice", "finance"];

const frameworkSegmentCatalog: Record<string, Omit<GRCFrameworkSegment, "framework">> = {
  "SOC 2": {
    alertTerms: [...identityTerms, ...cloudTerms, ...resilienceTerms, "audit", "change", "security", "confidentiality", "processing integrity"],
    assetTerms: [...identityTerms, ...cloudTerms, ...resilienceTerms, "owner", "public", "critical"],
    connectorFamilies: [...identityTerms, ...cloudTerms, ...resilienceTerms, "audit", "repository", "branch"],
    sourceIDs: [],
  },
  "ISO 27001:2022": {
    alertTerms: [...identityTerms, ...cloudTerms, ...resilienceTerms, "risk", "asset", "vulnerability", "supplier", "policy"],
    assetTerms: [...identityTerms, ...cloudTerms, ...resilienceTerms, "risk", "asset", "vulnerability", "supplier"],
    connectorFamilies: [...identityTerms, ...cloudTerms, ...resilienceTerms, "asset", "vulnerability", "policy"],
    sourceIDs: [],
  },
  "ISO 27701": {
    alertTerms: privacyTerms,
    assetTerms: privacyTerms,
    connectorFamilies: privacyTerms,
    sourceIDs: ["grc"],
  },
  "ISO 27701:2025": {
    alertTerms: privacyTerms,
    assetTerms: privacyTerms,
    connectorFamilies: privacyTerms,
    sourceIDs: ["grc"],
  },
  "ISO 42001": {
    alertTerms: aiTerms,
    assetTerms: aiTerms,
    connectorFamilies: aiTerms,
    sourceIDs: ["openai", "aws", "gcp", "azure"],
  },
  "NIST 800-53 r5": {
    alertTerms: [...identityTerms, ...cloudTerms, ...resilienceTerms, "federal", "authorization", "poam", "configuration", "audit"],
    assetTerms: [...identityTerms, ...cloudTerms, ...resilienceTerms, "federal", "authorization", "configuration"],
    connectorFamilies: [...identityTerms, ...cloudTerms, ...resilienceTerms, "authorization", "poam", "configuration"],
    sourceIDs: [],
  },
  "CIS Controls v8": {
    alertTerms: [...identityTerms, ...cloudTerms, "inventory", "vulnerability", "malware", "network", "audit"],
    assetTerms: [...identityTerms, ...cloudTerms, "inventory", "vulnerability", "endpoint", "network"],
    connectorFamilies: [...identityTerms, ...cloudTerms, "asset", "vulnerability", "endpoint", "network"],
    sourceIDs: [],
  },
  "CIS AWS Foundations Benchmark v2.0": {
    alertTerms: ["aws", "iam", "cloudtrail", "cloudwatch", "s3", "ec2", "kms", "guardduty", "securityhub"],
    assetTerms: ["aws", "iam", "cloudtrail", "cloudwatch", "s3", "ec2", "kms", "guardduty", "securityhub"],
    connectorFamilies: ["aws", "iam", "s3", "ec2", "kms", "cloudtrail", "cloudwatch", "guardduty", "securityhub"],
    sourceIDs: ["aws"],
  },
  "CIS Kubernetes Benchmark": {
    alertTerms: ["kubernetes", "k8s", "pod", "cluster", "rbac", "container"],
    assetTerms: ["kubernetes", "k8s", "pod", "cluster", "rbac", "container"],
    connectorFamilies: ["kubernetes", "k8s", "pod", "cluster", "rbac", "container"],
    sourceIDs: ["kubernetes"],
  },
  "CIS GKE Benchmark v1.4": {
    alertTerms: ["gcp", "gke", "kubernetes", "cluster", "node", "pod", "rbac"],
    assetTerms: ["gcp", "gke", "kubernetes", "cluster", "node", "pod", "rbac"],
    connectorFamilies: ["gcp", "gke", "kubernetes", "cluster", "node", "pod", "rbac"],
    sourceIDs: ["gcp", "kubernetes"],
  },
  "CIS EKS Benchmark v1.3": {
    alertTerms: ["aws", "eks", "kubernetes", "cluster", "node", "pod", "rbac"],
    assetTerms: ["aws", "eks", "kubernetes", "cluster", "node", "pod", "rbac"],
    connectorFamilies: ["aws", "eks", "kubernetes", "cluster", "node", "pod", "rbac"],
    sourceIDs: ["aws", "kubernetes"],
  },
  "CIS Benchmarks": {
    alertTerms: [...cloudTerms, "configuration", "benchmark", "hardening"],
    assetTerms: [...cloudTerms, "configuration", "benchmark", "hardening"],
    connectorFamilies: [...cloudTerms, "configuration", "benchmark", "hardening"],
    sourceIDs: [],
  },
  "PCI DSS v4.0.1": {
    alertTerms: [...financialTerms, ...identityTerms, "firewall", "logging", "segmentation", "vulnerability"],
    assetTerms: [...financialTerms, "database", "endpoint", "network", "firewall", "log", "segmentation"],
    connectorFamilies: [...financialTerms, "database", "endpoint", "network", "firewall", "log", "segmentation"],
    sourceIDs: ["stripe"],
  },
  "PCI DSS v4.0": {
    alertTerms: [...financialTerms, ...identityTerms, "firewall", "logging", "segmentation", "vulnerability"],
    assetTerms: [...financialTerms, "database", "endpoint", "network", "firewall", "log", "segmentation"],
    connectorFamilies: [...financialTerms, "database", "endpoint", "network", "firewall", "log", "segmentation"],
    sourceIDs: ["stripe"],
  },
  "PCI SAQ D-SP": {
    alertTerms: [...financialTerms, "service provider", "segmentation", "logging"],
    assetTerms: [...financialTerms, "service provider", "segmentation", "logging"],
    connectorFamilies: [...financialTerms, "service provider", "segmentation", "logging"],
    sourceIDs: ["stripe"],
  },
  HIPAA: {
    alertTerms: ["hipaa", "health", "phi", "patient", ...privacyTerms, ...identityTerms],
    assetTerms: ["hipaa", "health", "phi", "patient", ...privacyTerms],
    connectorFamilies: ["hipaa", "health", "phi", "patient", ...privacyTerms],
    sourceIDs: [],
  },
  GDPR: {
    alertTerms: privacyTerms,
    assetTerms: privacyTerms,
    connectorFamilies: privacyTerms,
    sourceIDs: ["grc"],
  },
  CCPA: {
    alertTerms: privacyTerms,
    assetTerms: privacyTerms,
    connectorFamilies: privacyTerms,
    sourceIDs: ["grc"],
  },
  "US Data Privacy": {
    alertTerms: privacyTerms,
    assetTerms: privacyTerms,
    connectorFamilies: privacyTerms,
    sourceIDs: ["grc"],
  },
  "EU AI Act": {
    alertTerms: [...aiTerms, "eu"],
    assetTerms: [...aiTerms, "eu"],
    connectorFamilies: aiTerms,
    sourceIDs: ["openai", "aws", "gcp", "azure"],
  },
  "HITRUST e1": {
    alertTerms: [...identityTerms, ...cloudTerms, ...privacyTerms, "hitrust", "health"],
    assetTerms: [...identityTerms, ...cloudTerms, ...privacyTerms, "hitrust", "health"],
    connectorFamilies: [...identityTerms, ...cloudTerms, ...privacyTerms, "hitrust", "health"],
    sourceIDs: [],
  },
  CISA: {
    alertTerms: [...cloudTerms, "cisa", "vulnerability", "incident", "logging"],
    assetTerms: [...cloudTerms, "cisa", "vulnerability", "incident", "logging"],
    connectorFamilies: [...cloudTerms, "cisa", "vulnerability", "incident", "logging"],
    sourceIDs: [],
  },
  DORA: {
    alertTerms: [...resilienceTerms, ...identityTerms, ...cloudTerms, "ict", "financial", "incident", "third party"],
    assetTerms: [...resilienceTerms, ...identityTerms, ...cloudTerms, "ict", "financial", "third party"],
    connectorFamilies: [...resilienceTerms, ...identityTerms, ...cloudTerms, "ict", "vendor", "third party"],
    sourceIDs: ["grc", "pagerduty"],
  },
  "FedRAMP Rev. 5": {
    alertTerms: [...identityTerms, ...cloudTerms, ...resilienceTerms, "fedramp", "federal", "authorization", "poam"],
    assetTerms: [...identityTerms, ...cloudTerms, ...resilienceTerms, "fedramp", "federal", "authorization", "poam"],
    connectorFamilies: [...identityTerms, ...cloudTerms, ...resilienceTerms, "authorization", "poam"],
    sourceIDs: ["grc"],
  },
  NIS2: {
    alertTerms: [...resilienceTerms, ...identityTerms, ...cloudTerms, "cybersecurity", "incident", "essential", "supplier"],
    assetTerms: [...resilienceTerms, ...identityTerms, ...cloudTerms, "cybersecurity", "essential", "supplier"],
    connectorFamilies: [...resilienceTerms, ...identityTerms, ...cloudTerms, "cybersecurity", "supplier"],
    sourceIDs: ["grc", "pagerduty"],
  },
  "CMMC 2.0": {
    alertTerms: [...identityTerms, ...cloudTerms, "cmmc", "cui", "fci", "defense", "federal"],
    assetTerms: [...identityTerms, ...cloudTerms, "cmmc", "cui", "fci", "defense", "federal"],
    connectorFamilies: [...identityTerms, ...cloudTerms, "cmmc", "cui", "fci"],
    sourceIDs: ["grc"],
  },
  "CJIS Security Policy": {
    alertTerms: [...identityTerms, ...cloudTerms, "cjis", "criminal", "justice", "encryption", "audit"],
    assetTerms: [...identityTerms, ...cloudTerms, "cjis", "criminal", "justice", "encryption", "audit"],
    connectorFamilies: [...identityTerms, ...cloudTerms, "cjis", "criminal", "justice", "encryption", "audit"],
    sourceIDs: ["grc"],
  },
  "NIST CSF 2.0": {
    alertTerms: [...identityTerms, ...cloudTerms, ...resilienceTerms, "govern", "identify", "protect", "detect", "respond", "recover"],
    assetTerms: [...identityTerms, ...cloudTerms, ...resilienceTerms, "govern", "identify", "protect", "detect", "respond", "recover"],
    connectorFamilies: [...identityTerms, ...cloudTerms, ...resilienceTerms, "govern", "identify", "protect", "detect", "respond", "recover"],
    sourceIDs: [],
  },
  "Cerebro AI Governance": {
    alertTerms: aiTerms,
    assetTerms: aiTerms,
    connectorFamilies: aiTerms,
    sourceIDs: ["openai", "aws", "gcp", "azure"],
  },
  "Cerebro Financial Controls": {
    alertTerms: financialTerms,
    assetTerms: financialTerms,
    connectorFamilies: financialTerms,
    sourceIDs: ["stripe", "salesforce"],
  },
  "Cerebro Operational Resilience": {
    alertTerms: resilienceTerms,
    assetTerms: resilienceTerms,
    connectorFamilies: resilienceTerms,
    sourceIDs: ["pagerduty"],
  },
  "Cerebro Organizational Resilience": {
    alertTerms: [...resilienceTerms, "hr", "training", "background", "owner"],
    assetTerms: [...resilienceTerms, "hr", "training", "background", "owner"],
    connectorFamilies: [...resilienceTerms, "hr", "training", "background", "owner"],
    sourceIDs: ["workday", "grc"],
  },
  "Cerebro Revenue Operations": {
    alertTerms: ["salesforce", "crm", "opportunity", "contract", "billing", "discount", "revenue"],
    assetTerms: ["salesforce", "crm", "opportunity", "contract", "billing", "discount", "revenue"],
    connectorFamilies: ["salesforce", "crm", "opportunity", "contract", "billing", "discount", "revenue"],
    sourceIDs: ["salesforce", "stripe"],
  },
  "CIS GitHub Benchmark": {
    alertTerms: ["github", "repository", "branch", "secret", "code", "action"],
    assetTerms: ["github", "repository", "branch", "secret", "code", "action"],
    connectorFamilies: ["github", "repository", "branch", "secret", "code", "action"],
    sourceIDs: ["github"],
  },
  "CIS Google Workspace Benchmark": {
    alertTerms: ["google_workspace", "workspace", "gmail", "group", "user", "admin", "mfa"],
    assetTerms: ["google_workspace", "workspace", "gmail", "group", "user", "admin", "mfa"],
    connectorFamilies: ["google_workspace", "workspace", "gmail", "group", "user", "admin", "mfa"],
    sourceIDs: ["google_workspace"],
  },
  "NIST SP 800-177": {
    alertTerms: ["email", "mail", "domain", "dkim", "dmarc", "spf", "tls"],
    assetTerms: ["email", "mail", "domain", "dkim", "dmarc", "spf", "tls"],
    connectorFamilies: ["email", "mail", "domain", "dkim", "dmarc", "spf", "tls"],
    sourceIDs: ["emaildomainhealth"],
  },
  "NIST AI RMF 1.0": {
    alertTerms: aiTerms,
    assetTerms: aiTerms,
    connectorFamilies: aiTerms,
    sourceIDs: ["openai", "aws", "gcp", "azure"],
  },
  "CSA CCM v4.0": {
    alertTerms: cloudTerms,
    assetTerms: cloudTerms,
    connectorFamilies: cloudTerms,
    sourceIDs: ["aws", "gcp", "azure", "kubernetes"],
  },
};

const uniqueTerms = (values: string[]) => Array.from(new Set(values.map(normalizeFrameworkText).filter(Boolean)));

export const frameworkSegmentFor = (query: string): GRCFrameworkSegment | null => {
  const framework = findSupportedGRCFramework(query);
  if (!framework) {
    return null;
  }
  const segment = frameworkSegmentCatalog[framework.name] ?? {
    alertTerms: [],
    assetTerms: [],
    connectorFamilies: [],
    sourceIDs: [],
  };
  return {
    framework,
    alertTerms: uniqueTerms([...frameworkSearchTerms(framework), ...segment.alertTerms]),
    assetTerms: uniqueTerms([...frameworkSearchTerms(framework), ...segment.assetTerms]),
    connectorFamilies: uniqueTerms([...frameworkSearchTerms(framework), ...segment.connectorFamilies]),
    sourceIDs: uniqueTerms(segment.sourceIDs),
  };
};

const stringValues = (values: unknown[]) =>
  values
    .flatMap(function flatten(value): unknown[] {
      return Array.isArray(value) ? value.flatMap(flatten) : [value];
    })
    .filter((value): value is string | number => typeof value === "string" || typeof value === "number")
    .map((value) => String(value));

const textContainsAny = (values: unknown[], terms: string[]) => {
  const text = normalizeFrameworkText(stringValues(values).join(" "));
  const compact = compactFrameworkText(text);
  return terms.some((term) => {
    const normalized = normalizeFrameworkText(term);
    return normalized.length > 1 && (text.includes(normalized) || compact.includes(compactFrameworkText(normalized)));
  });
};

const frameworkNameMatches = (candidate: string | undefined, segment: GRCFrameworkSegment) => {
  if (!candidate) {
    return false;
  }
  const normalized = normalizeFrameworkText(candidate);
  const compact = compactFrameworkText(candidate);
  return frameworkSearchTerms(segment.framework).some((term) =>
    normalizeFrameworkText(term) === normalized || compactFrameworkText(term) === compact,
  );
};

const coverageControlRefMatches = (refs: ConnectorCoverageControlRef[] | undefined, query: string) => {
  if (!refs?.length) {
    return false;
  }
  return refs.some((ref) => controlMatchesFrameworkQuery({
    framework_id: ref.framework_id,
    framework_name: ref.framework_name || ref.framework_id || "",
    control_id: ref.control_id,
  }, query));
};

type FrameworkControlCandidate = GRCControl | GRCControlRef | GRCInventoryTest;

const hasFrameworkQuery = (query: string) => normalizeFrameworkText(query).length > 0;

const controlFrameworkName = (control: FrameworkControlCandidate) =>
  "framework_name" in control ? control.framework_name : control.framework;

const controlMatchesFrameworkQuery = (control: FrameworkControlCandidate, query: string) => {
  if (!hasFrameworkQuery(query)) {
    return true;
  }
  const segment = frameworkSegmentFor(query);
  const frameworkName = controlFrameworkName(control);
  if (segment) {
    if (frameworkNameMatches(frameworkName, segment)) {
      return true;
    }
    return textContainsAny([frameworkName, control.control_id], segment.alertTerms);
  }
  return textContainsAny([frameworkName, control.control_id], [query]);
};

export const controlMatchesFrameworkSegment = (control: GRCControl | GRCInventoryTest, query: string) => {
  return controlMatchesFrameworkQuery(control, query);
};

export const findingMatchesFrameworkSegment = (finding: GRCFinding, query: string) => {
  if (!hasFrameworkQuery(query)) {
    return true;
  }
  const segment = frameworkSegmentFor(query);
  if ((finding.controls ?? []).some((control) => controlMatchesFrameworkQuery(control, query))) {
    return true;
  }
  if ((finding.source_coverage_refs ?? []).some((coverage) => coverageControlRefMatches(coverage.matched_control_refs, query))) {
    return true;
  }
  return textContainsAny([
    finding.policy_id,
    finding.policy_name,
    finding.rule_id,
    finding.runtime_id,
    finding.source_id,
    finding.entity,
    finding.resource_urns,
    finding.risk_reasons,
    finding.evidence_type,
    finding.assessment_methods,
    finding.auditor_guidance,
    finding.risk_statement,
    finding.remediation_intent,
    Object.keys(finding.attributes ?? {}),
    Object.values(finding.attributes ?? {}),
    (finding.source_coverage_refs ?? []).flatMap((coverage) => [
      coverage.source_id,
      coverage.dimension_id,
      coverage.dimension_type,
      coverage.support_level,
      coverage.families,
      coverage.evidence_types,
      coverage.control_domains,
      coverage.matched_control_refs?.map(connectorCoverageControlRefLabel),
    ]),
    finding.title,
    finding.summary,
  ], segment ? segment.alertTerms : [query]);
};

export const inventoryAssetMatchesFrameworkSegment = (asset: GRCInventoryAsset, query: string) => {
  if (!hasFrameworkQuery(query)) {
    return true;
  }
  const segment = frameworkSegmentFor(query);
  if (segment && asset.source_id && segment.sourceIDs.includes(normalizeFrameworkText(asset.source_id))) {
    return true;
  }
  return textContainsAny([
    asset.urn,
    asset.label,
    asset.entity_type,
    asset.source_id,
    asset.runtime_id,
    asset.risk_level,
    asset.risk_reasons,
    asset.scope_reason,
    Object.keys(asset.attributes ?? {}),
    Object.values(asset.attributes ?? {}),
  ], segment ? [...segment.assetTerms, ...segment.connectorFamilies, ...segment.sourceIDs] : [query]);
};

export const connectorScopeOptionMatchesFrameworkSegment = (
  option: ConnectorScopeOption,
  query: string,
  sourceID?: string,
) => {
  if (!hasFrameworkQuery(query)) {
    return true;
  }
  const segment = frameworkSegmentFor(query);
  if (segment && sourceID && segment.sourceIDs.includes(normalizeFrameworkText(sourceID))) {
    return true;
  }
  if (coverageControlRefMatches(option.control_refs, query)) {
    return true;
  }
  return textContainsAny([
    option.id,
    option.label,
    option.type,
    option.support,
    option.families,
    option.notes,
    option.known_unsupported_fields,
    option.evidence_types,
    option.control_domains,
    option.control_refs?.map(connectorCoverageControlRefLabel),
  ], segment ? [...segment.connectorFamilies, ...segment.assetTerms, ...segment.sourceIDs] : [query]);
};
