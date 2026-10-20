import { parse as parseYAML, stringify as stringifyYAML } from "yaml";

import type {
  RuleAuthoringIssue,
  RuleCatalogDetail,
  RuleCatalogEntry,
  RuleTestResult,
  RuleValidationResult,
} from "@/lib/finding-rules";

// Fixture-mode stand-in for internal/rulecatalog. Validation is a structural
// approximation; the real server compiles conditions and graph queries.

export type FindingRuleFixtureResult = { payload: unknown; status: number };

const fixtureGeneratedAt = "2026-01-15T12:00:00.000Z";

const builtin = (
  entry: Omit<RuleCatalogEntry, "enabled"> & { enabled?: boolean },
  detail: Partial<RuleCatalogDetail> = {},
): RuleCatalogDetail => ({
  enabled: true,
  description: entry.summary,
  attack_description: "",
  remediation: "",
  editable: false,
  testable: false,
  ...entry,
  ...detail,
});

const builtinRules: RuleCatalogDetail[] = [
  builtin(
    {
      id: "aws-s3-bucket-public-access",
      name: "S3 bucket allows public access",
      summary: "An S3 bucket policy or ACL grants access to anonymous principals.",
      severity: "high",
      origin: "builtin_policy",
      domain: "paas",
      posture: "cspm",
      provider: "aws",
      category: "aws",
      resource_type: "aws::s3::bucket",
      evaluation: "cel",
      detection: "posture",
      maturity: "stable",
      tags: ["aws", "s3", "exposure"],
      frameworks: ["SOC 2", "CIS AWS Foundations Benchmark v2.0"],
      mitre_techniques: ["T1530"],
    },
    {
      attack_description: "An attacker can list and download bucket objects without credentials. MITRE ATT&CK: Collection (T1530).",
      remediation: "Enable S3 Block Public Access and remove public grants.",
      remediation_steps: ["Enable account- and bucket-level Block Public Access.", "Remove ACL grants to AllUsers and AuthenticatedUsers."],
      control_refs: [{ framework: "SOC 2", control: "CC6.1" }, { framework: "CIS AWS Foundations Benchmark v2.0", control: "2.1.4" }],
      mitre_attack: [{ tactic: "Collection", technique: "T1530" }],
      conditions: ['cmp_eq(path(resource, "public_access"), true)'],
      source_path: "policies/aws/aws-s3-bucket-public-access.yaml",
      testable: true,
      document: `apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: aws-s3-bucket-public-access
  name: S3 bucket allows public access
  description: An S3 bucket policy or ACL grants access to anonymous principals.
  tags: [aws, s3, exposure]
spec:
  severity: high
  effect: forbid
  resource: aws::s3::bucket
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "public_access"), true)
  remediation:
    summary: Enable S3 Block Public Access and remove public grants.
  frameworks:
    - name: SOC 2
      controls: [CC6.1]
`,
    },
  ),
  builtin(
    {
      id: "gcp-compute-instance-public-ip-critical-vuln",
      name: "Public GCP VM with critical vulnerability",
      summary: "A Compute Engine instance with a public IP has a critical, exploitable vulnerability.",
      severity: "critical",
      origin: "builtin_policy",
      domain: "paas",
      posture: "cspm",
      provider: "gcp",
      category: "cerebro",
      resource_type: "gcp::compute::instance",
      evaluation: "cel",
      detection: "posture",
      maturity: "stable",
      tags: ["gcp", "vulnerability", "exposure"],
      frameworks: ["SOC 2"],
      mitre_techniques: ["T1190"],
    },
    {
      attack_description: "An internet-reachable VM runs software with a known exploit. MITRE ATT&CK: Initial Access (T1190).",
      remediation: "Patch the vulnerable package or remove the public IP.",
      mitre_attack: [{ tactic: "Initial Access", technique: "T1190" }],
      conditions: ['cmp_eq(path(resource, "has_public_ip"), true)', 'cmp_gt(path(resource, "critical_vulnerability_count"), 0)'],
    },
  ),
  builtin(
    {
      id: "github-repo-secret-scanning-disabled",
      name: "GitHub secret scanning disabled",
      summary: "A repository has secret scanning or push protection turned off.",
      severity: "medium",
      origin: "builtin_policy",
      domain: "saas",
      posture: "sspm",
      provider: "github",
      category: "github",
      resource_type: "github::repository",
      evaluation: "cel",
      detection: "posture",
      maturity: "stable",
      tags: ["github", "secrets"],
      frameworks: ["SOC 2"],
    },
    {
      remediation: "Enable secret scanning and push protection for the repository.",
      conditions: ['cmp_eq(path(resource, "secret_scanning_enabled"), false)'],
    },
  ),
  builtin(
    {
      id: "okta-admin-dormant",
      name: "Okta Dormant Admin Account",
      summary: "Okta admin account has not logged in for over 90 days.",
      severity: "medium",
      origin: "builtin_policy",
      domain: "identity",
      posture: "ispm",
      provider: "okta",
      category: "okta",
      resource_type: "okta::user",
      evaluation: "cel",
      detection: "posture",
      maturity: "stable",
      tags: ["okta", "identity", "privileged-access"],
      frameworks: ["NIST 800-53 r5"],
    },
    {
      remediation: "Review the admin account and remove admin privileges if no longer needed.",
      conditions: ['cmp_eq(path(resource, "is_admin"), true)', 'cmp_gt(path(resource, "last_login_days_ago"), 90)'],
      testable: true,
    },
  ),
  builtin(
    {
      id: "identity-offboarded-user-active-access",
      name: "Offboarded user retains active access",
      summary: "A terminated employee still has an active account in a connected application.",
      severity: "high",
      origin: "builtin_detection",
      domain: "correlation",
      posture: "correlation",
      provider: "identity",
      evaluation: "graph",
      detection: "correlation",
      maturity: "stable",
      tags: ["identity", "offboarding"],
      frameworks: ["SOC 2"],
    },
    {
      attack_description: "A departed user or anyone holding their credentials keeps access to company data.",
      remediation: "Deactivate the account and revoke active sessions and tokens.",
      lifecycle: "stale_resolve",
      fingerprint_fields: ["tenant_id", "identity_urn", "application"],
    },
  ),
  builtin(
    {
      id: "public-exposure-to-privileged-identity",
      name: "Public exposure reaches a privileged identity",
      summary: "Correlates a public-exposure finding with a privileged identity reachable from the same resource.",
      severity: "critical",
      origin: "correlation_pattern",
      domain: "correlation",
      posture: "correlation",
      provider: "cerebro",
      evaluation: "correlation",
      detection: "correlation",
      tags: ["correlation", "exposure"],
    },
    {
      remediation: "Remove the public exposure or the trust path to the privileged identity.",
      correlated_rule_ids: ["aws-s3-bucket-public-access", "okta-admin-dormant"],
      correlation_dimensions: ["resource_urn"],
      correlation_window: "24h",
    },
  ),
];

let customRules = new Map<string, RuleCatalogDetail>();

export const resetFindingRuleFixturesForTests = () => {
  customRules = new Map();
};

type RuleDocument = {
  metadata?: { id?: unknown; name?: unknown; description?: unknown; tags?: unknown };
  spec?: {
    severity?: unknown;
    resource?: unknown;
    match?: { conditions?: unknown };
    graph?: { query?: unknown };
    remediation?: { summary?: unknown; steps?: unknown };
    frameworks?: { name?: unknown; controls?: unknown }[];
    mitreAttack?: { tactic?: unknown; technique?: unknown }[];
  };
};

const strings = (value: unknown) => (Array.isArray(value) ? value.map(String) : []);
const text = (value: unknown) => (typeof value === "string" ? value.trim() : "");

const providerDomains: Record<string, RuleCatalogEntry["domain"]> = {
  aws: "paas", gcp: "paas", azure: "paas", kubernetes: "paas",
  okta: "identity", entra: "identity", google_workspace: "identity",
};
const postureForDomain: Record<string, string> = { paas: "cspm", saas: "sspm", identity: "ispm", correlation: "correlation" };

type ParsedDocument = { document: RuleDocument; issues: RuleAuthoringIssue[] };

const parseDocument = (format: string, content: string): ParsedDocument => {
  if (!content.trim()) return { document: {}, issues: [{ severity: "error", message: "document is empty" }] };
  if (format !== "yaml" && format !== "json") return { document: {}, issues: [{ severity: "error", message: 'format must be "yaml" or "json"' }] };
  let document: RuleDocument;
  try {
    document = (format === "json" ? JSON.parse(content) : parseYAML(content)) as RuleDocument;
  } catch (error) {
    return { document: {}, issues: [{ severity: "error", message: `invalid PolicyFindingRule ${format.toUpperCase()}: ${String(error)}` }] };
  }
  const issues: RuleAuthoringIssue[] = [];
  const id = text(document?.metadata?.id);
  if (!id) issues.push({ severity: "error", message: "metadata.id is required" });
  if (builtinRules.some((rule) => rule.id === id)) issues.push({ severity: "error", message: `metadata.id "${id}" is a built-in rule; choose a new id` });
  if (!text(document?.metadata?.name)) issues.push({ severity: "error", message: "metadata.name is required" });
  if (!["critical", "high", "medium", "low", "info"].includes(text(document?.spec?.severity).toLowerCase())) {
    issues.push({ severity: "error", message: "spec.severity must be one of critical, high, medium, low, info" });
  }
  const hasConditions = strings(document?.spec?.match?.conditions).length > 0;
  const hasGraph = Boolean(text(document?.spec?.graph?.query));
  if (!hasConditions && !hasGraph) issues.push({ severity: "error", message: "spec.match.conditions or spec.graph.query is required" });
  if (!document?.spec?.frameworks?.length) issues.push({ severity: "error", message: "spec.frameworks must map at least one control" });
  if (!text(document?.spec?.remediation?.summary)) issues.push({ severity: "warning", message: "spec.remediation.summary is recommended" });
  return { document, issues };
};

const previewFor = (document: RuleDocument, yaml: string): RuleCatalogDetail => {
  const spec = document.spec ?? {};
  const resource = text(spec.resource);
  const provider = resource.split("::")[0] || "custom";
  const graph = text(spec.graph?.query);
  const domain = graph && !resource ? "correlation" : providerDomains[provider] ?? "saas";
  const mitre = (spec.mitreAttack ?? []).map((ref) => ({ tactic: text(ref.tactic), technique: text(ref.technique) }));
  const summary = text(document.metadata?.description);
  return {
    id: text(document.metadata?.id),
    name: text(document.metadata?.name),
    summary,
    severity: text(spec.severity).toLowerCase(),
    origin: "custom",
    domain,
    posture: postureForDomain[domain],
    provider: graph && !resource ? "cerebro" : provider,
    resource_type: resource || undefined,
    evaluation: graph ? "graph" : "cel",
    detection: graph ? "correlation" : "posture",
    enabled: true,
    maturity: "custom",
    tags: strings(document.metadata?.tags),
    frameworks: (spec.frameworks ?? []).map((framework) => text(framework.name)).filter(Boolean),
    mitre_techniques: mitre.map((ref) => ref.technique).filter(Boolean),
    description: summary,
    attack_description: [summary, ...mitre.map((ref) => `MITRE ATT&CK: ${ref.tactic} (${ref.technique}).`)].filter(Boolean).join(" "),
    remediation: text(spec.remediation?.summary),
    remediation_steps: strings(spec.remediation?.steps),
    control_refs: (spec.frameworks ?? []).flatMap((framework) =>
      strings(framework.controls).map((control) => ({ framework: text(framework.name), control })),
    ),
    mitre_attack: mitre,
    conditions: strings(spec.match?.conditions),
    graph_query: graph || undefined,
    document: yaml,
    editable: true,
    testable: !graph,
  };
};

const validate = (format: string, content: string): RuleValidationResult => {
  const { document, issues } = parseDocument(format, content);
  if (issues.some((issue) => issue.severity === "error")) return { valid: false, issues };
  const yaml = stringifyYAML(document, { lineWidth: 0 });
  return { valid: true, issues, yaml, json: `${JSON.stringify(document, null, 2)}\n`, preview: previewFor(document, yaml) };
};

const pathValue = (resource: Record<string, unknown>, path: string) =>
  path.split(".").reduce<unknown>((value, key) => (value && typeof value === "object" ? (value as Record<string, unknown>)[key] : undefined), resource);

// Supports the cmp_eq/cmp_gt/cmp_lt(path(resource, "x"), literal) shape the
// templates use; anything richer is reported as not evaluated.
const evaluateCondition = (condition: string, resource: Record<string, unknown>): boolean | null => {
  const match = /^cmp_(eq|ne|gt|lt)\(path\(resource,\s*"([^"]+)"\),\s*(.+)\)$/.exec(condition.trim());
  if (!match) return null;
  const [, op, path, literal] = match;
  let expected: unknown;
  try {
    expected = JSON.parse(literal);
  } catch {
    return null;
  }
  const actual = pathValue(resource, path);
  switch (op) {
    case "eq": return actual === expected;
    case "ne": return actual !== expected;
    case "gt": return typeof actual === "number" && typeof expected === "number" && actual > expected;
    default: return typeof actual === "number" && typeof expected === "number" && actual < expected;
  }
};

const test = (format: string, content: string, resource: Record<string, unknown> = {}): RuleTestResult => {
  const result = validate(format, content);
  if (!result.valid || !result.preview) return { valid: false, issues: result.issues, evaluated: false, matched: false, message: "Fix validation errors before testing." };
  if (!result.preview.testable) {
    return { valid: true, issues: result.issues, evaluated: false, matched: false, message: "Sample testing supports CEL condition rules. Graph and SQL rules run against live data." };
  }
  const outcomes = (result.preview.conditions ?? []).map((condition) => evaluateCondition(condition, resource));
  if (outcomes.some((outcome) => outcome === null)) {
    return { valid: true, issues: result.issues, evaluated: false, matched: false, message: "Fixture mode can only evaluate simple cmp_* conditions." };
  }
  const matched = outcomes.every(Boolean);
  return {
    valid: true,
    issues: result.issues,
    evaluated: true,
    matched,
    message: matched ? "The sample resource matches every condition; this rule would open a finding." : "The sample resource does not match; no finding would open.",
  };
};

type DocumentBody = { format?: string; content?: string; resource?: Record<string, unknown> };

const parseBody = (body?: string): DocumentBody | null => {
  try {
    return body ? (JSON.parse(body) as DocumentBody) : null;
  } catch {
    return null;
  }
};

export const findingRuleFixtureResponse = (method: string, path: string, body?: string): FindingRuleFixtureResult | null => {
  if (method === "GET" && path === "finding-rules/catalog") {
    const rules = [...builtinRules, ...customRules.values()].map((detail) => {
      const entry: RuleCatalogEntry = {
        id: detail.id, name: detail.name, summary: detail.summary, severity: detail.severity, origin: detail.origin,
        domain: detail.domain, posture: detail.posture, provider: detail.provider, category: detail.category,
        resource_type: detail.resource_type, evaluation: detail.evaluation, detection: detail.detection,
        enabled: detail.enabled, maturity: detail.maturity, tags: detail.tags,
        frameworks: detail.frameworks, mitre_techniques: detail.mitre_techniques, updated_at: detail.updated_at,
      };
      return entry;
    });
    return { payload: { rules, total: rules.length, custom_rules_ready: true }, status: 200 };
  }

  const detailMatch = /^finding-rules\/catalog\/(.+)$/.exec(path);
  if (method === "GET" && detailMatch) {
    const id = decodeURIComponent(detailMatch[1]);
    const detail = builtinRules.find((rule) => rule.id === id) ?? customRules.get(id);
    return detail ? { payload: detail, status: 200 } : { payload: { error: `finding rule not found: ${id}` }, status: 404 };
  }

  if (method === "POST" && (path === "finding-rules/validate" || path === "finding-rules/test")) {
    const request = parseBody(body);
    if (!request) return { payload: { error: "invalid request body" }, status: 400 };
    const format = request.format ?? "yaml";
    const content = request.content ?? "";
    return {
      payload: path === "finding-rules/validate" ? validate(format, content) : test(format, content, request.resource),
      status: 200,
    };
  }

  const customMatch = /^finding-rules\/custom\/(.+)$/.exec(path);
  if (customMatch && (method === "PUT" || method === "DELETE")) {
    const id = decodeURIComponent(customMatch[1]);
    if (method === "DELETE") {
      if (!customRules.delete(id)) return { payload: { error: `custom finding rule not found: ${id}` }, status: 404 };
      return { payload: { id, deleted: true }, status: 200 };
    }
    const request = parseBody(body);
    if (!request) return { payload: { error: "invalid request body" }, status: 400 };
    const result = validate(request.format ?? "yaml", request.content ?? "");
    if (!result.valid || !result.preview) return { payload: result, status: 422 };
    if (result.preview.id !== id) {
      return { payload: { error: `metadata.id "${result.preview.id}" must match the rule id in the path "${id}"` }, status: 400 };
    }
    const existing = customRules.get(id);
    const saved: RuleCatalogDetail = {
      ...result.preview,
      created_by: existing?.created_by ?? "fixture-user",
      created_at: existing?.created_at ?? fixtureGeneratedAt,
      updated_by: "fixture-user",
      updated_at: fixtureGeneratedAt,
    };
    customRules.set(id, saved);
    return { payload: saved, status: 200 };
  }

  return null;
};
