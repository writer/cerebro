import {
  type GenericSecurityMetadata,
  type KandjiMetadata,
  type SecurityHealthSummary,
  type SecurityHealthVendorSummary,
  type HostSecurityInsight,
  type HostSecurityRecord,
  type HostSecurityScoreSummary,
  type FleetSecuritySummary,
  type SecurityIssueDefinition,
  type SecurityIssueOccurrenceSummary,
  type FleetIssueSummary,
  type SecurityInsightScore,
  type SecuritySoftwareInsight,
  type SecuritySoftwareRecord,
  type SentinelOneMetadata,
} from "../types";

const TRUE_VALUES = new Set([
  "true",
  "1",
  "yes",
  "on",
  "enabled",
  "active",
  "running",
  "enforced",
  "present",
]);

const FALSE_VALUES = new Set([
  "false",
  "0",
  "no",
  "off",
  "disabled",
  "inactive",
  "missing",
]);

const TRUTHY_PREFIXES = ["active", "running", "enabled", "connected", "true", "yes", "enforc", "present"];

const ISSUE_DEFINITIONS: Record<string, SecurityIssueDefinition> = {
  connectivity: {
    code: "connectivity",
    label: "Connectivity issue",
    severity: "critical",
    weight: 25,
    vendor: "SentinelOne",
    remediation: "Verify network connectivity between the agent and management console",
  },
  anti_tamper: {
    code: "anti_tamper",
    label: "Anti-tamper disabled",
    severity: "high",
    weight: 20,
    vendor: "SentinelOne",
  },
  agent_disabled: {
    code: "agent_disabled",
    label: "Agent disabled",
    severity: "critical",
    weight: 20,
    vendor: "SentinelOne",
  },
  service_inactive: {
    code: "service_inactive",
    label: "Service inactive",
    severity: "high",
    weight: 15,
    vendor: "SentinelOne",
  },
  token_missing: {
    code: "token_missing",
    label: "Registration token missing",
    severity: "medium",
    weight: 15,
    vendor: "SentinelOne",
  },
  token_stale: {
    code: "token_stale",
    label: "Registration token stale",
    severity: "medium",
    weight: 10,
    vendor: "SentinelOne",
  },
  profile_missing: {
    code: "profile_missing",
    label: "Management profile missing",
    severity: "medium",
    weight: 10,
    vendor: "SentinelOne",
  },
  package_mismatch: {
    code: "package_mismatch",
    label: "Package version mismatch",
    severity: "medium",
    weight: 10,
    vendor: "SentinelOne",
  },
  scan_stale: {
    code: "scan_stale",
    label: "Scan stale",
    severity: "medium",
    weight: 10,
    vendor: "SentinelOne",
  },
  library_state: {
    code: "library_state",
    label: "Library state unhealthy",
    severity: "high",
    weight: 20,
    vendor: "Kandji",
  },
  last_run_stale: {
    code: "last_run_stale",
    label: "Library last run stale",
    severity: "medium",
    weight: 10,
    vendor: "Kandji",
  },
  check_in_stale: {
    code: "check_in_stale",
    label: "Check-in stale",
    severity: "high",
    weight: 15,
    vendor: "Kandji",
  },
  not_enforced: {
    code: "not_enforced",
    label: "Blueprint not enforced",
    severity: "medium",
    weight: 10,
    vendor: "Kandji",
  },
  pending_items: {
    code: "pending_items",
    label: "Pending items outstanding",
    severity: "medium",
    weight: 10,
    vendor: "Kandji",
  },
  sensor_disabled: {
    code: "sensor_disabled",
    label: "Sensor disabled",
    severity: "high",
    weight: 15,
  },
};

const DEFAULT_ISSUE_DEFINITION: SecurityIssueDefinition = {
  code: "unknown_issue",
  label: "Issue",
  severity: "info",
  weight: 5,
};

const MAX_SCORE = 100;

const SEVERITY_RANK: Record<SecurityIssueDefinition["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function normaliseNotes(notes?: SecuritySoftwareRecord["notes"]): Record<string, string> {
  if (!notes) {
    return {};
  }
  return Object.entries(notes).reduce<Record<string, string>>((acc, [key, value]) => {
    if (value == null) {
      return acc;
    }
    acc[key] = String(value);
    return acc;
  }, {});
}

function parseBoolean(value?: string): boolean | null {
  if (value == null) {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed === "") {
    return null;
  }
  const lower = trimmed.toLowerCase();
  if (TRUE_VALUES.has(lower)) {
    return true;
  }
  if (FALSE_VALUES.has(lower)) {
    return false;
  }
  if (TRUTHY_PREFIXES.some((prefix) => lower.startsWith(prefix))) {
    return true;
  }
  if (lower.startsWith("not ") || lower.startsWith("no ")) {
    return false;
  }
  return null;
}

function parseNumber(value?: string): number | null {
  if (value == null) {
    return null;
  }
  const parsed = Number(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function parseInteger(value?: string): number | null {
  const parsed = parseNumber(value);
  return parsed == null ? null : Math.trunc(parsed);
}

function parseIssues(value?: string): string[] {
  if (!value) {
    return [];
  }
  return value
    .split(",")
    .map((issue) => issue.trim())
    .filter((issue) => issue.length > 0);
}

function getIssueDefinition(code: string): SecurityIssueDefinition {
  const definition = ISSUE_DEFINITIONS[code];
  if (definition) {
    return definition;
  }
  return {
    ...DEFAULT_ISSUE_DEFINITION,
    code,
    label: code.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase()),
  };
}

function filterIssueDefinitions(definitions: SecurityIssueDefinition[], vendor: string): SecurityIssueDefinition[] {
  const lowerVendor = vendor.toLowerCase();
  return definitions.filter((definition) => !definition.vendor || definition.vendor.toLowerCase() === lowerVendor);
}

function buildGenericMetadata(notes: Record<string, string>): GenericSecurityMetadata {
  return {
    healthOk: parseBoolean(notes["health_ok"]),
    healthIssues: parseIssues(notes["health_issues"]),
    rawNotes: notes,
  };
}

function buildSentinelOneMetadata(notes: Record<string, string>): SentinelOneMetadata {
  const healthIssues = parseIssues(notes["health_issues"]);
  return {
    healthOk: parseBoolean(notes["health_ok"]),
    healthIssues,
    rawNotes: notes,
    connectivityOk: parseBoolean(notes["connectivity_ok"]),
    antiTamperEnabled: parseBoolean(notes["anti_tamper_enabled"]),
    agentEnabled: parseBoolean(notes["agent_enabled"]),
    serviceActive: parseBoolean(notes["service_active"]),
    tokenPresent: parseBoolean(notes["registration_token_present"]),
    tokenStale: parseBoolean(notes["registration_token_stale"]),
    managementProfilePresent: parseBoolean(notes["management_profile_present"]),
    packageVersionMismatch: parseBoolean(notes["package_version_mismatch"]),
    scanRecent: parseBoolean(notes["scan_recent"]),
    managementUrlHost: notes["management_url_host"] ?? null,
    siteName: notes["site_name"] ?? null,
    policyName: notes["policy_name"] ?? null,
    packageVersion: notes["package_version"] ?? null,
    registrationTokenAgeHours: parseNumber(notes["registration_token_age_hours"]),
    registrationTokenSizeBytes: parseNumber(notes["registration_token_size_bytes"]),
    scanLastSeenHours: parseNumber(notes["scan_last_seen_hours"]),
  };
}

function buildKandjiMetadata(notes: Record<string, string>): KandjiMetadata {
  const healthIssues = parseIssues(notes["kandji_health_issues"]);
  return {
    healthOk: parseBoolean(notes["kandji_health_ok"]),
    healthIssues,
    rawNotes: notes,
    libraryStateOk: parseBoolean(notes["kandji_library_state_ok"]),
    lastRunRecent: parseBoolean(notes["kandji_last_run_recent"]),
    lastRunHours: parseNumber(notes["kandji_last_run_hours"]),
    lastCheckInRecent: parseBoolean(notes["kandji_last_check_in_recent"]),
    lastCheckInHours: parseNumber(notes["kandji_last_check_in_hours"]),
    enforced: parseBoolean(notes["kandji_enforced"]),
    hasPending: parseBoolean(notes["kandji_has_pending"]),
    pendingItems: parseInteger(notes["kandji_pending_items"]),
  };
}

function buildInsight(record: SecuritySoftwareRecord): SecuritySoftwareInsight {
  const notes = normaliseNotes(record.notes);
  const vendor = record.vendor.trim().toLowerCase();
  if (vendor === "sentinelone") {
    return {
      vendor: "SentinelOne",
      product: record.product,
      record,
      metadata: buildSentinelOneMetadata(notes),
    };
  }
  if (vendor === "kandji") {
    return {
      vendor: "Kandji",
      product: record.product,
      record,
      metadata: buildKandjiMetadata(notes),
    };
  }
  return {
    vendor: record.vendor,
    product: record.product,
    record,
    metadata: buildGenericMetadata(notes),
  };
}

export function deriveSecurityInsights(records: SecuritySoftwareRecord[]): SecuritySoftwareInsight[] {
  return records.map((record) => buildInsight(record));
}

export function summarizeSecurityHealth(insights: SecuritySoftwareInsight[]): SecurityHealthSummary {
  const summary: SecurityHealthSummary = {
    total: 0,
    healthy: 0,
    degraded: 0,
    unknown: 0,
    vendors: {},
  };

  const ensureVendor = (vendor: string): SecurityHealthVendorSummary => {
    if (!summary.vendors[vendor]) {
      summary.vendors[vendor] = { total: 0, healthy: 0, degraded: 0, unknown: 0 };
    }
    return summary.vendors[vendor];
  };

  for (const insight of insights) {
    const metadata = insight.metadata;
    const vendorSummary = ensureVendor(insight.vendor);
    summary.total += 1;
    vendorSummary.total += 1;

    const status = metadata.healthOk;
    if (status === true) {
      summary.healthy += 1;
      vendorSummary.healthy += 1;
    } else if (status === false) {
      summary.degraded += 1;
      vendorSummary.degraded += 1;
    } else {
      summary.unknown += 1;
      vendorSummary.unknown += 1;
    }
  }

  return summary;
}

function resolveIssueLabels(vendor: SecuritySoftwareInsight["vendor"], issues: string[]): string[] {
  const definitions = issues.map((issue) => getIssueDefinition(issue));
  const filtered = filterIssueDefinitions(definitions, vendor);
  const lookup = new Map(filtered.map((definition) => [definition.code, definition.label] as const));
  return issues.map((issue) => lookup.get(issue) ?? getIssueDefinition(issue).label);
}

export function scoreSecurityInsight(insight: SecuritySoftwareInsight): SecurityInsightScore {
  const issues = insight.metadata.healthIssues;
  const seen = new Set<string>();
  let penalty = 0;
  for (const issue of issues) {
    if (seen.has(issue)) {
      continue;
    }
    seen.add(issue);
    penalty += getIssueDefinition(issue).weight;
  }
  const score = Math.max(0, MAX_SCORE - penalty);
  const normalized = Math.round((score / MAX_SCORE) * 1000) / 10;
  return {
    score,
    maxScore: MAX_SCORE,
    normalized,
    issues,
    issueLabels: resolveIssueLabels(insight.vendor, issues),
  };
}

export function formatSecurityInsight(insight: SecuritySoftwareInsight): string {
  const score = scoreSecurityInsight(insight);
  const status = insight.metadata.healthOk === true ? "Healthy" : insight.metadata.healthOk === false ? "Degraded" : "Unknown";
  const issueText = score.issueLabels.length > 0 ? ` — Issues: ${score.issueLabels.join(", ")}` : "";
  return `${insight.vendor} ${insight.product} — ${status} (score ${score.normalized.toFixed(1)}%)${issueText}`;
}

function summarizeScores(scores: SecurityInsightScore[]): HostSecurityScoreSummary {
  if (scores.length === 0) {
    return { averageScore: null, averageNormalized: null, bestScore: null, worstScore: null };
  }
  const totalScore = scores.reduce((acc, score) => acc + score.score, 0);
  const totalNormalized = scores.reduce((acc, score) => acc + score.normalized, 0);
  const bestScore = scores.reduce((best, current) => (best == null || current.normalized > best.normalized ? current : best), scores[0]);
  const worstScore = scores.reduce((worst, current) => (worst == null || current.normalized < worst.normalized ? current : worst), scores[0]);
  return {
    averageScore: totalScore / scores.length,
    averageNormalized: totalNormalized / scores.length,
    bestScore,
    worstScore,
  };
}

type IssueAccumulator = Map<
  string,
  {
    definition: SecurityIssueDefinition;
    occurrences: number;
    vendors: Set<string>;
    products: Set<string>;
    hosts: Set<string>;
  }
>;

function addIssue(
  acc: IssueAccumulator,
  definition: SecurityIssueDefinition,
  vendor: string,
  product: string,
  hostId?: string,
  hostname?: string,
): void {
  const key = definition.code;
  if (!acc.has(key)) {
    acc.set(key, {
      definition,
      occurrences: 0,
      vendors: new Set<string>(),
      products: new Set<string>(),
      hosts: new Set<string>(),
    });
  }
  const entry = acc.get(key)!;
  entry.occurrences += 1;
  entry.vendors.add(vendor);
  entry.products.add(`${vendor} ${product}`.trim());
  if (hostId || hostname) {
    entry.hosts.add(hostId ?? hostname ?? "unknown");
  }
}

function buildFleetIssueSummary(acc: IssueAccumulator): FleetIssueSummary {
  const summaries: SecurityIssueOccurrenceSummary[] = [];
  let totalOccurrences = 0;
  for (const value of acc.values()) {
    totalOccurrences += value.occurrences;
    summaries.push({
      definition: value.definition,
      occurrences: value.occurrences,
      affectedVendors: Array.from(value.vendors).sort(),
      affectedProducts: Array.from(value.products).sort(),
      affectedHosts: Array.from(value.hosts).sort(),
    });
  }
  summaries.sort((a, b) => {
    const severityDelta = SEVERITY_RANK[a.definition.severity] - SEVERITY_RANK[b.definition.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }
    if (b.occurrences !== a.occurrences) {
      return b.occurrences - a.occurrences;
    }
    return a.definition.label.localeCompare(b.definition.label);
  });
  return { totalOccurrences, issues: summaries };
}

export function summarizeSecurityIssuesFromInsights(insights: SecuritySoftwareInsight[]): FleetIssueSummary {
  const acc: IssueAccumulator = new Map();
  for (const insight of insights) {
    for (const issue of insight.metadata.healthIssues) {
      addIssue(acc, getIssueDefinition(issue), insight.vendor, insight.product);
    }
  }
  return buildFleetIssueSummary(acc);
}

export function deriveHostSecurityInsights(record: HostSecurityRecord): HostSecurityInsight {
  const insights = deriveSecurityInsights(record.securitySoftware);
  const scores = insights.map((insight) => scoreSecurityInsight(insight));
  const health = summarizeSecurityHealth(insights);
  const scorecard = summarizeScores(scores);
  return {
    hostId: record.hostId,
    hostname: record.hostname,
    insights,
    health,
    scorecard,
  };
}

export function summarizeSecurityIssuesFromHosts(hosts: HostSecurityInsight[]): FleetIssueSummary {
  const acc: IssueAccumulator = new Map();
  for (const host of hosts) {
    for (const insight of host.insights) {
      for (const issue of insight.metadata.healthIssues) {
        addIssue(acc, getIssueDefinition(issue), insight.vendor, insight.product, host.hostId, host.hostname);
      }
    }
  }
  return buildFleetIssueSummary(acc);
}

export function summarizeFleetSecurity(hosts: HostSecurityRecord[]): FleetSecuritySummary {
  const hostInsights = hosts.map((host) => deriveHostSecurityInsights(host));
  const allInsights = hostInsights.flatMap((host) => host.insights);
  const health = summarizeSecurityHealth(allInsights);
  const scores = allInsights.map((insight) => scoreSecurityInsight(insight));
  const averageNormalizedScore = scores.length === 0 ? null : scores.reduce((acc, score) => acc + score.normalized, 0) / scores.length;
  let worstScore: SecurityInsightScore | null = null;
  let worstInsight: SecuritySoftwareInsight | null = null;
  for (let i = 0; i < allInsights.length; i += 1) {
    const insight = allInsights[i];
    const score = scores[i];
    if (!worstScore || score.normalized < worstScore.normalized) {
      worstScore = score;
      worstInsight = insight;
    }
  }

  const issues = summarizeSecurityIssuesFromHosts(hostInsights);

  return {
    totalHosts: hosts.length,
    hostsWithSecuritySoftware: hostInsights.filter((host) => host.insights.length > 0).length,
    totalInsights: allInsights.length,
    health,
    averageNormalizedScore,
    worstInsight,
    worstScore,
    issues,
  };
}
