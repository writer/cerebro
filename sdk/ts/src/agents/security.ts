import {
  type GenericSecurityMetadata,
  type KandjiMetadata,
  type SecurityHealthSummary,
  type SecurityHealthVendorSummary,
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

const SENTINELONE_ISSUE_LABELS: Record<string, string> = {
  connectivity: "Connectivity issue",
  anti_tamper: "Anti-tamper disabled",
  agent_disabled: "Agent disabled",
  service_inactive: "Service inactive",
  token_missing: "Registration token missing",
  token_stale: "Registration token stale",
  profile_missing: "Management profile missing",
  package_mismatch: "Package version mismatch",
  scan_stale: "Scan stale",
};

const KANDJI_ISSUE_LABELS: Record<string, string> = {
  library_state: "Library state unhealthy",
  last_run_stale: "Library last run stale",
  check_in_stale: "Check-in stale",
  not_enforced: "Blueprint not enforced",
  pending_items: "Pending items outstanding",
};

const DEFAULT_ISSUE_LABEL = "Issue";

const ISSUE_WEIGHTS: Record<string, number> = {
  connectivity: 25,
  anti_tamper: 20,
  agent_disabled: 20,
  service_inactive: 15,
  token_missing: 15,
  token_stale: 10,
  profile_missing: 10,
  package_mismatch: 10,
  scan_stale: 10,
  library_state: 20,
  last_run_stale: 10,
  check_in_stale: 15,
  not_enforced: 10,
  pending_items: 10,
};

const MAX_SCORE = 100;

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
  const labelMap = vendor === "SentinelOne" ? SENTINELONE_ISSUE_LABELS : vendor === "Kandji" ? KANDJI_ISSUE_LABELS : {};
  return issues.map((issue) => labelMap[issue] ?? DEFAULT_ISSUE_LABEL);
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
    penalty += ISSUE_WEIGHTS[issue] ?? 5;
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
