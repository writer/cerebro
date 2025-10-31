import {
  type GenericSecurityMetadata,
  type KandjiMetadata,
  type SecurityHealthSummary,
  type SecurityHealthVendorSummary,
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
