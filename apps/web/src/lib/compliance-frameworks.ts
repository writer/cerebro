import type { GRCFinding, GRCFramework } from "@/lib/grc";
import { grcPath } from "@/lib/grc-client";
import { GRC_WORKLIST_LIMIT } from "@/lib/grc-list";

export { frameworkDetailHref } from "@/lib/compliance-links";

export const FRAMEWORK_SETTINGS_PATH = "/grc/framework-settings";
export const FRAMEWORK_FINDING_LIMIT = GRC_WORKLIST_LIMIT;

export const frameworkFindingsPath = (framework: { name: string }, tenantID: string) =>
  grcPath("/grc/findings", { tenant_id: tenantID, framework: framework.name, status: "open", limit: FRAMEWORK_FINDING_LIMIT });

export type FrameworkSettingsResponse = {
  settings: {
    tenant_id: string;
    enabled_frameworks: string[];
    created_at?: string;
    updated_at?: string;
  };
  persisted: boolean;
};

export type ControlViolation = {
  controlID: string;
  findings: GRCFinding[];
  /** Rule IDs whose open findings fail this control, most findings first. */
  rules: Array<{ ruleID: string; findings: number }>;
  critical: number;
  high: number;
  maxRisk: number;
};

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

const normalizeName = (value: string | undefined) => value?.trim().toLowerCase() ?? "";

/**
 * Framework names on finding control refs come from rule metadata, so they are
 * compared case-insensitively and may also match the framework id.
 */
export const controlRefMatchesFramework = (
  ref: { framework_name?: string; framework_id?: string },
  framework: { id?: string; name: string },
) => {
  const name = normalizeName(framework.name);
  const id = normalizeName(framework.id);
  return normalizeName(ref.framework_name) === name || Boolean(id && normalizeName(ref.framework_id) === id);
};

// Natural ordering keeps CC6.1 before CC6.10 and 2.1.4 before 2.10.
const compareControlIDs = (left: string, right: string) =>
  left.localeCompare(right, undefined, { numeric: true, sensitivity: "base" });

/** Groups open findings into the framework controls they violate. */
export const controlViolations = (findings: GRCFinding[], framework: { id?: string; name: string }): ControlViolation[] => {
  const byControl = new Map<string, Map<string, GRCFinding>>();
  for (const finding of findings) {
    if (normalizeName(finding.status) && normalizeName(finding.status) !== "open") continue;
    for (const ref of finding.controls ?? []) {
      const controlID = ref.control_id?.trim();
      if (!controlID || !controlRefMatchesFramework(ref, framework)) continue;
      const entries = byControl.get(controlID) ?? new Map<string, GRCFinding>();
      entries.set(finding.id, finding);
      byControl.set(controlID, entries);
    }
  }
  return [...byControl.entries()].map(([controlID, entries]) => {
    const controlFindings = [...entries.values()].sort((left, right) =>
      (SEVERITY_RANK[right.severity?.toUpperCase()] ?? 0) - (SEVERITY_RANK[left.severity?.toUpperCase()] ?? 0)
      || (right.risk_score ?? 0) - (left.risk_score ?? 0));
    const ruleCounts = new Map<string, number>();
    for (const finding of controlFindings) {
      const ruleID = finding.rule_id?.trim();
      if (ruleID) ruleCounts.set(ruleID, (ruleCounts.get(ruleID) ?? 0) + 1);
    }
    return {
      controlID,
      findings: controlFindings,
      rules: [...ruleCounts.entries()]
        .map(([ruleID, count]) => ({ ruleID, findings: count }))
        .sort((left, right) => right.findings - left.findings || left.ruleID.localeCompare(right.ruleID)),
      critical: controlFindings.filter((finding) => finding.severity?.toUpperCase() === "CRITICAL").length,
      high: controlFindings.filter((finding) => finding.severity?.toUpperCase() === "HIGH").length,
      maxRisk: Math.max(0, ...controlFindings.map((finding) => finding.risk_score ?? 0)),
    };
  }).sort((left, right) =>
    right.critical - left.critical
    || right.high - left.high
    || right.findings.length - left.findings.length
    || compareControlIDs(left.controlID, right.controlID));
};

export type FrameworkViolationSummary = {
  controls: number;
  findings: number;
  rules: number;
  critical: number;
};

export const frameworkViolationSummary = (violations: ControlViolation[]): FrameworkViolationSummary => {
  const findingIDs = new Set<string>();
  const ruleIDs = new Set<string>();
  let critical = 0;
  for (const violation of violations) {
    for (const finding of violation.findings) {
      if (!findingIDs.has(finding.id) && finding.severity?.toUpperCase() === "CRITICAL") critical += 1;
      findingIDs.add(finding.id);
    }
    violation.rules.forEach((rule) => ruleIDs.add(rule.ruleID));
  }
  return { controls: violations.length, findings: findingIDs.size, rules: ruleIDs.size, critical };
};

/** Resolves saved framework names to catalog entries, keeping catalog order and dropping names the catalog no longer has. */
export const enabledFrameworks = (catalog: GRCFramework[], enabledNames: string[]) => {
  const enabled = new Set(enabledNames.map(normalizeName));
  return catalog.filter((framework) => enabled.has(normalizeName(framework.name)));
};

/** Frameworks a tenant can enable: rules only map to active frameworks. */
export const selectableFrameworks = (catalog: GRCFramework[]) =>
  catalog.filter((framework) => framework.lifecycle !== "upcoming");

export const toggleFrameworkName = (names: string[], name: string) => {
  const key = normalizeName(name);
  return names.some((value) => normalizeName(value) === key)
    ? names.filter((value) => normalizeName(value) !== key)
    : [...names, name];
};
