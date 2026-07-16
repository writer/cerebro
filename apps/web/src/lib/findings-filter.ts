import type { GRCFinding } from "@/lib/grc";
import { riskSort } from "@/lib/grc";
import { findingMatchesFrameworkSegment } from "@/lib/grc-frameworks";

export type RiskInboxFindingFilters = {
  framework?: string;
  owner?: string;
  query?: string;
};

export const findingMatchesRiskInboxFilters = (finding: GRCFinding, filters: RiskInboxFindingFilters = {}) => {
  const framework = filters.framework ?? "";
  const ownerFilter = (filters.owner ?? "").trim().toLowerCase();
  const q = (filters.query ?? "").trim().toLowerCase();

  if (!findingMatchesFrameworkSegment(finding, framework)) return false;
  if (ownerFilter) {
    const findingOwner = (finding.owner || "").trim().toLowerCase();
    const isUnassigned = !findingOwner || findingOwner === "unassigned";
    if (ownerFilter === "unassigned") {
      if (!isUnassigned) return false;
    } else if (!findingOwner.includes(ownerFilter)) {
      return false;
    }
  }
  if (!q) return true;
  return [
    finding.id,
    finding.title,
    finding.summary,
    finding.severity,
    finding.status,
    finding.owner,
    finding.sla_status,
    finding.entity,
    finding.runtime_id,
    finding.source_id,
    finding.rule_id,
    finding.policy_id,
    finding.policy_name,
    finding.risk_score,
    finding.likelihood_score,
    finding.impact_score,
    finding.confidence_score,
    finding.likelihood_level,
    finding.impact_level,
    ...(finding.risk_reasons ?? []),
    ...(finding.resource_urns ?? []),
    ...(finding.controls ?? []).map((control) => `${control.framework_name} ${control.control_id}`),
  ].filter(Boolean).some((value) => String(value).toLowerCase().includes(q));
};

export const filterRiskInboxFindings = (findings: GRCFinding[], filters: RiskInboxFindingFilters = {}) =>
  findings
    .filter((finding) => findingMatchesRiskInboxFilters(finding, filters))
    .slice()
    .sort(riskSort);
