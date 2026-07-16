import type { GRCListMeta, GRCVendor, GRCVendorDiscoveriesResponse, GRCVendorDiscovery, GRCVendorsResponse } from "@/lib/grc";
import { displayDate, humanize } from "@/lib/grc";

const numericCount = (value: number | undefined) =>
  typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;

const boundedRows = <Row>(rows: Row[], limit: number) => {
  const safeLimit = Math.max(0, Math.floor(limit));
  return rows.slice(0, safeLimit);
};

const boundedMeta = ({
  loaded,
  meta,
  originalCount,
  summaryTotal,
  limit,
}: {
  loaded: number;
  meta?: GRCListMeta;
  originalCount: number;
  summaryTotal?: number;
  limit: number;
}): GRCListMeta => {
  const totalCandidate = numericCount(meta?.total) ?? numericCount(summaryTotal) ?? originalCount;
  const total = Math.max(totalCandidate, loaded);
  return {
    limit,
    returned: loaded,
    total,
    truncated: Boolean(meta?.truncated ?? (originalCount > loaded || total > loaded)),
  };
};

export const boundedVendorRows = (response: GRCVendorsResponse | null | undefined, limit: number) => {
  const rows = response?.vendors ?? [];
  const vendors = boundedRows(rows, limit);
  return {
    vendors,
    meta: response ? boundedMeta({
      loaded: vendors.length,
      limit,
      meta: response.meta,
      originalCount: rows.length,
      summaryTotal: response.summary?.total_vendors,
    }) : undefined,
  };
};

export const boundedVendorDiscoveries = (response: GRCVendorDiscoveriesResponse | null | undefined, limit: number) => {
  const rows = response?.discoveries ?? [];
  const discoveries = boundedRows(rows, limit);
  return {
    discoveries,
    meta: response ? boundedMeta({
      loaded: discoveries.length,
      limit,
      meta: response.meta,
      originalCount: rows.length,
      summaryTotal: response.summary?.total_discoveries,
    }) : undefined,
  };
};

export const vendorOwnerLabel = (vendor: GRCVendor) => {
  if (vendor.owner) return vendor.owner;
  if (vendor.security_owner_user_id) return vendor.security_owner_user_id;
  if (vendor.business_owner_user_id) return vendor.business_owner_user_id;
  return "Owner missing";
};

export const vendorSourceLabel = (vendor: GRCVendor) =>
  vendor.provider || vendor.source_id || vendor.attributes?.source_system || "Source not set";

export const vendorFirstQueueAction = (vendor: GRCVendor) =>
  vendor.next_actions?.slice().sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0))[0];

export const vendorReviewDetail = (vendor: GRCVendor) => {
  if (vendor.review_due_at) {
    return `Due ${displayDate(vendor.review_due_at)}`;
  }
  if (vendor.last_review_completed_at) {
    return `Last done ${displayDate(vendor.last_review_completed_at)}`;
  }
  return "No due date";
};

export const vendorFreshnessLabel = (vendor: GRCVendor) =>
  vendor.evidence_freshness_state ? humanize(vendor.evidence_freshness_state) : "Not measured";

export const vendorRiskScoreLabel = (vendor: GRCVendor) =>
  typeof vendor.risk_score === "number" ? `${vendor.risk_score}/100` : "Not scored";

export const vendorPacketDetail = (vendor: GRCVendor) => {
  const missing = vendor.packet_missing_items?.length ?? 0;
  if (missing > 0) return `${missing} missing`;
  const ready = vendor.packet_ready_items?.length ?? 0;
  return ready > 0 ? `${ready} ready` : "No packet items";
};

export const vendorAssuranceItemCount = (vendor: GRCVendor) =>
  (vendor.contract_count ?? 0) +
  (vendor.security_review_count ?? 0) +
  (vendor.questionnaire_count ?? 0) +
  (vendor.assurance_document_count ?? 0);

export const vendorRiskDrivers = (vendor: GRCVendor) => {
  const drivers = [
    ...(vendor.risk_drivers ?? []),
    ...(vendor.exposure_reasons ?? []),
    ...(vendor.queue_reasons ?? []).map(humanize),
  ];
  if (vendor.owner_state === "missing") drivers.push("No owner");
  if (["stale", "expired"].includes(vendor.evidence_freshness_state ?? "")) drivers.push("Stale evidence");
  if (["critical", "high"].includes(vendor.risk_level)) drivers.push(`${humanize(vendor.risk_level)} risk`);
  if (vendor.access_level === "privileged") drivers.push("Privileged access");
  if (vendor.open_findings && vendor.open_findings > 0) drivers.push(`${vendor.open_findings} open risks`);
  return Array.from(new Set(drivers.filter(Boolean))).slice(0, 6);
};

const reviewStates = new Set(["discovered", "pending", "needs_review"]);

export const discoveryNeedsReviewState = (discovery: Pick<GRCVendorDiscovery, "decision_state">) =>
  reviewStates.has((discovery.decision_state || "discovered").toLowerCase());
