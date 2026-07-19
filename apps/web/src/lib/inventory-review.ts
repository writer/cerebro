import type { GRCInventoryAccountability, GRCInventoryAsset, GRCInventoryReviewDisposition } from "@/lib/grc";

export type InventoryReviewFilter = "all" | "needs_review" | "reported_issue" | "baseline" | "out_of_scope";
export type InventoryReviewState = Exclude<InventoryReviewFilter, "all">;
export type InventoryAccountabilityFilter = "all" | "not_required" | "known" | "candidate" | "required_missing" | "disputed";

export const inventoryAttr = (asset: GRCInventoryAsset, ...keys: string[]) => {
  for (const key of keys) {
    const value = asset.attributes?.[key];
    if (value) return value;
  }
  return "";
};

export const inventoryOwnerPrincipal = (asset: GRCInventoryAsset) =>
  inventoryAttr(asset, "owner", "owner_email", "assignee", "account_manager_email", "owner_login");

export const inventoryOwnerLabel = (asset: GRCInventoryAsset) => inventoryOwnerPrincipal(asset) || "Unassigned";

export const inventoryScopeState = (asset: GRCInventoryAsset) => asset.scope_state || "in_scope";

export const inventoryScopeCopy = (state: string) => state === "out_of_scope" ? "Scoped out" : "In scope";

export const inventoryIsPublicAsset = (asset: GRCInventoryAsset) =>
  ["public", "publicly_accessible", "internet_exposed", "external"].some((key) =>
    ["1", "true", "yes", "y"].includes((asset.attributes?.[key] || "").toLowerCase()),
  );

const assetOwnerNotRequired = (asset: GRCInventoryAsset) =>
  asset.attributes?.accountability_state === "not_required" ||
  ["1", "true", "yes", "y"].includes((asset.attributes?.owner_not_required || "").toLowerCase());

const assetHasActiveReport = (asset: GRCInventoryAsset) => {
  if (!asset.asset_report_count) return false;
  const status = (asset.latest_asset_report_status || "").toLowerCase();
  return status !== "rejected" && status !== "resolved";
};

const assetNeedsAccountability = (asset: GRCInventoryAsset) => {
  if (inventoryScopeState(asset) === "out_of_scope" || inventoryOwnerPrincipal(asset)) return false;
  if (assetOwnerNotRequired(asset)) return false;
  if (["owner_required", "requires_owner", "accountability_required"].some((key) =>
    ["1", "true", "yes", "y"].includes((asset.attributes?.[key] || "").toLowerCase()),
  )) return true;
  return (asset.risk_score ?? 0) >= 70 || inventoryIsPublicAsset(asset);
};

export const inventoryAccountability = (asset: GRCInventoryAsset): GRCInventoryAccountability => {
  if (asset.accountability?.state) return asset.accountability;
  if (inventoryScopeState(asset) === "out_of_scope") {
    return { state: "not_required", label: "Owner not required", reasons: [{ code: "scope_exclusion", label: "Scoped out" }] };
  }
  if (assetOwnerNotRequired(asset)) {
    return {
      state: "not_required",
      label: "Owner not required",
      reasons: [{ code: "accountability_not_required", label: asset.attributes?.accountability_reason || "Owner not required" }],
    };
  }
  const owner = inventoryOwnerPrincipal(asset);
  if (owner) return { state: "known", label: "Owner known", principal: owner };
  if (assetNeedsAccountability(asset)) {
    return { state: "required_missing", label: "Owner required", reasons: [{ code: "accountability_missing", label: "Owner missing where required" }] };
  }
  return { state: "not_required", label: "Owner not required", reasons: [{ code: "baseline_no_action", label: "No active GRC action" }] };
};

export const inventoryReviewDisposition = (asset: GRCInventoryAsset): GRCInventoryReviewDisposition => {
  if (asset.review_disposition?.state) return asset.review_disposition;
  if (inventoryScopeState(asset) === "out_of_scope") {
    return {
      state: "out_of_scope",
      label: "Scoped out",
      detail: asset.scope_reason || "Excluded from controls, evidence collection, and review until scoped back in.",
      reasons: [{ code: "scope_exclusion", label: "Scoped out of GRC review" }],
    };
  }
  if (assetHasActiveReport(asset)) {
    return {
      state: "reported_issue",
      label: "Reported issue",
      detail: asset.latest_asset_report_reason || "A reviewer reported this asset for triage.",
      reasons: [{ code: "reported_issue", label: "Reviewer report" }],
    };
  }
  if (inventoryAccountability(asset).state === "required_missing") {
    return {
      state: "needs_review",
      label: "Needs review",
      detail: "GRC-relevant evidence indicates this asset needs an accountable owner.",
      reasons: [{ code: "accountability_missing", label: "Owner missing where required" }],
    };
  }
  return {
    state: "baseline",
    label: "Baseline",
    detail: "No immediate GRC action required.",
    reasons: [{ code: "baseline_no_action", label: "No active GRC action" }],
  };
};

export const inventoryReviewState = (asset: GRCInventoryAsset) => inventoryReviewDisposition(asset).state;

export const inventoryReviewLabel = (state: string) => {
  switch (state) {
    case "needs_review":
      return "Needs review";
    case "reported_issue":
      return "Reported issue";
    case "out_of_scope":
      return "Scoped out";
    case "baseline":
    default:
      return "Baseline";
  }
};

export const inventoryReviewDetail = (asset: GRCInventoryAsset) => inventoryReviewDisposition(asset).detail || "";

export const inventoryNeedsReview = (asset: GRCInventoryAsset) => {
  const state = inventoryReviewDisposition(asset).state;
  return state === "needs_review" || state === "reported_issue";
};

export const inventoryMatchesReviewFilter = (asset: GRCInventoryAsset, filter: string) => {
  if (!filter || filter === "all") return true;
  return inventoryReviewDisposition(asset).state === filter;
};

export const inventoryMatchesAccountabilityFilter = (asset: GRCInventoryAsset, filter: string) => {
  if (!filter || filter === "all") return true;
  return inventoryAccountability(asset).state === filter;
};

export const inventoryMatchesOwnerFilter = (asset: GRCInventoryAsset, filter: string) => {
  const normalized = filter.trim().toLowerCase();
  if (!normalized) return true;
  const owner = inventoryOwnerLabel(asset);
  if (normalized === "unassigned") return owner === "Unassigned";
  return owner.toLowerCase().includes(normalized);
};

export const inventoryReviewSort = (left: GRCInventoryAsset, right: GRCInventoryAsset) => {
  const priority = (asset: GRCInventoryAsset) => {
    const state = inventoryReviewDisposition(asset).state;
    if (state === "reported_issue") return 3;
    if (state === "needs_review") return 2;
    if (state === "out_of_scope") return 0;
    return 1;
  };
  const priorityDelta = priority(right) - priority(left);
  if (priorityDelta !== 0) return priorityDelta;
  const riskDelta = (right.risk_score ?? 0) - (left.risk_score ?? 0);
  if (riskDelta !== 0) return riskDelta;
  const publicDelta = Number(inventoryIsPublicAsset(right)) - Number(inventoryIsPublicAsset(left));
  if (publicDelta !== 0) return publicDelta;
  return left.label.localeCompare(right.label);
};
