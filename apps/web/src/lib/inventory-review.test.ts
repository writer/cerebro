import { describe, expect, it } from "vitest";

import type { GRCInventoryAsset } from "@/lib/grc";
import {
  inventoryAccountability,
  inventoryMatchesReviewFilter,
  inventoryReviewDetail,
  inventoryReviewDisposition,
  inventoryReviewSort,
} from "./inventory-review";

const asset = (overrides: Partial<GRCInventoryAsset>): GRCInventoryAsset => ({
  urn: "urn:test:asset",
  entity_type: "aws.s3_bucket",
  label: "Test asset",
  risk_score: 20,
  scope_state: "in_scope",
  attributes: {},
  ...overrides,
});

describe("inventory review posture", () => {
  it("keeps ordinary unowned assets in the baseline instead of forcing ownership", () => {
    const item = asset({ risk_score: 35, attributes: { public: "false" } });

    expect(inventoryReviewDisposition(item).state).toBe("baseline");
    expect(inventoryAccountability(item).state).toBe("not_required");
    expect(inventoryReviewDetail(item)).toBe("No immediate GRC action required.");
    expect(inventoryMatchesReviewFilter(item, "needs_review")).toBe(false);
  });

  it("requires accountability only when risk or exposure makes ownership useful", () => {
    expect(inventoryReviewDisposition(asset({ risk_score: 78 })).state).toBe("needs_review");
    expect(inventoryReviewDisposition(asset({ risk_score: 22, attributes: { public: "true" } })).state).toBe("needs_review");
    expect(inventoryAccountability(asset({ risk_score: 78 })).state).toBe("required_missing");
    expect(inventoryMatchesReviewFilter(asset({ risk_score: 78 }), "needs_review")).toBe(true);
  });

  it("honors explicit owner-not-required decisions even for high-risk inventory", () => {
    const item = asset({
      risk_score: 91,
      attributes: {
        accountability_state: "not_required",
        owner_not_required: "true",
        accountability_reason: "Ephemeral build output",
      },
    });

    expect(inventoryAccountability(item).state).toBe("not_required");
    expect(inventoryReviewDisposition(item).state).toBe("baseline");
    expect(inventoryReviewDetail(item)).toBe("No immediate GRC action required.");
  });

  it("lets owner-not-required override noisy source owner hints", () => {
    const item = asset({
      attributes: {
        owner: "detected-owner@example.com",
        accountability_state: "not_required",
        owner_not_required: "true",
      },
    });

    expect(inventoryAccountability(item).state).toBe("not_required");
  });

  it("separates owned, reported, and scoped-out assets into explicit states", () => {
    expect(inventoryAccountability(asset({ attributes: { owner: "platform" }, risk_score: 90 })).state).toBe("known");
    expect(inventoryReviewDisposition(asset({ asset_report_count: 1, latest_asset_report_reason: "Classification needs review" })).state).toBe("reported_issue");
    expect(inventoryReviewDisposition(asset({ scope_state: "out_of_scope", scope_reason: "Temporary exclusion" })).state).toBe("out_of_scope");
  });

  it("prioritizes reported issues and review-needed assets", () => {
    const lowReported = asset({ label: "Reported asset", risk_score: 20, asset_report_count: 1 });
    const highUnowned = asset({ label: "High asset", risk_score: 90 });
    const mediumPublic = asset({ label: "Public asset", risk_score: 50, attributes: { public: "true" } });

    expect([mediumPublic, highUnowned, lowReported].sort(inventoryReviewSort).map((item) => item.label)).toEqual([
      "Reported asset",
      "High asset",
      "Public asset",
    ]);
  });
});
