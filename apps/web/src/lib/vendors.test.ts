import { describe, expect, it } from "vitest";

import type { GRCVendor, GRCVendorDiscovery } from "@/lib/grc";
import {
  boundedVendorDiscoveries,
  boundedVendorRows,
  vendorOwnerLabel,
  vendorRiskDrivers,
} from "@/lib/vendors";

const vendor = (index: number, patch: Partial<GRCVendor> = {}): GRCVendor => ({
  urn: `urn:cerebro:test:vendor:${index}`,
  name: `Vendor ${index}`,
  risk_level: "unknown",
  owner_state: "missing",
  review_state: "not_scheduled",
  contract_count: 0,
  security_review_count: 0,
  questionnaire_count: 0,
  assurance_document_count: 0,
  ...patch,
});

const discovery = (index: number, patch: Partial<GRCVendorDiscovery> = {}): GRCVendorDiscovery => ({
  urn: `urn:cerebro:test:vendor.discovery:${index}`,
  name: `Candidate ${index}`,
  source_status: "discovered",
  decision_state: "discovered",
  ...patch,
});

describe("vendor scale model helpers", () => {
  it("bounds vendor rows and preserves total-result metadata", () => {
    const response = {
      summary: {
        total_vendors: 1_234,
        active_vendors: 1_000,
        high_risk_vendors: 12,
        owner_missing_vendors: 9,
        review_overdue_vendors: 4,
        review_due_soon_vendors: 7,
        review_not_scheduled: 3,
        open_findings: 20,
        critical_findings: 2,
        high_findings: 8,
        evidence_items: 4_000,
      },
      vendors: Array.from({ length: 1_000 }, (_, index) => vendor(index)),
      generated_at: "2026-06-28T00:00:00Z",
    };

    const rows = boundedVendorRows(response, 200);

    expect(rows.vendors).toHaveLength(200);
    expect(rows.meta).toEqual({
      limit: 200,
      returned: 200,
      total: 1_234,
      truncated: true,
    });
  });

  it("bounds discovery rows even when the backend returns more than requested", () => {
    const rows = boundedVendorDiscoveries({
      summary: {
        total_discoveries: 950,
        discovered: 920,
        approved: 20,
        rejected: 5,
        ignored: 3,
        linked: 2,
      },
      discoveries: Array.from({ length: 600 }, (_, index) => discovery(index)),
      generated_at: "2026-06-28T00:00:00Z",
    }, 100);

    expect(rows.discoveries).toHaveLength(100);
    expect(rows.meta?.total).toBe(950);
    expect(rows.meta?.truncated).toBe(true);
  });

  it("uses explicit owner fields before the missing-owner fallback", () => {
    expect(vendorOwnerLabel(vendor(1, { owner: "Security" }))).toBe("Security");
    expect(vendorOwnerLabel(vendor(2, { security_owner_user_id: "sec@example.com" }))).toBe("sec@example.com");
    expect(vendorOwnerLabel(vendor(3, { business_owner_user_id: "ops@example.com" }))).toBe("ops@example.com");
    expect(vendorOwnerLabel(vendor(4))).toBe("Owner missing");
  });

  it("deduplicates and caps risk driver labels", () => {
    const drivers = vendorRiskDrivers(vendor(1, {
      access_level: "privileged",
      evidence_freshness_state: "stale",
      open_findings: 3,
      owner_state: "missing",
      queue_reasons: ["owner_missing", "owner_missing", "security_review_due"],
      risk_drivers: ["Privileged access"],
      risk_level: "high",
    }));

    expect(drivers).toEqual([
      "Privileged access",
      "Owner Missing",
      "Security Review Due",
      "No owner",
      "Stale evidence",
      "High risk",
    ]);
  });
});
