import type { ListCustomersOptions, ListVendorsOptions } from "../clients/securityCenter.js";

export type VendorFilterPresetName =
  | "criticalVendors"
  | "overdueReviews"
  | "newVendors"
  | "highSpend"
  | "complianceGaps";

export type CustomerFilterPresetName =
  | "atRiskRenewals"
  | "inactiveAccounts"
  | "highGrowth"
  | "strategicPartners"
  | "supportHotlist";

export const vendorFilterPresets: Record<VendorFilterPresetName, Readonly<ListVendorsOptions>> = {
  criticalVendors: {
    riskLevel: "high",
    businessCriticality: "high",
  },
  overdueReviews: {
    riskLevel: "medium",
    lifecycleStage: "active",
  },
  newVendors: {
    lifecycleStage: "onboarding",
  },
  highSpend: {
    businessCriticality: "high",
  },
  complianceGaps: {
    complianceFramework: "missing",
  },
} as const;

export const customerFilterPresets: Record<CustomerFilterPresetName, Readonly<ListCustomersOptions>> = {
  atRiskRenewals: {
    lifecycleStage: "renewal",
    healthBand: "at_risk",
  },
  inactiveAccounts: {
    lifecycleStage: "active",
    successProgram: "none",
  },
  highGrowth: {
    segment: "enterprise",
    healthBand: "healthy",
  },
  strategicPartners: {
    successProgram: "design_partner",
  },
  supportHotlist: {
    accountManager: "support_escalations",
    healthBand: "at_risk",
  },
} as const;

export function resolveVendorPreset(
  preset: VendorFilterPresetName,
  overrides: ListVendorsOptions = {},
): ListVendorsOptions {
  return { ...vendorFilterPresets[preset], ...overrides };
}

export function resolveCustomerPreset(
  preset: CustomerFilterPresetName,
  overrides: ListCustomersOptions = {},
): ListCustomersOptions {
  return { ...customerFilterPresets[preset], ...overrides };
}
