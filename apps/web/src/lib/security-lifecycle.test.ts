import { describe, expect, it } from "vitest";

import {
  lifecycleActionLabel,
  lifecycleCompleteness,
  lifecycleCoveragePresentation,
  lifecycleCoverageReason,
  lifecycleEffectiveState,
  lifecycleOwnerLabel,
  lifecyclePolicyStateCount,
  summarizeSecurityLifecycle,
  type SecurityLifecycleRecord,
} from "./security-lifecycle";

const record = (
  observedState: string,
  policyState?: string,
): SecurityLifecycleRecord => ({
  observation: {
    subject_ref: {
      kind: "credential",
      id: "urn:cerebro:tenant-a:credential:aws:slot",
    },
    subject_kind: "SECURITY_LIFECYCLE_SUBJECT_KIND_CREDENTIAL",
    provider: "aws",
    authority_id: "aws",
    stable_locator: "slot",
    display_name: "Deployment credential",
    state: observedState,
    observed_at: "2026-07-26T12:00:00Z",
  },
  policy_evaluations: policyState
    ? [
        {
          policy_id: "credential-expiry",
          policy_version: "1",
          subject_ref: {
            kind: "credential",
            id: "urn:cerebro:tenant-a:credential:aws:slot",
          },
          state: policyState,
          warning_window_days: 30,
          evaluated_at: "2026-07-26T12:00:00Z",
        },
      ]
    : undefined,
});

describe("security lifecycle summaries", () => {
  it("uses policy evaluation state before the observed provider state", () => {
    const expiring = record("SECURITY_LIFECYCLE_STATE_ACTIVE", "expiring");
    const expired = record("SECURITY_LIFECYCLE_STATE_ACTIVE", "expired");

    expect(lifecycleEffectiveState(expiring)).toBe("expiring");
    expect(summarizeSecurityLifecycle([expiring, expired])).toMatchObject({
      expiring: 1,
      expired: 1,
    });
  });

  it("falls back to observed state when no policy evaluation is present", () => {
    expect(
      lifecycleEffectiveState(record("SECURITY_LIFECYCLE_STATE_EXPIRED")),
    ).toBe("expired");
  });

  it("keeps malformed owner identifiers readable", () => {
    expect(lifecycleOwnerLabel("urn:cerebro:tenant-a:team:security%ZZ")).toBe(
      "security%ZZ",
    );
    expect(lifecycleOwnerLabel("urn:cerebro:tenant-a:team:security%")).toBe(
      "security%",
    );
  });

  it("reads policy metrics only from typed policy-state counts", () => {
    expect(lifecyclePolicyStateCount([
      { policy_state: "SECURITY_LIFECYCLE_POLICY_STATE_EXPIRED", count: 8 },
      { policy_state: "expiring", count: 5 },
    ], "expired")).toBe(8);
    expect(lifecyclePolicyStateCount([{ policy_state: "expiring", count: 5 }], "expiring")).toBe(5);
    expect(lifecyclePolicyStateCount(undefined, "expired")).toBeUndefined();
  });

  it("keeps source coverage separate from page truncation", () => {
    expect(lifecycleCompleteness({
      records: [],
      truncated: false,
      as_of: "2026-07-26T12:00:00Z",
      metadata: {
        page_truncated: true,
        coverage: { complete: false, truncated: true, reason: "scan in progress" },
      },
    })).toEqual({
      complete: false,
      pageTruncated: true,
      reason: "scan in progress",
      sourceTruncated: true,
      total: undefined,
    });
    expect(lifecycleCompleteness({
      records: [],
      truncated: true,
      as_of: "2026-07-26T12:00:00Z",
    })).toMatchObject({
      complete: undefined,
      pageTruncated: true,
      sourceTruncated: false,
    });
  });

  it("turns coverage reason enums into operator guidance", () => {
    expect(lifecycleCoveragePresentation({
      complete: true,
      reason: "SECURITY_LIFECYCLE_COVERAGE_REASON_COMPLETE",
    })).toEqual({
      label: "Source coverage complete",
      detail: "Every lifecycle entity in this graph revision was evaluated.",
    });
    expect(lifecycleCoveragePresentation({
      complete: false,
      truncated: true,
      reason: "SECURITY_LIFECYCLE_COVERAGE_REASON_SCAN_LIMIT",
    })).toEqual({
      label: "Source coverage limited",
      detail: "The scan limit was reached before every lifecycle entity was evaluated.",
    });
    expect(lifecycleCoveragePresentation({
      complete: false,
      reason: "SECURITY_LIFECYCLE_COVERAGE_REASON_GRAPH_CHANGED",
    })).toEqual({
      label: "Graph changed during read",
      detail: "Refresh to load a consistent lifecycle snapshot.",
    });
    expect(lifecycleCoverageReason({
      reason: "SECURITY_LIFECYCLE_COVERAGE_REASON_GRAPH_CHANGED",
    })).toBe("graph_changed");
  });

  it("formats provider-neutral action types as operator copy", () => {
    expect(lifecycleActionLabel("rotate_credential")).toBe("Rotate credential");
  });

});
