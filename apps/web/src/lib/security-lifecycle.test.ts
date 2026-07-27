import { describe, expect, it } from "vitest";

import {
  lifecycleAggregateCount,
  lifecycleActionLabel,
  lifecycleCompleteness,
  lifecycleEffectiveState,
  lifecycleFindingID,
  lifecycleOwnerLabel,
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

  it("reads full-population aggregate counts across typed enum keys", () => {
    expect(lifecycleAggregateCount([
      { state: "SECURITY_LIFECYCLE_STATE_EXPIRED", count: 8 },
      { state: "expiring", count: 5 },
    ], "expired")).toBe(8);
    expect(lifecycleAggregateCount([{ state: "expiring", count: 5 }], "expiring")).toBe(5);
    expect(lifecycleAggregateCount(undefined, "expired")).toBeUndefined();
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

  it("formats provider-neutral action types as operator copy", () => {
    expect(lifecycleActionLabel("rotate_credential")).toBe("Rotate credential");
  });

  it("builds finding detail ids from canonical refs", () => {
    expect(lifecycleFindingID({ kind: "finding", id: "urn:cerebro:tenant:finding:expiry%2Fslot" })).toBe("expiry/slot");
  });
});
