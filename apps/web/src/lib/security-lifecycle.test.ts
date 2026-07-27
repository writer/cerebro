import { describe, expect, it } from "vitest";

import {
  lifecycleEffectiveState,
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
});
