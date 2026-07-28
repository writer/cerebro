/**
 * @vitest-environment jsdom
 */
import { act, type AnchorHTMLAttributes } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ActionOperation } from "@/lib/actions";

const mocks = vi.hoisted(() => ({
  actionReload: vi.fn(),
  historyReload: vi.fn(),
  useGRCQuery: vi.fn(),
  useParams: vi.fn(),
}));

vi.mock("next/navigation", () => ({ useParams: mocks.useParams }));
vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: AnchorHTMLAttributes<HTMLAnchorElement>) => (
    <a href={typeof href === "string" ? href : ""} {...props}>{children}</a>
  ),
}));
vi.mock("@/lib/grc-client", () => ({ useGRCQuery: mocks.useGRCQuery }));

import ActionDetailPage from "./page";

const action: ActionOperation = {
  proposal: {
    operation_id: "operation-1",
    tenant_id: "tenant-1",
    finding_id: "finding-1",
    finding_revision_digest: "finding-revision-digest",
    finding_validation_receipt_digest: "validation-receipt-digest",
    graph_revision: 42,
    action_kind: "restart_service",
    action_definition_digest: "action-definition-digest",
    target_id: "service-1",
    expected_effects: [{
      target_id: "service-1",
      effect_kind: "service_restarted",
      expected_state_digest: "expected-state-digest",
    }],
    rollback_ref: "rollback-1",
    idempotency_key: "test",
    simulation_digest: "simulation-digest",
    verification_plan_digest: "verification-plan-digest",
    proposed_by: "actor-1",
    proposed_at_unix_ms: 1_700_000_000_000,
    proposal_expires_at_unix_ms: 1_700_003_600_000,
    proposal_digest: "proposal-digest",
  },
  state: "waiting_for_approval",
  version: 3,
  approval_receipt: null,
  claimed_by: null,
  claimed_at_unix_ms: null,
  claim_expires_at_unix_ms: null,
  executor_actor_id: null,
  executed_at_unix_ms: null,
  external_receipt_ref: null,
  observed_effect_digest: null,
  verification_state: "pending",
  verification_receipt: null,
};

describe("Action detail page", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    mocks.actionReload.mockReset().mockResolvedValue(undefined);
    mocks.historyReload.mockReset().mockResolvedValue(undefined);
    mocks.useParams.mockReset().mockReturnValue({ operationID: "operation-1" });
    mocks.useGRCQuery.mockReset().mockImplementation((path: string | null) => {
      if (path?.endsWith("/history")) {
        return {
          data: null,
          error: "Cerebro request failed (502) for Action history",
          loading: false,
          reload: mocks.historyReload,
        };
      }
      return {
        data: action,
        error: null,
        loading: false,
        reload: mocks.actionReload,
      };
    });
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("keeps a loaded Action visible when its history request fails", async () => {
    await act(async () => {
      root.render(<ActionDetailPage />);
    });

    expect(container.textContent).toContain("restart service");
    expect(container.textContent).toContain("finding-1");
    expect(container.textContent).toContain("Authority history");
    expect(container.textContent).toContain("History unavailable");
    expect(container.textContent).toContain("The Action record is available. Retry loading its committed history.");
    expect(container.textContent).not.toContain("Confirm the operation ID and signed tenant identity");

    const retry = Array.from(container.querySelectorAll<HTMLButtonElement>("button"))
      .find((button) => button.textContent?.includes("Retry"));

    await act(async () => {
      retry?.click();
    });

    expect(mocks.historyReload).toHaveBeenCalledTimes(1);
    expect(mocks.actionReload).not.toHaveBeenCalled();
  });

  it("decodes a route segment before constructing authority paths", async () => {
    mocks.useParams.mockReturnValue({
      operationID: "operation%3Arust-action-e2e",
    });

    await act(async () => {
      root.render(<ActionDetailPage />);
    });

    expect(mocks.useGRCQuery).toHaveBeenCalledWith(
      "/v1/actions/operation%3Arust-action-e2e",
    );
    expect(mocks.useGRCQuery).toHaveBeenCalledWith(
      "/v1/actions/operation%3Arust-action-e2e/history",
    );
    expect(mocks.useGRCQuery).not.toHaveBeenCalledWith(
      expect.stringContaining("%253A"),
    );
  });

  it("shows provider acceptance without claiming the effect completed", async () => {
    const dispatched: ActionOperation = {
      ...action,
      state: "dispatched",
      version: 7,
      claimed_by: "worker-1",
      executor_actor_id: "worker-1",
      external_receipt_ref: "provider-receipt-1",
      provider_receipt_digest: "provider-receipt-digest",
      provider_status: "queued",
      provider_observed_at_unix_ms: 1_700_000_001_000,
    };
    mocks.useGRCQuery.mockImplementation((path: string | null) => {
      if (path?.endsWith("/history")) {
        return { data: [], error: null, loading: false, reload: mocks.historyReload };
      }
      return { data: dispatched, error: null, loading: false, reload: mocks.actionReload };
    });

    await act(async () => {
      root.render(<ActionDetailPage />);
    });

    expect(container.textContent).toContain("Provider Queued");
    expect(container.textContent).toContain("provider-receipt-1");
    expect(container.textContent).toContain("Provider receipt digest");
    expect(container.textContent).toContain("Effect recordedNot recorded");
    expect(container.textContent).not.toContain("Receipt recorded");
  });
});
