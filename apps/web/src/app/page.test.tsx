/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { GRCDashboard, GRCProgramReadiness } from "@/lib/grc";
import { defaultUserPreferences } from "@/lib/user-preferences";

const mocks = vi.hoisted(() => ({
  reload: vi.fn(),
  useGRCQuery: vi.fn(),
  useUserPreferences: vi.fn(),
}));

vi.mock("@/components/providers", () => ({
  useUserPreferences: mocks.useUserPreferences,
}));
vi.mock("@/lib/grc-client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/grc-client")>();
  return { ...actual, useGRCQuery: mocks.useGRCQuery };
});

import { grcDashboardPath, grcPath, grcProgramReadinessPath } from "@/lib/grc-client";

import Home, { buildHomeQueue, ReviewNowPanel } from "./page";

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};

describe("Home review links", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    mocks.reload.mockReset().mockResolvedValue(undefined);
    mocks.useUserPreferences.mockReset().mockReturnValue({ preferences: defaultUserPreferences });
    mocks.useGRCQuery.mockReset().mockImplementation((path: string | null) => ({
      data: null,
      durationMs: null,
      error: null,
      lastSuccessfulAt: null,
      loading: Boolean(path),
      reload: mocks.reload,
      state: path ? "loading" : "empty",
    }));
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("renders a legacy control work item at the current controls route", async () => {
    const items = buildHomeQueue({
      connectors: [],
      controls: [],
      coverageBlindSpots: [],
      findings: [],
      readinessData: {
        work_items: [{
          id: "soc2-cc6.6",
          kind: "control",
          status: "failing",
          title: "SOC 2 CC6.6",
          href: "/grc/controls?framework=SOC%202&control=CC6.6",
        }],
      } as GRCProgramReadiness,
    });

    expect(items[0]?.href).toBe("/controls?framework=SOC%202&control=CC6.6");

    await act(async () => {
      root.render(<ReviewNowPanel items={items} />);
    });

    const links = [...container.querySelectorAll<HTMLAnchorElement>("a")];
    expect(links.map((link) => link.getAttribute("href"))).toContain("/controls?framework=SOC%202&control=CC6.6");
  });

  it("starts the dashboard before secondary Home queries", async () => {
    await act(async () => {
      root.render(<Home />);
    });

    expect(mocks.useGRCQuery.mock.calls.map(([path]) => path)).toEqual([
      grcDashboardPath({ limit: 12 }),
      null,
      null,
    ]);
  });

  it("starts secondary Home queries after dashboard data arrives", async () => {
    const dashboardPath = grcDashboardPath({ limit: 12 });
    const dashboardData: GRCDashboard = {
      summary: {
        open_findings: 0,
        critical_findings: 0,
        high_findings: 0,
        overdue_findings: 0,
        unassigned: 0,
        controls_failing: 0,
        evidence_items: 0,
        connectors: 0,
        stale_connectors: 0,
      },
      findings: [],
      controls: [],
      evidence: [],
      connectors: [],
      generated_at: "2026-08-25T00:00:00Z",
    };
    mocks.useGRCQuery.mockImplementation((path: string | null) => ({
      data: path === dashboardPath ? dashboardData : null,
      durationMs: null,
      error: null,
      lastSuccessfulAt: null,
      loading: Boolean(path),
      reload: mocks.reload,
      state: path ? "loading" : "empty",
    }));

    await act(async () => {
      root.render(<Home />);
    });

    expect(mocks.useGRCQuery.mock.calls.map(([path]) => path)).toEqual([
      dashboardPath,
      grcProgramReadinessPath(),
      grcPath("/connectors/coverage", {
        coverage_scope: "configured",
        coverage_view: "page",
        blind_spots_only: "true",
        page_size: 3,
      }),
    ]);
  });
});
