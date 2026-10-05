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
  useGRCScopeQueryState: vi.fn(),
  useUserPreferences: vi.fn(),
}));

vi.mock("@/components/providers", () => ({
  useUserPreferences: mocks.useUserPreferences,
}));
vi.mock("@/lib/grc-client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/grc-client")>();
  return { ...actual, useGRCQuery: mocks.useGRCQuery };
});
vi.mock("@/lib/grc-scope", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/grc-scope")>();
  return { ...actual, useGRCScopeQueryState: mocks.useGRCScopeQueryState };
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
    mocks.useGRCScopeQueryState.mockReset().mockReturnValue({
      tenantID: "",
      workspaceID: "",
      setTenantID: vi.fn(),
      setWorkspaceID: vi.fn(),
    });
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

  it("starts all independent Home queries on the initial render", async () => {
    await act(async () => {
      root.render(<Home />);
    });

    expect(mocks.useGRCQuery.mock.calls.map(([path]) => path)).toEqual([
      grcDashboardPath({ limit: 12, enrichments: "deferred" }),
      grcProgramReadinessPath({ enrichments: "deferred" }),
      grcPath("/connectors/coverage", {
        coverage_scope: "configured",
        coverage_view: "page",
        blind_spots_only: "true",
        page_size: 3,
      }),
      grcPath("/grc/trends", { interval: "day", days: 30 }),
    ]);
  });

  it("preserves tenant-only Home reads when no workspace is active", async () => {
    mocks.useGRCScopeQueryState.mockReturnValue({
      tenantID: "tenant-a",
      workspaceID: "",
      setTenantID: vi.fn(),
      setWorkspaceID: vi.fn(),
    });

    await act(async () => {
      root.render(<Home />);
    });

    expect(mocks.useGRCQuery.mock.calls.map(([path]) => path)).toEqual([
      grcDashboardPath({ limit: 12, enrichments: "deferred", tenant_id: "tenant-a" }),
      grcProgramReadinessPath({ enrichments: "deferred", tenant_id: "tenant-a" }),
      grcPath("/connectors/coverage", {
        coverage_scope: "configured",
        coverage_view: "page",
        blind_spots_only: "true",
        page_size: 3,
        tenant_id: "tenant-a",
      }),
      grcPath("/grc/trends", { interval: "day", days: 30, tenant_id: "tenant-a" }),
    ]);
  });

  it("keeps all Home reads isolated when the active workspace changes", async () => {
    mocks.useGRCScopeQueryState.mockReturnValue({
      tenantID: "tenant-a",
      workspaceID: "workspace-a",
      setTenantID: vi.fn(),
      setWorkspaceID: vi.fn(),
    });
    await act(async () => {
      root.render(<Home />);
    });

    expect(mocks.useGRCQuery.mock.calls.map(([path]) => path)).toEqual([
      grcDashboardPath({ limit: 12, enrichments: "deferred", tenant_id: "tenant-a", workspace_id: "workspace-a" }),
      grcProgramReadinessPath({ enrichments: "deferred", tenant_id: "tenant-a", workspace_id: "workspace-a" }),
      grcPath("/connectors/coverage", {
        coverage_scope: "configured",
        coverage_view: "page",
        blind_spots_only: "true",
        page_size: 3,
        tenant_id: "tenant-a",
        workspace_id: "workspace-a",
      }),
      grcPath("/grc/trends", { interval: "day", days: 30, tenant_id: "tenant-a", workspace_id: "workspace-a" }),
    ]);

    mocks.useGRCQuery.mockClear();
    mocks.useGRCScopeQueryState.mockReturnValue({
      tenantID: "tenant-a",
      workspaceID: "workspace-b",
      setTenantID: vi.fn(),
      setWorkspaceID: vi.fn(),
    });
    await act(async () => {
      root.render(<Home />);
    });

    expect(mocks.useGRCQuery.mock.calls.map(([path]) => path)).toEqual([
      grcDashboardPath({ limit: 12, enrichments: "deferred", tenant_id: "tenant-a", workspace_id: "workspace-b" }),
      grcProgramReadinessPath({ enrichments: "deferred", tenant_id: "tenant-a", workspace_id: "workspace-b" }),
      grcPath("/connectors/coverage", {
        coverage_scope: "configured",
        coverage_view: "page",
        blind_spots_only: "true",
        page_size: 3,
        tenant_id: "tenant-a",
        workspace_id: "workspace-b",
      }),
      grcPath("/grc/trends", { interval: "day", days: 30, tenant_id: "tenant-a", workspace_id: "workspace-b" }),
    ]);
  });

  it("fails closed when the backend rejects a tenant and workspace pairing", async () => {
    mocks.useGRCScopeQueryState.mockReturnValue({
      tenantID: "tenant-a",
      workspaceID: "workspace-b",
      setTenantID: vi.fn(),
      setWorkspaceID: vi.fn(),
    });
    mocks.useGRCQuery.mockImplementation((path: string | null) => ({
      data: null,
      durationMs: null,
      error: path ? "Cerebro request failed (403): forbidden" : null,
      lastSuccessfulAt: null,
      loading: false,
      reload: mocks.reload,
      state: path ? "permission-denied" : "empty",
    }));

    await act(async () => {
      root.render(<Home />);
    });

    expect(mocks.useGRCQuery).toHaveBeenCalledTimes(4);
    for (const [path] of mocks.useGRCQuery.mock.calls) {
      expect(path).toContain("tenant_id=tenant-a");
      expect(path).toContain("workspace_id=workspace-b");
    }
    expect(container.textContent).toContain("Graph data access unavailable");
    expect(container.textContent).not.toContain("Fix first");
  });

  it("does not issue Home reads for a workspace without an explicit tenant", async () => {
    mocks.useGRCScopeQueryState.mockReturnValue({
      tenantID: "",
      workspaceID: "workspace-a",
      setTenantID: vi.fn(),
      setWorkspaceID: vi.fn(),
    });

    await act(async () => {
      root.render(<Home />);
    });

    expect(mocks.useGRCQuery.mock.calls.map(([path]) => path)).toEqual([null, null, null, null]);
    expect(container.textContent).toContain("Select a tenant before loading a workspace.");
  });

  it("renders dashboard work while both secondary queries are still pending", async () => {
    const dashboardPath = grcDashboardPath({ limit: 12, enrichments: "deferred" });
    const dashboardData = {
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
    } as GRCDashboard;
    mocks.useGRCQuery.mockImplementation((path: string | null) => ({
      data: path === dashboardPath ? dashboardData : null,
      durationMs: null,
      error: null,
      lastSuccessfulAt: path === dashboardPath ? Date.parse(dashboardData.generated_at) : null,
      loading: path !== dashboardPath,
      reload: mocks.reload,
      state: path === dashboardPath ? "ready" : "loading",
    }));

    await act(async () => {
      root.render(<Home />);
    });

    expect(container.textContent).toContain("Fix first");
    expect(container.textContent).toContain("Loading source coverage.");
  });

  it("summarises opened against closed work for the trend window", async () => {
    const dashboardPath = grcDashboardPath({ limit: 12, enrichments: "deferred" });
    const trendsPath = grcPath("/grc/trends", { interval: "day", days: 30 });
    const dashboardData = {
      summary: {
        open_findings: 4,
        critical_findings: 1,
        high_findings: 2,
        overdue_findings: 1,
        unassigned: 1,
        controls_failing: 0,
        evidence_items: 0,
        connectors: 3,
        stale_connectors: 0,
      },
      findings: [],
      controls: [],
      evidence: [],
      connectors: [],
      generated_at: "2026-08-25T00:00:00Z",
    } as GRCDashboard;
    const trendsData = {
      interval: "day",
      start: "2026-07-26",
      end: "2026-08-25",
      points: [
        { date: "2026-08-23", opened: 4, opened_critical: 1, opened_high: 1, closed: 1, closed_critical: 0, closed_high: 0, closed_sla_breached: 0, avg_time_to_close_seconds: 0, open_total: 4 },
        { date: "2026-08-24", opened: 3, opened_critical: 0, opened_high: 1, closed: 2, closed_critical: 0, closed_high: 1, closed_sla_breached: 0, avg_time_to_close_seconds: 0, open_total: 5 },
      ],
      summary: { total_opened: 7, total_closed: 3, net: 4, current_open: 4, peak_open: 5, opened_critical: 1, opened_high: 2, closed_critical: 0, closed_high: 1 },
      generated_at: "2026-08-25T00:00:00Z",
    };
    mocks.useGRCQuery.mockImplementation((path: string | null) => ({
      data: path === dashboardPath ? dashboardData : path === trendsPath ? trendsData : null,
      durationMs: null,
      error: null,
      lastSuccessfulAt: null,
      loading: false,
      reload: mocks.reload,
      state: path ? "ready" : "empty",
    }));

    await act(async () => {
      root.render(<Home />);
    });

    expect(container.textContent).toContain("What changed");
    const trendLink = [...container.querySelectorAll<HTMLAnchorElement>("a")]
      .find((link) => link.getAttribute("href") === "/trends" && link.textContent?.includes("Net 30 days"));
    expect(trendLink?.textContent).toContain("+4");
    expect(trendLink?.textContent).toContain("Backlog grew");
  });

  it("reports source trust from dashboard and readiness coverage", async () => {
    const dashboardPath = grcDashboardPath({ limit: 12, enrichments: "deferred" });
    const dashboardData = {
      summary: {
        open_findings: 0,
        critical_findings: 0,
        high_findings: 0,
        overdue_findings: 0,
        unassigned: 0,
        controls_failing: 0,
        evidence_items: 0,
        connectors: 6,
        stale_connectors: 2,
      },
      findings: [],
      controls: [],
      evidence: [],
      connectors: [],
      generated_at: "2026-08-25T00:00:00Z",
    } as GRCDashboard;
    const readinessData = {
      summary: {
        controls: 36,
        passing_controls: 0,
        missing_evidence_items: 32,
        stale_evidence_items: 2,
        coverage_blind_spots: 4,
      },
      frameworks: [],
      controls: [],
      work_items: [],
      connectors: [],
    };
    mocks.useGRCQuery.mockImplementation((path: string | null) => ({
      data: path === dashboardPath ? dashboardData : path === grcProgramReadinessPath({ enrichments: "deferred" }) ? readinessData : null,
      durationMs: null,
      error: null,
      lastSuccessfulAt: null,
      loading: false,
      reload: mocks.reload,
      state: path ? "ready" : "empty",
    }));

    await act(async () => {
      root.render(<Home />);
    });

    const sourceLinks = [...container.querySelectorAll<HTMLAnchorElement>("a")]
      .filter((link) => link.getAttribute("href") === "/connectors")
      .map((link) => link.textContent ?? "");
    const reporting = sourceLinks.find((text) => text.includes("Sources reporting"));
    expect(reporting).toContain("4/6");
    expect(reporting).toContain("2 stale sources");
    const gaps = sourceLinks.find((text) => text.includes("Collection gaps"));
    expect(gaps).toContain("4");
    // Compliance readiness still loads, but Home must not surface it.
    expect(container.textContent).not.toContain("32 missing, 2 stale");
    expect(container.textContent).not.toContain("Export audit packet");
  });
});
