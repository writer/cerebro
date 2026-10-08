/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { GRCDashboard } from "@/lib/grc";
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
// The home page renders Ask prompts through the agent dock, which has its own provider and tests.
vi.mock("@/components/ask/AskAboutLink", () => ({
  default: ({ children }: { children?: React.ReactNode }) => <button type="button">{children}</button>,
}));

import { grcDashboardPath, grcPath } from "@/lib/grc-client";

import Home from "./page";

const coveragePath = (scope: Record<string, string> = {}) =>
  grcPath("/connectors/coverage", {
    coverage_scope: "configured",
    coverage_view: "page",
    blind_spots_only: "true",
    page_size: 3,
    ...scope,
  });
const inventoryPath = (scope: Record<string, string> = {}) =>
  grcPath("/grc/inventory/assets", { surface: "asset", page_size: 1, ...scope });
const trendsPath = (scope: Record<string, string> = {}) =>
  grcPath("/grc/trends", { interval: "day", days: 30, ...scope });

const dashboardSummary = {
  open_findings: 4,
  critical_findings: 1,
  high_findings: 2,
  overdue_findings: 1,
  unassigned: 1,
  controls_failing: 0,
  evidence_items: 0,
  connectors: 6,
  stale_connectors: 2,
};

const dashboardFixture = {
  summary: dashboardSummary,
  findings: [],
  controls: [],
  evidence: [],
  connectors: [],
  generated_at: "2026-08-25T00:00:00Z",
} as GRCDashboard;

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};

describe("Security overview", () => {
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

  it("starts all independent Home queries on the initial render", async () => {
    await act(async () => {
      root.render(<Home />);
    });

    expect(mocks.useGRCQuery.mock.calls.map(([path]) => path)).toEqual([
      grcDashboardPath({ limit: 12, enrichments: "deferred" }),
      coveragePath(),
      inventoryPath(),
      trendsPath(),
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
      coveragePath({ tenant_id: "tenant-a" }),
      inventoryPath({ tenant_id: "tenant-a" }),
      trendsPath({ tenant_id: "tenant-a" }),
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

    const scopeA = { tenant_id: "tenant-a", workspace_id: "workspace-a" };
    expect(mocks.useGRCQuery.mock.calls.map(([path]) => path)).toEqual([
      grcDashboardPath({ limit: 12, enrichments: "deferred", ...scopeA }),
      coveragePath(scopeA),
      inventoryPath(scopeA),
      trendsPath(scopeA),
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

    const scopeB = { tenant_id: "tenant-a", workspace_id: "workspace-b" };
    expect(mocks.useGRCQuery.mock.calls.map(([path]) => path)).toEqual([
      grcDashboardPath({ limit: 12, enrichments: "deferred", ...scopeB }),
      coveragePath(scopeB),
      inventoryPath(scopeB),
      trendsPath(scopeB),
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
    expect(container.textContent).not.toContain("Asset Coverage");
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

  it("renders dashboard counts while the secondary queries are still pending", async () => {
    const dashboardPath = grcDashboardPath({ limit: 12, enrichments: "deferred" });
    mocks.useGRCQuery.mockImplementation((path: string | null) => ({
      data: path === dashboardPath ? dashboardFixture : null,
      durationMs: null,
      error: null,
      lastSuccessfulAt: path === dashboardPath ? Date.parse(dashboardFixture.generated_at) : null,
      loading: path !== dashboardPath,
      reload: mocks.reload,
      state: path === dashboardPath ? "ready" : "loading",
    }));

    await act(async () => {
      root.render(<Home />);
    });

    expect(container.textContent).toContain("Open Findings");
    expect(container.textContent).toContain("Loading source coverage.");
    expect(container.textContent).toContain("Loading asset inventory.");
  });

  it("summarises opened against closed work for the trend window", async () => {
    const dashboardPath = grcDashboardPath({ limit: 12, enrichments: "deferred" });
    const trends = {
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
      data: path === dashboardPath ? dashboardFixture : path === trendsPath() ? trends : null,
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

    expect(container.textContent).toContain("What Changed");
    const trendLink = [...container.querySelectorAll<HTMLAnchorElement>("a")]
      .find((link) => link.getAttribute("href") === "/trends");
    expect(trendLink?.textContent).toContain("Open Trends");
    expect(container.textContent).toContain("+4");
  });

  it("reports asset inventory coverage from the inventory summary", async () => {
    const dashboardPath = grcDashboardPath({ limit: 12, enrichments: "deferred" });
    const inventory = {
      assets: [],
      summary: {
        total_assets: 120,
        in_scope_assets: 110,
        out_of_scope_assets: 10,
        high_risk_assets: 7,
        unassigned_assets: 24,
        needs_review_assets: 5,
        accountable_assets: 96,
        owner_required_assets: 24,
        org_groups: 9,
        public_assets: 3,
        scoped_coverage_pct: 92,
        assigned_coverage_pct: 80,
      },
      generated_at: "2026-08-25T00:00:00Z",
    };
    mocks.useGRCQuery.mockImplementation((path: string | null) => ({
      data: path === dashboardPath ? dashboardFixture : path === inventoryPath() ? inventory : null,
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

    const inventoryLinks = [...container.querySelectorAll<HTMLAnchorElement>("a")]
      .filter((link) => link.getAttribute("href") === "/inventory")
      .map((link) => link.textContent ?? "");

    expect(inventoryLinks.find((text) => text.includes("Assets Tracked"))).toContain("120");
    const ownerCoverage = inventoryLinks.find((text) => text.includes("Owner Coverage"));
    expect(ownerCoverage).toContain("80%");
    expect(ownerCoverage).toContain("24 assets unowned");
    expect(inventoryLinks.find((text) => text.includes("Unowned Assets"))).toContain("96 of 120");
    expect(inventoryLinks.find((text) => text.includes("Publicly Reachable"))).toContain("3");
  });

  it("reports source trust from the dashboard summary", async () => {
    const dashboardPath = grcDashboardPath({ limit: 12, enrichments: "deferred" });
    mocks.useGRCQuery.mockImplementation((path: string | null) => ({
      data: path === dashboardPath ? dashboardFixture : null,
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
    expect(sourceLinks.find((text) => text.includes("Sources Reporting"))).toContain("4/6");
    expect(sourceLinks.find((text) => text.includes("Sources Connected"))).toContain("2 stale sources");
    // Compliance reporting is owned elsewhere; Home must not grow it back.
    expect(container.textContent).not.toContain("Export audit packet");
    expect(container.textContent).not.toContain("SOC 2");
  });
});
