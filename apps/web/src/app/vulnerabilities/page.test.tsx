/**
 * @vitest-environment jsdom
 */
import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CurrentUser } from "@/lib/identity";
import type { VulnerabilityObservationPage, VulnerabilityProfile, VulnerabilitySummary } from "@/lib/vulnerabilities";

const mocks = vi.hoisted(() => ({
  mutate: vi.fn(),
  reload: vi.fn(),
  useGRCQuery: vi.fn(),
  user: null as CurrentUser | null,
}));

vi.mock("@/components/providers", () => ({
  useCurrentUser: () => ({ actor: "analyst@example.com", error: null, loading: false, user: mocks.user }),
}));
vi.mock("@/lib/grc-client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/grc-client")>();
  return {
    ...actual,
    useDebouncedValue: <T,>(value: T) => value,
    useGRCMutation: () => ({ mutate: mocks.mutate, saving: false, error: null, setError: vi.fn() }),
    useGRCQuery: mocks.useGRCQuery,
  };
});
vi.mock("@/lib/query-params", () => ({
  useQueryParamState: (_key: string, fallback = "") => useState(fallback),
}));

import VulnerabilitiesPage from "./page";

const observedAt = "2026-01-15T12:00:00.000Z";
const summary: VulnerabilitySummary = {
  total: 2,
  open: 2,
  distinct_open_vulnerabilities: 1,
  multi_source_open: 2,
  by_severity: { critical: 1, high: 1 },
  by_class: {},
  by_status: { open: 2 },
  by_source: [
    { source_id: "internal-scanner", total: 1, open: 1, by_severity: { high: 1 } },
    { source_id: "strix", total: 1, open: 1, by_severity: { critical: 1 } },
  ],
  profiles: 2,
  profiles_needing_attention: 1,
};
const page: VulnerabilityObservationPage = {
  observations: [
    {
      id: "o-1", profile_id: "strix", source_id: "strix", source_record_id: "s-1", correlation_key: "k", format: "strix",
      title: "Backdoored xz-utils", class: "package", primary_vulnerability_id: "CVE-2024-3094", severity: "critical", status: "open",
      asset: { identifier: "payments-api" }, package: { name: "xz-libs", version: "5.6.0", fixed_version: "5.6.2" },
      observed_at: observedAt, ingested_at: observedAt,
    },
    {
      id: "o-2", profile_id: "internal-scanner", source_id: "internal-scanner", source_record_id: "r-1", correlation_key: "k", format: "generic",
      title: "xz-utils compromise", class: "package", severity: "high", status: "open", asset: { identifier: "payments-api" },
      observed_at: observedAt, ingested_at: observedAt,
    },
  ],
};
const draftProfile: VulnerabilityProfile = {
  tenant_id: "tenant-a",
  id: "internal-scanner",
  source_id: "internal-scanner",
  display_name: "Internal scanner",
  format: "generic",
  enabled: true,
  mapping_version: 0,
  transports: ["push_api", "mcp"],
  last_status: "pending_mapping",
  draft_mapping: {
    mapping: {},
    report: {
      detected_format: "generic",
      records_path: "results",
      sample_size: 12,
      fields: { title: { path: "name", confidence: 0.95, coverage: 1, reason: "name" } },
      confidence: 0.88,
      ready_to_activate: true,
    },
  },
};

const reactActEnvironment = globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean };

const ready = <T,>(data: T) => ({ data, durationMs: null, error: null, lastSuccessfulAt: 1, loading: false, reload: mocks.reload, state: "ready" });

describe("Vulnerabilities page", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    mocks.user = null;
    mocks.mutate.mockReset().mockResolvedValue({});
    mocks.reload.mockReset().mockResolvedValue(undefined);
    mocks.useGRCQuery.mockReset().mockImplementation((path: string) => {
      if (path.startsWith("/vulnerabilities/summary")) return ready(summary);
      if (path.startsWith("/vulnerabilities/profiles")) return ready({ profiles: [draftProfile] });
      const sourceID = new URL(path, "http://cerebro.local").searchParams.get("source_id");
      return ready({ observations: page.observations.filter((observation) => !sourceID || observation.source_id === sourceID) });
    });
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("tags every observation with its source and requests open records by default", async () => {
    await act(async () => root.render(<VulnerabilitiesPage />));

    const rows = Array.from(container.querySelectorAll("[data-vulnerability-observation]"));
    expect(rows.map((row) => row.querySelector("button[aria-label^='Filter by source']")?.textContent)).toEqual(["strix", "internal-scanner"]);
    expect(container.textContent).toContain("xz-libs@5.6.0 (fix 5.6.2)");
    const observationPath = mocks.useGRCQuery.mock.calls.map(([path]) => path as string).find((path) => path.startsWith("/vulnerabilities?"));
    expect(observationPath).toContain("status=open");
  });

  it("filters by source when a source tag is selected", async () => {
    await act(async () => root.render(<VulnerabilitiesPage />));
    const strixTag = container.querySelector<HTMLButtonElement>("[data-vulnerability-observation='o-1'] button[aria-label='Filter by source strix']");
    await act(async () => strixTag?.click());

    expect(container.querySelectorAll("[data-vulnerability-observation]")).toHaveLength(1);
    expect(mocks.useGRCQuery.mock.calls.at(-1)?.[0]).toContain("source_id=strix");
  });

  it("shows learned mappings for review and hides actions without write permission", async () => {
    await act(async () => root.render(<VulnerabilitiesPage />));

    const card = container.querySelector("[data-vulnerability-profile='internal-scanner']");
    expect(card?.textContent).toContain("Learned mapping for review");
    expect(card?.textContent).toContain("88% confidence");
    expect(card?.querySelector("button")).toBeNull();
  });

  it("activates a reviewed mapping for users who can write vulnerabilities", async () => {
    mocks.user = { actorId: "analyst", actorLabel: "Analyst", displayName: "Analyst", initials: "A", source: "sso-session", entitlements: { scopes: ["cerebro.vulnerabilities.write"] } } as CurrentUser;
    await act(async () => root.render(<VulnerabilitiesPage />));

    const activate = Array.from(container.querySelectorAll<HTMLButtonElement>("[data-vulnerability-profile='internal-scanner'] button"))
      .find((button) => button.textContent === "Activate mapping");
    await act(async () => activate?.click());

    expect(mocks.mutate).toHaveBeenCalledWith("/vulnerabilities/profiles/internal-scanner/mapping/activate?tenant_id=tenant-a", {});
    expect(mocks.reload).toHaveBeenCalled();
  });

  it("tells the user a sync was queued rather than finished", async () => {
    mocks.user = { actorId: "manager", actorLabel: "Manager", displayName: "Manager", initials: "M", source: "sso-session", entitlements: { scopes: ["cerebro.vulnerabilities.write"] } } as CurrentUser;
    const pulledProfile: VulnerabilityProfile = { ...draftProfile, id: "strix-pull", source_id: "strix", display_name: "Strix", pull_kind: "strix", draft_mapping: undefined, last_status: "failed" };
    mocks.useGRCQuery.mockImplementation((path: string) => {
      if (path.startsWith("/vulnerabilities/summary")) return ready(summary);
      if (path.startsWith("/vulnerabilities/profiles")) return ready({ profiles: [pulledProfile] });
      return ready(page);
    });
    await act(async () => root.render(<VulnerabilitiesPage />));

    const sync = Array.from(container.querySelectorAll<HTMLButtonElement>("[data-vulnerability-profile='strix-pull'] button"))
      .find((button) => button.textContent === "Sync now");
    await act(async () => sync?.click());

    expect(mocks.mutate).toHaveBeenCalledWith("/vulnerabilities/profiles/strix-pull/sync?tenant_id=tenant-a", {});
    expect(container.querySelector("[role='status']")?.textContent).toContain("Sync queued for Strix");
  });
});
