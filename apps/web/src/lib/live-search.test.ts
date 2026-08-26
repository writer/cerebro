/**
 * @vitest-environment jsdom
 */
import { act, createElement, type ComponentProps } from "react";
import { createRoot, type Root } from "react-dom/client";
import { NuqsTestingAdapter } from "nuqs/adapters/testing";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiKeyProvider } from "@/components/providers";

import {
  LIVE_SEARCH_TIMEOUT_MS,
  LIVE_SEARCH_UNAVAILABLE_COPY,
  liveSearchDashboardPath,
  liveSearchScopeIsReady,
  liveSearchScopeKey,
  useLiveSearchCommands,
} from "./live-search";

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};

function LiveSearchHarness() {
  useLiveSearchCommands("needle", true);
  return null;
}

describe("live search status copy", () => {
  it("finishes unavailable searches with page-action fallback copy", () => {
    expect(LIVE_SEARCH_TIMEOUT_MS).toBe(8_000);
    expect(LIVE_SEARCH_UNAVAILABLE_COPY).toBe("Page actions are ready. Live search is unavailable.");
  });
});

describe("live search scope", () => {
  it("includes the canonical tenant and workspace selectors in the dashboard path", () => {
    expect(liveSearchDashboardPath({ tenantID: " tenant-a ", workspaceID: " workspace-a " })).toBe(
      "/grc/dashboard?limit=100&tenant_id=tenant-a&workspace_id=workspace-a&view=summary",
    );
  });

  it("partitions shared state by API key, tenant, and workspace", () => {
    const scope = { tenantID: "tenant-a", workspaceID: "workspace-a" };
    const keys = new Set([
      liveSearchScopeKey("key-a", scope),
      liveSearchScopeKey("key-a", { ...scope, workspaceID: "workspace-b" }),
      liveSearchScopeKey("key-a", { ...scope, tenantID: "tenant-b" }),
      liveSearchScopeKey("key-b", scope),
    ]);

    expect(keys).toHaveLength(4);
  });

  it("does not permit a workspace selector without an explicit tenant", () => {
    expect(liveSearchScopeIsReady({ tenantID: "", workspaceID: "workspace-a" })).toBe(false);
    expect(liveSearchScopeIsReady({ tenantID: "tenant-a", workspaceID: "workspace-a" })).toBe(true);
    expect(liveSearchScopeIsReady({ tenantID: "tenant-a", workspaceID: "" })).toBe(true);
  });
});

describe("live search scope requests", () => {
  let container: HTMLDivElement;
  let root: Root;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    window.localStorage.setItem("cerebro.apiKey", "live-search-test-key");
    window.__cerebroLiveSearchDashboard = undefined;
    fetchMock = vi.fn(async () => new Response("{}", {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
    window.localStorage.removeItem("cerebro.apiKey");
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  const renderSearch = async (searchParams: string) => {
    act(() => {
      root.render(
        createElement(
          NuqsTestingAdapter,
          {
            hasMemory: true,
            searchParams,
          } as ComponentProps<typeof NuqsTestingAdapter>,
          createElement(ApiKeyProvider, null, createElement(LiveSearchHarness)),
        ),
      );
    });
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 100));
    });
  };

  it("does not issue a read for an orphan workspace", async () => {
    await renderSearch("?workspace_id=workspace-a");

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("issues the scoped dashboard read for a tenant and workspace", async () => {
    await renderSearch("?tenant_id=tenant-a&workspace_id=workspace-a");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      "/api/cerebro/grc/dashboard?limit=100&tenant_id=tenant-a&workspace_id=workspace-a&view=summary",
    );
  });
});
