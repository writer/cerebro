/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/components/providers", () => ({
  useApiKey: () => ({ apiKey: "" }),
  useConsoleConfig: () => ({ config: { apiBase: "/api/cerebro", serverAuthConfigured: true } }),
  useCurrentUser: () => ({ error: null, loading: false, user: null }),
}));

vi.mock("@/lib/identity", () => ({
  identityPosture: () => ({ label: "Trusted proxy", sourceLabel: "Auth proxy headers" }),
}));

import StatusPanel, { statusProbes } from "./StatusPanel";

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};

describe("StatusPanel cache behavior", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
    vi.unstubAllGlobals();
  });

  it("uses normal caches automatically and bypasses them only for operator refresh", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ status: "ready" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    }));
    vi.stubGlobal("fetch", fetchMock);

    await act(async () => {
      root.render(<StatusPanel />);
      await new Promise((resolve) => window.setTimeout(resolve, 0));
    });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(6));

    for (const [, init] of fetchMock.mock.calls) {
      expect((init as RequestInit | undefined)?.cache).toBeUndefined();
    }

    const refresh = Array.from(container.querySelectorAll("button")).find((button) => button.textContent === "Refresh");
    expect(refresh).toBeDefined();
    await act(async () => {
      refresh?.click();
    });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(12));

    for (const [, init] of fetchMock.mock.calls.slice(6)) {
      expect((init as RequestInit | undefined)?.cache).toBe("no-store");
    }
  });

  it("scopes product probes without changing liveness and readiness paths", () => {
    const probes = statusProbes({ tenantID: "tenant-a", workspaceID: "workspace-a" });
    expect(probes.find((probe) => probe.key === "healthz")?.path).toBe("/api/cerebro/healthz");
    expect(probes.find((probe) => probe.key === "health")?.path).toBe("/api/cerebro/health");
    expect(probes.find((probe) => probe.key === "inventory")?.path)
      .toBe("/api/cerebro/grc/inventory/categories?limit=1&tenant_id=tenant-a&workspace_id=workspace-a");
    expect(probes.find((probe) => probe.key === "vendors")?.path)
      .toContain("workspace_id=workspace-a");
    expect(probes.find((probe) => probe.key === "policies")?.path)
      .toContain("tenant_id=tenant-a");
  });

  it("publishes probe results without waiting for the slowest request", async () => {
    const pending = new Map<string, (response: Response) => void>();
    const fetchMock = vi.fn<typeof fetch>((input) => new Promise<Response>((resolve) => {
      pending.set(String(input), resolve);
    }));
    vi.stubGlobal("fetch", fetchMock);

    await act(async () => {
      root.render(<StatusPanel />);
      await new Promise((resolve) => window.setTimeout(resolve, 0));
    });
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(6));

    await act(async () => {
      pending.get("/api/cerebro/healthz")?.(new Response(JSON.stringify({ status: "ready" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }));
    });
    await vi.waitFor(() => {
      const rows = Array.from(container.querySelectorAll("tbody tr"));
      expect(rows[0]?.textContent).toContain("Ready");
      expect(rows[1]?.textContent).toContain("Loading");
      expect(container.textContent).toContain("Healthz");
      expect(container.textContent).toContain("Checking...");
    });

    await act(async () => {
      for (const [path, resolve] of pending) {
        if (path === "/api/cerebro/healthz") continue;
        resolve(new Response(JSON.stringify({ status: "ready" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }));
      }
    });
    await vi.waitFor(() => expect(container.textContent).toContain("Refresh"));
  });
});
