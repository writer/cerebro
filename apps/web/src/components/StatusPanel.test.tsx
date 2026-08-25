/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/components/providers", () => ({
  useApiKey: () => ({ apiKey: "" }),
  useConsoleConfig: () => ({ config: { apiBase: "/api/cerebro", serverAuthConfigured: true } }),
  useCurrentUser: () => ({ error: null, loading: false, user: null }),
}));

vi.mock("@/lib/identity", () => ({
  identityPosture: () => ({ label: "Trusted proxy", sourceLabel: "Auth proxy headers" }),
}));

import StatusPanel from "./StatusPanel";

describe("StatusPanel cache behavior", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
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
});
