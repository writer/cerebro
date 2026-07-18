/**
 * @vitest-environment jsdom
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiKeyProvider } from "@/components/providers";

import { downloadGRCExport, grcDashboardPath, grcEntityImpactPath, grcExportFilename, grcPath, grcProgramReadinessPath, grcQueryKey, GRC_QUERY_TIMEOUT_MS, grcResponseErrorMessage, grcTimeoutMessage, useGRCMutation } from "./grc-client";

describe("grc client error copy", () => {
  it("includes status, endpoint, elapsed time, and upstream text", () => {
    expect(grcResponseErrorMessage("/grc/control-packets", 404, "page not found", 215)).toBe(
      "Cerebro request failed (404) for /grc/control-packets after 215ms: page not found",
    );
  });

  it("extracts structured proxy errors", () => {
    expect(grcResponseErrorMessage("/grc/evidence", 504, { error: "Cerebro API request timed out" }, 30_100)).toBe(
      "Cerebro request failed (504) for /grc/evidence after 30s: Cerebro API request timed out",
    );
  });

  it("formats client-side timeouts as unavailable API errors", () => {
    expect(grcTimeoutMessage("/grc/evidence", 30_000)).toBe(
      "Cerebro request timed out after 30s for /grc/evidence",
    );
  });

  it("keeps default query waits short enough to show recovery state", () => {
    expect(GRC_QUERY_TIMEOUT_MS).toBe(12_000);
    expect(grcTimeoutMessage("/grc/control-packets", GRC_QUERY_TIMEOUT_MS)).toBe(
      "Cerebro request timed out after 12s for /grc/control-packets",
    );
  });
});

describe("grc client paths", () => {
  it("omits empty query parameters from GRC proxy paths", () => {
    expect(grcPath("/grc/control-packets", {
      control: "",
      framework: "SOC 2",
      limit: 25,
      tenant_id: undefined,
    })).toBe("/grc/control-packets?framework=SOC+2&limit=25");
  });

  it("encodes impact root URNs inside the proxy path segment", () => {
    const path = grcEntityImpactPath("urn:cerebro:writer:github_code_repository:writer/cerebro", {
      tenant_id: "writer",
      limit: 50,
    });

    expect(path).toBe(
      "/grc/entities/urn%3Acerebro%3Awriter%3Agithub_code_repository%3Awriter%2Fcerebro/impact?tenant_id=writer&limit=50",
    );
  });

  it("requests compact dashboard and readiness responses", () => {
    expect(grcDashboardPath({ limit: 12 })).toBe("/grc/dashboard?limit=12&view=summary");
    expect(grcProgramReadinessPath({ tenant_id: "writer" })).toBe("/grc/program-readiness?tenant_id=writer&view=summary");
  });
});

describe("grc query keys", () => {
  it("scopes TanStack Query cache entries by API key and path", () => {
    expect(grcQueryKey("/grc/dashboard?limit=10", "key-a")).toEqual(["grc", "key-a", "/grc/dashboard?limit=10"]);
    expect(grcQueryKey("/grc/dashboard?limit=10", "key-b")).not.toEqual(grcQueryKey("/grc/dashboard?limit=10", "key-a"));
  });

  it("uses a stable disabled key for inactive queries", () => {
    expect(grcQueryKey(null)).toEqual(["grc", "", "disabled"]);
  });
});

describe("grc export helpers", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("date-stamps export filenames per entity", () => {
    expect(grcExportFilename("findings")).toMatch(/^cerebro-findings-\d{4}-\d{2}-\d{2}\.csv$/);
    expect(grcExportFilename("controls")).toMatch(/^cerebro-controls-\d{4}-\d{2}-\d{2}\.csv$/);
  });

  it("streams a successful CSV response into a browser download", async () => {
    const csv = "id,title\nfinding-1,Risky";
    vi.stubGlobal("fetch", vi.fn(async () => new Response(csv, { status: 200, headers: { "content-type": "text/csv" } })));
    const createObjectURL = vi.fn((blob: Blob | MediaSource) => {
      void blob;
      return "blob:csv";
    });
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("window", { URL: { createObjectURL, revokeObjectURL } });
    const anchor = { href: "", download: "", click: vi.fn() };
    vi.stubGlobal("document", { createElement: vi.fn(() => anchor) });

    const result = await downloadGRCExport("/grc/findings/export?tenant_id=acme", "key", "cerebro-findings-2026-06-22.csv");

    expect(result).toEqual({ ok: true });
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    const blobArg = createObjectURL.mock.calls[0][0] as Blob;
    expect(blobArg).toBeInstanceOf(Blob);
    expect(await blobArg.text()).toBe(csv);
    expect(blobArg.type).toContain("text/csv");
    expect(anchor.download).toBe("cerebro-findings-2026-06-22.csv");
    expect(anchor.href).toBe("blob:csv");
    expect(anchor.click).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:csv");
  });

  it("returns a descriptive error when the export request fails", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("nope", { status: 500, headers: { "content-type": "text/plain" } })));
    vi.stubGlobal("window", { URL: { createObjectURL: vi.fn(), revokeObjectURL: vi.fn() } });
    vi.stubGlobal("document", { createElement: vi.fn() });

    const result = await downloadGRCExport("/grc/controls/export", "key", "cerebro-controls.csv");

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("(500)");
      expect(result.error).toContain("/grc/controls/export");
    }
  });
});

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};
const flushReactUpdates = () => new Promise((resolve) => setTimeout(resolve, 0));

function GRCMutationHarness() {
  const mutation = useGRCMutation<{ saved: boolean }>();
  const [result, setResult] = useState("");

  return (
    <div>
      <span id="mutation-result">{result}</span>
      <span id="mutation-error">{mutation.error ?? ""}</span>
      <button
        id="run-mutation"
        type="button"
        onClick={() => {
          void mutation.mutate("/grc/actions", { name: "ready" }, "PATCH")
            .then((response) => setResult(response.saved ? "saved" : "done"))
            .catch(() => undefined);
        }}
      >
        Run
      </button>
    </div>
  );
}

describe("useGRCMutation", () => {
  let container: HTMLDivElement;
  let queryClient: QueryClient;
  let root: Root;

  beforeEach(() => {
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    window.localStorage.setItem("cerebro.apiKey", "key-a");
    container = document.createElement("div");
    document.body.appendChild(container);
    queryClient = new QueryClient({
      defaultOptions: {
        mutations: { retry: false },
        queries: { retry: false },
      },
    });
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => {
      root.unmount();
    });
    container.remove();
    window.localStorage.clear();
    queryClient.clear();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("runs JSON mutations through TanStack Query and invalidates GRC reads", async () => {
    const invalidateSpy = vi.spyOn(queryClient, "invalidateQueries");
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(JSON.stringify({ saved: true }), {
        headers: { "content-type": "application/json" },
        status: 200,
      })));

    await act(async () => {
      root.render(
        <QueryClientProvider client={queryClient}>
          <ApiKeyProvider>
            <GRCMutationHarness />
          </ApiKeyProvider>
        </QueryClientProvider>,
      );
    });

    await act(async () => {
      container.querySelector<HTMLButtonElement>("#run-mutation")?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      await flushReactUpdates();
    });

    expect(container.querySelector("#mutation-result")?.textContent).toBe("saved");
    expect(fetch).toHaveBeenCalledWith(
      "/api/cerebro/grc/actions",
      expect.objectContaining({
        body: JSON.stringify({ name: "ready" }),
        method: "PATCH",
      }),
    );
    const headers = (vi.mocked(fetch).mock.calls[0][1] as RequestInit).headers as Headers;
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(headers.get("X-API-Key")).toBe("key-a");
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ["grc", "key-a"] });
  });
});
