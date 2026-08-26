/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const currentScope = vi.hoisted(() => ({ actor: "actor-a", apiKey: "key-a" }));
const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};

vi.mock("@/components/providers", () => ({
  useApiKey: () => ({ apiKey: currentScope.apiKey }),
  useCurrentUser: () => ({ actor: currentScope.actor, loading: false }),
}));

import { useConnectorLibraryQuery } from "./connector-library-query";

const flushReactUpdates = async () => {
  await new Promise((resolve) => setTimeout(resolve, 10));
  await new Promise((resolve) => setTimeout(resolve, 10));
};

function ConnectorLibraryHarness({ tenantID }: { tenantID: string }) {
  const query = useConnectorLibraryQuery({ tenantID });
  return <output id="connector-state">{query.loading ? "loading" : query.data?.connectors?.[0]?.source_id ?? "empty"}</output>;
}

const connectorResponse = (tenantID: string, sourceID: string) => new Response(JSON.stringify({
  tenant_id: tenantID,
  connectors: [{ source_id: sourceID, name: sourceID }],
  page: { total: 1, returned: 1, limit: 200, has_more: false },
}), {
  headers: { "content-type": "application/json" },
  status: 200,
});

describe("connector library scope transitions", () => {
  let container: HTMLDivElement;
  let root: Root;
  let pending: Array<(response: Response) => void>;

  beforeEach(() => {
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    currentScope.actor = "actor-a";
    currentScope.apiKey = "key-a";
    pending = [];
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>((resolve) => pending.push(resolve))));
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("does not render the prior tenant while the replacement page is loading", async () => {
    await act(() => {
      root.render(<ConnectorLibraryHarness tenantID="tenant-a" />);
    });
    await act(async () => {
      await flushReactUpdates();
    });
    expect(pending).toHaveLength(1);

    await act(async () => {
      pending.shift()?.(connectorResponse("tenant-a", "connector-a"));
      await flushReactUpdates();
    });
    expect(container.querySelector("#connector-state")?.textContent).toBe("connector-a");

    await act(async () => {
      root.render(<ConnectorLibraryHarness tenantID="tenant-b" />);
    });
    expect(container.querySelector("#connector-state")?.textContent).not.toBe("connector-a");

    await act(async () => {
      await flushReactUpdates();
    });
    expect(pending).toHaveLength(1);
    await act(async () => {
      pending.shift()?.(connectorResponse("tenant-b", "connector-b"));
      await flushReactUpdates();
    });
    expect(container.querySelector("#connector-state")?.textContent).toBe("connector-b");
  });
});
