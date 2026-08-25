/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { NuqsTestingAdapter, type UrlUpdateEvent } from "nuqs/adapters/testing";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { grcScopeQuery, useGRCScopeQueryState, withGRCScope } from "./grc-scope";

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};
const flushNuqsUpdates = () => new Promise((resolve) => setTimeout(resolve, 80));

function ScopeHarness() {
  const { tenantID, workspaceID, setTenantID, setWorkspaceID } = useGRCScopeQueryState();
  return (
    <div>
      <span id="tenant">{tenantID}</span>
      <span id="workspace">{workspaceID}</span>
      <button id="change-tenant" type="button" onClick={() => setTenantID(" tenant-b ")}>Change tenant</button>
      <button id="change-workspace" type="button" onClick={() => setWorkspaceID(" workspace-b ")}>Change workspace</button>
    </div>
  );
}

describe("GRC scope", () => {
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
  });

  it("uses only the public tenant and workspace selectors", () => {
    expect(grcScopeQuery({ tenantID: " tenant-a ", workspaceID: " workspace-a " })).toEqual({
      tenant_id: "tenant-a",
      workspace_id: "workspace-a",
    });
    expect(grcScopeQuery({ tenantID: "tenant-a", workspaceID: " " })).toEqual({
      tenant_id: "tenant-a",
      workspace_id: undefined,
    });
  });

  it("preserves existing link queries and fragments", () => {
    expect(withGRCScope("/inventory/asset?tab=reports#events", { tenantID: "tenant-a", workspaceID: "workspace-a" }))
      .toBe("/inventory/asset?tab=reports&tenant_id=tenant-a&workspace_id=workspace-a#events");
  });

  it("clears workspace when tenant changes and keeps it for workspace-only changes", async () => {
    const updates: UrlUpdateEvent[] = [];
    await act(async () => {
      root.render(
        <NuqsTestingAdapter
          hasMemory
          onUrlUpdate={(event) => updates.push(event)}
          searchParams="?tenant_id=tenant-a&workspace_id=workspace-a"
        >
          <ScopeHarness />
        </NuqsTestingAdapter>,
      );
    });

    await act(async () => {
      container.querySelector<HTMLButtonElement>("#change-workspace")?.click();
      await flushNuqsUpdates();
    });
    expect(updates.at(-1)?.searchParams.get("workspace_id")).toBe("workspace-b");

    await act(async () => {
      container.querySelector<HTMLButtonElement>("#change-tenant")?.click();
      await flushNuqsUpdates();
    });
    expect(updates.at(-1)?.searchParams.get("tenant_id")).toBe("tenant-b");
    expect(updates.at(-1)?.searchParams.has("workspace_id")).toBe(false);
  });
});
