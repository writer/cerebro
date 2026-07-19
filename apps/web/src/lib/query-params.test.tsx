/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { NuqsTestingAdapter, type UrlUpdateEvent } from "nuqs/adapters/testing";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { useAuditPackageParams } from "./audit-package-view";
import { useQueryParamState } from "./query-params";

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};
const flushNuqsUpdates = () => new Promise((resolve) => setTimeout(resolve, 80));

function QueryParamHarness() {
  const [status, setStatus] = useQueryParamState("status", "open");

  return (
    <div>
      <span id="value">{status}</span>
      <button id="set-triaged" type="button" onClick={() => setStatus("  triaged  ")}>
        Set triaged
      </button>
      <button id="set-default" type="button" onClick={() => setStatus("open")}>
        Set default
      </button>
    </div>
  );
}

function AuditPackageParamHarness() {
  const {
    clear,
    controlID,
    framework,
    profileID,
    setFramework,
    setTenantID,
    tenantID,
  } = useAuditPackageParams();

  return (
    <div>
      <span id="audit-tenant">{tenantID}</span>
      <span id="audit-profile">{profileID}</span>
      <span id="audit-framework">{framework}</span>
      <span id="audit-control">{controlID}</span>
      <button id="audit-set-tenant" type="button" onClick={() => setTenantID("  acme  ")}>
        Set tenant
      </button>
      <button id="audit-clear-framework" type="button" onClick={() => setFramework("   ")}>
        Clear framework
      </button>
      <button id="audit-clear" type="button" onClick={clear}>
        Clear all
      </button>
    </div>
  );
}

describe("useQueryParamState", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => {
      root.unmount();
    });
    container.remove();
  });

  it("reads, trims, and clears default values through nuqs", async () => {
    const updates: UrlUpdateEvent[] = [];

    await act(async () => {
      root.render(
        <NuqsTestingAdapter
          hasMemory
          onUrlUpdate={(event) => updates.push(event)}
          searchParams="?status=closed"
        >
          <QueryParamHarness />
        </NuqsTestingAdapter>,
      );
    });

    expect(container.querySelector("#value")?.textContent).toBe("closed");

    await act(async () => {
      container.querySelector<HTMLButtonElement>("#set-triaged")?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      await flushNuqsUpdates();
    });

    expect(updates.at(-1)?.searchParams.get("status")).toBe("triaged");
    expect(container.querySelector("#value")?.textContent).toBe("triaged");

    await act(async () => {
      container.querySelector<HTMLButtonElement>("#set-default")?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      await flushNuqsUpdates();
    });

    expect(updates.at(-1)?.searchParams.has("status")).toBe(false);
    expect(container.querySelector("#value")?.textContent).toBe("open");
  });

  it("keeps audit package filters in typed URL keys", async () => {
    const updates: UrlUpdateEvent[] = [];

    await act(async () => {
      root.render(
        <NuqsTestingAdapter
          hasMemory
          onUrlUpdate={(event) => updates.push(event)}
          searchParams="?tenant_id=writer&profile=baseline&framework=SOC%202&control=CC6.1"
        >
          <AuditPackageParamHarness />
        </NuqsTestingAdapter>,
      );
    });

    expect(container.querySelector("#audit-tenant")?.textContent).toBe("writer");
    expect(container.querySelector("#audit-profile")?.textContent).toBe("baseline");
    expect(container.querySelector("#audit-framework")?.textContent).toBe("SOC 2");
    expect(container.querySelector("#audit-control")?.textContent).toBe("CC6.1");

    await act(async () => {
      container.querySelector<HTMLButtonElement>("#audit-set-tenant")?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      await flushNuqsUpdates();
    });

    expect(updates.at(-1)?.searchParams.get("tenant_id")).toBe("acme");
    expect(container.querySelector("#audit-tenant")?.textContent).toBe("acme");

    await act(async () => {
      container.querySelector<HTMLButtonElement>("#audit-clear-framework")?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      await flushNuqsUpdates();
    });

    expect(updates.at(-1)?.searchParams.has("framework")).toBe(false);
    expect(container.querySelector("#audit-framework")?.textContent).toBe("");

    await act(async () => {
      container.querySelector<HTMLButtonElement>("#audit-clear")?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      await flushNuqsUpdates();
    });

    expect(updates.at(-1)?.searchParams.toString()).toBe("");
    expect(container.querySelector("#audit-control")?.textContent).toBe("");
  });
});
