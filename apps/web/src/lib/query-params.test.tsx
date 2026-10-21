/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { NuqsTestingAdapter, type UrlUpdateEvent } from "nuqs/adapters/testing";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

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
});
