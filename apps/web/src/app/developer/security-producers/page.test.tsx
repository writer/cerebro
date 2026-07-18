/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SecurityProducerCatalogProvider } from "@/components/SecurityProducerCatalogProvider";

const mocks = vi.hoisted(() => ({
  fetchCerebro: vi.fn(),
  fetchSecurityProducers: vi.fn(),
}));

vi.mock("@/lib/cerebro-client", () => ({ fetchCerebro: mocks.fetchCerebro }));
vi.mock("@/lib/security-producers-client", () => ({
  fetchSecurityProducers: mocks.fetchSecurityProducers,
}));

import SecurityProducersPage from "./page";

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};
const flushUpdates = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("security producer catalog page", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    mocks.fetchCerebro.mockReset().mockResolvedValue({ ok: true, status: 200, data: [] });
    mocks.fetchSecurityProducers.mockReset();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
  });

  it("keeps unavailable distinct from configured-empty and retries", async () => {
    mocks.fetchSecurityProducers
      .mockResolvedValueOnce({ state: "unavailable" })
      .mockResolvedValueOnce({ state: "ready", producers: [] });

    await act(async () => {
      root.render(
        <SecurityProducerCatalogProvider>
          <SecurityProducersPage />
        </SecurityProducerCatalogProvider>,
      );
      await flushUpdates();
    });

    expect(container.textContent).toContain("Producer catalog is unavailable.");
    expect(container.textContent).not.toContain("No security producers are configured");
    const status = container.querySelector<HTMLElement>("[role='status']");
    expect(status?.getAttribute("aria-live")).toBe("polite");
    expect(status?.getAttribute("aria-busy")).toBe("false");
    const retry = container.querySelector<HTMLButtonElement>("button");
    retry?.focus();
    expect(document.activeElement).toBe(retry);

    await act(async () => {
      retry?.click();
      await flushUpdates();
      await flushUpdates();
    });

    expect(mocks.fetchSecurityProducers).toHaveBeenCalledTimes(2);
    expect(container.textContent).toContain("No security producers are configured for this deployment.");
    expect(container.textContent).not.toContain("Producer catalog is unavailable.");
    expect(document.activeElement).toBe(status);
  });
});
