/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { GRCGraph } from "@/lib/grc";

const mocks = vi.hoisted(() => ({
  openAgent: vi.fn(),
}));

vi.mock("@/components/agent/CerebroAgentProvider", () => ({
  useCerebroAgent: () => ({ openAgent: mocks.openAgent }),
}));

import EntityChip from "./EntityChip";

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};
const flushUpdates = () => new Promise((resolve) => setTimeout(resolve, 0));

const urn = "urn:cerebro:writer:okta_user:jdoe";

const graph: GRCGraph = {
  root: {
    urn,
    entity_type: "okta_user",
    label: "J. Doe",
    attributes: { risk_score: "88" },
  },
};

describe("EntityChip", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true;
    mocks.openAgent.mockReset();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => {
      root.unmount();
      await flushUpdates();
    });
    container.remove();
  });

  const render = async (element: React.ReactElement) => {
    await act(async () => {
      root.render(element);
      await flushUpdates();
    });
  };

  const chipButton = () =>
    container.querySelector<HTMLButtonElement>(`button[data-urn="${urn}"]`);

  it("renders the cited label on the chip", async () => {
    await render(<EntityChip urn={urn} label="the user" />);
    expect(chipButton()?.textContent).toContain("the user");
    expect(chipButton()?.getAttribute("title")).toBe(urn);
  });

  it("opens a peek with type, risk, and entity actions on click", async () => {
    await render(<EntityChip urn={urn} graph={graph} />);
    expect(container.textContent).not.toContain("Blast radius");

    await act(async () => {
      chipButton()?.click();
      await flushUpdates();
    });

    expect(container.textContent).toContain("J. Doe");
    expect(container.textContent).toContain("identity");
    expect(container.textContent).toContain("Risk critical · 88");

    const blastRadius = Array.from(container.querySelectorAll("a")).find(
      (link) => link.textContent === "Blast radius",
    );
    expect(blastRadius?.getAttribute("href")).toBe(
      `/impact?root_urn=${encodeURIComponent(urn)}`,
    );
    const open = Array.from(container.querySelectorAll("a")).find(
      (link) => link.textContent === "Open",
    );
    expect(open?.getAttribute("href")).toBe(`/inventory/${encodeURIComponent(urn)}`);
  });

  it("pivots by seeding a scoped agent question", async () => {
    await render(<EntityChip urn={urn} graph={graph} />);
    await act(async () => {
      chipButton()?.click();
      await flushUpdates();
    });

    const pivot = Array.from(container.querySelectorAll("button")).find(
      (button) => button.textContent === "Pivot here",
    );
    await act(async () => {
      pivot?.click();
      await flushUpdates();
    });

    expect(mocks.openAgent).toHaveBeenCalledWith({
      question: "Explore what connects to jdoe",
      scopeUrn: urn,
      autoSubmit: true,
    });
  });

  it("notes when details come from the urn alone", async () => {
    await render(<EntityChip urn="urn:cerebro:writer:finding:f-1" />);
    await act(async () => {
      container.querySelector<HTMLButtonElement>("button[data-urn]")?.click();
      await flushUpdates();
    });
    expect(container.textContent).toContain("Details from URN only");
  });
});
