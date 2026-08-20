/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { GRCProgramReadiness } from "@/lib/grc";

import { buildHomeQueue, ReviewNowPanel } from "./page";

const reactActEnvironment = globalThis as typeof globalThis & {
  IS_REACT_ACT_ENVIRONMENT?: boolean;
};

describe("Home review links", () => {
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

  it("renders a legacy control work item at the current controls route", async () => {
    const items = buildHomeQueue({
      connectors: [],
      controls: [],
      coverageBlindSpots: [],
      findings: [],
      readinessData: {
        work_items: [{
          id: "soc2-cc6.6",
          kind: "control",
          status: "failing",
          title: "SOC 2 CC6.6",
          href: "/grc/controls?framework=SOC%202&control=CC6.6",
        }],
      } as GRCProgramReadiness,
    });

    expect(items[0]?.href).toBe("/controls?framework=SOC%202&control=CC6.6");

    await act(async () => {
      root.render(<ReviewNowPanel items={items} />);
    });

    const links = [...container.querySelectorAll<HTMLAnchorElement>("a")];
    expect(links.map((link) => link.getAttribute("href"))).toContain("/controls?framework=SOC%202&control=CC6.6");
  });
});
