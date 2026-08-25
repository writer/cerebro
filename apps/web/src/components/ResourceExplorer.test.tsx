/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { OpenApiOperation } from "@/lib/openapi";

vi.mock("@/components/providers", () => ({
  useApiKey: () => ({ apiKey: "" }),
}));

import ResourceExplorer from "./ResourceExplorer";

const operation: OpenApiOperation = {
  id: "list-assessment-lenses",
  tag: "GRC",
  method: "GET",
  path: "/grc/assessment-lenses",
  summary: "List assessment lenses",
  parameters: [],
  source: "openapi",
};

describe("ResourceExplorer", () => {
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
  });

  it("opens read-only endpoints through the authenticated same-origin proxy", async () => {
    await act(async () => {
      root.render(<ResourceExplorer operations={[operation]} schemas={{}} />);
    });

    const openLink = Array.from(container.querySelectorAll("a")).find(
      (link) => link.textContent === "Open",
    );

    expect(openLink?.getAttribute("href")).toBe(
      "/api/cerebro/grc/assessment-lenses",
    );
    expect(openLink?.getAttribute("target")).toBe("_blank");
  });
});
