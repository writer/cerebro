/**
 * @vitest-environment jsdom
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { CoverageMetadata } from "@/components/connectors/CoverageMetadata";

describe("CoverageMetadata", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
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

  it("renders evidence types, control domains, and mapped control refs", async () => {
    await act(async () => {
      root.render(
        <CoverageMetadata
          item={{
            id: "auth0.users.identity",
            type: "app_entitlement",
            title: "User entitlements",
            support: "supported",
            high_value: true,
            evidence_types: ["identity_configuration"],
            control_domains: ["identity_and_access"],
            control_refs: [{ framework_name: "SOC 2", control_id: "CC6.1" }],
          }}
          showTitle
        />,
      );
    });

    expect(container.textContent).toContain("User entitlements");
    expect(container.textContent).toContain("Identity Configuration");
    expect(container.textContent).toContain("Identity And Access");
    expect(container.textContent).toContain("SOC 2 CC6.1");
    expect(container.querySelector("a")?.getAttribute("href")).toBe("/controls?framework=SOC%202&control=CC6.1");
  });
});
