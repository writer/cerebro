/**
 * @vitest-environment jsdom
 */
import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { GRCFinding, GRCFramework } from "@/lib/grc";

const mocks = vi.hoisted(() => ({
  mutate: vi.fn(),
  useGRCQuery: vi.fn(),
  useSearchParams: vi.fn(),
}));

vi.mock("next/navigation", () => ({ useSearchParams: mocks.useSearchParams }));
vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: { children: unknown; href: string }) => createElement("a", { href, ...props }, children as never),
}));
vi.mock("@/lib/grc-client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/grc-client")>();
  return {
    ...actual,
    useGRCQuery: mocks.useGRCQuery,
    useGRCMutation: () => ({ mutate: mocks.mutate, saving: false, error: null, setError: vi.fn() }),
  };
});

import CompliancePage from "./page";

const catalog: GRCFramework[] = [
  { name: "SOC 2", lifecycle: "active", control_count: 61, family_count: 9, coverage: { selected_controls: 61, mapped_controls: 40, unmapped_controls: 21, mapped_rules: 1076 } },
  { name: "ISO 27001:2022", lifecycle: "active", control_count: 93, family_count: 4 },
  { name: "CSA CCM v4.0", lifecycle: "upcoming", control_count: 197, family_count: 17 },
];

const openFinding: GRCFinding = {
  id: "f1",
  title: "Admin without MFA",
  severity: "CRITICAL",
  status: "open",
  rule_id: "okta.admin_no_mfa",
  controls: [{ framework_name: "SOC 2", control_id: "CC6.1" }],
  evidence_count: 0,
  owner: "",
  sla_status: "",
};

const query = (data: unknown) => ({ data, error: null, loading: false, reload: vi.fn(), state: "ready" });

describe("Compliance page", () => {
  let container: HTMLDivElement;
  let root: Root;
  const requestedPaths: string[] = [];

  beforeEach(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    requestedPaths.length = 0;
    mocks.useSearchParams.mockReturnValue(new URLSearchParams("tenant_id=acme"));
    mocks.useGRCQuery.mockImplementation((path: string | null) => {
      if (path) requestedPaths.push(path);
      if (path?.startsWith("/grc/framework-settings")) {
        return query({ settings: { tenant_id: "acme", enabled_frameworks: ["SOC 2", "Retired Framework"] }, persisted: true });
      }
      if (path === "/grc/frameworks") return query({ version: "1", frameworks: catalog, generated_at: "" });
      if (path?.startsWith("/grc/findings")) return query({ findings: [openFinding] });
      return query(null);
    });
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    act(() => root.unmount());
    container.remove();
    vi.clearAllMocks();
  });

  it("shows control violations for each enabled framework only", () => {
    act(() => root.render(createElement(CompliancePage)));

    const cards = container.querySelectorAll("[data-compliance-framework]");
    expect([...cards].map((card) => card.getAttribute("data-compliance-framework"))).toEqual(["SOC 2"]);
    expect(container.textContent).toContain("CC6.1");
    expect(container.textContent).toContain("1076 mapped rules");
    expect(requestedPaths).toContain("/grc/framework-settings?tenant_id=acme");
    expect(requestedPaths).toContain("/grc/findings?tenant_id=acme&framework=SOC+2&status=open&limit=200");
    expect(container.querySelector('a[href="/frameworks/soc-2?tenant_id=acme&control=CC6.1"]')).not.toBeNull();
  });

  it("saves the tenant framework selection and offers only active frameworks", async () => {
    mocks.mutate.mockResolvedValue({});
    act(() => root.render(createElement(CompliancePage)));

    const manage = [...container.querySelectorAll("button")].find((button) => button.textContent === "Manage frameworks");
    act(() => manage?.click());

    const labels = [...container.querySelectorAll("label")].map((label) => label.textContent ?? "");
    expect(labels.some((label) => label.includes("CSA CCM v4.0"))).toBe(false);
    const iso = [...container.querySelectorAll("label")].find((label) => label.textContent?.includes("ISO 27001:2022"));
    act(() => (iso?.querySelector("input") as HTMLInputElement).click());

    const save = [...container.querySelectorAll("button")].find((button) => button.textContent?.startsWith("Save"));
    await act(async () => save?.click());

    expect(mocks.mutate).toHaveBeenCalledWith(
      "/grc/framework-settings",
      { tenant_id: "acme", enabled_frameworks: ["SOC 2", "ISO 27001:2022"] },
      "PUT",
    );
  });
});
