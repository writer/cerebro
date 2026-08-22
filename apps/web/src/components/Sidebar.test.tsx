import { describe, expect, it } from "vitest";

import { operatorNavLinks } from "@/lib/navigation";

import { hasSidebarIcon, isSidebarLinkActive, sidebarNavGroups, sidebarNavLinks, sidebarPrimaryLinks, sidebarSupportLinks } from "./Sidebar";

const links = [
  { href: "/trends" },
  { href: "/trends/dashboards" },
  { href: "/developer" },
];

describe("isSidebarLinkActive", () => {
  it("prefers the most specific visible sidebar route", () => {
    expect(isSidebarLinkActive("/trends/dashboards", "/trends", links)).toBe(false);
    expect(isSidebarLinkActive("/trends/dashboards", "/trends/dashboards", links)).toBe(true);
  });

  it("keeps parent routes active for unmatched child paths", () => {
    expect(isSidebarLinkActive("/trends/unknown", "/trends", links)).toBe(true);
  });

  it("prefers the child route for deeper child paths", () => {
    expect(isSidebarLinkActive("/trends/dashboards/example", "/trends", links)).toBe(false);
    expect(isSidebarLinkActive("/trends/dashboards/example", "/trends/dashboards", links)).toBe(true);
  });

  it("has icons for visible sidebar routes", () => {
    const missingIcons = sidebarNavLinks
      .filter((link) => !hasSidebarIcon(link.href))
      .map((link) => link.href);

    expect(missingIcons).toEqual([]);
  });

  it("keeps platform machinery behind Advanced", () => {
    const advancedGroup = sidebarNavGroups.find((group) => group.id === "advanced");
    const hrefs = advancedGroup?.links.map((link) => link.href);

    expect(advancedGroup?.label).toBe("Advanced");
    expect(advancedGroup?.href).toBeUndefined();
    expect(hrefs).toEqual([
      "/risk-inbox",
      "/actions",
      "/inventory",
      "/impact",
      "/explore",
      "/ask",
      "/security/lifecycle",
      "/credential-stores",
    ]);
  });

  it("leads with the compliance jobs customers use every week", () => {
    expect(sidebarPrimaryLinks.map((link) => link.href)).toEqual([
      "/",
      "/frameworks",
      "/evidence",
      "/controls",
      "/policies",
      "/vendors",
      "/questionnaires",
      "/reports/audit-packages",
      "/connectors",
    ]);
    expect(sidebarSupportLinks).toEqual([]);
  });

  it("keeps trend pages outside the visible sidebar", () => {
    const sidebarHrefs = sidebarNavLinks.map((link) => link.href);
    const operatorHrefs = operatorNavLinks.map((link) => link.href);

    expect(operatorHrefs).toContain("/trends");
    expect(operatorHrefs).toContain("/trends/dashboards");
    expect(sidebarHrefs).not.toContain("/trends");
    expect(sidebarHrefs).not.toContain("/trends/dashboards");
  });
});
