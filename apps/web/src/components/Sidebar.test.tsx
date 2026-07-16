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

  it("groups core compliance routes under Compliance", () => {
    const grcGroup = sidebarNavGroups.find((group) => group.id === "grc");
    const hrefs = grcGroup?.links.map((link) => link.href);

    expect(grcGroup?.label).toBe("Compliance");
    expect(grcGroup?.href).toBe("/grc");
    expect(hrefs).toEqual([
      "/controls",
      "/evidence",
      "/frameworks",
      "/reports",
    ]);
  });

  it("keeps issues, Compliance, and Ask in the visible sidebar", () => {
    const sidebarHrefs = sidebarNavLinks.map((link) => link.href);

    expect(sidebarPrimaryLinks.map((link) => link.href)).toEqual(["/", "/risk-inbox"]);
    expect(sidebarHrefs).toContain("/grc");
    expect(sidebarSupportLinks.map((link) => link.href)).toEqual(["/ask"]);
    expect(hasSidebarIcon("/grc")).toBe(true);
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
