import { describe, expect, it } from "vitest";

import { navigationEntries, operatorNavLinks } from "@/lib/navigation";

import { hasSidebarIcon, isSidebarLinkActive, sidebarNavGroups, sidebarNavLinks, sidebarPrimaryLinks, sidebarSupportLinks, sidebarUtilityGroups, sidebarUtilityLinks } from "./Sidebar";

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
      "/actions",
      "/inventory",
      "/impact",
      "/explore",
      "/ask",
      "/security/lifecycle",
    ]);
  });

  it("keeps specialist compliance records available without leading with them", () => {
    const complianceGroup = sidebarNavGroups.find((group) => group.id === "compliance");

    expect(complianceGroup?.label).toBe("Compliance");
    expect(complianceGroup?.links.map((link) => link.href)).toEqual([
      "/controls",
      "/evidence",
      "/questionnaires",
    ]);
  });

  it("leads with the compliance jobs customers use every week", () => {
    expect(sidebarPrimaryLinks.map((link) => link.href)).toEqual([
      "/",
      "/risk-inbox",
      "/frameworks",
      "/policies",
      "/vendors",
      "/connectors",
      "/reports/audit-packages",
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

describe("admin sub-tree", () => {
  const adminGroup = sidebarUtilityGroups.find((group) => group.id === "admin");

  it("expands admin into the pages an administrator manages", () => {
    expect(adminGroup?.href).toBe("/admin");
    expect(adminGroup?.links.map((link) => link.href)).toEqual([
      "/admin/access-control",
      "/identity",
      "/credential-stores",
    ]);
  });

  it("reuses the existing entry for a page rather than declaring a second one", () => {
    const duplicated = navigationEntries.filter((entry) => entry.href === "/credential-stores");
    expect(duplicated).toHaveLength(1);
    expect(adminGroup?.links).toContain(duplicated[0]);
  });

  it("keeps credential stores out of Advanced now that Admin owns it", () => {
    const advanced = sidebarNavGroups.find((group) => group.id === "advanced");
    expect(advanced?.links.map((link) => link.href)).not.toContain("/credential-stores");
  });

  it("does not render a grouped page twice in the utility list", () => {
    const utilityHrefs = sidebarUtilityLinks.map((link) => link.href);
    expect(utilityHrefs).not.toContain("/admin");
    expect(utilityHrefs).not.toContain("/admin/access-control");
    expect(utilityHrefs).toContain("/developer");
  });

  it("keeps the parent inactive when a child page owns the route", () => {
    expect(isSidebarLinkActive("/admin/access-control", "/admin")).toBe(false);
    expect(isSidebarLinkActive("/admin/access-control", "/admin/access-control")).toBe(true);
    expect(isSidebarLinkActive("/admin", "/admin")).toBe(true);
  });
});
