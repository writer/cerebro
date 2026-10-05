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

  it("leads the inventory section with the asset register itself", () => {
    const inventoryGroup = sidebarNavGroups.find((group) => group.id === "inventory");
    const hrefs = inventoryGroup?.links.map((link) => link.href);

    expect(inventoryGroup?.label).toBe("Inventory");
    expect(inventoryGroup?.href).toBe("/inventory");
    expect(hrefs).toEqual([
      "/explore",
      "/impact",
      "/ask",
      "/identity",
      "/security/lifecycle",
    ]);
  });

  it("gathers every governance record under Compliance", () => {
    const complianceGroup = sidebarNavGroups.find((group) => group.id === "compliance");

    expect(complianceGroup?.label).toBe("Compliance");
    expect(complianceGroup?.links.map((link) => link.href)).toEqual([
      "/controls",
      "/evidence",
      "/frameworks",
      "/policies",
      "/questionnaires",
      "/vendors",
      "/reports",
      "/reports/audit-packages",
    ]);
  });

  it("leads with daily work rather than governance records", () => {
    expect(sidebarPrimaryLinks.map((link) => link.href)).toEqual([
      "/",
      "/risk-inbox",
      "/actions",
    ]);
    expect(sidebarSupportLinks.map((link) => link.href)).toEqual(["/connectors"]);
  });

  it("never shows a report child without its parent", () => {
    const hrefs = sidebarNavLinks.map((link) => link.href);

    expect(hrefs).toContain("/reports/audit-packages");
    expect(hrefs).toContain("/reports");
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

  it("expands admin into the settings an administrator changes", () => {
    expect(adminGroup?.href).toBe("/admin");
    expect(adminGroup?.links.map((link) => link.href)).toEqual([
      "/admin/access-control",
      "/credential-stores",
      "/developer/audit-log",
      "/developer",
    ]);
  });

  it("keeps ingested directory data out of admin settings", () => {
    const inventory = sidebarNavGroups.find((group) => group.id === "inventory");

    expect(adminGroup?.links.map((link) => link.href)).not.toContain("/identity");
    expect(inventory?.links.map((link) => link.href)).toContain("/identity");
  });

  it("reuses the existing entry for a page rather than declaring a second one", () => {
    const duplicated = navigationEntries.filter((entry) => entry.href === "/credential-stores");
    expect(duplicated).toHaveLength(1);
    expect(adminGroup?.links).toContain(duplicated[0]);
  });

  it("keeps credential stores out of Inventory now that Admin owns it", () => {
    const inventory = sidebarNavGroups.find((group) => group.id === "inventory");
    expect(inventory?.links.map((link) => link.href)).not.toContain("/credential-stores");
  });

  it("does not render a grouped page twice in the utility list", () => {
    const utilityHrefs = sidebarUtilityLinks.map((link) => link.href);
    expect(utilityHrefs).not.toContain("/admin");
    expect(utilityHrefs).not.toContain("/admin/access-control");
    expect(utilityHrefs).not.toContain("/developer");
  });

  it("keeps the parent inactive when a child page owns the route", () => {
    expect(isSidebarLinkActive("/admin/access-control", "/admin")).toBe(false);
    expect(isSidebarLinkActive("/admin/access-control", "/admin/access-control")).toBe(true);
    expect(isSidebarLinkActive("/admin", "/admin")).toBe(true);
  });
});
