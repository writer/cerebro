import { describe, expect, it } from "vitest";

import { navigationEntries, operatorNavLinks, utilityLinks } from "./navigation";

describe("navigation entries", () => {
  it("has unique hrefs across all entries", () => {
    const hrefs = navigationEntries.map((e) => e.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
  });

  it("has unique labels across all entries", () => {
    const labels = navigationEntries.map((e) => e.label);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("all entries have non-empty keywords", () => {
    for (const entry of navigationEntries) {
      expect(entry.keywords.length, `${entry.label} should have keywords`).toBeGreaterThan(0);
    }
  });

  it("includes expected core operator pages", () => {
    const hrefs = operatorNavLinks.map((e) => e.href);
    expect(hrefs).toContain("/");
    expect(hrefs).toContain("/risk-inbox");
    expect(hrefs).toContain("/grc");
    expect(hrefs).toContain("/ask");
    expect(hrefs).toContain("/controls");
    expect(hrefs).toContain("/connectors");
    expect(hrefs).toContain("/credential-stores");
  });

  it("uses operator labels for issues and compliance", () => {
    expect(operatorNavLinks.find((entry) => entry.href === "/risk-inbox")).toMatchObject({
      label: "Issues",
    });
    expect(operatorNavLinks.find((entry) => entry.href === "/grc")).toMatchObject({
      label: "Compliance",
    });
  });

  it("keeps members discoverable outside the sidebar", () => {
    expect(navigationEntries.find((entry) => entry.href === "/identity")).toMatchObject({
      label: "Members",
      section: "Advanced",
    });
  });

  it("includes developer tools in utility links", () => {
    const hrefs = utilityLinks.map((e) => e.href);
    expect(hrefs).toContain("/developer");
  });
});
