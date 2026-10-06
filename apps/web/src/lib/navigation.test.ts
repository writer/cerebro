import { describe, expect, it } from "vitest";

import { MINOR_TITLE_WORDS, navigationEntries, normalizeLegacyControlHref, operatorNavLinks, utilityLinks } from "./navigation";

describe("navigation entries", () => {
  it("has unique hrefs across all entries", () => {
    const hrefs = navigationEntries.map((e) => e.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
  });

  it("has unique labels across all entries", () => {
    const labels = navigationEntries.map((e) => e.label);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("keeps every label in title case", () => {
    for (const entry of navigationEntries) {
      for (const [index, word] of entry.label.split(" ").entries()) {
        if (!/^[A-Za-z]/.test(word)) continue;
        if (index > 0 && MINOR_TITLE_WORDS.has(word.toLowerCase())) {
          expect(word, `"${entry.label}" should not capitalise "${word}"`).toBe(word.toLowerCase());
          continue;
        }
        expect(word.slice(0, 1), `"${entry.label}" should capitalise "${word}"`).toBe(word.slice(0, 1).toUpperCase());
      }
    }
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
    expect(hrefs).toContain("/verified-findings");
    expect(hrefs).toContain("/grc");
    expect(hrefs).toContain("/ask");
    expect(hrefs).toContain("/controls");
    expect(hrefs).toContain("/connectors");
    expect(hrefs).toContain("/credential-stores");
  });

  it("uses operator labels for risks, actions, and compliance", () => {
    // The sidebar label has to match the page heading and the pinned
    // information area, which are both "Risks".
    expect(operatorNavLinks.find((entry) => entry.href === "/risk-inbox")).toMatchObject({
      label: "Risks",
    });
    expect(operatorNavLinks.find((entry) => entry.href === "/grc")).toMatchObject({
      label: "Compliance",
    });
    expect(operatorNavLinks.find((entry) => entry.href === "/verified-findings")).toMatchObject({
      label: "Verified Findings",
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

  it("normalizes only the legacy internal control route", () => {
    expect(normalizeLegacyControlHref("/grc/controls?framework=SOC%202&control=CC6.6")).toBe(
      "/controls?framework=SOC%202&control=CC6.6",
    );
    expect(normalizeLegacyControlHref("/grc/controls")).toBe("/controls");
    expect(normalizeLegacyControlHref("/grc/controls/export?format=csv")).toBe("/grc/controls/export?format=csv");
    expect(normalizeLegacyControlHref("/api/grc/controls?framework=SOC%202")).toBe("/api/grc/controls?framework=SOC%202");
  });
});
