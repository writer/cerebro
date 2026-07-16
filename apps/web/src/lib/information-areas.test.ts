import { describe, expect, it } from "vitest";

import { DEFAULT_INFORMATION_AREA_ID, informationAreas, routeHrefsForArea, routeIsAvailable } from "./information-areas";

const pathOnly = (href: string) => href.split("?")[0];

describe("information areas", () => {
  it("has unique IDs and labels", () => {
    const ids = informationAreas.map((area) => area.id);
    const labels = informationAreas.map((area) => area.label);

    expect(new Set(ids).size).toBe(ids.length);
    expect(new Set(labels).size).toBe(labels.length);
    expect(ids).toContain(DEFAULT_INFORMATION_AREA_ID);
  });

  it("points every area route at a known navigation entry", () => {
    for (const area of informationAreas) {
      const hrefs = routeHrefsForArea(area);
      expect(hrefs.length, `${area.label} should expose routes`).toBeGreaterThan(0);
      expect(new Set(hrefs).size, `${area.label} should not duplicate routes`).toBe(hrefs.length);
      for (const href of hrefs) {
        expect(routeIsAvailable(href), `${area.label} references ${href}`).toBe(true);
      }
    }
  });

  it("enriches each area with summary signals and work queues", () => {
    for (const area of informationAreas) {
      expect(area.headline, `${area.label} should have a headline`).toBeTruthy();
      expect(area.label, `${area.label} should use a concrete information area`).toMatch(/^(Risks|Controls|Sources|Review)$/);
      expect(area.summaryFocus.length, `${area.label} should explain its summary focus`).toBeGreaterThanOrEqual(3);
      expect(area.signals.length, `${area.label} should expose prioritized signals`).toBe(6);
      expect(new Set(area.signals.map((signal) => signal.key)).size, `${area.label} should not duplicate signals`).toBe(area.signals.length);
      expect(area.workQueue.title, `${area.label} should name its work queue`).toBeTruthy();
      expect(area.workQueue.actionHref, `${area.label} should link to its primary queue surface`).toBeTruthy();

      for (const signal of area.signals) {
        expect(routeIsAvailable(pathOnly(signal.href)), `${area.label} signal ${signal.label} references ${signal.href}`).toBe(true);
      }
      expect(routeIsAvailable(pathOnly(area.workQueue.actionHref)), `${area.label} queue action references ${area.workQueue.actionHref}`).toBe(true);
    }
  });

  it("keeps first-read operator routes reachable through at least one area", () => {
    const assignedRoutes = new Set(informationAreas.flatMap(routeHrefsForArea));
    const coreRoutes = ["/", "/risk-inbox", "/grc", "/controls", "/evidence", "/connectors", "/reports"];

    for (const href of coreRoutes) {
      expect(assignedRoutes.has(href), `${href} should belong to at least one information area`).toBe(true);
    }
  });

  it("separates the first-read routes by information priority", () => {
    const byID = Object.fromEntries(informationAreas.map((area) => [area.id, area]));

    expect(byID.risks.primaryRoutes.map((route) => route.href)).toEqual(
      expect.arrayContaining(["/risk-inbox", "/impact", "/ask"]),
    );
    expect(byID.controls.primaryRoutes.map((route) => route.href)).toEqual(
      expect.arrayContaining(["/controls", "/frameworks", "/evidence", "/reports"]),
    );
    expect(byID.sources.primaryRoutes.map((route) => route.href)).toEqual(
      expect.arrayContaining(["/connectors", "/inventory", "/explore"]),
    );
    expect(byID.reports.primaryRoutes.map((route) => route.href)).toEqual(
      expect.arrayContaining(["/trends", "/trends/dashboards", "/reports"]),
    );
  });
});
