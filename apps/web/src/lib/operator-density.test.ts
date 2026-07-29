import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const readProjectFile = (...parts: string[]) => readFileSync(join(process.cwd(), ...parts), "utf8");

describe("operator density", () => {
  it("keeps inventory work ahead of secondary analytics", () => {
    const inventorySource = readProjectFile("src/app/inventory/page.tsx");

    expect(inventorySource).toContain("aria-expanded={filtersOpen}");
    expect(inventorySource).toContain("inventoryNarrowingFilterCount");
    expect(inventorySource).toContain('className="hidden xl:block"');
    expect(inventorySource).toContain("secondaryAssetID");
    expect(inventorySource).not.toContain("ReviewQueuePanel");
    expect(inventorySource).not.toContain("Review posture");
    expect(inventorySource).not.toContain("Org parity");
  });

  it("does not repeat generated guidance on asset detail", () => {
    const inventoryDetailSource = readProjectFile("src/app/inventory/[urn]/page.tsx");

    expect(inventoryDetailSource).toContain(">Posture</h2>");
    expect(inventoryDetailSource).not.toContain("Generated summary");
    expect(inventoryDetailSource).not.toContain("Next best actions");
    expect(inventoryDetailSource).not.toContain("Recommendation</div>");
  });

  it("keeps finding actions collapsed and tabs reachable on mobile", () => {
    const findingDetailSource = readProjectFile("src/app/findings/[id]/page.tsx");
    const homeSource = readProjectFile("src/app/page.tsx");
    const reportsSource = readProjectFile("src/app/reports/page.tsx");

    expect(findingDetailSource).toContain("<details");
    expect(findingDetailSource).toContain("Update finding");
    expect(findingDetailSource).toContain("/audit-preview");
    expect(findingDetailSource).not.toContain("grcPath(`/grc/audit-packets/");
    expect(homeSource).not.toContain("prefetchTopFindings");
    expect(homeSource).not.toContain("grc-prefetch");
    expect(reportsSource).toContain("/audit-preview");
    expect(reportsSource).not.toContain("/grc/audit-packets/${encodeURIComponent(selectedFindingID)}");
    expect(reportsSource).toContain('const exportHref = reportMode === "control"');
    expect(reportsSource).toContain('label="Finding preview"');
    expect(reportsSource).toContain("This preview reflects current finding evidence");
    expect(reportsSource).not.toContain('label="Finding packet"');
    expect(findingDetailSource).toContain("grid grid-cols-2 gap-3");
    expect(findingDetailSource).toContain("overflow-x-auto border-b");
    expect(findingDetailSource).not.toContain("RiskBreakdown");
    expect(findingDetailSource).not.toContain('MetricCard label="Severity"');
  });
});
