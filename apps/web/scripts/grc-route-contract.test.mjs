import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { grcBrowserRouteContracts } from "./grc-route-contract.mjs";

const pageSourcesByRoute = {
  "/": "src/app/page.tsx",
  "/risk-inbox": "src/app/risk-inbox/page.tsx",
  "/controls": "src/app/controls/page.tsx",
  "/policies": "src/app/policies/page.tsx",
  "/frameworks": "src/app/frameworks/page.tsx",
  "/controls/builder": "src/app/controls/builder/page.tsx",
  "/evidence": "src/app/evidence/page.tsx",
  "/questionnaires": "src/app/questionnaires/page.tsx",
  "/vendors": "src/app/vendors/page.tsx",
  "/connectors": "src/app/connectors/page.tsx",
  "/impact": "src/app/impact/page.tsx",
  "/reports": "src/app/reports/page.tsx",
  "/reports/audit-packages": "src/app/reports/audit-packages/page.tsx",
};

describe("GRC browser route contract", () => {
  it("provides stable page ids for each browser-validated route", () => {
    const contracts = grcBrowserRouteContracts({ adminURN: "urn:cerebro:e2e-tenant:identity:admin" });
    expect(contracts.map((contract) => contract.route)).toEqual([
      "/",
      "/risk-inbox",
      "/controls",
      "/policies",
      "/frameworks",
      "/controls/builder",
      "/evidence",
      "/questionnaires",
      "/vendors",
      "/connectors",
      "/impact?root_urn=urn%3Acerebro%3Ae2e-tenant%3Aidentity%3Aadmin",
      "/reports",
      "/reports/audit-packages",
    ]);
    expect(contracts.map((contract) => contract.pageId)).toEqual([
      "overview",
      "risk-inbox",
      "controls",
      "policies",
      "frameworks",
      "control-builder",
      "evidence",
      "questionnaires",
      "vendors",
      "connectors",
      "impact-map",
      "reports",
      "audit-packages",
    ]);
    expect(new Set(contracts.map((contract) => contract.pageId)).size).toBe(contracts.length);
  });

  it("keeps volatile page copy out of the route contract", () => {
    const serialized = JSON.stringify(grcBrowserRouteContracts({ adminURN: "urn:cerebro:e2e-tenant:identity:admin" }));
    expect(serialized).not.toMatch(/Security posture|Open findings|Priority Findings|Needs attention/);
  });

  it("matches the PageHeader contract ids used by the covered pages", () => {
    const contracts = grcBrowserRouteContracts({ adminURN: "urn:cerebro:e2e-tenant:identity:admin" });
    for (const contract of contracts) {
      const sourcePath = pageSourcesByRoute[contract.route.split("?")[0]];
      const source = readFileSync(new URL(`../${sourcePath}`, import.meta.url), "utf8");
      expect(source).toContain(`contractId="${contract.pageId}"`);
    }
  });
});
