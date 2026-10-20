import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { grcBrowserRouteContracts } from "./grc-route-contract.mjs";

const pageSourcesByRoute = {
  "/": "src/app/page.tsx",
  "/risks": "src/app/risks/page.tsx",
  "/grc": "src/app/grc/page.tsx",
  "/connectors": "src/app/connectors/page.tsx",
  "/explore": "src/app/explore/page.tsx",
  "/reports": "src/app/reports/page.tsx",
};

describe("GRC browser route contract", () => {
  it("provides stable page ids for each browser-validated route", () => {
    const contracts = grcBrowserRouteContracts({ adminURN: "urn:cerebro:e2e-tenant:identity:admin" });
    expect(contracts.map((contract) => contract.route)).toEqual([
      "/",
      "/risks",
      "/grc",
      "/connectors",
      "/explore?root_urn=urn%3Acerebro%3Ae2e-tenant%3Aidentity%3Aadmin",
      "/reports",
    ]);
    expect(contracts.map((contract) => contract.pageId)).toEqual([
      "overview",
      "risks",
      "grc",
      "connectors",
      "graph-explorer",
      "reports",
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

  // The browser run matches these headings exactly, so a page rename must fail here first.
  it("matches the PageHeader titles the browser run waits for", () => {
    const contracts = grcBrowserRouteContracts({ adminURN: "urn:cerebro:e2e-tenant:identity:admin" });
    for (const contract of contracts) {
      const sourcePath = pageSourcesByRoute[contract.route.split("?")[0]];
      const source = readFileSync(new URL(`../${sourcePath}`, import.meta.url), "utf8");
      // title may sit either side of contractId, so read the enclosing PageHeader tag.
      const at = source.indexOf(`contractId="${contract.pageId}"`);
      const open = source.lastIndexOf("<PageHeader", at);
      const header = source.slice(open, source.indexOf("/>", at));
      const title = /title=\{?"([^"]+)"/.exec(header)?.[1];
      expect(title, `${contract.route} renders a different heading than the contract`).toBe(contract.heading);
    }
  });
});
