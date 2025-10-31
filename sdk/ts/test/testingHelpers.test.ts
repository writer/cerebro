import { describe, expect, it } from "vitest";

import {
  StubIntegrationCoverageClient,
  StubRuntimeHealthClient,
  buildIntegrationCoverageRecord,
  buildRuntimeHealthRecord,
} from "../src/testing";

describe("testing helpers", () => {
  it("builds runtime health records", async () => {
    const record = buildRuntimeHealthRecord("runtime-a", {
      windowStart: new Date("2024-01-01T00:00:00Z"),
      windowEnd: new Date("2024-01-01T01:00:00Z"),
    });

    const client = new StubRuntimeHealthClient([record], 1, new Date("2024-01-01T01:00:00Z"));
    const summary = await client.getRuntimeHealth();

    expect(summary.runtimes[0].runtime).toBe("runtime-a");
  });

  it("builds integration coverage records", async () => {
    const record = buildIntegrationCoverageRecord({
      integration: "salesforce",
      providers: ["salesforce"],
      status: "healthy",
      scopes: { total: 1, healthy: 1, warning: 0, critical: 0 },
      accounts: { total: 1 },
      coverageRatio: 1,
      lastSuccess: new Date("2024-01-01T00:00:00Z"),
      evaluatedAt: new Date("2024-01-01T00:00:00Z"),
    });

    const client = new StubIntegrationCoverageClient([record]);
    const coverage = await client.getCoverage();

    expect(coverage).toHaveLength(1);
    expect(coverage[0].integration).toBe("salesforce");
  });
});
