import { beforeEach, describe, expect, it, vi } from "vitest";

import { IntegrationsClient } from "../../src/clients/integrations";
import HttpClient from "../../src/httpClient";
import type { components } from "../../src/generated/openapi";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
});

describe("IntegrationsClient contract", () => {
  it("maps coverage responses defined in OpenAPI", async () => {
    const coverage: components["schemas"]["IntegrationCoverageSummary"] = {
      integration: "sentinelone",
      providers: ["sentinelone"],
      status: "healthy",
      scopes: {
        total: 10,
        healthy: 9,
        warning: 1,
        critical: 0,
      },
      accounts: {
        total: 3,
      },
      coverage_ratio: 0.9,
      last_success: new Date().toISOString(),
      evaluated_at: new Date().toISOString(),
    };

    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => [coverage],
    });

    const client = new IntegrationsClient(new HttpClient({ baseUrl: "https://api.example.com", fetch: fetchMock }));
    const result = await client.getCoverage();

    expect(result).toHaveLength(1);
    expect(result[0].integration).toBe("sentinelone");
    expect(result[0].lastSuccess).toBeInstanceOf(Date);
    expect(result[0].scopes.total).toBe(10);
  });
});
