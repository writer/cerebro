import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import { IntegrationsClient } from "../src/clients/integrations";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error assign test double
  globalThis.fetch = fetchMock;
});

describe("IntegrationsClient", () => {
  it("maps integration coverage responses", async () => {
    const evaluatedAt = new Date().toISOString();
    const lastSuccess = new Date(Date.now() - 60000).toISOString();
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          integration: "kandji",
          providers: ["kandji"],
          status: "healthy",
          scopes: {
            total: 2,
            healthy: 2,
            warning: 0,
            critical: 0,
          },
          accounts: { total: 1 },
          coverage_ratio: 1.0,
          last_success: lastSuccess,
          evaluated_at: evaluatedAt,
        },
      ]),
    });

    const client = new IntegrationsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const records = await client.getCoverage({ staleSeconds: 900 });

    expect(records).toHaveLength(1);
    const record = records[0];
    expect(record.integration).toBe("kandji");
    expect(record.coverageRatio).toBe(1.0);
    expect(record.lastSuccess).toBeInstanceOf(Date);

    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("stale_seconds=900");
  });
});
