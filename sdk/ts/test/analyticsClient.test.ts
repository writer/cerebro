import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import { AnalyticsClient } from "../src/clients/analytics";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error assign test double
  globalThis.fetch = fetchMock;
});

describe("AnalyticsClient", () => {
  it("transforms runtime health payloads", async () => {
    const generatedAt = new Date().toISOString();
    const windowStart = new Date().toISOString();
    const windowEnd = new Date(Date.now() + 1000).toISOString();
    const lastSeen = new Date().toISOString();

    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        window_hours: 6,
        generated_at: generatedAt,
        runtimes: [
          {
            runtime: "bedrock",
            window_start: windowStart,
            window_end: windowEnd,
            events: {
              runtime_warning: {
                count: 3,
                last_seen: lastSeen,
              },
            },
            warnings: {},
            latest_metadata: {
              payload: { region: "us-east-1" },
              captured_at: lastSeen,
            },
          },
        ],
      }),
    });

    const http = new HttpClient({ baseUrl: "https://api.example.com" });
    const analytics = new AnalyticsClient(http);

    const summary = await analytics.getRuntimeHealth(6);

    expect(summary.windowHours).toBe(6);
    expect(summary.generatedAt).toBeInstanceOf(Date);
    expect(summary.runtimes).toHaveLength(1);
    const record = summary.runtimes[0];
    expect(record.runtime).toBe("bedrock");
    expect(record.events.runtime_warning.lastSeen).toBeInstanceOf(Date);
    expect(record.latestMetadata?.payload.region).toBe("us-east-1");

    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("hours=6");
  });
});
