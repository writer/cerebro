import { describe, expect, it, vi } from "vitest";

import { fetchSecurityProducers } from "./security-producers-client";

const jsonResponse = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });

describe("security producer catalog client", () => {
  it("fetches each runtime catalog response without caching a prior value", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(jsonResponse({
        producers: [{ id: "producer-one", label: "First value" }],
      }))
      .mockResolvedValueOnce(jsonResponse({
        producers: [{ id: "producer-two", label: "Second value" }],
      }));

    await expect(fetchSecurityProducers({ fetcher })).resolves.toEqual([
      expect.objectContaining({ id: "producer-one", label: "First value" }),
    ]);
    await expect(fetchSecurityProducers({ fetcher })).resolves.toEqual([
      expect.objectContaining({ id: "producer-two", label: "Second value" }),
    ]);
    expect(fetcher).toHaveBeenNthCalledWith(1, "/api/security-producers", {
      cache: "no-store",
      signal: undefined,
    });
  });

  it("re-sanitizes the route payload before returning it", async () => {
    const fetcher = vi.fn().mockResolvedValue(jsonResponse({
      producers: [{ id: "producer-one", label: "Producer One", extra: "not-portable" }],
      extra: "not-portable",
    }));

    const producers = await fetchSecurityProducers({ fetcher });

    expect(producers).toEqual([expect.objectContaining({ id: "producer-one" })]);
    expect(JSON.stringify(producers)).not.toContain("not-portable");
  });

  it("fails closed for unsuccessful, invalid, or unavailable responses", async () => {
    await expect(fetchSecurityProducers({
      fetcher: vi.fn().mockResolvedValue(jsonResponse({ error: "unavailable" }, 503)),
    })).resolves.toEqual([]);
    await expect(fetchSecurityProducers({
      fetcher: vi.fn().mockResolvedValue(new Response("not-json")),
    })).resolves.toEqual([]);
    await expect(fetchSecurityProducers({
      fetcher: vi.fn().mockRejectedValue(new Error("unavailable")),
    })).resolves.toEqual([]);
  });
});
