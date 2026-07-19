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

    await expect(fetchSecurityProducers({ fetcher })).resolves.toEqual({
      state: "ready",
      producers: [expect.objectContaining({ id: "producer-one", label: "First value" })],
    });
    await expect(fetchSecurityProducers({ fetcher })).resolves.toEqual({
      state: "ready",
      producers: [expect.objectContaining({ id: "producer-two", label: "Second value" })],
    });
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

    const result = await fetchSecurityProducers({ fetcher });

    expect(result).toEqual({
      state: "ready",
      producers: [expect.objectContaining({ id: "producer-one" })],
    });
    expect(JSON.stringify(result)).not.toContain("not-portable");
  });

  it("represents a successful empty catalog as ready", async () => {
    await expect(fetchSecurityProducers({
      fetcher: vi.fn().mockResolvedValue(jsonResponse({ producers: [] })),
    })).resolves.toEqual({ state: "ready", producers: [] });
  });

  it("keeps access, service, network, and payload failures distinct from configured-empty", async () => {
    for (const fetcher of [
      vi.fn().mockResolvedValue(jsonResponse({ error: "unauthorized-marker" }, 401)),
      vi.fn().mockResolvedValue(jsonResponse({ error: "forbidden-marker" }, 403)),
      vi.fn().mockResolvedValue(jsonResponse({ error: "service-marker" }, 503)),
      vi.fn().mockResolvedValue(new Response("invalid-json-marker")),
      vi.fn().mockResolvedValue(jsonResponse({ producers: "invalid-envelope-marker" })),
      vi.fn().mockResolvedValue(jsonResponse({ producers: [{ id: "", label: "invalid-record-marker" }] })),
      vi.fn().mockRejectedValue(new Error("network-marker")),
    ]) {
      const result = await fetchSecurityProducers({ fetcher });
      expect(result).toEqual({ state: "unavailable" });
      expect(JSON.stringify(result)).not.toMatch(/marker/);
    }
  });
});
