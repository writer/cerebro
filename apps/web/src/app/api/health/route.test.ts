import { describe, expect, it } from "vitest";

import { GET } from "./route";

describe("web health", () => {
  it("returns generic readiness without identity configuration", async () => {
    const response = await GET();
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(payload).toMatchObject({ status: "ready" });
    expect(payload).not.toHaveProperty("identity");
    expect(JSON.stringify(payload)).not.toMatch(/trustedHeaders|jwks|issuer|audience/i);
  });
});
