import { beforeEach, describe, expect, it, vi } from "vitest";

const upstream = vi.hoisted(() => ({
  requests: [] as { url: URL; init: RequestInit }[],
  status: 200,
  body: "{}",
}));

vi.mock("@/lib/cerebro-proxy", () => ({
  buildCerebroUrl: (path: string, search = "") => {
    const url = new URL(`https://api.example.com/${path}`);
    url.search = search;
    return url;
  },
  fetchCerebro: vi.fn(async (url: URL, init: RequestInit) => {
    upstream.requests.push({ url, init });
    return new Response(upstream.body, { status: upstream.status, headers: { "content-type": "application/json" } });
  }),
  serviceAuthHeaders: () => ({ "X-Cerebro-API-Key": "service-key" }),
}));

vi.mock("@/lib/fixture-mode", () => ({ isCerebroFixtureMode: () => false }));

const { AssertionReplayedError, consumeSamlAssertion, IdentityApiError, identityApiRequest, upsertJitDirectoryUser } =
  await import("./identity-api");

beforeEach(() => {
  upstream.requests = [];
  upstream.status = 200;
  upstream.body = "{}";
});

const headerOf = (index: number, name: string) => new Headers(upstream.requests[index].init.headers).get(name);

describe("partition selectors", () => {
  it("never forwards a browser-supplied tenant_id or X-Cerebro-Tenant", async () => {
    await identityApiRequest("GET", "sso/connections", { search: "?tenant_id=other&limit=5", headers: { "X-Cerebro-Tenant": "other" } });
    await identityApiRequest("GET", "scim/v2/Users", { search: "?tenant_id=other", headers: { "X-Cerebro-Tenant": "other", "X-Cerebro-SCIM-Token": "t" } });
    expect(upstream.requests).toHaveLength(2);
    for (let index = 0; index < 2; index += 1) {
      expect(upstream.requests[index].url.searchParams.has("tenant_id")).toBe(false);
      expect(headerOf(index, "x-cerebro-tenant")).toBeNull();
    }
    expect(upstream.requests[0].url.searchParams.get("limit")).toBe("5");
  });
});

describe("identity API errors", () => {
  it("exposes the Go error code", async () => {
    upstream.status = 409;
    upstream.body = JSON.stringify({ code: "subject_mismatch" });
    const error = await upsertJitDirectoryUser({ connectionId: "c", subject: "s", email: "a@example.com", name: "A", groups: [] }).catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(IdentityApiError);
    expect(error).toMatchObject({ status: 409, code: "subject_mismatch" });
  });
});

describe("consumeSamlAssertion", () => {
  const input = { connectionId: "c", assertionId: "_a", requestId: "_r", notOnOrAfter: "2030-01-01T00:00:00.000Z" };

  it("posts the assertion to the replay cache", async () => {
    upstream.status = 201;
    upstream.body = JSON.stringify({ consumed: true });
    await consumeSamlAssertion(input);
    expect(upstream.requests[0].url.pathname).toBe("/platform/identity/saml/assertions");
    expect(upstream.requests[0].init.method).toBe("POST");
    expect(JSON.parse(String(upstream.requests[0].init.body))).toEqual(input);
  });

  it("reports a replay as AssertionReplayedError and other failures as IdentityApiError", async () => {
    upstream.status = 409;
    upstream.body = JSON.stringify({ code: "assertion_replayed" });
    await expect(consumeSamlAssertion(input)).rejects.toBeInstanceOf(AssertionReplayedError);
    upstream.status = 400;
    await expect(consumeSamlAssertion(input)).rejects.toBeInstanceOf(IdentityApiError);
    upstream.status = 409;
    upstream.body = JSON.stringify({ code: "something_else" });
    await expect(consumeSamlAssertion(input)).rejects.not.toBeInstanceOf(AssertionReplayedError);
  });
});
