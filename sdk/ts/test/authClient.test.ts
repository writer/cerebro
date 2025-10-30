import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import { AuthClient } from "../src/clients/auth";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error assign test double
  globalThis.fetch = fetchMock;
});

describe("AuthClient", () => {
  it("logs in with JSON credentials", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        access_token: "access",
        refresh_token: "refresh",
        token_type: "bearer",
        access_token_expires_in: 3600,
        refresh_token_expires_in: 7200,
        csrf_token: "csrf",
      }),
    });

    const client = new AuthClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const token = await client.login({ username: "user", password: "pass" });

    expect(token.accessToken).toBe("access");
    expect(token.refreshTokenExpiresIn).toBe(7200);

    const [, init] = fetchMock.mock.calls[0];
    expect((init as RequestInit).body).toBe(JSON.stringify({ username: "user", password: "pass" }));
  });

  it("fetches the current user profile", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        user_id: "123",
        username: "user",
        email: "user@example.com",
        is_admin: true,
        scopes: ["read:findings"],
        org_id: "456",
      }),
    });

    const client = new AuthClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const profile = await client.currentUser();

    expect(profile.userId).toBe("123");
    expect(profile.isAdmin).toBe(true);
    expect(profile.scopes).toContain("read:findings");
  });
});
