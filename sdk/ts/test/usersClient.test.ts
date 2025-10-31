import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import {
  InMemoryUsersAdapter,
  UsersClient,
} from "../src/clients/users";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error assigning test double
  globalThis.fetch = fetchMock;
});

describe("UsersClient", () => {
  it("lists users via HTTP adapter", async () => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          user_id: "user-1",
          username: "alice",
          email: "alice@example.com",
          is_admin: true,
          scopes: ["admin"],
        },
      ]),
    });

    const client = UsersClient.fromHttpClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const users = await client.list({ limit: 10 });

    expect(users).toHaveLength(1);
    expect(users[0].isAdmin).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("limit=10"), expect.anything());
  });

  it("raises when create is invoked without configured endpoint", async () => {
    const client = UsersClient.fromHttpClient(new HttpClient({ baseUrl: "https://api.example.com" }));

    await expect(
      client.create({ username: "bob", email: "bob@example.com", password: "secret" }),
    ).rejects.toThrow(/not configured/);
  });

  it("supports in-memory adapter operations", async () => {
    const adapter = new InMemoryUsersAdapter();
    const client = new UsersClient(adapter);

    const created = await client.create({ username: "carol", email: "carol@example.com", password: "pw" });
    await client.addScopes(created.userId, ["read", "write"]);

    const fetched = await client.get("carol");
    expect(fetched?.scopes).toContain("read");

    await client.removeScopes(created.userId, ["read"]);
    const updated = await client.get("carol");
    expect(updated?.scopes).not.toContain("read");
  });
});
