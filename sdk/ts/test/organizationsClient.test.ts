import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import { OrganizationsClient } from "../src/clients/organizations";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error assign test double
  globalThis.fetch = fetchMock;
});

describe("OrganizationsClient", () => {
  it("lists organizations with pagination params", async () => {
    const createdAt = new Date().toISOString();
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          org_id: "org-1",
          name: "Org",
          created_at: createdAt,
        },
      ]),
    });

    const client = new OrganizationsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const organizations = await client.list({ skip: 10, limit: 5 });

    expect(organizations[0].orgId).toBe("org-1");
    expect(organizations[0].createdAt).toBeInstanceOf(Date);
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("skip=10");
    expect(url).toContain("limit=5");
  });
});
