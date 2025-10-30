import { beforeEach, describe, expect, it, vi } from "vitest";

import HttpClient from "../src/httpClient";
import { FindingsClient } from "../src/clients/findings";

const fetchMock = vi.fn();

beforeEach(() => {
  fetchMock.mockReset();
  // @ts-expect-error assign test double
  globalThis.fetch = fetchMock;
});

describe("FindingsClient", () => {
  it("lists findings with filters", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ([
        {
          finding_id: "finding-1",
          org_id: "org-1",
          account_id: "acct-1",
          provider: "aws",
          rule_id: "rule-1",
          rule_version: 1,
          resource_id: null,
          principal_id: null,
          first_seen: now,
          last_seen: now,
          status: "open",
          severity: "high",
          fingerprint: "fp",
          title: "Finding",
          summary: "Summary",
          evidence: null,
        },
      ]),
    });

    const client = new FindingsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const findings = await client.list({ orgId: "org-1", status: "open", limit: 20 });

    expect(findings).toHaveLength(1);
    expect(findings[0].findingId).toBe("finding-1");
    expect(findings[0].firstSeen).toBeInstanceOf(Date);
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("org_id=org-1");
    expect(url).toContain("status=open");
    expect(url).toContain("limit=20");
  });

  it("lists findings using cursor-based pagination", async () => {
    const now = new Date().toISOString();
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({
        items: [
          {
            finding_id: "finding-1",
            org_id: "org-1",
            account_id: "acct-1",
            provider: "aws",
            rule_id: "rule-1",
            rule_version: 1,
            resource_id: null,
            principal_id: null,
            first_seen: now,
            last_seen: now,
            status: "open",
            severity: "high",
            fingerprint: "fp",
            title: "Finding",
            summary: "Summary",
            evidence: null,
          },
        ],
        next_cursor: "next-cursor",
      }),
    });

    const client = new FindingsClient(new HttpClient({ baseUrl: "https://api.example.com" }));
    const page = await client.listPage({ orgId: "org-1", cursor: "cursor-token", limit: 2 });

    expect(page.items).toHaveLength(1);
    expect(page.nextCursor).toBe("next-cursor");
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/v1/findings/page");
    expect(url).toContain("org_id=org-1");
    expect(url).toContain("cursor=cursor-token");
    expect(url).toContain("limit=2");
  });
});
