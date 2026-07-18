import { describe, expect, it, vi } from "vitest";

import { defaultAuditLogQuery } from "./audit-log";
import { AuditLogReaderError, createHttpAuditLogReader } from "./audit-log-reader";

describe("HTTP audit event reader", () => {
  it("sends bounded query parameters and returns normalized events", async () => {
    const fetcher = vi.fn(async () => new Response(JSON.stringify({
      events: [{
        action: "resource.updated",
        id: "event-1",
        occurred_at: "2026-07-18T08:00:00Z",
        outcome: "success",
      }],
    }), {
      headers: { "content-type": "application/json" },
      status: 200,
    })) as unknown as typeof fetch;
    const reader = createHttpAuditLogReader({
      endpoint: new URL("https://example.invalid/platform/audit-events"),
      fetcher,
      headers: { "x-request-id": "request-1" },
    });

    const page = await reader.list({
      ...defaultAuditLogQuery(),
      limit: 25,
      minutes: 15,
      outcome: "success",
      service: "service-a",
    });

    expect(page.events).toHaveLength(1);
    const [target, init] = vi.mocked(fetcher).mock.calls[0];
    expect(String(target)).toBe(
      "https://example.invalid/platform/audit-events?limit=25&minutes=15&outcome=success&service=service-a",
    );
    expect(init).toMatchObject({ cache: "no-store", method: "GET" });
    expect(new Headers(init?.headers).get("x-request-id")).toBe("request-1");
  });

  it("does not return upstream response details in errors", async () => {
    const fetcher = vi.fn(async () => new Response("provider-specific failure detail", {
      status: 500,
    })) as unknown as typeof fetch;
    const reader = createHttpAuditLogReader({
      endpoint: new URL("https://example.invalid/platform/audit-events"),
      fetcher,
    });

    await expect(reader.list(defaultAuditLogQuery())).rejects.toEqual(
      new AuditLogReaderError("Audit events are unavailable."),
    );
  });

  it("rejects non-JSON success responses", async () => {
    const fetcher = vi.fn(async () => new Response("not-json", {
      headers: { "content-type": "text/plain" },
      status: 200,
    })) as unknown as typeof fetch;
    const reader = createHttpAuditLogReader({
      endpoint: new URL("https://example.invalid/platform/audit-events"),
      fetcher,
    });

    await expect(reader.list(defaultAuditLogQuery())).rejects.toMatchObject({
      message: "Audit events response was invalid.",
      status: 502,
    });
  });
});
