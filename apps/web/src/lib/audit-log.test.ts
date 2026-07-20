import { describe, expect, it } from "vitest";

import {
  auditLogQueryFromSearchParams,
  auditLogSearchParams,
  normalizeAuditLogPage,
  normalizeAuditOutcome,
} from "./audit-log";

describe("audit event contracts", () => {
  it("bounds query inputs and preserves only supported filters", () => {
    const query = auditLogQueryFromSearchParams(new URLSearchParams({
      action: "resource.updated",
      actor: "actor-1",
      cursor: "c".repeat(700),
      limit: "9000",
      minutes: "1",
      outcome: "not-a-state",
      q: "change",
      resource_type: "repository",
      service: "service-a",
      trace_id: "trace-1",
    }));

    expect(query).toMatchObject({
      action: "resource.updated",
      actor: "actor-1",
      limit: 500,
      minutes: 5,
      outcome: "",
      query: "change",
      resourceType: "repository",
      service: "service-a",
      traceId: "trace-1",
    });
    expect(query.cursor).toHaveLength(512);
    expect(Object.fromEntries(auditLogSearchParams(query))).toMatchObject({
      action: "resource.updated",
      actor: "actor-1",
      limit: "500",
      minutes: "5",
      q: "change",
      resource_type: "repository",
      service: "service-a",
      trace_id: "trace-1",
    });
  });

  it("normalizes provider-neutral events and drops invalid records", () => {
    const page = normalizeAuditLogPage({
      events: [
        {
          action: "resource.updated",
          actor: { id: "actor-1", kind: "user", label: "Operator" },
          category: "configuration",
          duration_ms: 120,
          id: "event-1",
          occurred_at: "2026-07-18T08:00:00Z",
          outcome: "completed",
          request_id: "request-1",
          resource: { id: "resource-1", label: "Repository", type: "repository" },
          service: "service-a",
          summary: "Access setting changed.",
          trace_id: "trace-1",
          backend_metadata: { unexpected_value: "must-not-pass-through" },
        },
        { id: "missing-required-fields" },
      ],
      next_cursor: "next-1",
      status: "partial",
      window: {
        end_time: "2026-07-18T09:00:00Z",
        start_time: "2026-07-18T08:00:00Z",
      },
    });

    expect(page.events).toHaveLength(1);
    expect(page.events[0]).toEqual({
      action: "resource.updated",
      actor: { id: "actor-1", kind: "user", label: "Operator" },
      category: "configuration",
      durationMs: 120,
      id: "event-1",
      occurredAt: "2026-07-18T08:00:00Z",
      outcome: "success",
      requestId: "request-1",
      resource: { id: "resource-1", label: "Repository", type: "repository" },
      service: "service-a",
      summary: "Access setting changed.",
      traceId: "trace-1",
    });
    expect(page.nextCursor).toBe("next-1");
    expect(page.status).toBe("partial");
    expect(JSON.stringify(page)).not.toMatch(/backend_metadata|must-not-pass-through/);
  });

  it("derives summary counts from normalized events", () => {
    const page = normalizeAuditLogPage({
      events: [
        event({ duration_ms: 10, id: "event-1", outcome: "success", service: "service-a" }),
        event({ duration_ms: 20, id: "event-2", outcome: "failed", service: "service-a" }),
        event({ duration_ms: 30, id: "event-3", outcome: "denied", service: "service-b" }),
      ],
    });

    expect(page.summary).toMatchObject({
      averageDurationMs: 20,
      denied: 1,
      failures: 1,
      p95DurationMs: 30,
      services: [
        { count: 2, label: "service-a" },
        { count: 1, label: "service-b" },
      ],
      total: 3,
    });
  });

  it("maps common terminal states onto the public outcome set", () => {
    expect(normalizeAuditOutcome("allowed")).toBe("success");
    expect(normalizeAuditOutcome("timed_out")).toBe("failure");
    expect(normalizeAuditOutcome("forbidden")).toBe("denied");
    expect(normalizeAuditOutcome("pending")).toBe("unknown");
  });

  it("rejects payloads without the contract event collection", () => {
    expect(() => normalizeAuditLogPage({ status: "complete" })).toThrow(
      "Audit event response must include an events array.",
    );
  });
});

const event = (overrides: Record<string, unknown>) => ({
  action: "resource.updated",
  id: "event",
  occurred_at: "2026-07-18T08:00:00Z",
  ...overrides,
});
