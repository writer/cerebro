import { describe, expect, it } from "vitest";

import {
  auditLogLimit,
  auditLogWindowMinutes,
  isFailureStatus,
  summarizeAuditLog,
  type AuditLogEvent,
} from "./audit-log";

const event = (overrides: Partial<AuditLogEvent> = {}): AuditLogEvent => ({
  id: "event-1",
  timestamp: "2026-01-02T03:04:05Z",
  service: "public-api",
  name: "work.completed",
  status: "completed",
  outcome: "success",
  durationMs: 50,
  traceId: "trace-1",
  runtimeId: "runtime-1",
  sourceId: "source-1",
  phase: "execute",
  dependency: "event-store",
  errorKind: "",
  attributes: {},
  rawEvent: {},
  ...overrides,
});

describe("audit log helpers", () => {
  it("clamps request windows and limits", () => {
    expect(auditLogWindowMinutes("1")).toBe(5);
    expect(auditLogWindowMinutes("99999")).toBe(1440);
    expect(auditLogWindowMinutes("bad")).toBe(60);
    expect(auditLogLimit("0")).toBe(1);
    expect(auditLogLimit("99999")).toBe(500);
    expect(auditLogLimit("bad")).toBe(100);
  });

  it("summarizes normalized events without depending on a telemetry provider", () => {
    const summary = summarizeAuditLog([
      event(),
      event({
        id: "event-2",
        status: "failed",
        outcome: "failure",
        durationMs: 150,
        service: "worker",
        runtimeId: "runtime-2",
        errorKind: "execution_failed",
      }),
    ]);

    expect(summary).toMatchObject({
      total: 2,
      failures: 1,
      failureRate: 0.5,
      averageDurationMs: 100,
      p95DurationMs: 150,
    });
    expect(summary.services).toEqual([
      { label: "public-api", count: 1 },
      { label: "worker", count: 1 },
    ]);
    expect(summary.errors).toEqual([{ label: "execution_failed", count: 1 }]);
  });

  it("recognizes terminal failure states", () => {
    expect(isFailureStatus("timed_out")).toBe(true);
    expect(isFailureStatus("completed")).toBe(false);
  });
});
