import { describe, expect, it } from "vitest";

import { parseTraceparent, startWebSpan } from "./observability";

describe("web observability", () => {
  it("validates W3C traceparent headers", () => {
    expect(parseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")).toMatchObject({
      traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
      spanId: "00f067aa0ba902b7",
    });
    expect(parseTraceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01")).toBeNull();
    expect(parseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01")).toBeNull();
    expect(parseTraceparent("not-a-trace")).toBeNull();
  });

  it("emits bounded error events without raw messages or secrets", () => {
    const writes = captureStderr(() => {
      const span = startWebSpan("test.web.operation", {
        component: "test",
        authorization: "Bearer secret-token",
      });
      span.captureException(new Error("raw secret-token message"), {
        component: "test",
        operation: "fetch",
      });
      span.end("failed");
    });

    const output = writes.join("");
    const payloads = writes.map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(payloads[0]).toMatchObject({
      kind: "span_start",
      "event.dataset": "cerebro.telemetry",
      "event.type": "start",
      "operation.name": "test.web.operation",
      "telemetry.signal.kind": "span",
    });
    expect(payloads.at(-1)).toMatchObject({
      component: "test",
      kind: "span_end",
      "event.outcome": "failure",
      "event.type": "end",
      status: "failed",
    });
    expect(output).toContain("\"name\":\"error.capture\"");
    expect(output).toContain("\"error_fingerprint\"");
    expect(output).toContain("\"authorization\":\"[redacted]\"");
    expect(output).not.toContain("raw secret-token message");
    expect(output).not.toContain("Bearer secret-token");
  });
});

const captureStderr = (fn: () => void) => {
  const original = process.stderr.write;
  const writes: string[] = [];
  process.stderr.write = ((chunk: string | Uint8Array) => {
    writes.push(String(chunk));
    return true;
  }) as typeof process.stderr.write;
  try {
    fn();
  } finally {
    process.stderr.write = original;
  }
  return writes;
};
