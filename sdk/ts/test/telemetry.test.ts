import { beforeEach, describe, expect, it } from "vitest";

import {
  configureLogging,
  createCounter,
  createHistogram,
  getLogger,
  timeOperation,
  type LogEntry,
} from "../src/telemetry";

describe("telemetry", () => {
  const entries: LogEntry[] = [];

  beforeEach(() => {
    entries.length = 0;
    configureLogging("debug", {
      jsonOutput: false,
      sink: (entry) => entries.push(entry),
    });
  });

  it("emits log entries at or above configured level", () => {
    const logger = getLogger("test");
    logger.debug("debug message");
    logger.trace("ignored");

    expect(entries).toHaveLength(1);
    expect(entries[0].level).toBe("debug");
    expect(entries[0].message[0]).toBe("debug message");
  });

  it("increments counter values", () => {
    const counter = createCounter("tests_total", "Number of test events");
    counter.inc();
    counter.inc({}, 2);

    expect(counter.get()).toBe(3);

    counter.reset();
    expect(counter.get()).toBe(0);
  });

  it("records histogram observations via timeOperation", async () => {
    const histogram = createHistogram("duration_seconds", "Operation timing");
    const stopTimer = timeOperation(histogram);

    // Simulate work
    await new Promise((resolve) => setTimeout(resolve, 5));

    const duration = stopTimer();
    expect(duration).toBeGreaterThanOrEqual(0);

    const buckets = histogram.getBuckets();
    const total = buckets[buckets.length - 1].count;
    expect(total).toBeGreaterThan(0);
  });
});
