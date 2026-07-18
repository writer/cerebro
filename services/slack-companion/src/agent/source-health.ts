const DEFAULT_FAILURE_THRESHOLD = 2;
const DEFAULT_COOLDOWN_MS = 5 * 60 * 1000;
const DEFAULT_MAX_SOURCES = 200;
const DEFAULT_SLOW_THRESHOLD_MS = 30_000;

export type SourceHealthStatus = "healthy" | "degraded" | "cooldown";

export interface SourceHealthSnapshot {
  source: string;
  status: SourceHealthStatus;
  allowed: boolean;
  attempts: number;
  consecutive_failures: number;
  success_rate: number;
  average_latency_ms: number;
  slow: boolean;
  retry_after_ms?: number;
}

interface SourceHealthRecord {
  successes: number;
  failures: number;
  consecutiveFailures: number;
  totalLatencyMs: number;
  cooldownUntil: number;
  lastObservedAt: number;
}

interface SourceHealthRegistryOptions {
  failureThreshold?: number;
  cooldownMs?: number;
  maxSources?: number;
  slowThresholdMs?: number;
  now?: () => number;
}

export class SourceHealthRegistry {
  private readonly records = new Map<string, SourceHealthRecord>();
  private readonly failureThreshold: number;
  private readonly cooldownMs: number;
  private readonly maxSources: number;
  private readonly slowThresholdMs: number;
  private readonly now: () => number;

  constructor(options: SourceHealthRegistryOptions = {}) {
    this.failureThreshold = positiveInteger(options.failureThreshold, DEFAULT_FAILURE_THRESHOLD);
    this.cooldownMs = positiveInteger(options.cooldownMs, DEFAULT_COOLDOWN_MS);
    this.maxSources = positiveInteger(options.maxSources, DEFAULT_MAX_SOURCES);
    this.slowThresholdMs = positiveInteger(options.slowThresholdMs, DEFAULT_SLOW_THRESHOLD_MS);
    this.now = options.now ?? Date.now;
  }

  recordSuccess(source: string, latencyMs = 0): void {
    const record = this.recordFor(source);
    record.successes += 1;
    record.consecutiveFailures = 0;
    record.cooldownUntil = 0;
    record.totalLatencyMs += safeLatency(latencyMs);
    record.lastObservedAt = this.now();
  }

  recordFailure(source: string, latencyMs = 0): void {
    const record = this.recordFor(source);
    record.failures += 1;
    record.consecutiveFailures += 1;
    record.totalLatencyMs += safeLatency(latencyMs);
    record.lastObservedAt = this.now();
    if (record.consecutiveFailures >= this.failureThreshold) {
      record.cooldownUntil = record.lastObservedAt + this.cooldownMs;
    }
  }

  snapshot(source: string): SourceHealthSnapshot {
    const record = this.records.get(source);
    if (!record) return emptySnapshot(source);
    const attempts = record.successes + record.failures;
    const retryAfterMs = Math.max(0, record.cooldownUntil - this.now());
    const allowed = retryAfterMs === 0;
    const averageLatencyMs = attempts === 0 ? 0 : Math.round(record.totalLatencyMs / attempts);
    const slow = averageLatencyMs >= this.slowThresholdMs;
    const status: SourceHealthStatus = !allowed
      ? "cooldown"
      : record.consecutiveFailures > 0 || slow
        ? "degraded"
        : "healthy";
    return {
      source,
      status,
      allowed,
      attempts,
      consecutive_failures: record.consecutiveFailures,
      success_rate: attempts === 0 ? 1 : record.successes / attempts,
      average_latency_ms: averageLatencyMs,
      slow,
      ...(retryAfterMs > 0 ? { retry_after_ms: retryAfterMs } : {}),
    };
  }

  rank(sources: string[]): string[] {
    return [...sources].sort((left, right) => compareHealth(this.snapshot(left), this.snapshot(right)));
  }

  private recordFor(source: string): SourceHealthRecord {
    const existing = this.records.get(source);
    if (existing) return existing;
    this.evictOldestIfFull();
    const record: SourceHealthRecord = {
      successes: 0,
      failures: 0,
      consecutiveFailures: 0,
      totalLatencyMs: 0,
      cooldownUntil: 0,
      lastObservedAt: this.now(),
    };
    this.records.set(source, record);
    return record;
  }

  private evictOldestIfFull(): void {
    if (this.records.size < this.maxSources) return;
    let oldestSource: string | undefined;
    let oldestObservedAt = Number.POSITIVE_INFINITY;
    for (const [source, record] of this.records) {
      if (record.lastObservedAt < oldestObservedAt) {
        oldestSource = source;
        oldestObservedAt = record.lastObservedAt;
      }
    }
    if (oldestSource) this.records.delete(oldestSource);
  }
}

function emptySnapshot(source: string): SourceHealthSnapshot {
  return {
    source,
    status: "healthy",
    allowed: true,
    attempts: 0,
    consecutive_failures: 0,
    success_rate: 1,
    average_latency_ms: 0,
    slow: false,
  };
}

function compareHealth(left: SourceHealthSnapshot, right: SourceHealthSnapshot): number {
  if (left.allowed !== right.allowed) return left.allowed ? -1 : 1;
  if (left.status !== right.status) return left.status === "healthy" ? -1 : 1;
  if (left.success_rate !== right.success_rate) return right.success_rate - left.success_rate;
  return left.average_latency_ms - right.average_latency_ms;
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return Number.isInteger(value) && (value ?? 0) > 0 ? value as number : fallback;
}

function safeLatency(value: number): number {
  return Number.isFinite(value) && value > 0 ? value : 0;
}
