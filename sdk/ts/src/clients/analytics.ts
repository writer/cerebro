import HttpClient, { RequestOptions } from "../httpClient.js";
import { parseDate, transformOpenApi } from "../serialization.js";
import {
  RuntimeEventAggregate,
  RuntimeHealthRecord,
  RuntimeHealthSummary,
  RuntimeMetadataSnapshot,
} from "../types.js";

interface RuntimeEventAggregatePayload extends Record<string, unknown> {
  count: number;
  last_seen: string | null;
}

interface RuntimeMetadataPayload extends Record<string, unknown> {
  payload: Record<string, unknown>;
  captured_at: string;
}

interface RuntimeHealthPayload extends Record<string, unknown> {
  runtime: string;
  window_start: string;
  window_end: string;
  events: Record<string, RuntimeEventAggregatePayload>;
  warnings: Record<string, RuntimeEventAggregatePayload>;
  latest_metadata: RuntimeMetadataPayload | null;
}

interface RuntimeHealthResponse extends Record<string, unknown> {
  window_hours: number;
  generated_at: string;
  runtimes: RuntimeHealthPayload[];
}

export class AnalyticsClient {
  constructor(private readonly http: HttpClient) {}

  async getRuntimeHealth(hours?: number): Promise<RuntimeHealthSummary> {
    const options: RequestOptions = {};
    if (hours !== undefined) {
      options.searchParams = { hours };
    }

    const payload = await this.http.get<RuntimeHealthResponse>('/api/v1/analytics/runtime-health', options);
    return {
      windowHours: payload.window_hours,
      generatedAt: parseDate(payload.generated_at) ?? new Date(),
      runtimes: payload.runtimes.map(mapRuntimeHealthRecord),
    };
  }
}

function mapRuntimeHealthRecord(entry: RuntimeHealthPayload): RuntimeHealthRecord {
  return transformOpenApi(entry, (data) => ({
    runtime: data.runtime,
    windowStart: coerceDate(data.windowStart, entry.window_start) ?? new Date(entry.window_start),
    windowEnd: coerceDate(data.windowEnd, entry.window_end) ?? new Date(entry.window_end),
    events: mapRuntimeEventCollection(entry.events),
    warnings: mapRuntimeEventCollection(entry.warnings),
    latestMetadata: entry.latest_metadata ? mapRuntimeMetadata(entry.latest_metadata) : null,
  }), {
    snakeCaseDateKeys: ["window_start", "window_end"],
  });
}

function mapRuntimeEventCollection(source: Record<string, RuntimeEventAggregatePayload>): Record<string, RuntimeEventAggregate> {
  const target: Record<string, RuntimeEventAggregate> = {};
  for (const [key, value] of Object.entries(source)) {
    target[key] = transformOpenApi(value, (data) => ({
      count: data.count,
      lastSeen: coerceDate(data.lastSeen, value.last_seen),
    }), {
      snakeCaseDateKeys: ["last_seen"],
    });
  }
  return target;
}

function mapRuntimeMetadata(payload: RuntimeMetadataPayload): RuntimeMetadataSnapshot {
  return transformOpenApi(payload, (data) => ({
    payload: data.payload,
    capturedAt: coerceDate(data.capturedAt, payload.captured_at) ?? new Date(payload.captured_at),
  }), {
    snakeCaseDateKeys: ["captured_at"],
    deep: true,
  });
}

function coerceDate(value: unknown, fallback?: string | null): Date | null {
  const parsed = parseDate(value as string | Date | null);
  if (parsed) return parsed;
  if (!fallback) return null;
  return parseDate(fallback) ?? new Date(fallback);
}

export default AnalyticsClient;
