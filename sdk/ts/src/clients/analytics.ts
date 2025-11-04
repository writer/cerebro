import HttpClient, { RequestOptions } from "../httpClient.js";
import {
  RuntimeEventAggregate,
  RuntimeHealthRecord,
  RuntimeHealthSummary,
  RuntimeMetadataSnapshot,
} from "../types.js";

interface RuntimeEventAggregatePayload {
  count: number;
  last_seen: string | null;
}

interface RuntimeMetadataPayload {
  payload: Record<string, unknown>;
  captured_at: string;
}

interface RuntimeHealthPayload {
  runtime: string;
  window_start: string;
  window_end: string;
  events: Record<string, RuntimeEventAggregatePayload>;
  warnings: Record<string, RuntimeEventAggregatePayload>;
  latest_metadata: RuntimeMetadataPayload | null;
}

interface RuntimeHealthResponse {
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
  return {
    runtime: entry.runtime,
    windowStart: parseDate(entry.window_start) ?? new Date(entry.window_start),
    windowEnd: parseDate(entry.window_end) ?? new Date(entry.window_end),
    events: mapRuntimeEventCollection(entry.events),
    warnings: mapRuntimeEventCollection(entry.warnings),
    latestMetadata: entry.latest_metadata ? mapRuntimeMetadata(entry.latest_metadata) : null,
  };
}

function mapRuntimeEventCollection(source: Record<string, RuntimeEventAggregatePayload>): Record<string, RuntimeEventAggregate> {
  const target: Record<string, RuntimeEventAggregate> = {};
  for (const [key, value] of Object.entries(source)) {
    target[key] = {
      count: value.count,
      lastSeen: parseDate(value.last_seen),
    };
  }
  return target;
}

function mapRuntimeMetadata(payload: RuntimeMetadataPayload): RuntimeMetadataSnapshot {
  return {
    payload: payload.payload,
    capturedAt: parseDate(payload.captured_at) ?? new Date(payload.captured_at),
  };
}

function parseDate(value: string | null | undefined): Date | null {
  if (!value) {
    return null;
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

export default AnalyticsClient;
