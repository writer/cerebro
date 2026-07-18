export type TelemetryStatus = "completed" | "failed" | "skipped" | "miss" | "degraded" | "queued" | "matched" | "suppressed";
export type TelemetryAttributes = Record<string, unknown>;

export interface TelemetryOptions {
  enabled: boolean;
  metricsEnabled: boolean;
  serviceName: string;
  serviceVersion: string;
  deploymentEnvironment: string;
  resourceAttributes?: string;
  cloudRegion?: string;
  cloudProvider?: string;
  ecsClusterName?: string;
  ecsServiceName?: string;
  ecsTaskFamily?: string;
  ecsTaskRevision?: string;
}

export interface TelemetrySpan {
  name: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  startedAt: number;
  main: boolean;
  annotations: TelemetryAttributes;
}
