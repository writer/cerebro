import type { ParsedEnv } from "./env.js";
import { parseBoolean } from "./parsing.js";
import type { AppConfig } from "./types.js";

export function buildTelemetryConfig(parsed: ParsedEnv): AppConfig["telemetry"] {
  return {
    enabled: parseBoolean(parsed.CEREBRO_TELEMETRY_ENABLED),
    metricsEnabled: parseBoolean(parsed.CEREBRO_METRICS_ENABLED),
    serviceName: parsed.CEREBRO_TELEMETRY_SERVICE_NAME,
    deploymentEnvironment: parsed.CEREBRO_DEPLOYMENT_ENVIRONMENT ?? parsed.NODE_ENV,
    resourceAttributes: parsed.OTEL_RESOURCE_ATTRIBUTES,
  };
}
