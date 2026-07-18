import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import { EOL } from "node:os";
import type { ServerResponse } from "node:http";
import type { AppConfig } from "./config/index.js";
import { registry, normalizeLabelValue } from "./telemetry/metrics.js";
import { boundedKeyPart, cleanTelemetryName, componentFromSpanName } from "./telemetry/names.js";
import { runtimeAttributes } from "./telemetry/resource.js";
import { safeAttributeValue, telemetryErrorFingerprint, telemetryErrorKind } from "./telemetry/sanitize.js";
import { durationBucket, eventOutcomeForStatus, spanBaseAttributes, telemetrySchemaVersion } from "./telemetry/span-attributes.js";
import type { TelemetryAttributes, TelemetryOptions, TelemetrySpan, TelemetryStatus } from "./telemetry/types.js";

export { hashTelemetryId, slackTelemetryAttributes, telemetryErrorFingerprint, telemetryErrorKind } from "./telemetry/sanitize.js";
export type { TelemetryAttributes, TelemetryOptions, TelemetrySpan, TelemetryStatus } from "./telemetry/types.js";

interface TelemetryContext {
  traceId: string;
  spanId: string;
  mainSpan?: TelemetrySpan;
}

const processStartedAt = Date.now();
const asyncContext = new AsyncLocalStorage<TelemetryContext>();

let runtimeOptions: TelemetryOptions = {
  enabled: false,
  metricsEnabled: false,
  serviceName: "cerebro-slack-companion",
  serviceVersion: "local",
  deploymentEnvironment: "unknown",
};

export function configureTelemetry(options: TelemetryOptions): void {
  runtimeOptions = {
    ...runtimeOptions,
    ...options,
    serviceName: options.serviceName || runtimeOptions.serviceName,
    serviceVersion: options.serviceVersion || runtimeOptions.serviceVersion,
    deploymentEnvironment: options.deploymentEnvironment || runtimeOptions.deploymentEnvironment,
  };
  registry.setEnabled(runtimeOptions.metricsEnabled);
}

export function telemetryOptionsFromConfig(config: AppConfig): TelemetryOptions {
  return {
    enabled: config.telemetry.enabled,
    metricsEnabled: config.telemetry.metricsEnabled,
    serviceName: config.telemetry.serviceName,
    serviceVersion: config.coordination.version,
    deploymentEnvironment: config.telemetry.deploymentEnvironment,
    resourceAttributes: config.telemetry.resourceAttributes,
    cloudRegion: process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION,
    cloudProvider: process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION ? "aws" : undefined,
    ecsClusterName: config.coordination.ecsClusterName,
    ecsServiceName: config.coordination.ecsServiceName,
    ecsTaskFamily: process.env.ECS_TASK_FAMILY,
    ecsTaskRevision: process.env.ECS_TASK_REVISION,
  };
}

export function startTelemetrySpan(name: string, attributes: TelemetryAttributes = {}, options: { main?: boolean } = {}): TelemetrySpan {
  const current = asyncContext.getStore();
  const traceId = current?.traceId ?? randomHex(16);
  const span: TelemetrySpan = {
    name: cleanTelemetryName(name),
    traceId,
    spanId: randomHex(8),
    parentSpanId: current?.spanId,
    startedAt: Date.now(),
    main: Boolean(options.main),
    annotations: {},
  };
  const base = span.main
    ? runtimeAttributes(runtimeOptions, processStartedAt)
    : {};
  annotateSpan(span, {
    ...base,
    ...spanBaseAttributes(span.name, span.main),
    ...attributes,
    ...(span.main ? { main: true, wide_event: true } : {}),
  });
  emitTelemetry("span_start", span, span.annotations);
  return span;
}

export function endTelemetrySpan(span: TelemetrySpan | undefined, status: TelemetryStatus | string = "completed", attributes: TelemetryAttributes = {}): void {
  if (!span) return;
  const durationMs = Math.max(0, Date.now() - span.startedAt);
  const endAttributes = {
    ...span.annotations,
    ...attributes,
    status,
    "operation.name": span.name,
    "operation.status": status,
    "event.type": "end",
    "event.outcome": eventOutcomeForStatus(status),
    duration_ms: durationMs,
    "duration.bucket": durationBucket(durationMs),
  };
  emitTelemetry("span_end", span, endAttributes);
  recordMetric("cerebro_slack_companion_operations_total", {
    operation: span.name,
    status: normalizeLabelValue(status),
    outcome: String(endAttributes["event.outcome"]),
  }, 1);
  recordMetric("cerebro_slack_companion_operation_duration_seconds_sum", {
    operation: span.name,
    status: normalizeLabelValue(status),
  }, durationMs / 1000);
  recordMetric("cerebro_slack_companion_operation_duration_seconds_count", {
    operation: span.name,
    status: normalizeLabelValue(status),
  }, 1);
}

export async function withTelemetrySpan<T>(
  name: string,
  attributes: TelemetryAttributes,
  work: (span: TelemetrySpan) => Promise<T>,
  options: {
    main?: boolean;
    statusForResult?: (result: T) => TelemetryStatus | string;
    errorEventName?: string;
  } = {},
): Promise<T> {
  const span = startTelemetrySpan(name, attributes, { main: options.main });
  const parent = asyncContext.getStore();
  const context: TelemetryContext = {
    traceId: span.traceId,
    spanId: span.spanId,
    mainSpan: span.main ? span : parent?.mainSpan,
  };
  return asyncContext.run(context, async () => {
    try {
      const result = await work(span);
      endTelemetrySpan(span, options.statusForResult?.(result) ?? "completed");
      return result;
    } catch (error) {
      captureTelemetryError(options.errorEventName ?? `${span.name}.error`, error, {
        component: componentFromSpanName(span.name),
        operation: span.name,
      });
      endTelemetrySpan(span, "failed", { error_kind: telemetryErrorKind(error) });
      throw error;
    }
  });
}

export function telemetryEvent(name: string, attributes: TelemetryAttributes = {}): void {
  const current = asyncContext.getStore();
  const eventAttributes = {
    "telemetry.schema.version": telemetrySchemaVersion,
    "event.dataset": "cerebro_slack_companion.telemetry",
    "telemetry.signal.kind": "event",
    "event.category": "application",
    "event.type": "info",
    "event.name": cleanTelemetryName(name),
    ...attributes,
  };
  emitTelemetry("event", {
    name: cleanTelemetryName(name),
    traceId: current?.traceId ?? "",
    spanId: current?.spanId ?? "",
    startedAt: Date.now(),
    main: false,
    annotations: {},
  }, eventAttributes);
}

export function captureTelemetryError(name: string, error: unknown, attributes: TelemetryAttributes = {}): void {
  const kind = telemetryErrorKind(error);
  telemetryEvent(name || "error.capture", {
    ...attributes,
    error_kind: kind,
    error_fingerprint: telemetryErrorFingerprint(name, error, attributes),
    handled: true,
  });
}

export function annotateMain(attributes: TelemetryAttributes): void {
  const main = asyncContext.getStore()?.mainSpan;
  if (main) annotateSpan(main, attributes);
}

export function annotateMainIfAbsent(attributes: TelemetryAttributes): void {
  const main = asyncContext.getStore()?.mainSpan;
  if (!main) return;
  const next: TelemetryAttributes = {};
  for (const [key, value] of Object.entries(attributes)) {
    if (!(key in main.annotations)) {
      next[key] = value;
    }
  }
  annotateSpan(main, next);
}

export function incrementMain(key: string, delta = 1): void {
  const main = asyncContext.getStore()?.mainSpan;
  if (!main || !key.trim() || delta === 0) return;
  const current = Number(main.annotations[key] ?? 0);
  main.annotations[key] = Number.isFinite(current) ? current + delta : delta;
}

export function maxMain(key: string, value: number): void {
  const main = asyncContext.getStore()?.mainSpan;
  if (!main || !key.trim() || !Number.isFinite(value)) return;
  const current = Number(main.annotations[key]);
  if (!Number.isFinite(current) || value > current) {
    main.annotations[key] = value;
  }
}

export function annotateMainDependency(
  system: string,
  component: string,
  operation: string,
  status: TelemetryStatus | string,
  attributes: TelemetryAttributes = {},
): void {
  const systemKey = boundedKeyPart(system || "unknown");
  incrementMain("dependency.operation.count", 1);
  incrementMain(`dependency.${systemKey}.operation.count`, 1);
  if (eventOutcomeForStatus(status) === "failure") {
    incrementMain("dependency.error.count", 1);
    incrementMain(`dependency.${systemKey}.error.count`, 1);
  }
  annotateMain({
    ...attributes,
    "dependency.last_system": systemKey,
    "dependency.last_component": component,
    "dependency.last_operation": operation,
    "dependency.last_status": status || "unknown",
    [`dependency.${systemKey}.last_component`]: component,
    [`dependency.${systemKey}.last_operation`]: operation,
    [`dependency.${systemKey}.last_status`]: status || "unknown",
  });
}

export function annotateMainPhase(phase: string, status: TelemetryStatus | string, attributes: TelemetryAttributes = {}): void {
  const phaseKey = boundedKeyPart(phase || "unknown");
  incrementMain("phase.count", 1);
  incrementMain(`phase.${phaseKey}.count`, 1);
  if (eventOutcomeForStatus(status) === "failure") {
    incrementMain("phase.error.count", 1);
    incrementMain(`phase.${phaseKey}.error.count`, 1);
  }
  annotateMain({
    ...attributes,
    "phase.last_name": phase,
    "phase.last_status": status || "unknown",
    [`phase.${phaseKey}.status`]: status || "unknown",
  });
}

export function annotateSpan(span: TelemetrySpan | undefined, attributes: TelemetryAttributes): void {
  if (!span) return;
  for (const [key, value] of Object.entries(attributes)) {
    if (!key.trim() || value === undefined) continue;
    span.annotations[key] = value;
  }
}

export function recordMetric(name: string, labels: Record<string, string | number | boolean | undefined> = {}, value = 1): void {
  registry.add(name, labels, value);
}

export function recordGauge(name: string, labels: Record<string, string | number | boolean | undefined> = {}, value = 0): void {
  registry.set(name, labels, value);
}

export function renderMetrics(): string {
  return registry.render();
}

export function metricsCustomRoute() {
  return {
    path: "/metrics",
    method: "GET",
    handler: (_req: unknown, res: ServerResponse) => {
      const body = renderMetrics();
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
      res.end(body);
    },
  };
}

export function resetTelemetryForTests(): void {
  runtimeOptions = {
    enabled: false,
    metricsEnabled: false,
    serviceName: "cerebro-slack-companion",
    serviceVersion: "local",
    deploymentEnvironment: "unknown",
  };
  registry.clear();
}

export function currentTraceIds(): { traceId?: string; spanId?: string } {
  const current = asyncContext.getStore();
  return { traceId: current?.traceId, spanId: current?.spanId };
}

function emitTelemetry(kind: string, span: TelemetrySpan, attributes: TelemetryAttributes): void {
  if (!runtimeOptions.enabled) return;
  const payload: TelemetryAttributes = {
    kind,
    ts: new Date().toISOString(),
  };
  if (span.name) payload.name = span.name;
  if (span.traceId) payload.trace_id = span.traceId;
  if (span.spanId) payload.span_id = span.spanId;
  if (span.parentSpanId) payload.parent_span_id = span.parentSpanId;
  for (const [key, value] of Object.entries(attributes)) {
    if (value === undefined) continue;
    payload[key] = safeAttributeValue(key, value);
  }
  process.stderr.write(`${JSON.stringify(payload)}${EOL}`);
}

function randomHex(byteCount: number): string {
  return randomBytes(byteCount).toString("hex");
}
