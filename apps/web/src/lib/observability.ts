import { createHash, randomBytes } from "crypto";

import { appVersion } from "./app-version";

type AttributeValue = string | number | boolean | null | undefined;
type Attributes = Record<string, AttributeValue>;

export type WebSpan = {
  name: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  traceparent: string;
  annotate: (attributes?: Attributes) => void;
  increment: (key: string, value?: number) => void;
  event: (name: string, attributes?: Attributes) => void;
  captureException: (error: unknown, attributes?: Attributes) => void;
  end: (status?: "completed" | "failed" | "cancelled", attributes?: Attributes) => void;
};

const traceIdPattern = /^[0-9a-f]{32}$/;
const spanIdPattern = /^[0-9a-f]{16}$/;
const traceFlagsPattern = /^[0-9a-f]{2}$/;
const secretKeyPattern = /(authorization|api[-_.]?key|token|secret|password|cookie|credential)/i;
const MAX_ATTRIBUTE_STRING_LENGTH = 512;
const WIDE_EVENT_SCHEMA_VERSION = "2026-06-19.1";

export const parseTraceparent = (value: string | null | undefined) => {
  const parts = value?.trim().toLowerCase().split("-") ?? [];
  if (parts.length !== 4 || parts[0] !== "00") {
    return null;
  }
  const [, traceId, spanId, flags] = parts;
  if (
    !traceIdPattern.test(traceId)
    || !spanIdPattern.test(spanId)
    || !traceFlagsPattern.test(flags)
    || /^0+$/.test(traceId)
    || /^0+$/.test(spanId)
  ) {
    return null;
  }
  return { traceId, spanId, flags };
};

export const startWebSpan = (
  name: string,
  attributes: Attributes = {},
  parentTraceparent?: string | null,
): WebSpan => {
  const parent = parseTraceparent(parentTraceparent);
  const traceId = parent?.traceId ?? randomHex(16);
  const spanId = randomHex(8);
  const startedAt = Date.now();
  let ended = false;
  const annotations: Attributes = safeAttributes(attributes);
  const base = {
    name,
    trace_id: traceId,
    span_id: spanId,
    ...(parent?.spanId ? { parent_span_id: parent.spanId } : {}),
  };
  const startAttributes = { ...annotations };

  emit("span_start", {
    ...base,
    ...serviceAttributes(),
    ...telemetryAttributes(name, "span", "start", startAttributes),
    ...startAttributes,
  });

  return {
    name,
    traceId,
    spanId,
    parentSpanId: parent?.spanId,
    traceparent: `00-${traceId}-${spanId}-01`,
    annotate: (nextAttributes = {}) => {
      Object.assign(annotations, safeAttributes(nextAttributes));
    },
    increment: (key, value = 1) => {
      if (!key.trim()) {
        return;
      }
      const current = typeof annotations[key] === "number" ? annotations[key] : 0;
      annotations[key] = current + value;
    },
    event: (eventName, eventAttributes = {}) => {
      const eventPayload = safeAttributes(eventAttributes);
      emit("event", {
        ...base,
        name: eventName,
        ...telemetryAttributes(eventName, "event", "info", eventPayload),
        "event.name": eventName,
        ...eventPayload,
      });
    },
    captureException: (error, errorAttributes = {}) => {
      const kind = errorKind(error);
      const eventPayload = safeAttributes({
        ...errorAttributes,
        handled: true,
        error_kind: kind,
        error_fingerprint: errorFingerprint(name, kind, errorAttributes),
      });
      emit("event", {
        ...base,
        name: "error.capture",
        ...telemetryAttributes("error.capture", "event", "info", eventPayload),
        "event.name": "error.capture",
        ...eventPayload,
      });
    },
    end: (status = "completed", endAttributes = {}) => {
      if (ended) {
        return;
      }
      ended = true;
      const terminalAttributes = safeAttributes({
        ...annotations,
        status,
        duration_ms: Date.now() - startedAt,
        ...endAttributes,
      });
      emit("span_end", {
        ...base,
        ...serviceAttributes(),
        ...telemetryAttributes(name, "span", "end", terminalAttributes),
        "event.outcome": eventOutcomeForStatus(status),
        ...terminalAttributes,
      });
    },
  };
};

export const headersWithTrace = (headers: HeadersInit | undefined, span: Pick<WebSpan, "traceId" | "traceparent">) => {
  const next = new Headers(headers);
  if (!next.has("traceparent")) {
    next.set("traceparent", span.traceparent);
  }
  next.set("x-cerebro-web-trace-id", span.traceId);
  return next;
};

export const responseHeadersWithTrace = (
  headers: Record<string, string>,
  span: Pick<WebSpan, "traceId">,
): Record<string, string> => ({
  ...headers,
  "x-cerebro-web-trace-id": span.traceId,
});

export const errorKind = (error: unknown) => {
  if (error instanceof DOMException && error.name === "AbortError") {
    return "abort_error";
  }
  if (error instanceof Error) {
    return snakeCase(error.constructor.name || error.name || "error");
  }
  return snakeCase(typeof error || "unknown");
};

const errorFingerprint = (spanName: string, kind: string, attributes: Attributes) =>
  createHash("sha256")
    .update([
      spanName.trim(),
      kind,
      String(attributes.component ?? ""),
      String(attributes.operation ?? ""),
    ].join("|"))
    .digest("hex")
    .slice(0, 16);

const randomHex = (bytes: number) => randomBytes(bytes).toString("hex");

const emit = (kind: string, fields: Record<string, unknown>) => {
  const payload = {
    kind,
    ts: new Date().toISOString(),
    service: "cerebro-web",
    ...fields,
  };
  process.stderr.write(`${JSON.stringify(payload)}\n`);
};

const safeAttributes = (attributes: Attributes) =>
  Object.fromEntries(
    Object.entries(attributes)
      .filter(([key]) => key.trim())
      .map(([key, value]) => [
        key,
        secretKeyPattern.test(key) ? "[redacted]" : normalizeAttributeValue(value),
      ])
      .filter(([, value]) => value !== undefined),
  );

const normalizeAttributeValue = (value: AttributeValue) => {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.length <= MAX_ATTRIBUTE_STRING_LENGTH) {
      return trimmed;
    }
    return `${trimmed.slice(0, MAX_ATTRIBUTE_STRING_LENGTH)}...`;
  }
  return value;
};

const telemetryAttributes = (
  name: string,
  signalKind: "event" | "span",
  eventType: "end" | "info" | "start",
  attributes: Attributes,
): Attributes => {
  const wideEvent = attributes.wide_event === true || attributes.wide_event === 1;
  return {
    "telemetry.schema.version": WIDE_EVENT_SCHEMA_VERSION,
    "event.dataset": wideEvent ? "cerebro.wide_events" : "cerebro.telemetry",
    "telemetry.signal.kind": signalKind,
    "event.category": signalKind === "span" ? "operation" : "application",
    "event.type": eventType,
    ...(signalKind === "span" ? { "operation.name": name } : { "event.name": name }),
    ...(wideEvent ? {
      "wide_event.contract": "main-span",
      "wide_event.schema.version": WIDE_EVENT_SCHEMA_VERSION,
    } : {}),
  };
};

const eventOutcomeForStatus = (status: string) => {
  switch (status.trim().toLowerCase()) {
    case "completed":
    case "ok":
    case "success":
    case "succeeded":
      return "success";
    case "cancelled":
    case "failed":
    case "failure":
    case "timeout":
    case "timed_out":
      return "failure";
    case "skipped":
      return "neutral";
    default:
      return "unknown";
  }
};

const serviceAttributes = (): Attributes => ({
  "service.name": "cerebro-web",
  "service.version": appVersion,
  "deployment.environment": process.env.VERCEL_ENV ?? process.env.NODE_ENV ?? "unknown",
  "cloud.provider": process.env.VERCEL ? "vercel" : process.env.AWS_REGION ? "aws" : "unknown",
  "cloud.region": process.env.VERCEL_REGION ?? process.env.AWS_REGION ?? undefined,
  "service.instance.id": process.env.VERCEL_REGION ?? process.env.AWS_EXECUTION_ENV ?? undefined,
  "process.runtime.name": "nodejs",
  "process.runtime.version": process.version,
});

const snakeCase = (value: string) =>
  value
    .trim()
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase() || "error";
