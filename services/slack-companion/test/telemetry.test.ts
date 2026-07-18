import assert from "node:assert/strict";
import test from "node:test";
import { createSecurityAgentTools } from "../src/agent/tools/index.js";
import {
  annotateMainDependency,
  annotateMainPhase,
  captureTelemetryError,
  configureTelemetry,
  recordMetric,
  renderMetrics,
  resetTelemetryForTests,
  withTelemetrySpan,
} from "../src/telemetry.js";
import { testConfig } from "./fixtures.js";

test("telemetry emits wide events, bounded errors, and metrics without raw payloads", async () => {
  resetTelemetryForTests();
  configureTelemetry({
    enabled: true,
    metricsEnabled: true,
    serviceName: "cerebro-slack-companion",
    serviceVersion: "test",
    deploymentEnvironment: "test",
  });

  const stderr = await captureStderr(async () => {
    await withTelemetrySpan("test.operation", {
      component: "test",
      operation: "operation",
      question: "raw question with secret-token-shaped value",
      api_key: "secret-api-key",
      "safe.status": "ok",
    }, async () => {
      annotateMainDependency("cerebro", "test", "read", "completed");
      annotateMainPhase("test.phase", "completed");
      captureTelemetryError("test.handled", new Error("raw secret-token-shaped failure"), {
        component: "test",
        operation: "operation",
      });
      recordMetric("cerebro_slack_companion_test_total", { status: "ok" }, 1);
    }, { main: true });
  });

  assert.doesNotMatch(stderr, /secret-token-shaped|secret-api-key|raw question/);
  const lines = stderr.trim().split("\n").map((line) => JSON.parse(line) as Record<string, unknown>);
  const end = lines.find((line) => line.kind === "span_end" && line.name === "test.operation");
  assert.ok(end);
  assert.equal(end.main, true);
  assert.equal(end.wide_event, true);
  assert.equal(end["event.dataset"], "cerebro_slack_companion.wide_events");
  assert.equal(end.question, "[redacted]");
  assert.equal(end.api_key, "[redacted]");
  assert.equal(end["dependency.cerebro.operation.count"], 1);
  assert.equal(end["phase.test_phase.count"], 1);
  assert.equal(end["operation.status"], "completed");

  const handled = lines.find((line) => line.kind === "event" && line.name === "test.handled");
  assert.ok(handled);
  assert.equal(handled.error_kind, "error");
  assert.equal(typeof handled.error_fingerprint, "string");

  const metrics = renderMetrics();
  assert.match(metrics, /cerebro_slack_companion_test_total\{status="ok"\} 1/);
  assert.match(metrics, /cerebro_slack_companion_operations_total\{operation="test_operation",outcome="success",status="completed"\} 1/);

  resetTelemetryForTests();
});

test("agent tool telemetry records tool identity without tool arguments", async () => {
  resetTelemetryForTests();
  configureTelemetry({
    enabled: true,
    metricsEnabled: false,
    serviceName: "cerebro-slack-companion",
    serviceVersion: "test",
    deploymentEnvironment: "test",
  });

  const tools = createSecurityAgentTools({
    config: testConfig({ telemetry: { enabled: true } }),
    memory: {
      readWorkingMemory: () => [],
      writeWorkingMemory: () => ({ success: true }),
      search: async () => [],
    } as any,
    cerebro: {} as any,
  });
  const tool = tools.find((item) => item.name === "security_memory_search");
  assert.ok(tool);

  const stderr = await captureStderr(async () => {
    await tool.execute("tool-1", { query: "raw Slack text with ghp_secret", limit: 3 });
  });

  assert.doesNotMatch(stderr, /raw Slack text|ghp_secret/);
  const end = stderr.trim().split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .find((line) => line.kind === "span_end" && line.name === "assistant.tool.execute");
  assert.ok(end);
  assert.equal(end["tool.name"], "security_memory_search");
  assert.equal(end["tool.family"], "memory");
  assert.equal(end["tool.authority"], "read");
  assert.equal(end["tool.target_source"], "model_arguments");
  assert.equal(end["tool.retry"], "transient_retry");
  assert.equal(end["tool.result.error_present"], false);

  resetTelemetryForTests();
});

async function captureStderr(work: () => Promise<void>): Promise<string> {
  const original = process.stderr.write.bind(process.stderr);
  let output = "";
  process.stderr.write = ((chunk: string | Uint8Array, ...args: unknown[]) => {
    output += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
    const callback = args.find((arg): arg is (error?: Error | null) => void => typeof arg === "function");
    callback?.();
    return true;
  }) as typeof process.stderr.write;
  try {
    await work();
  } finally {
    process.stderr.write = original;
  }
  return output;
}
