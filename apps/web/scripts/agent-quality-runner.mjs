#!/usr/bin/env node

import fixture from "./fixtures/agent-quality-scenarios.json" with { type: "json" };

const config = qualityRunnerConfig(process.env);
const endpoint = config.endpoint;
const timeoutMs = config.timeoutMs;
const concurrency = config.concurrency;
const endpointURL = new URL(endpoint);
const allowedHosts = new Set([
  "127.0.0.1",
  "localhost",
  ...config.allowedHosts,
]);

if (!allowedHosts.has(endpointURL.hostname)) {
  throw new Error(
    `Refusing to send agent scenarios to ${endpointURL.hostname}. Add it to CEREBRO_AGENT_EVAL_ALLOW_HOSTS.`,
  );
}
if (endpointURL.protocol !== "http:" && endpointURL.protocol !== "https:") {
  throw new Error("CEREBRO_AGENT_EVAL_URL must use http or https.");
}

if (fixture.schema_version !== "cerebro.web-agent-quality/v1" || !Array.isArray(fixture.scenarios)) {
  throw new Error("Agent quality fixture must use cerebro.web-agent-quality/v1 with scenarios.");
}

const results = await mapConcurrent(fixture.scenarios, concurrency, runScenario);
const failed = results.filter((result) => !result.passed);
const report = {
  schema_version: "cerebro.web-agent-quality-report/v1",
  endpoint: `${endpointURL.origin}${endpointURL.pathname}`,
  total: results.length,
  passed: results.length - failed.length,
  failed: failed.length,
  results,
};
console.log(JSON.stringify(report, null, 2));
if (failed.length) process.exitCode = 1;

async function runScenario(scenario) {
  const startedAt = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const request = {
    tenant_id: config.tenantId,
    question: String(scenario.question || "").trim(),
    surface: "agent_quality_runner",
    agent_mode: scenario.agent_mode === "deep" ? "deep" : "auto",
    context: scenario.context && typeof scenario.context === "object" ? scenario.context : {},
  };
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "text/event-stream",
        "content-type": "application/json",
        ...(config.apiKey
          ? { "x-api-key": config.apiKey }
          : {}),
      },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    if (!response.ok) {
      return failedResult(scenario, startedAt, [`http_${response.status}`]);
    }
    const events = parseSSE(await response.text());
    const summary = events.findLast((event) => event.event === "summary")?.data;
    const done = events.findLast((event) => event.event === "done")?.data;
    const errors = events.filter((event) => event.event === "error");
    const failures = [];
    if (errors.length) failures.push(...errors.map((event) => `agent_error:${event.data?.code || "unknown"}`));
    if (!summary?.markdown?.trim()) failures.push("missing_summary");
    if (!done?.trace_id) failures.push("missing_done");
    if (scenario.requires_tool && !(done?.tool_calls > 0 && done?.tool_results > 0)) {
      failures.push("missing_tool_result");
    }
    if (scenario.requires_citation && !summary?.citations?.length) failures.push("missing_citation");
    if (scenario.expected_profile && done?.agent_profile !== scenario.expected_profile) {
      failures.push(`profile:${done?.agent_profile || "missing"}`);
    }
    if (scenario.max_total_ms && done?.total_ms > scenario.max_total_ms) {
      failures.push(`latency:${done.total_ms}`);
    }
    return {
      id: scenario.id,
      passed: failures.length === 0,
      failures,
      elapsed_ms: Date.now() - startedAt,
      trace_id: done?.trace_id,
      model_route: done?.model_route,
      agent_profile: done?.agent_profile,
      tool_calls: done?.tool_calls ?? 0,
      citations: summary?.citations?.length ?? 0,
      evidence_gaps: summary?.evidence_gaps?.length ?? 0,
      total_tokens: done?.total_tokens ?? 0,
    };
  } catch (error) {
    return failedResult(scenario, startedAt, [
      error?.name === "AbortError" ? "timeout" : `request:${error?.message || String(error)}`,
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function parseSSE(body) {
  return body.split(/\r?\n\r?\n/).flatMap((block) => {
    let event = "message";
    const data = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
    }
    if (!data.length) return [];
    try {
      return [{ event, data: JSON.parse(data.join("\n")) }];
    } catch {
      return [{ event, data: null }];
    }
  });
}

function failedResult(scenario, startedAt, failures) {
  return {
    id: scenario.id,
    passed: false,
    failures,
    elapsed_ms: Date.now() - startedAt,
  };
}

async function mapConcurrent(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index]);
    }
  }));
  return results;
}

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value || "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function splitList(value) {
  return (value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function qualityRunnerConfig(env) {
  return {
    endpoint: env.CEREBRO_AGENT_EVAL_URL?.trim() || "http://127.0.0.1:3000/api/agent/ask",
    timeoutMs: positiveInt(env.CEREBRO_AGENT_EVAL_TIMEOUT_MS, 180_000),
    concurrency: positiveInt(env.CEREBRO_AGENT_EVAL_CONCURRENCY, 2),
    allowedHosts: splitList(env.CEREBRO_AGENT_EVAL_ALLOW_HOSTS),
    tenantId: env.CEREBRO_AGENT_EVAL_TENANT?.trim() || "writer",
    apiKey: env.CEREBRO_AGENT_EVAL_API_KEY?.trim() || "",
  };
}
