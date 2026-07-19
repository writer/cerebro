#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import {
  DEFAULT_CANDIDATE_OUT_DIR,
  assertLocalURL,
  buildTraceFixtureCandidate,
  writeTraceFixtureCandidates,
} from "./eval-lib.mjs";

const defaultFixturePath = new URL("./fixtures/ask-eval-scenarios.json", import.meta.url);

function parseArgs(argv) {
  const args = {
    source: `fixture:${defaultFixturePath.pathname}`,
    outDir: process.env.CEREBRO_ASK_CANDIDATE_OUT_DIR ?? DEFAULT_CANDIDATE_OUT_DIR,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--source") {
      args.source = argv[++index];
    } else if (arg === "--out") {
      args.outDir = argv[++index];
    } else if (arg === "--help") {
      args.help = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return args;
}

function usage() {
  return `Usage:
  node scripts/generate-ask-eval-candidates.mjs --source fixture:scripts/fixtures/ask-eval-scenarios.json
  node scripts/generate-ask-eval-candidates.mjs --source report:.eval-reports/ask/latest.json
  node scripts/generate-ask-eval-candidates.mjs --source jsonl:/tmp/cerebro-ask-telemetry.jsonl
  node scripts/generate-ask-eval-candidates.mjs --source local_sse:http://127.0.0.1:8080/grc/ask/demo

Candidates are sanitized and written to .eval-reports/ask/candidates by default.`;
}

async function loadCandidates(source) {
  const [kind, ...rest] = source.split(":");
  const location = rest.join(":");
  if (!location) {
    throw new Error(`Source must be kind:path, got ${source}`);
  }
  switch (kind) {
    case "fixture":
      return loadFixtureCandidates(location);
    case "report":
      return loadReportCandidates(location);
    case "jsonl":
      return loadJSONLCandidates(location);
    case "local_sse":
      return loadLocalSSECandidates(location);
    case "cloudwatch":
      throw new Error("cloudwatch source is intentionally disabled until a reviewed production adapter adds allowlists, audit logging, retention, and redaction tests");
    default:
      throw new Error(`Unsupported source kind ${kind}`);
  }
}

async function loadLocalSSECandidates(location) {
  assertLocalURL(location, "local_sse source");
  const response = await fetch(location);
  if (!response.ok) {
    throw new Error(`local_sse source failed (${response.status})`);
  }
  const stream = parseSSE(await response.text());
  return [
    buildTraceFixtureCandidate({
      id: `local-sse-${Date.now()}`,
      question: "<redacted local SSE request>",
      tenant_id: "local",
      model: "unknown",
      stream,
    }, { source: "local_sse", synthetic: false }),
  ];
}

async function loadFixtureCandidates(location) {
  const scenarios = JSON.parse(await readFile(location, "utf8"));
  return scenarios.map((scenario) => buildTraceFixtureCandidate(scenario, { source: "fixture", synthetic: true }));
}

async function loadReportCandidates(location) {
  const report = JSON.parse(await readFile(location, "utf8"));
  return (report.runs ?? []).map((run) =>
    buildTraceFixtureCandidate({
      id: run.id,
      question: run.question,
      tenant_id: run.tenantId,
      scope_urn: run.scopeUrn,
      model: run.model,
      stream: run.events ?? eventsFromReportRun(run),
    }, { source: "local_eval_report", synthetic: false }),
  );
}

async function loadJSONLCandidates(location) {
  const lines = (await readFile(location, "utf8")).split("\n").filter(Boolean);
  const scenarios = [];
  for (const [index, line] of lines.entries()) {
    const record = JSON.parse(line);
    if (record.name !== "cerebro.grc.ask") continue;
    scenarios.push({
      id: `telemetry-${record.ask_trace_id ?? index}`,
      question: `<redacted length=${record.question_len ?? 0}>`,
      tenant_id: record.tenant_id,
      scope_urn: record.scope_urn,
      model: record.model,
      stream: eventsFromTelemetry(record),
    });
  }
  return scenarios.map((scenario) => buildTraceFixtureCandidate(scenario, { source: "local_jsonl", synthetic: false }));
}

function eventsFromReportRun(run) {
  return [
    {
      event: "query_plan",
      data: {
        plan: { intent: run.queryPlanIntent },
        source: run.queryPlanSource,
        corrected: Boolean(run.queryPlanCorrected),
        diagnostics: Array.from({ length: run.conversionDiagnosticsCount ?? 0 }, (_, index) => ({ code: `diagnostic_${index + 1}` })),
      },
    },
    { event: "rows", data: { rows: Array.from({ length: run.rowCount ?? 0 }, () => ({})) } },
    { event: "summary", data: { markdown: run.summary ?? "", citations: Array.from({ length: run.citationCount ?? 0 }, () => ({ urn: "urn:cerebro:redacted", span: [0, 0] })) } },
    { event: "done", data: { trace_id: run.traceId, total_ms: run.durationMs, cypher_refused: Boolean(run.cypherRefused) } },
  ];
}

function eventsFromTelemetry(record) {
  return [
    {
      event: "query_plan",
      data: {
        plan: { intent: record["query_plan.intent"] },
        source: record["query_plan.source"],
        deterministic: Boolean(record["query_plan.deterministic"]),
        corrected: Boolean(record["query_plan.corrected"]),
        diagnostics: String(record["query_plan.diagnostic_codes"] ?? "")
          .split(",")
          .filter(Boolean)
          .map((code) => ({ code })),
      },
    },
    { event: "rows", data: { rows: Array.from({ length: Number(record.row_count ?? 0) }, () => ({})) } },
    { event: "summary", data: { markdown: "", citations: Array.from({ length: Number(record.citation_count ?? 0) }, () => ({ urn: "urn:cerebro:redacted", span: [0, 0] })) } },
    { event: "done", data: { trace_id: record.ask_trace_id, total_ms: record.duration_ms, cypher_refused: Boolean(record.cypher_refused) } },
  ];
}

function parseSSE(text) {
  const events = [];
  let name = "";
  let data = "";
  for (const line of text.split(/\r?\n/)) {
    if (line === "") {
      if (name) {
        events.push({ event: name, data: data ? JSON.parse(data) : {} });
      }
      name = "";
      data = "";
      continue;
    }
    if (line.startsWith("event: ")) {
      name = line.slice("event: ".length);
    } else if (line.startsWith("data: ")) {
      data += line.slice("data: ".length);
    }
  }
  if (name) {
    events.push({ event: name, data: data ? JSON.parse(data) : {} });
  }
  return events;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage());
    return;
  }
  const candidates = await loadCandidates(args.source);
  const outputPaths = await writeTraceFixtureCandidates(candidates, args.outDir);
  console.log(JSON.stringify({ generated: outputPaths.length, outputPaths }, null, 2));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
