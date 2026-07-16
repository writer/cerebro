#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { stableHash } from "./eval-lib.mjs";

const defaultPrompts = [
  {
    id: "live-findings-by-source",
    name: "Live-backed finding source aggregation",
    question: "Count findings by source family.",
    max_rows: 25,
  },
  {
    id: "live-top-risk-findings",
    name: "Live-backed top risk findings",
    question: "Show the top risk findings.",
    max_rows: 25,
    min_citations: 1,
  },
  {
    id: "live-identity-bridge",
    name: "Live-backed identity bridge",
    question: "Which identities bridge Okta and GitHub accounts?",
    max_rows: 50,
    min_citations: 1,
  },
  {
    id: "live-connector-health-empty",
    name: "Live-backed connector health empty result",
    question: "Show source health and freshness for security integrations.",
    max_rows: 25,
  },
];

function parseArgs(argv) {
  const args = {
    apiBase: process.env.CEREBRO_API_BASE,
    apiKey: process.env.CEREBRO_API_KEY,
    tenantId: process.env.CEREBRO_ASK_TENANT_ID ?? "example",
    output: "scripts/fixtures/ask-live-golden-scenarios.json",
    model: "claude-sonnet-4-6",
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--api-base") args.apiBase = argv[++index];
    else if (arg === "--api-key") args.apiKey = argv[++index];
    else if (arg === "--tenant-id") args.tenantId = argv[++index];
    else if (arg === "--model") args.model = argv[++index];
    else if (arg === "--out") args.output = argv[++index];
    else if (arg === "--help") args.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return args;
}

function usage() {
  return `Usage:
  CEREBRO_API_BASE=http://127.0.0.1:8080 CEREBRO_API_KEY=... npm run eval:ask:harvest-live-goldens

The harvester calls a configured read-only /grc/ask endpoint, then writes a
syntheticized fixture. Raw live rows, labels, tenant IDs, trace IDs, summaries,
and URNs are not written.`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage());
    return;
  }
  if (!args.apiBase) {
    throw new Error("CEREBRO_API_BASE or --api-base is required");
  }
  if (!args.apiKey) {
    throw new Error("CEREBRO_API_KEY or --api-key is required");
  }
  const apiKey = args.apiKey;
  const scenarios = [];
  const observations = [];
  for (const prompt of defaultPrompts) {
    const events = await ask(args.apiBase, apiKey, {
      tenant_id: args.tenantId,
      question: prompt.question,
      model: args.model,
    });
    const refused = Boolean(events.find((event) => event.event === "done")?.data?.cypher_refused);
    if (refused && !prompt.expect_refusal) {
      observations.push({
        id: prompt.id,
        skipped: true,
        reason: "live_refusal",
        intent: events.find((event) => event.event === "query_plan")?.data?.plan?.intent,
      });
      continue;
    }
    const scenario = syntheticScenarioFromLive(prompt, events, args);
    scenarios.push(scenario);
    observations.push({
      id: scenario.id,
      intent: scenario.stream.find((event) => event.event === "query_plan")?.data?.plan?.intent,
      row_count: scenario.stream.find((event) => event.event === "rows")?.data?.rows?.length ?? 0,
      citation_count: scenario.stream.find((event) => event.event === "summary")?.data?.citations?.length ?? 0,
      refused: Boolean(scenario.stream.find((event) => event.event === "done")?.data?.cypher_refused),
    });
  }
  await mkdir(path.dirname(args.output), { recursive: true });
  await writeFile(args.output, `${JSON.stringify(scenarios, null, 2)}\n`);
  console.log(JSON.stringify({ output: args.output, observations }, null, 2));
}

async function ask(apiBase, apiKey, request) {
  const response = await fetch(`${apiBase.replace(/\/+$/, "")}/grc/ask`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-cerebro-api-key": apiKey,
    },
    body: JSON.stringify(request),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`/grc/ask failed (${response.status}): ${text.slice(0, 200)}`);
  }
  return parseSSE(text);
}

function parseSSE(text) {
  const events = [];
  let name = "";
  let data = "";
  for (const line of text.split(/\r?\n/)) {
    if (line === "") {
      if (name) events.push({ event: name, data: data ? JSON.parse(data) : {} });
      name = "";
      data = "";
      continue;
    }
    if (line.startsWith("event: ")) name = line.slice("event: ".length);
    if (line.startsWith("data: ")) data += line.slice("data: ".length);
  }
  if (name) events.push({ event: name, data: data ? JSON.parse(data) : {} });
  return events;
}

function syntheticScenarioFromLive(prompt, events, args) {
  const maps = { urns: new Map(), values: new Map() };
  const queryPlan = clone(events.find((event) => event.event === "query_plan") ?? { event: "query_plan", data: {} });
  queryPlan.data.diagnostics = (queryPlan.data.diagnostics ?? []).map((diagnostic) => ({
    level: diagnostic.level,
    code: diagnostic.code,
    message: `Live-derived ${diagnostic.code} diagnostic.`,
  }));
  const cypher = clone(events.find((event) => event.event === "cypher") ?? { event: "cypher", data: { cypher: "", validator: { ok: false } } });
  const liveRows = clone(events.find((event) => event.event === "rows")?.data?.rows ?? []);
  const rows = liveRows.map((row) => syntheticRow(row, maps));
  const done = events.find((event) => event.event === "done")?.data ?? {};
  const summary = summaryFor(prompt, queryPlan.data?.plan?.intent, rows);
  const expectedEntities = [...new Set([
    ...rows.flatMap((row) => Object.values(row)).flatMap(flatten).filter((value) => typeof value === "string").slice(0, 4),
    ...summary.citations.map((citation) => citation.urn),
  ])].filter(Boolean);

  return {
    id: prompt.id,
    name: prompt.name,
    tenant_id: "example",
    model: args.model,
    question: prompt.question,
    expected_entities: expectedEntities,
    min_citations: prompt.min_citations ?? 0,
    max_rows: prompt.max_rows,
    live_observation: {
      source: "configured /grc/ask endpoint",
      observed_row_count: liveRows.length,
      observed_event_names: events.map((event) => event.event),
      observed_trace_hash: stableHash(done.trace_id, "live-trace"),
    },
    stream: [
      { event: "rationale", data: { text: `Live-derived ${queryPlan.data?.plan?.intent ?? "ask"} golden path from configured graph shape.` } },
      queryPlan,
      cypher,
      { event: "rows", data: { rows, graph: null, exec_ms: events.find((event) => event.event === "rows")?.data?.exec_ms ?? 0 } },
      { event: "summary", data: summary },
      { event: "done", data: { trace_id: `live-derived-${prompt.id}`, total_ms: done.total_ms ?? 0, cypher_refused: Boolean(done.cypher_refused) } },
    ].filter((event) => event.event !== "rows" || !done.cypher_refused),
  };
}

function summaryFor(prompt, intent, rows) {
  const firstURN = firstSyntheticURN(rows);
  if (firstURN) {
    const markdown = `${prompt.name} returned ${rows.length} live-shaped rows for ${intent}; inspect \`${firstURN}\`.`;
    const start = markdown.indexOf(firstURN);
    return { markdown, citations: [{ urn: firstURN, span: [start, start + firstURN.length] }] };
  }
  return {
    markdown: `${prompt.name} returned ${rows.length} live-shaped rows for ${intent}; broaden scope or verify connector freshness if needed.`,
    citations: [],
  };
}

function firstSyntheticURN(rows) {
  for (const value of flatten(rows)) {
    if (typeof value === "string" && value.startsWith("urn:cerebro:example:")) return value;
  }
  return "";
}

function syntheticRow(row, maps) {
  return Object.fromEntries(Object.entries(row).map(([key, value]) => [key, syntheticValue(key, value, maps)]));
}

function syntheticValue(key, value, maps) {
  if (value === null || value === undefined || typeof value === "boolean") return value;
  if (typeof value === "number") return syntheticNumber(key, value);
  if (Array.isArray(value)) return value.map((item) => syntheticValue(key, item, maps));
  if (typeof value === "object") return syntheticRow(value, maps);
  const text = String(value);
  if (text.startsWith("urn:cerebro:")) return syntheticURN(text, maps);
  if (/severity/i.test(key)) return text.toUpperCase();
  if (/source_family/i.test(key)) return syntheticToken("source_family", text, maps);
  if (/source_id/i.test(key)) return syntheticToken("source", text, maps);
  if (/runtime_id/i.test(key)) return syntheticToken("runtime", text, maps);
  if (/label|title|summary|owner|entity|principal/i.test(key)) return syntheticToken(key.replace(/[^a-z0-9]+/gi, "_").toLowerCase(), text, maps);
  return syntheticToken("value", text, maps);
}

function syntheticNumber(key, value) {
  const hashed = Number.parseInt(stableHash(`${key}:${value}`, "live-number").slice(0, 6), 16);
  if (/risk|score/i.test(key)) return 50 + (hashed % 50);
  if (/count|total/i.test(key)) return 1 + (hashed % 250);
  return hashed % 1000;
}

function syntheticURN(value, maps) {
  if (!maps.urns.has(value)) {
    const type = /finding/.test(value) ? "finding" : /identity/.test(value) ? "identity" : /source/.test(value) ? "source" : "entity";
    maps.urns.set(value, `urn:cerebro:example:${type}:${maps.urns.size + 1}`);
  }
  return maps.urns.get(value);
}

function syntheticToken(prefix, value, maps) {
  const key = `${prefix}:${value}`;
  if (!maps.values.has(key)) {
    maps.values.set(key, `${prefix}_${stableHash(value, "live-value").slice(0, 8)}`);
  }
  return maps.values.get(key);
}

function flatten(value) {
  if (Array.isArray(value)) return value.flatMap(flatten);
  if (value && typeof value === "object") return Object.values(value).flatMap(flatten);
  return [value];
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
