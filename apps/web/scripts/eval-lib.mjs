import { createHash, randomBytes } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

export const DEFAULT_OUT_DIR = ".eval-reports/ask";
export const DEFAULT_CANDIDATE_OUT_DIR = ".eval-reports/ask/candidates";
export const TRACE_FIXTURE_SCHEMA_VERSION = "cerebro.trace-fixture/v1";

export function assertLocalURL(raw, label) {
  const url = new URL(raw);
  const host = url.hostname.toLowerCase();
  if (host !== "localhost" && host !== "127.0.0.1" && host !== "::1") {
    throw new Error(`${label} must be localhost or a loopback IP, got ${raw}`);
  }
}

export function nowISO() {
  return new Date().toISOString();
}

export function stableHex(input, bytes) {
  return createHash("sha256").update(input).digest("hex").slice(0, bytes * 2);
}

export function randomHex(bytes) {
  return randomBytes(bytes).toString("hex");
}

export async function writeReport(report, outDir = DEFAULT_OUT_DIR) {
  await mkdir(outDir, { recursive: true });
  const filename = `ask-eval-${new Date(report.generatedAt).toISOString().replaceAll(":", "-")}.json`;
  const outputPath = path.join(outDir, filename);
  const withPath = { ...report, outputPath };
  await writeFile(outputPath, JSON.stringify(withPath, null, 2));
  await writeFile(path.join(outDir, "latest.json"), JSON.stringify(withPath, null, 2));
  if (outDir.startsWith(".eval-reports")) {
    const publicDir = path.join("public", "evals", path.basename(outDir));
    await mkdir(publicDir, { recursive: true });
    await writeFile(path.join(publicDir, "latest.json"), JSON.stringify(withPath, null, 2));
  }
  return withPath;
}

export function summaryFromEvents(events) {
  return events.find((event) => event.event === "summary")?.data?.markdown ?? "";
}

export function rowsFromEvents(events) {
  return events.find((event) => event.event === "rows")?.data?.rows ?? [];
}

export function citationsFromEvents(events) {
  return events.find((event) => event.event === "summary")?.data?.citations ?? [];
}

export function doneFromEvents(events) {
  return events.find((event) => event.event === "done")?.data ?? {};
}

export function cypherFromEvents(events) {
  return events.find((event) => event.event === "cypher")?.data ?? {};
}

export function queryPlanFromEvents(events) {
  return events.find((event) => event.event === "query_plan")?.data ?? {};
}

export function isReadOnlyCypher(cypher) {
  const normalized = String(cypher ?? "").toLowerCase();
  return !/\b(create|merge|delete|detach|set|remove|drop|call\s+dbms)\b/.test(normalized);
}

export function hasSchemaHallucination(cypher) {
  const text = String(cypher ?? "");
  if (text.trim() === "") return false;
  return /:\s*(Finding|FINDING|finding|repo|repository|identity|connector)\b/.test(text)
    || /:\s*(HAS_SOURCE|BELONGS_TO_SOURCE|HAS_FINDING|BELONGS_TO|IDENTITY_EMAIL)\b/.test(text)
    || /\bapoc\./i.test(text)
    || /entity_type\s*=\s*'Finding'/.test(text)
    || /entity_type\s*=\s*'(connector|source_runtime|runtime)'/i.test(text)
    || /entity_type\s+IN\s+\[[^\]]*'(connector|source_runtime|runtime)'/i.test(text)
    || /entity_type\s+CONTAINS\s+'(connector|runtime)'/i.test(text);
}

export function collectRowUrns(rows) {
  const urns = new Set();
  const visit = (value) => {
    if (typeof value === "string" && value.startsWith("urn:cerebro:")) {
      urns.add(value);
      return;
    }
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (value && typeof value === "object") {
      Object.values(value).forEach(visit);
    }
  };
  visit(rows);
  return urns;
}

export function urnsFromText(text) {
  return Array.from(String(text ?? "").matchAll(/urn:cerebro:[A-Za-z0-9_:@./#%+-]+/g), (match) =>
    match[0].replace(/[.,;:!?]+$/, ""),
  );
}

export function judgeCitationIntegrity(summary, rows, citations, expectedEntities = []) {
  const rowUrns = collectRowUrns(rows);
  const details = [];
  const seen = new Set();
  let passed = true;
  for (const citation of citations) {
    const urn = citation?.urn;
    const span = citation?.span;
    if (typeof urn !== "string" || !urn.startsWith("urn:cerebro:")) {
      passed = false;
      details.push("citation missing Cerebro URN");
      continue;
    }
    if (seen.has(urn)) {
      passed = false;
      details.push(`duplicate citation ${urn}`);
    }
    seen.add(urn);
    if (!rowUrns.has(urn) && !expectedEntities.includes(urn)) {
      passed = false;
      details.push(`citation ${urn} not present in rows`);
    }
    if (!Array.isArray(span) || span.length !== 2 || span[0] < 0 || span[1] <= span[0] || span[1] > summary.length) {
      passed = false;
      details.push(`citation ${urn} has invalid span`);
      continue;
    }
    if (summary.slice(span[0], span[1]) !== urn) {
      passed = false;
      details.push(`citation ${urn} span does not match summary text`);
    }
  }
  if (details.length === 0) {
    details.push(`${citations.length} citations validated`);
  }
  return { passed, detail: details.join("; ") };
}

export function judgeSummaryGrounding(summary, rows, expectedEntities = []) {
  const rowUrns = collectRowUrns(rows);
  const expected = new Set(expectedEntities.filter((entity) => String(entity).startsWith("urn:cerebro:")));
  const ungrounded = urnsFromText(summary).filter((urn) => !rowUrns.has(urn) && !expected.has(urn));
  return {
    passed: ungrounded.length === 0,
    detail: ungrounded.length === 0 ? "all Cerebro URNs in summary are row-backed" : `ungrounded URNs: ${ungrounded.join(", ")}`,
  };
}

export function rubricResults(scenario, events) {
  const summary = summaryFromEvents(events);
  const rows = rowsFromEvents(events);
  const citations = citationsFromEvents(events);
  const done = doneFromEvents(events);
  const cypher = cypherFromEvents(events);
  const queryPlan = queryPlanFromEvents(events);
  const streamOrder = events.map((event) => event.event).join(">");
  const expected = scenario.expected_entities ?? [];
  const citationJudge = judgeCitationIntegrity(summary, rows, citations, expected);
  const groundingJudge = judgeSummaryGrounding(summary, rows, expected);

  return [
    {
      id: "stream-shape",
      label: "stream reached terminal done/error",
      passed: events.some((event) => event.event === "done" || event.event === "error"),
      detail: streamOrder,
    },
    {
      id: "read-only-cypher",
      label: "Cypher is read-only or refused",
      passed: scenario.expect_refusal ? Boolean(done.cypher_refused) : isReadOnlyCypher(cypher.cypher),
      detail: scenario.expect_refusal ? `refused=${Boolean(done.cypher_refused)}` : String(cypher.cypher ?? "").slice(0, 160),
    },
    {
      id: "row-limit",
      label: "row count stays bounded",
      passed: rows.length <= (scenario.max_rows ?? 100),
      detail: `${rows.length} rows <= ${scenario.max_rows ?? 100}`,
    },
    {
      id: "schema-canonical",
      label: "Cypher uses canonical Cerebro schema",
      passed: scenario.expect_refusal ? Boolean(done.cypher_refused) : !hasSchemaHallucination(cypher.cypher),
      detail: scenario.expect_refusal ? "refusal path" : String(cypher.cypher ?? "").slice(0, 160),
    },
    {
      id: "query-plan",
      label: "query plan diagnostics are present",
      passed:
        Boolean(queryPlan.plan?.intent) &&
        (scenario.expect_conversion_diagnostics
          ? Array.isArray(queryPlan.diagnostics) && queryPlan.diagnostics.length > 0
          : true),
      detail: `${queryPlan.plan?.intent ?? "missing"} source=${queryPlan.source ?? "missing"}`,
    },
    {
      id: "citations",
      label: "required citations are present",
      passed: citations.length >= (scenario.min_citations ?? 0),
      detail: `${citations.length} citations >= ${scenario.min_citations ?? 0}`,
    },
    {
      id: "citation-integrity",
      label: "citations point at row-backed URNs and valid spans",
      passed: citationJudge.passed,
      detail: citationJudge.detail,
    },
    {
      id: "summary-grounding",
      label: "summary URNs are grounded in returned rows",
      passed: groundingJudge.passed,
      detail: groundingJudge.detail,
    },
    {
      id: "expected-entities",
      label: "summary or rows mention expected entities",
      passed: expected.every((entity) => JSON.stringify({ summary, rows }).includes(entity)),
      detail: expected.length ? expected.join(", ") : "no expected entities",
    },
    {
      id: "trace-id",
      label: "upstream trace id captured",
      passed: typeof done.trace_id === "string" && done.trace_id.length > 0,
      detail: done.trace_id ?? "missing",
    },
  ];
}

export function scoreRubrics(rubrics) {
  if (rubrics.length === 0) return 0;
  return Math.round((rubrics.filter((rubric) => rubric.passed).length / rubrics.length) * 100);
}

export function summaryDiff(baseline, current) {
  const baselineWords = String(baseline ?? "").split(/\s+/).filter(Boolean);
  const currentWords = String(current ?? "").split(/\s+/).filter(Boolean);
  const added = currentWords.filter((word) => !baselineWords.includes(word));
  const removed = baselineWords.filter((word) => !currentWords.includes(word));
  return { added: added.slice(0, 40), removed: removed.slice(0, 40), changed: added.length > 0 || removed.length > 0 };
}

export function buildAskEvalRunFromEvents(scenario, events, options = {}) {
  const startedAt = options.startedAt ?? Date.now();
  const rows = rowsFromEvents(events);
  const citations = citationsFromEvents(events);
  const done = doneFromEvents(events);
  const cypher = cypherFromEvents(events);
  const queryPlan = queryPlanFromEvents(events);
  const summary = summaryFromEvents(events);
  const rubrics = rubricResults(scenario, events);
  const score = scoreRubrics(rubrics);
  const status = rubrics.every((rubric) => rubric.passed) ? "passed" : "failed";
  const durationMs = Number(done.total_ms ?? Date.now() - startedAt);
  const completedAtMs = startedAt + durationMs;
  const baselineSummary = scenario.baseline_summary ?? scenario.expected_summary;
  return {
    id: scenario.id,
    kind: "ask",
    name: scenario.name,
    question: scenario.question,
    tenantId: scenario.tenant_id,
    model: scenario.model,
    scopeUrn: scenario.scope_urn,
    status,
    score,
    startedAt: new Date(startedAt).toISOString(),
    completedAt: new Date(completedAtMs).toISOString(),
    durationMs,
    traceId: done.trace_id,
    rowCount: rows.length,
    citationCount: citations.length,
    cypherRefused: Boolean(done.cypher_refused),
    queryPlanIntent: queryPlan.plan?.intent,
    queryPlanSource: queryPlan.source,
    queryPlanCorrected: Boolean(queryPlan.corrected),
    conversionDiagnosticsCount: Array.isArray(queryPlan.diagnostics) ? queryPlan.diagnostics.length : 0,
    summary,
    events,
    provenance: scenario.provenance ?? { source: "ask-eval-scenarios", generatedAt: nowISO() },
    fixtureKind: scenario.fixture_kind ?? "golden",
    baseline: baselineSummary ? { summary: baselineSummary } : undefined,
    diff: baselineSummary ? summaryDiff(baselineSummary, summary) : undefined,
    judges: {
      citationIntegrity: judgeCitationIntegrity(summary, rows, citations, scenario.expected_entities ?? []),
      summaryGrounding: judgeSummaryGrounding(summary, rows, scenario.expected_entities ?? []),
    },
    rubrics,
    cypherPreview: String(cypher.cypher ?? "").slice(0, 240),
  };
}

export function reportTotals(runs) {
  return {
    passed: runs.filter((run) => run.status === "passed").length,
    failed: runs.filter((run) => run.status === "failed").length,
    total: runs.length,
  };
}

export function stableHash(value, salt = "local") {
  return stableHex(`${salt}:${String(value ?? "")}`, 12);
}

export function redactedToken(label, value, salt = "local") {
  if (value === undefined || value === null || value === "") return undefined;
  return `<REDACTED:${label}:sha256=${stableHash(value, salt)}>`;
}

export function sanitizeTraceEvent(event, options = {}) {
  const salt = options.salt ?? "local";
  const data = event.data ?? {};
  switch (event.event) {
    case "query_plan":
      return {
        event: event.event,
        data: {
          intent: data.plan?.intent,
          source: data.source,
          deterministic: Boolean(data.deterministic),
          corrected: Boolean(data.corrected),
          diagnostics_count: Array.isArray(data.diagnostics) ? data.diagnostics.length : 0,
          diagnostic_codes: Array.isArray(data.diagnostics) ? data.diagnostics.map((diagnostic) => diagnostic.code).filter(Boolean) : [],
        },
      };
    case "cypher":
      return {
        event: event.event,
        data: {
          cypher_hash: redactedToken("cypher", data.cypher, salt),
          validator: data.validator ?? {},
        },
      };
    case "rows":
      return { event: event.event, data: { row_count: Array.isArray(data.rows) ? data.rows.length : 0, graph_present: Boolean(data.graph) } };
    case "summary":
      return {
        event: event.event,
        data: {
          summary_hash: redactedToken("summary", data.markdown, salt),
          citation_count: Array.isArray(data.citations) ? data.citations.length : 0,
          citation_urn_hashes: Array.isArray(data.citations) ? data.citations.map((citation) => redactedToken("urn", citation.urn, salt)) : [],
        },
      };
    case "rationale":
      return { event: event.event, data: { rationale_hash: redactedToken("rationale", data.text, salt) } };
    case "done":
      return { event: event.event, data: { trace_id_hash: redactedToken("trace", data.trace_id, salt), total_ms: data.total_ms, cypher_refused: Boolean(data.cypher_refused) } };
    case "progress":
      return { event: event.event, data: { stage: data.stage, elapsed_ms: data.elapsed_ms } };
    default:
      return { event: event.event ?? "unknown", data: { payload_redacted: true } };
  }
}

export function buildTraceFixtureCandidate(scenario, options = {}) {
  const salt = options.salt ?? randomHex(8);
  const events = scenario.stream ?? scenario.events ?? [];
  const rows = rowsFromEvents(events);
  const citations = citationsFromEvents(events);
  const done = doneFromEvents(events);
  const queryPlan = queryPlanFromEvents(events);
  return {
    schema_version: TRACE_FIXTURE_SCHEMA_VERSION,
    fixture_id: scenario.id,
    local_only: true,
    synthetic: Boolean(options.synthetic ?? true),
    provenance: {
      source: options.source ?? "ask-eval-scenarios",
      generated_at: nowISO(),
      source_trace_id_hash: redactedToken("trace", done.trace_id, salt),
    },
    request: {
      operation: "grc.ask",
      question_template: redactedToken("question", scenario.question, salt),
      model: scenario.model,
      tenant_hash: redactedToken("tenant", scenario.tenant_id, salt),
      scope_urn_hash: redactedToken("urn", scenario.scope_urn, salt),
      history_len: Array.isArray(scenario.history) ? scenario.history.length : 0,
    },
    events: events.map((event, index) => ({ seq: index + 1, ...sanitizeTraceEvent(event, { salt }) })),
    metrics: {
      duration_ms: Number(done.total_ms ?? 0),
      row_count: rows.length,
      citation_count: citations.length,
      cypher_refused: Boolean(done.cypher_refused),
      query_plan_intent: queryPlan.plan?.intent,
      query_plan_source: queryPlan.source,
      query_plan_corrected: Boolean(queryPlan.corrected),
    },
    redaction: {
      policy: "allowlist-v1",
      salt_hash: stableHash(salt, "manifest"),
      raw_payload_included: false,
      redacted_fields: ["tenant_id", "scope_urn", "question", "history", "rationale", "cypher", "rows", "summary", "citations"],
    },
  };
}

export async function writeTraceFixtureCandidates(candidates, outDir = DEFAULT_CANDIDATE_OUT_DIR) {
  await mkdir(outDir, { recursive: true });
  const written = [];
  for (const candidate of candidates) {
    const filename = `${candidate.fixture_id}-${new Date(candidate.provenance.generated_at).toISOString().replaceAll(":", "-")}.json`;
    const outputPath = path.join(outDir, filename);
    await writeFile(outputPath, JSON.stringify({ ...candidate, outputPath }, null, 2));
    written.push(outputPath);
  }
  return written;
}
