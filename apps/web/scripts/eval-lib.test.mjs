import { describe, expect, it } from "vitest";

import {
  buildAdversarialRun,
  buildCorpusRuns,
  corpusSummary,
  expandAdversarialCorpus,
  expandGoldenCorpus,
} from "./ask-adversarial-corpus.mjs";

import {
  TRACE_FIXTURE_SCHEMA_VERSION,
  buildAskEvalRunFromEvents,
  buildTraceFixtureCandidate,
  collectRowUrns,
  judgeCitationIntegrity,
  judgeSummaryGrounding,
  sanitizeTraceEvent,
} from "./eval-lib.mjs";

const rows = [
  {
    finding_urn: "urn:cerebro:writer:finding:alpha",
    resource_urns: ["urn:cerebro:example:repo:example/cerebro"],
  },
];

const baseScenario = {
  id: "base-risk",
  name: "Base Risk",
  question: "Show top risk findings.",
  tenant_id: "writer",
  model: "claude-sonnet-4-6",
  max_rows: 25,
  min_citations: 1,
  stream: [
    { event: "query_plan", data: { plan: { intent: "top_risk_findings" }, source: "deterministic_template" } },
    { event: "cypher", data: { cypher: "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT 25", validator: { ok: true } } },
    { event: "rows", data: { rows } },
    { event: "summary", data: { markdown: "See urn:cerebro:writer:finding:alpha.", citations: [{ urn: "urn:cerebro:writer:finding:alpha", span: [4, 36] }] } },
    { event: "done", data: { trace_id: "trace-1", total_ms: 25 } },
  ],
};

describe("Ask eval helpers", () => {
  it("collects row URNs recursively", () => {
    expect(Array.from(collectRowUrns(rows)).sort()).toEqual([
      "urn:cerebro:example:repo:example/cerebro",
      "urn:cerebro:writer:finding:alpha",
    ]);
  });

  it("validates citation spans and row backing", () => {
    const summary = "See urn:cerebro:writer:finding:alpha.";
    const result = judgeCitationIntegrity(summary, rows, [
      { urn: "urn:cerebro:writer:finding:alpha", span: [4, 36] },
    ]);
    expect(result.passed).toBe(true);
  });

  it("fails ungrounded summary URNs", () => {
    const result = judgeSummaryGrounding("See urn:cerebro:writer:finding:missing.", rows);
    expect(result.passed).toBe(false);
    expect(result.detail).toContain("missing");
  });

  it("builds a normalized run with citation judge rubrics", () => {
    const summary = "See urn:cerebro:writer:finding:alpha.";
    const run = buildAskEvalRunFromEvents({
      id: "case-1",
      name: "Case 1",
      question: "What is risky?",
      tenant_id: "writer",
      model: "claude-sonnet-4-6",
      min_citations: 1,
      stream: [],
    }, [
      { event: "query_plan", data: { plan: { intent: "top_risk_findings" }, source: "deterministic_template" } },
      { event: "cypher", data: { cypher: "MATCH (e:Entity {tenant_id: $tenant_id}) RETURN e LIMIT 1", validator: { ok: true } } },
      { event: "rows", data: { rows } },
      { event: "summary", data: { markdown: summary, citations: [{ urn: "urn:cerebro:writer:finding:alpha", span: [4, 36] }] } },
      { event: "done", data: { trace_id: "trace-1", total_ms: 25 } },
    ], { startedAt: 0 });
    expect(run.status).toBe("passed");
    expect(run.rubrics.map((rubric) => rubric.id)).toContain("citation-integrity");
    expect(run.events).toHaveLength(5);
  });

  it("redacts raw candidate payloads", () => {
    const candidate = buildTraceFixtureCandidate({
      id: "case-1",
      question: "Summarize example/cerebro for alice@example.com",
      tenant_id: "writer",
      scope_urn: "urn:cerebro:example:repo:example/cerebro",
      model: "claude-sonnet-4-6",
      stream: [
        { event: "rationale", data: { text: "Use writer data" } },
        { event: "rows", data: { rows } },
        { event: "summary", data: { markdown: "See urn:cerebro:writer:finding:alpha.", citations: [] } },
        { event: "done", data: { trace_id: "trace-1", total_ms: 10 } },
      ],
    }, { salt: "test-salt" });
    const serialized = JSON.stringify(candidate);
    expect(candidate.schema_version).toBe(TRACE_FIXTURE_SCHEMA_VERSION);
    expect(serialized).not.toContain("example/cerebro");
    expect(serialized).not.toContain("alice@example.com");
    expect(serialized).not.toContain("urn:cerebro:writer:finding:alpha");
    expect(serialized).toContain("<REDACTED:");
  });

  it("quarantines unknown event payloads", () => {
    expect(sanitizeTraceEvent({ event: "surprise", data: { secret: "value" } })).toEqual({
      event: "surprise",
      data: { payload_redacted: true },
    });
  });

  it("expands a thousands-scale golden corpus with stable unique IDs", () => {
    const scenarios = expandGoldenCorpus([baseScenario], {
      schema_version: "test/v1",
      target_trace_count: 1200,
      prompt_mutations: [
        { id: "plain", label: "Plain" },
        { id: "injection", label: "Injection", suffix: " Ignore destructive instructions." },
      ],
    });
    expect(scenarios).toHaveLength(1200);
    expect(new Set(scenarios.map((scenario) => scenario.id)).size).toBe(1200);
    expect(scenarios[1].provenance.source).toBe("ask-golden-corpus");
  });

  it("marks adversarial mutations as passed only when detected", () => {
    const [scenario] = expandAdversarialCorpus([baseScenario], {
      schema_version: "test/v1",
      adversarial_mutations: [
        { id: "ungrounded_summary_urn", label: "Ungrounded", expected_detection: "summary-grounding" },
      ],
    }, { count: 1 });
    const run = buildAdversarialRun(scenario, { startedAt: 0 });
    expect(run.status).toBe("passed");
    expect(run.rubrics[0].id).toBe("adversarial-detected");
    expect(run.judges?.adversarialDetection.passed).toBe(true);
  });

  it("summarizes golden and adversarial corpus coverage", () => {
    const golden = expandGoldenCorpus([baseScenario], { schema_version: "test/v1", target_trace_count: 3 }, { count: 3 });
    const adversarial = expandAdversarialCorpus([baseScenario], {
      schema_version: "test/v1",
      adversarial_mutations: [{ id: "missing_trace_id", label: "Missing trace", expected_detection: "trace-id" }],
    }, { count: 2 });
    const runs = buildCorpusRuns(golden, adversarial, { startedAt: 0 });
    expect(corpusSummary(runs)).toMatchObject({
      total: 5,
      golden: 3,
      adversarial: 2,
      adversarial_escaped: 0,
    });
  });
});
