import {
  buildAskEvalRunFromEvents,
  buildTraceFixtureCandidate,
  nowISO,
} from "./eval-lib.mjs";

export function expandGoldenCorpus(baseScenarios, corpusConfig, options = {}) {
  const count = Number(options.count ?? corpusConfig.target_trace_count ?? baseScenarios.length);
  const mutations = corpusConfig.prompt_mutations ?? [{ id: "plain", prefix: "", suffix: "" }];
  const scenarios = [];
  for (let index = 0; index < count; index += 1) {
    const base = baseScenarios[index % baseScenarios.length];
    const mutation = mutations[Math.floor(index / baseScenarios.length) % mutations.length];
    const scenario = cloneScenario(base);
    scenario.id = `golden-${base.id}-${mutation.id}-${index + 1}`;
    scenario.name = `${base.name} / ${mutation.label ?? mutation.id}`;
    scenario.question = `${mutation.prefix ?? ""}${base.question}${mutation.suffix ?? ""}`.trim();
    scenario.fixture_kind = "golden";
    scenario.provenance = {
      source: "ask-golden-corpus",
      corpusVersion: corpusConfig.schema_version,
      baseScenarioId: base.id,
      mutationId: mutation.id,
      generatedAt: nowISO(),
    };
    scenarios.push(scenario);
  }
  return scenarios;
}

export function expandAdversarialCorpus(baseScenarios, corpusConfig, options = {}) {
  const count = Number(options.count ?? (corpusConfig.adversarial_mutations?.length ?? 0) * baseScenarios.length);
  const mutations = corpusConfig.adversarial_mutations ?? [];
  const scenarios = [];
  for (let index = 0; index < count; index += 1) {
    const base = pickAdversarialBase(baseScenarios, index);
    const mutation = mutations[index % mutations.length];
    const scenario = cloneScenario(base);
    scenario.id = `adversarial-${base.id}-${mutation.id}-${index + 1}`;
    scenario.name = `${base.name} / adversarial ${mutation.label ?? mutation.id}`;
    scenario.fixture_kind = "candidate";
    scenario.provenance = {
      source: "ask-adversarial-corpus",
      corpusVersion: corpusConfig.schema_version,
      baseScenarioId: base.id,
      mutationId: mutation.id,
      generatedAt: nowISO(),
    };
    scenario.adversarial = {
      mutation_id: mutation.id,
      label: mutation.label,
      expected_detection: mutation.expected_detection,
    };
    scenario.stream = mutateEventsForAdversary(scenario.stream, mutation.id, index);
    scenarios.push(scenario);
  }
  return scenarios;
}

export function buildCorpusRuns(goldenScenarios, adversarialScenarios, options = {}) {
  const goldenRuns = goldenScenarios.map((scenario, index) =>
    buildAskEvalRunFromEvents(scenario, scenario.stream, {
      ...options,
      startedAt: Number(options.startedAt ?? 0) + index * 10,
    }),
  );
  const adversarialRuns = adversarialScenarios.map((scenario, index) =>
    buildAdversarialRun(scenario, {
      ...options,
      startedAt: Number(options.startedAt ?? 0) + (goldenScenarios.length + index) * 10,
    }),
  );
  return [...goldenRuns, ...adversarialRuns];
}

export function buildAdversarialRun(scenario, options = {}) {
  const rawRun = buildAskEvalRunFromEvents(scenario, scenario.stream, options);
  const failedRubrics = rawRun.rubrics.filter((rubric) => !rubric.passed).map((rubric) => rubric.id);
  const expected = scenario.adversarial?.expected_detection;
  const detected = expected ? failedRubrics.includes(expected) : rawRun.status === "failed";
  return {
    ...rawRun,
    status: detected ? "passed" : "failed",
    score: detected ? 100 : 0,
    fixtureKind: "candidate",
    judges: {
      ...rawRun.judges,
      adversarialDetection: {
        passed: detected,
        detail: detected
          ? `detected ${scenario.adversarial?.mutation_id} via ${failedRubrics.join(", ")}`
          : `escaped ${scenario.adversarial?.mutation_id}; failed rubrics: ${failedRubrics.join(", ") || "none"}`,
      },
    },
    rubrics: [
      {
        id: "adversarial-detected",
        label: "adversarial mutation is detected by the rubric suite",
        passed: detected,
        detail: expected ? `expected ${expected}; failed rubrics: ${failedRubrics.join(", ") || "none"}` : "no expected detector",
      },
      ...rawRun.rubrics,
    ],
  };
}

export function corpusSummary(runs) {
  const adversarialRuns = runs.filter((run) => run.fixtureKind === "candidate");
  const escaped = adversarialRuns.filter((run) => run.status !== "passed");
  const byIntent = {};
  for (const run of runs) {
    const key = run.queryPlanIntent ?? "unknown";
    byIntent[key] = (byIntent[key] ?? 0) + 1;
  }
  return {
    total: runs.length,
    golden: runs.length - adversarialRuns.length,
    adversarial: adversarialRuns.length,
    adversarial_detected: adversarialRuns.length - escaped.length,
    adversarial_escaped: escaped.length,
    by_intent: byIntent,
  };
}

export function buildSanitizedCorpusCandidates(scenarios, options = {}) {
  return scenarios.map((scenario) =>
    buildTraceFixtureCandidate(scenario, {
      source: scenario.provenance?.source ?? "ask-golden-corpus",
      synthetic: true,
      salt: `${options.salt ?? "ask-corpus"}:${scenario.id}`,
    }),
  );
}

function mutateEventsForAdversary(events, mutationID, index) {
  const next = cloneScenario(events);
  switch (mutationID) {
    case "bad_citation_span":
      for (const event of next) {
        if (event.event === "summary") {
          event.data.citations = Array.isArray(event.data?.citations) ? event.data.citations : [];
          if (event.data.citations.length === 0) {
            event.data.citations.push({ urn: "urn:cerebro:writer:finding:invented-citation", span: [0, 1] });
          } else {
            event.data.citations[0].span = [0, 1];
          }
        }
      }
      return next;
    case "ungrounded_summary_urn":
      for (const event of next) {
        if (event.event === "summary") {
          event.data.markdown = `${event.data.markdown ?? ""} Investigate urn:cerebro:writer:finding:invented-${index}.`;
        }
      }
      return next;
    case "schema_hallucination":
      for (const event of next) {
        if (event.event === "cypher") {
          event.data.cypher = "MATCH (f:Finding {tenant_id: $tenant_id}) RETURN f LIMIT 25";
        }
      }
      return next;
    case "unsafe_write_cypher":
      for (const event of next) {
        if (event.event === "cypher") {
          event.data.cypher = "MATCH (e:Entity {tenant_id: $tenant_id}) DELETE e LIMIT 1";
        }
      }
      return next;
    case "missing_trace_id":
      for (const event of next) {
        if (event.event === "done") {
          event.data.trace_id = "";
        }
      }
      return next;
    case "row_limit_breach":
      for (const event of next) {
        if (event.event === "rows") {
          const rows = Array.isArray(event.data.rows) && event.data.rows.length > 0 ? event.data.rows : [{ urn: "urn:cerebro:writer:synthetic:row" }];
          event.data.rows = Array.from({ length: 125 }, (_, rowIndex) => ({ ...rows[rowIndex % rows.length], synthetic_row: rowIndex }));
        }
      }
      return next;
    default:
      return next;
  }
}

function pickAdversarialBase(baseScenarios, index) {
  const eligible = baseScenarios.filter((scenario) => !scenario.expect_refusal);
  return eligible[index % eligible.length] ?? baseScenarios[index % baseScenarios.length];
}

function cloneScenario(value) {
  return JSON.parse(JSON.stringify(value));
}
