# Graph Intelligence Layer

This document defines how Cerebro's graph becomes the organization's intelligence layer: decision-grade, evidence-backed, and action-oriented.

See [GRAPH_ONTOLOGY_ARCHITECTURE.md](./GRAPH_ONTOLOGY_ARCHITECTURE.md) for ontology layering, extension workflow, and metadata contract details.

## Principles
- Every insight must be **decision-grade**: include evidence, confidence, coverage, and clear next actions.
- Every important recommendation should have a **counterfactual** path (what-if simulation).
- Query interfaces must serve both deterministic systems and agentic workflows.
- Confidence is not static: it must be adjusted by ontology coverage, schema conformance, recency freshness, and realized outcomes.

## Canonical Ontology Spine

### Node kinds
- `identity_alias`: provider-scoped external identities and aliases.
- `service`: durable software/business services.
- `workload`: runtime execution units (jobs, deploy units, pods, workers).
- `pull_request`: source-control change proposals with lifecycle state.
- `deployment_run`: deployment executions linked to services/workloads.
- `meeting`: calendar-driven operational coordination events.
- `document`: living knowledge artifacts and operational runbooks.
- `communication_thread`: threaded collaboration streams (for example Slack).
- `incident`: incident lifecycle entities for timeline/action correlation.
- `decision`: explicit organizational decisions.
- `outcome`: measured outcomes tied back to decisions.
- `evidence`: observations supporting decisions or risk insights.
- `action`: interventions and operational steps.

### Edge kinds
- `alias_of`: alias identity to canonical identity.
- `runs`: service to workload runtime relationship.
- `depends_on`: service/workload dependency relationship.
- `targets`: decision/action/evidence/outcome targeting relationship.
- `based_on`: decision relationship to supporting evidence.
- `executed_by`: decision relationship to implementation action.
- `evaluates`: outcome relationship back to decision/action.

All write surfaces must populate provenance and temporal metadata (`source_system`, `source_event_id`, `observed_at`, `valid_from`, optional `valid_to`, `confidence`) so ontology conformance and temporal traversal remain consistent.

## Query Interfaces

### 1) Deterministic Insight API
Primary interface for product surfaces and automations.

Current endpoint:
- `GET /api/v1/graph/intelligence/insights`
- `GET /api/v1/graph/intelligence/quality`
- `GET /api/v1/graph/intelligence/leverage`

Output characteristics:
- Prioritized `insights[]`
- `evidence[]` for each insight
- `confidence` and `coverage`
- `freshness` metrics and recency-sensitive confidence weighting
- Optional `counterfactual` simulation previews
- Embedded ontology health and outcome calibration context

Quality report characteristics:
- Top-line graph maturity score and grade.
- Ontology coverage/conformance and unknown-kind counts.
- Identity alias linkage quality.
- Temporal metadata completeness and freshness KPIs.
- Decision/outcome write-back closure rate.
- Prioritized recommendations with suggested remediation actions.

### 2) Power Query API
Read-only, bounded graph exploration for analysts and advanced workflows.

Current endpoint:
- `GET /api/v1/graph/query`
- `GET /api/v1/graph/query/templates`

Supported modes:
- `neighbors` (with direction + limits)
- `paths` (k-shortest paths with max depth)

Temporal scope:
- `as_of` (point-in-time graph view)
- `from` + `to` (windowed graph view)

Guardrails:
- Hard caps on `limit`, `k`, and `max_depth`
- Strict mode validation
- Explain metadata in responses

### 3) Write-Back API Surface
Graph intelligence compounds only when decisions and outcomes write back.

Current endpoints:
- `POST /api/v1/graph/write/observation`
- `POST /api/v1/graph/write/annotation`
- `POST /api/v1/graph/write/decision`
- `POST /api/v1/graph/write/outcome`
- `POST /api/v1/graph/identity/resolve`
- `POST /api/v1/graph/identity/split`
- `POST /api/v1/graph/identity/review`
- `GET /api/v1/graph/identity/calibration`
- `POST /api/v1/graph/actuate/recommendation`

### 4) Agent/MCP-Ready Tool Surface
Agent workflows should call a curated tool surface, not raw graph internals.

Current tools:
- `cerebro.intelligence_report`
- `cerebro.graph_quality_report`
- `cerebro.graph_leverage_report`
- `cerebro.graph_query`
- `cerebro.graph_query_templates`
- `cerebro.record_observation`
- `cerebro.annotate_entity`
- `cerebro.record_decision`
- `cerebro.record_outcome`
- `cerebro.resolve_identity`
- `cerebro.split_identity`
- `cerebro.identity_review`
- `cerebro.identity_calibration`
- `cerebro.actuate_recommendation`

MCP adapter strategy:
- Wrap existing tool publisher protocol with MCP transport adapters.
- Keep tool contracts stable and deterministic.
- Enforce permission boundaries per tool/action.
- Preserve traceability: every response carries IDs/evidence references.

## Identity Resolution Lifecycle
- Ingest each provider assertion as `identity_alias`.
- Score candidates using deterministic matches (email/id joins) plus heuristics (name similarity and hints).
- Auto-link high-confidence matches via `alias_of`.
- Return ranked candidates for ambiguous cases.
- Support split/reversal of incorrect merges (`identity/split`) and re-resolve.
- Persist reviewer decisions on alias history and expose calibration metrics (`precision`, `review_coverage`, `backlog`) for continuous quality control.

## Unified Leverage Surface
- `GET /api/v1/graph/intelligence/leverage` and `cerebro.graph_leverage_report` provide one combined operating view across:
  - ontology/quality maturity
  - ontology SLOs (`canonical_kind_coverage_percent`, `fallback_activity_percent`, `schema_valid_write_percent`) with trend samples
  - ingestion source breadth and gaps
  - identity linkage and review calibration
  - temporal freshness and recent activity coverage
  - closed-loop decision/outcome execution
  - predictive readiness and actuation readiness
  - action efficacy (`actions_with_outcomes`, `outcome_completion_rate_percent`, `median_outcome_latency_hours`, `stale_actions_without_outcome`)
- The leverage report includes prioritized recommendations so teams can sequence high-impact remediation work.

## Query Template Surface
- `GET /api/v1/graph/query/templates` and `cerebro.graph_query_templates` expose reusable investigations for common workflows (blast radius, incident windows, decision-outcome tracing, customer impact paths).
- Templates are intentionally temporal-capable (`as_of`, `from`, `to`) to keep investigations repeatable and time-bounded.

## Declarative Ingestion Mapper
The event mapper provides breadth without one-off ingestion code per source.

Core contract:
- Source selector (exact or wildcard event types).
- Node upsert templates.
- Edge upsert templates.
- Runtime identity canonicalization via `{{resolve(...)}}`.

Example:

```yaml
source: ensemble.tap.github.pull_request.merged
nodes:
  - id: "service:{{data.repository}}"
    kind: service
edges:
  - source: "{{resolve(data.merged_by_email)}}"
    target: "service:{{data.repository}}"
    kind: interacted_with
```

## Temporal Semantics
- Graph supports point-in-time and windowed traversal through node/edge `valid_from`/`valid_to` and observation timestamps.
- Query endpoints and tools can scope reads with `as_of` or `from`/`to`.
- Intelligence confidence is down-weighted when graph freshness degrades.

## Closed-Loop Intelligence Model
- Agents and APIs write observations, annotations, decisions, and outcomes.
- Outcomes evaluate prior decisions and feed calibration loops.
- Identity resolution and ingestion updates improve future graph context.
- Every write strengthens the next intelligence report.

## Expansion Priorities

### Data Domains to Add
- Identity lifecycle graph: hires, departures, role transitions, privileged grants.
- Runtime execution graph: workload identity, process behavior, runtime detections.
- Delivery graph: deploys, incidents, rollback history, ownership transitions.
- Collaboration graph: code review, incident response, meeting and communication pathways.
- Business topology graph: customer critical journeys, ARR dependencies, SLA surfaces.

### Ontology Expansion
- Increase dynamic kind registration for new systems before ingesting them.
- Extend capability tagging (`internet_exposable`, `stores_sensitive_data`, etc.) to all major kinds.
- Require key properties for high-impact entities (identity, secrets, data stores, internet entry points).
- Track ontology debt explicitly (unknown kinds, invalid relationships, missing required properties).

### Confidence Model Expansion
- Coverage-aware confidence penalties by domain.
- Recency weighting for stale evidence.
- Outcome-calibrated reliability by signal family.
- Drift impact weighting for sudden topology changes.

### Closed-Loop Intelligence
- Capture decision outcomes (accepted/rejected recommendations and reason).
- Re-score recommendations post-remediation to measure realized impact.
- Feed outcomes back into rule, weight, and severity calibration.

## Near-Term Build Roadmap
- Add domain-level coverage reporting (identity/runtime/business slices).
- Add confidence decomposition in every insight (`coverage`, `calibration`, `recency`).
- Add policy and workflow triggers from top insights (ticket/task auto-generation).
- Add persistent query templates for repeatable investigations.
- Add signed provenance references for every high-severity recommendation.
