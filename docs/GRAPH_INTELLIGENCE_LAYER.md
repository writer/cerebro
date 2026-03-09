# Graph Intelligence Layer

This document defines how Cerebro's graph becomes the organization's intelligence layer: decision-grade, evidence-backed, and action-oriented.

## Principles
- Every insight must be **decision-grade**: include evidence, confidence, coverage, and clear next actions.
- Every important recommendation should have a **counterfactual** path (what-if simulation).
- Query interfaces must serve both deterministic systems and agentic workflows.
- Confidence is not static: it must be adjusted by ontology coverage, schema conformance, and realized outcomes.

## Query Interfaces

### 1) Deterministic Insight API
Primary interface for product surfaces and automations.

Current endpoint:
- `GET /api/v1/graph/intelligence/insights`

Output characteristics:
- Prioritized `insights[]`
- `evidence[]` for each insight
- `confidence` and `coverage`
- Optional `counterfactual` simulation previews
- Embedded ontology health and outcome calibration context

### 2) Power Query API
Read-only, bounded graph exploration for analysts and advanced workflows.

Current endpoint:
- `GET /api/v1/graph/query`

Supported modes:
- `neighbors` (with direction + limits)
- `paths` (k-shortest paths with max depth)

Guardrails:
- Hard caps on `limit`, `k`, and `max_depth`
- Strict mode validation
- Explain metadata in responses

### 3) Agent/MCP-Ready Tool Surface
Agent workflows should call a curated tool surface, not raw graph internals.

Current tool:
- `cerebro.intelligence_report`

MCP adapter strategy:
- Wrap existing tool publisher protocol with MCP transport adapters.
- Keep tool contracts stable and deterministic.
- Enforce permission boundaries per tool/action.
- Preserve traceability: every response carries IDs/evidence references.

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
