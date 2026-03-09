# Graph Intelligence Layer TODO

Last updated: 2026-03-08 (America/Los_Angeles)
Owner: @haasonsaas
Execution mode: ship incrementally, keep CI green

## Phase 1 - Decision-grade intelligence outputs
- [x] Define execution plan and success criteria in-repo.
- [x] Implement `DecisionInsight` schema with evidence, confidence, and coverage fields.
- [x] Generate prioritized insights from risk, ontology health, and outcome feedback.
- [x] Add optional counterfactual previews (simulate likely high-impact fixes).
- [x] Add tests for deterministic ordering and stable insight IDs.

## Phase 2 - Query interfaces (future-proof)
- [x] Add deterministic API endpoint: `GET /api/v1/graph/intelligence/insights`.
- [x] Add power query API endpoint: `GET /api/v1/graph/query` (neighbors + k-shortest paths).
- [x] Add guardrails (limits, max depth, bounded k, strict query validation).
- [x] Add OpenAPI contracts for both endpoints.
- [x] Add API tests for success + invalid input paths.

## Phase 3 - Agent/MCP-ready interface
- [x] Add `cerebro.intelligence_report` tool in agent tool manifest.
- [x] Ensure payloads align with deterministic API semantics.
- [x] Add tool tests (happy path + invalid args).
- [x] Document MCP adapter strategy over existing tool publisher protocol.

## Phase 4 - Ontology and outcome loop hardening
- [x] Extend schema health report with actionable recommendations (coverage/conformance/drift).
- [x] Feed ontology health into intelligence insights as first-class evidence.
- [x] Include calibration/feedback signals from realized outcomes in confidence scoring.
- [x] Add tests validating ontology debt surfaces in top insights.

## Phase 5 - Expand graph into org intelligence layer
- [x] Publish deep expansion roadmap doc (data domains, provenance, freshness, ownership).
- [x] Define next ingestion priorities:
  - [x] Control-plane + runtime join keys for end-to-end blast radius.
  - [x] Identity resolution graph (human/service/workload lifecycle joins).
  - [x] Collaboration graph enrichments (code/review/incident/meeting/calendar/chat).
  - [x] Business topology graph (customers, revenue flows, critical journeys, SLAs).
- [x] Define confidence model upgrades:
  - [x] Coverage-aware confidence penalties.
  - [x] Evidence recency weighting.
  - [x] Outcome-calibrated signal reliability weights.
- [x] Define write-back loop:
  - [x] Decision capture (accepted/rejected remediation, reason).
  - [x] Post-remediation verification tasks.
  - [x] Continuous model recalibration.

## Validation and delivery
- [x] `gofmt` all changed files.
- [x] Run targeted tests for graph/api/app changes.
- [x] Run `make openapi-check`.
- [x] Run `go test ./... -count=1`.
- [x] Run gosec + golangci-lint.
- [x] Push branch and monitor CI to completion.
