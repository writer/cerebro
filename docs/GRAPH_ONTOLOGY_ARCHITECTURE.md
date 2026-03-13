# Graph Ontology Architecture

This document describes how Cerebro's graph ontology should be structured and evolved so the graph remains a durable intelligence substrate, not just a collection of one-off entity types.

## Design Goals

- Encode real-world operational domains with explicit node and edge semantics.
- Keep provenance and temporal metadata uniform across all write paths.
- Make ingestion breadth additive: new sources should map into existing ontology first.
- Preserve query stability: higher-level interfaces should target semantic kinds, not source-specific IDs.

## Ontology Layers

### 1) Foundation Layer

Core identity and infrastructure backbone used by most traversals:

- Identity: `person`, `user`, `role`, `group`, `service_account`, `identity_alias`
- Infra resources: `organization`, `folder`, `project`, `service`, `workload`, `database`, `bucket`, `secret`, `function`, `network`, `application`
- Access edges: `can_read`, `can_write`, `can_admin`, `can_assume`, `member_of`, `alias_of`

### 2) Operational Activity Layer

First-class kinds for high-frequency organizational operations:

- `pull_request`
- `deployment_run`
- `pipeline_run`
- `check_run`
- `meeting`
- `document`
- `communication_thread`
- `incident`

These kinds intentionally replace ambiguous "activity-only" modeling for primary operational events.

### 3) Decision Intelligence Layer

Closed-loop reasoning surfaces:

- Nodes: `decision`, `action`, `evidence`, `outcome`
- Edges: `targets`, `based_on`, `executed_by`, `evaluates`

This layer captures what the organization decided, why, what was executed, and what result occurred.

### 4) World-Model Knowledge Layer

First-class truth and contradiction handling:

- Nodes: `claim`, `source`, `observation`, `evidence`
- Edges: `asserted_by`, `based_on`, `supports`, `refutes`, `supersedes`, `contradicts`

This layer separates entities from assertions about those entities so Cerebro can retain provenance, disagreement, and correction history without flattening everything into one mutable node state.

## Metadata Contract

All graph writes should include the same temporal and provenance fields:

- `source_system`
- `source_event_id`
- `observed_at`
- `valid_from`
- `valid_to` (optional)
- `recorded_at`
- `transaction_from`
- `transaction_to` (optional)
- `confidence`

To enforce consistency, use the graph-level helper:

- `graph.NormalizeWriteMetadata(...)`
- `WriteMetadata.ApplyTo(...)`
- `WriteMetadata.PropertyMap()`

API handlers, tool writeback handlers, and graph actuation flows should all normalize metadata through this contract.

Generated ontology snapshot:

- `docs/GRAPH_ONTOLOGY_AUTOGEN.md` (via `go run ./scripts/generate_graph_ontology_docs/main.go`)
- Includes node metadata profile matrix (required keys, timestamp keys, enum constraints).
- `docs/CLOUDEVENTS_AUTOGEN.md` (via `go run ./scripts/generate_cloudevents_docs/main.go`) for event envelope and mapping-level contract extraction.
- `docs/CLOUDEVENTS_CONTRACTS.json` for machine-readable event/mapping contracts and per-mapping generated data schemas.
- `go run ./scripts/check_cloudevents_contract_compat/main.go` to enforce required-key/enum compatibility with versioning discipline.
- External benchmark references: `docs/GRAPH_ONTOLOGY_EXTERNAL_PATTERNS.md`
- World-model target state and implemented claim substrate: `docs/GRAPH_WORLD_MODEL_ARCHITECTURE.md`

## Ingestion Mapping Strategy

`internal/graphingest/mappings.yaml` should follow these rules:

- Prefer specific ontology kinds when the domain has stable semantics.
- Reserve generic `activity` only for unknown/unstructured fallback ingestion paths.
- Keep ID shape deterministic and source-scoped (`pull_request:{repo}:{number}`, `meeting:{id}`, etc.).
- Use `{{resolve(...)}}` for identity references whenever available.
- Avoid source-specific edge names when a canonical edge kind already exists.
- Always rely on mapper-injected temporal/provenance defaults unless the event provides stronger values.
- Run mapper validation in `enforce` mode by default and dead-letter invalid writes for replay/debugging.
- Maintain fixture-driven mapper contract tests (`internal/graphingest/testdata/mapper_contracts.json`) so CI catches ontology regressions per source.
- Monitor mapper runtime counters and DLQ tail health through `GET /api/v1/graph/ingest/health`.
- Use `cerebro ingest replay-dead-letter` to replay previously rejected events after ontology/mapping fixes.

## Query and Intelligence Usage

The query surface should target semantic kinds instead of source formats:

- Example: "all stale `deployment_run` nodes targeting `service:payments`"
- Example: "all `incident` nodes without recent `evidence` updates"

Intelligence surfaces should use this ontology directly:

- Leverage report domain coverage by kind family (identity, operational activity, closed loop).
- Claim conflict intelligence over `subject_id` + `predicate` groups with source/evidence supportability checks.
- Calibration/reporting on decision-to-outcome closure segmented by operational kind.
- Recommendations grounded in missing links between operational events and decisions/outcomes.

## Evolution Rules

When adding a new kind:

1. Add `NodeKind` constant.
2. Register built-in schema definition with required properties and relationships.
3. Add or update mapper rules to emit that kind.
4. Add schema and mapper tests.
5. Update this doc and `GRAPH_INTELLIGENCE_LAYER.md`.

When adding a new edge:

1. Add `EdgeKind` constant.
2. Register edge kind in built-ins.
3. Add relationship allowances on source node definitions.
4. Add validation tests for allowed/disallowed relationships.

## Review Checklist

Before merging ontology changes, confirm:

- New writes pass schema validation in current mode.
- Temporal/provenance metadata is present on nodes and edges.
- Query templates and intelligence outputs still operate on canonical kinds.
- OpenAPI/tool contracts remain backward compatible where required.
- Docs and tests are updated alongside code.
