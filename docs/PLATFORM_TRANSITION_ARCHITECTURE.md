# Platform Transition Architecture

This document defines the architectural transition from a CSPM/security product with graph-like features into a domain-agnostic graph and intelligence platform where security remains the first major application surface.

Research inputs for this design are captured in [GRAPH_ONTOLOGY_EXTERNAL_PATTERNS.md](./GRAPH_ONTOLOGY_EXTERNAL_PATTERNS.md), especially the contract and metadata patterns taken from Backstage, DataHub, OpenMetadata, OpenLineage, and CloudEvents.

## 1. Executive Summary

Cerebro currently exposes one API contract for two distinct layers:

- a shared graph platform with ingest, ontology, identity, temporal/provenance, reasoning, and actuation primitives
- a security application that uses that platform for CSPM, identity governance, compliance, attack-path analysis, runtime detection/response, and remediation

Today those two layers are entangled. The result is that:

- general graph capabilities live beside security-specific workflows under `/api/v1/graph`
- org-intelligence endpoints also live inside `/api/v1/graph`
- several capabilities exist twice under different namespaces
- platform contracts still expose security-first language and too many untyped payloads

The target state is:

- `/api/v1/platform/*` for shared platform primitives
- `/api/v1/security/*` for CSPM/security application workflows
- `/api/v1/org/*` for organization-intelligence workflows
- `/api/v1/admin/*` for operational control-plane concerns

Additional boundary rule:

- org and security dynamics should default to report surfaces built on the shared graph, not new platform primitives
- examples include bus factor, coordination fragility, privilege concentration, blast-radius posture, and other derived analytics
- only promote those views into standalone resources when they require their own write lifecycle, durable IDs, approvals, or actuation semantics

This is an evolutionary refactor, not a rewrite. Existing CSPM flows should keep working, but when there are no known API consumers Cerebro should remove temporary aliases quickly instead of preserving drift indefinitely.

## 2. Current-State Diagnosis

### Inventory Summary

The current OpenAPI exposes 237 `/api/v1/*` paths. Of those, 47 sit under `/api/v1/graph`, but a meaningful fraction of those are not platform primitives. They are security or org application workflows.

### Current API Grouping

`Platform primitives`

- `/api/v1/platform/graph/queries`
- `/api/v1/platform/graph/templates`
- `/api/v1/platform/graph/diffs`
- `/api/v1/platform/graph/diffs/{diff_id}`
- `/api/v1/platform/graph/snapshots*`
- `/api/v1/graph/schema`
- `/api/v1/graph/schema/health`
- `/api/v1/graph/schema/register`
- `/api/v1/graph/ingest/*`
- `/api/v1/graph/write/*`
- `/api/v1/graph/identity/*`
- `/api/v1/graph/intelligence/quality`
- `/api/v1/graph/intelligence/metadata-quality`
- `/api/v1/graph/intelligence/claim-conflicts`
- `/api/v1/graph/intelligence/calibration/weekly`
- `/api/v1/graph/evaluate-change`
- `/api/v1/graph/simulate`

`Analytic programs that need sharper classification before entering platform v1`

- `/api/v1/impact-analysis`
- `/api/v1/entities/{id}/cohort`
- `/api/v1/entities/{id}/outlier-score`

These should be treated as report programs over the graph until proven to be reusable primitives. The same rule applies to most org-dynamics and security-dynamics outputs.

`Security application endpoints`

- `/api/v1/assets/*`
- `/api/v1/policies*`
- `/api/v1/findings*`
- `/api/v1/compliance/*`
- `/api/v1/identity/*`
- `/api/v1/attack-paths*`
- `/api/v1/graph/attack-paths*`
- `/api/v1/graph/blast-radius/*`
- `/api/v1/graph/cascading-blast-radius/*`
- `/api/v1/graph/reverse-access/*`
- `/api/v1/graph/privilege-escalation/*`
- `/api/v1/graph/toxic-combinations`
- `/api/v1/graph/chokepoints`
- `/api/v1/graph/peer-groups`
- `/api/v1/graph/effective-permissions/*`
- `/api/v1/graph/compare-permissions`
- `/api/v1/runtime/*`
- `/api/v1/threatintel/*`
- `/api/v1/remediation/*`
- `/api/v1/reports/*`
- `/api/v1/lineage/*`
- `/api/v1/incidents*`
- `/api/v1/tickets*`

`Org/application-specific endpoints`

- `/api/v1/graph/who-knows`
- `/api/v1/graph/recommend-team`
- `/api/v1/graph/simulate-reorg`
- `/api/v1/org/information-flow`
- `/api/v1/org/clock-speed`
- `/api/v1/org/recommended-connections`
- `/api/v1/org/onboarding/{id}/plan`
- `/api/v1/org/meeting-insights`
- `/api/v1/org/meetings/{id}/analysis`

`Admin/ops endpoints`

- `/api/v1/admin/*`
- `/api/v1/providers/*`
- `/api/v1/sync/*`
- `/api/v1/scheduler/*`
- `/api/v1/audit`
- `/api/v1/webhooks*`
- `/api/v1/notifications*`
- `/api/v1/slack/commands`
- `/api/v1/telemetry/ingest`
- `/api/v1/rbac/*`

### Architectural Problems

1. Platform and application boundaries are mixed.
   - `/api/v1/graph` contains graph primitives, security analytics, access-review workflows, and org-intelligence capabilities.

2. Security concepts leak into shared abstractions.
   - The OpenAPI and user-facing graph responses still refer to a "security graph" even when the capability is clearly platform-level.
   - Many graph endpoints are effectively security analytics packaged as graph APIs.

3. Duplicate surfaces encode historical drift.
   - `/api/v1/policies/evaluate` and `/api/v1/policy/evaluate`
   - `/api/v1/identity/reviews/*` and `/api/v1/graph/access-reviews/*`
   - `/api/v1/attack-paths*` and `/api/v1/graph/attack-paths*`
   - `/api/v1/providers/{name}/sync` and `/api/v1/sync/*`

4. Read, simulate, and actuate concerns are mixed together.
   - Query endpoints, mutation simulation, write-back, and recommendation actuation all live under `/api/v1/graph` without a clear lifecycle model.

5. Contract quality is uneven.
   - Many important graph/platform endpoints still return `type: object` with `additionalProperties: true`.
   - Long-running or computationally expensive operations are not consistently modeled as jobs/executions.

6. Several endpoints are really views over the same primitive.
   - Blast radius, attack path, privilege escalation, toxic combination, and impact analysis are all specialized traversal or simulation programs over the same graph substrate.

7. Current top-level naming implies one product.
   - `assets`, `findings`, `compliance`, `runtime`, and `threatintel` are valid security application nouns, but they should not define the platform vocabulary.

### What The Current System Actually Is

Cerebro currently exposes one API contract for two distinct layers:

- a shared platform
- a security application

The transition work is to make that explicit in contracts, namespaces, and lifecycle boundaries.

## 3. Target Platform Model

### Namespace Decision

Use `/api/v1/platform/*` for all domain-agnostic shared primitives.

Rationale:

- not every shared primitive is a graph traversal; some are identity, ingest, schema, jobs, or actuation contracts
- it creates a clean home for future non-security applications without forcing them through a security-flavored `/graph` namespace
- `/api/v1/graph/*` may be preserved temporarily as compatibility aliases when there are real consumers, but exact replacement routes should be removed quickly when there are none

### Platform Resource Families

- `/api/v1/platform/graph/*`: graph reads, diffs, neighborhood/path/subgraph queries
- `/api/v1/platform/knowledge/*`: observations, evidence, claims, annotations, decisions, actions, outcomes
  - `/api/v1/platform/identity/*`: alias resolution, merge/split review, calibration
- `/api/v1/platform/schema/*`: ontology modules, health, registration, compatibility
- `/api/v1/platform/ingest/*`: contracts, validation, dead-letter, pipeline health
- `/api/v1/platform/intelligence/*`: quality, freshness, contradiction, coverage, calibration, report registries, benchmark/section contracts, and durable report execution history
- `/api/v1/platform/intelligence/*` also owns report-runtime execution control (`retry`, `cancel`) and compatibility-governed contract catalogs for reusable report surfaces
- `/api/v1/platform/simulations/*`: graph mutation simulation, scenario evaluation, change impact
- `/api/v1/platform/jobs/*`: async execution objects and status

`Note`

- `knowledge` is acceptable as the first resource family name, but it is carrying two different lifecycles today: fact-like records and workflow-like records.
- If permissions and audit semantics start diverging, split it into `/platform/facts/*` and `/platform/workflows/*` rather than letting one family accumulate too much meaning.
- Treat report execution as an internal runtime domain even if it remains exposed under `/platform/intelligence/*`; once retry, cancel, attempt history, and retention policy are all first-class, that logic should not stay scattered across unrelated handlers.

### Node Categories

| Category | Purpose | Typical kinds |
| --- | --- | --- |
| `actor` | human or machine principals that initiate or own activity | `person`, `user`, `service_account`, `team`, `organization` |
| `resource` | durable systems, infrastructure, data, or business assets | `service`, `workload`, `bucket`, `database`, `dataset`, `customer`, `facility` |
| `artifact` | authored or produced things | `document`, `ticket`, `policy`, `repository`, `image`, `contract` |
| `event` | things that happened | `deployment_run`, `meeting`, `runtime_event`, `incident`, `review`, `scan_execution` |
| `knowledge` | truth-carrying or evidence-carrying objects | `observation`, `evidence`, `claim`, `annotation` |
| `workflow` | closed-loop execution and governance | `decision`, `action`, `outcome`, `job`, `approval` |
| `governance` | normative or evaluative objects | `control`, `framework`, `risk`, `obligation`, `exception` |
| `external` | external signal or source authority | `source`, `provider`, `feed`, `indicator`, `advisory` |

### Edge Categories

| Category | Purpose | Example kinds |
| --- | --- | --- |
| `identity` | aliasing and canonicalization | `alias_of`, `same_as`, `merged_into` |
| `structural` | topology and composition | `part_of`, `runs_on`, `hosted_in`, `member_of`, `owned_by` |
| `access` | authorization and reachability | `can_read`, `can_write`, `can_admin`, `can_assume`, `granted_by` |
| `dependency` | causal and operational dependency | `depends_on`, `targets`, `built_from`, `derived_from`, `blocks` |
| `knowledge` | support and contradiction | `asserted_by`, `based_on`, `supports`, `refutes`, `contradicts`, `supersedes` |
| `workflow` | decision/action/outcome flow | `evaluates`, `approves`, `executes`, `results_in`, `mitigates` |
| `social` | organizational knowledge flow | `collaborates_with`, `consults`, `informs`, `bridges` |

### Canonical Concepts

#### Entity

Purpose:
Represent a durable object, actor, artifact, event, or governance object in the world model.

Required fields:

- `id`
- `kind`
- `category`
- `display_name`
- `provenance`
- `temporal`

Optional fields:

- `properties`
- `labels`
- `external_refs`
- `confidence`
- `state`

Invariants:

- `id` is stable and canonical within the graph platform.
- `kind` must be registered in the schema registry.
- `category` must match the registry definition for `kind`.
- entity writes are append-safe; hard deletes are administrative, not application-level.

Current security mapping:

- assets become entities in `resource`
- tickets become entities in `artifact`
- runtime events and incidents become entities in `event`
- controls/frameworks become entities in `governance`

#### Edge

Purpose:
Represent a typed relationship between two entities or between a knowledge object and its target.

Required fields:

- `id`
- `kind`
- `source_id`
- `target_id`
- `category`
- `provenance`
- `temporal`

Optional fields:

- `properties`
- `confidence`
- `state`

Invariants:

- source and target kinds must be allowed by the schema registry.
- edges with lifecycle semantics should be reified into first-class entities when evidence, approvals, or versioning matter.

Current security mapping:

- IAM permissions map to `access` edges
- cloud topology maps to `structural` and `dependency` edges
- attack path steps are projections over existing edges, not a new foundational edge category

#### Observation

Purpose:
Represent a raw source-level observation before normalization or adjudication.

Required fields:

- `id`
- `subject_id`
- `observation_type`
- `content`
- `provenance`
- `temporal`

Optional fields:

- `object_id`
- `object_value`
- `payload_ref`
- `confidence`

Invariants:

- observations are write-once and source-attributed
- observations do not replace higher-level claims; they support them

Current security mapping:

- runtime events, scan records, cloud configuration snapshots, and threat-intel feed entries all arrive first as observations

#### Evidence

Purpose:
Represent curated or grouped support material assembled from observations or external artifacts.

Required fields:

- `id`
- `evidence_type`
- `summary`
- `provenance`
- `temporal`

Optional fields:

- `observation_ids`
- `artifact_ids`
- `subject_id`
- `confidence`

Invariants:

- evidence must point to at least one observation, artifact, or external reference
- evidence can support or refute multiple claims

Current security mapping:

- control test results, runtime trace bundles, ticket attachments, and attack-path proofs become evidence objects

#### Claim

Purpose:
Represent a truth assertion about a subject/predicate/object or subject/predicate/value.

Required fields:

- `id`
- `subject_id`
- `predicate`
- one of `object_id` or `object_value`
- `status`
- `provenance`
- `temporal`

Optional fields:

- `claim_type`
- `summary`
- `source_id`
- `evidence_ids`
- `supporting_claim_ids`
- `refuting_claim_ids`
- `supersedes_claim_id`
- `confidence`

Invariants:

- a claim cannot have both an empty object reference and an empty scalar value
- competing active claims may coexist until resolved; contradiction is explicit, not overwritten
- claim truth is bitemporal: fact-time and system-time are both queryable

Current security mapping:

- findings become security application views over one or more claims such as `resource violates policy`, `principal can_admin resource`, or `control status = failed`
- threat intel assertions become claims supported by source and evidence nodes

#### Annotation

Purpose:
Represent analyst or agent commentary that should not be treated as a first-class truth claim.

Required fields:

- `id`
- `target_id`
- `body`
- `author`
- `provenance`
- `temporal`

Optional fields:

- `tags`
- `visibility`
- `related_claim_ids`

Invariants:

- annotations do not change canonical truth state on their own
- annotations may reference claims or evidence but are not substitutes for them

Current security mapping:

- finding notes, triage comments, and review comments become annotations

#### Decision

Purpose:
Represent a chosen course of action or adjudication.

Required fields:

- `id`
- `decision_type`
- `status`
- `target_ids`
- `made_by`
- `provenance`
- `temporal`

Optional fields:

- `rationale`
- `evidence_ids`
- `input_claim_ids`
- `input_simulation_id`
- `policy_ref`
- `confidence`

Invariants:

- decisions should reference the targets they govern
- decisions can be revised but not silently replaced; revision is represented through status change or superseding decision

Current security mapping:

- remediation approvals, access-review decisions, policy exception approvals, and incident decisions all map here

#### Action

Purpose:
Represent an intended or executed actuation step.

Required fields:

- `id`
- `action_type`
- `status`
- `target_ids`
- `provenance`
- `temporal`

Optional fields:

- `decision_id`
- `executor`
- `automation_ref`
- `job_id`
- `metadata`

Invariants:

- actions are operational records, not recommendations only
- actions may exist before execution and later link to execution jobs and outcomes

Current security mapping:

- remediation execution, ticket creation, response policy enablement, and provider write-back all map here

#### Outcome

Purpose:
Represent the observed result of a decision or action.

Required fields:

- `id`
- `outcome_type`
- `verdict`
- `decision_id` or `action_id`
- `provenance`
- `temporal`

Optional fields:

- `target_ids`
- `impact_score`
- `summary`
- `confidence`

Invariants:

- outcomes close the loop on decisions and actions
- outcomes should be linkable back to supporting observations and claims

Current security mapping:

- post-remediation success/failure, control pass/fail results, and incident postmortem outcomes map here

#### Provenance

Purpose:
Make every write attributable and auditable.

Required fields:

- `source_system`
- `source_record_id`
- `observed_at`
- `recorded_at`
- `transaction_from`

Optional fields:

- `valid_from`
- `valid_to`
- `transaction_to`
- `source_schema_url`
- `producer_fingerprint`
- `contract_version`
- `contract_api_version`
- `ingest_pipeline`
- `collector_job_id`
- `confidence`

Invariants:

- every platform write must carry both fact-time and system-time fields when the object represents a durable fact
- provenance fields are normalized centrally, not hand-built in handlers

Current security mapping:

- existing graph write metadata already provides the basis; it should become universal across all platform/application writes

#### Temporal Semantics

Purpose:
Support both historical truth and historical system state.

Required fields:

- `observed_at`
- `recorded_at`
- `transaction_from`

Optional fields:

- `valid_from`
- `valid_to`
- `transaction_to`

Invariants:

- `observed_at` is when the source says the observation occurred
- `valid_*` describes when the fact is true in the modeled world
- `recorded_at` and `transaction_*` describe what Cerebro knew and when

Current security mapping:

- snapshot diff, change evaluation, and post-incident analysis all become more correct when they query bitemporal state instead of only current state

#### Identity And Alias Model

Purpose:
Separate canonical entities from source-specific aliases and provide merge/split governance.

Required fields:

- canonical entity id
- alias entity id
- alias source metadata
- resolution status
- confidence score

Optional fields:

- matching features
- reviewer verdicts
- superseded merge refs
- split reason

Invariants:

- alias records are not discarded after merge; they remain evidence for how canonical identity was formed
- merge and split operations are reviewable workflow events

Current security mapping:

- identity resolution today should become the platform-wide alias resolution service, not a security-only feature

#### Schema Registry And Ontology Modules

Purpose:
Control kind registration, compatibility, allowed relationships, metadata profiles, and module ownership.

Required fields:

- `module`
- `api_version`
- `kind`
- `category`
- `required_properties`
- `allowed_edges`
- `metadata_profile`

Optional fields:

- `deprecation`
- `compatibility_notes`
- `generated_docs_ref`
- `examples`

Invariants:

- no platform or application write may emit an unregistered kind in enforce mode
- schema evolution must be versioned and compatibility-checked
- application modules may extend platform modules but may not redefine platform primitives incompatibly

Current security mapping:

- policy, finding, control, indicator, and incident kinds should become application modules layered on top of the same registry

## 4. Endpoint Reorganization Proposal

### Target Namespace Layout

`Platform`

- `GET /api/v1/platform/graph/queries`
- `POST /api/v1/platform/graph/queries`
- `POST /api/v1/platform/graph/diffs`
- `GET /api/v1/platform/graph/templates`
- `GET /api/v1/platform/intelligence/measures`
- `GET /api/v1/platform/intelligence/checks`
- `GET /api/v1/platform/intelligence/reports`
- `GET /api/v1/platform/intelligence/reports/{id}`
- `GET /api/v1/platform/intelligence/reports/{id}/runs`
- `POST /api/v1/platform/intelligence/reports/{id}/runs`
- `GET /api/v1/platform/intelligence/reports/{id}/runs/{run_id}`
- `GET /api/v1/platform/schema`
- `GET /api/v1/platform/schema/health`
- `POST /api/v1/platform/schema/modules`
- `GET /api/v1/platform/ingest/contracts`
- `GET /api/v1/platform/ingest/health`
- `GET /api/v1/platform/ingest/dead-letter`
- `POST /api/v1/platform/knowledge/observations`
- `POST /api/v1/platform/knowledge/evidence`
- `POST /api/v1/platform/knowledge/claims`
- `POST /api/v1/platform/knowledge/annotations`
- `POST /api/v1/platform/knowledge/decisions`
- `POST /api/v1/platform/knowledge/actions`
- `POST /api/v1/platform/knowledge/outcomes`
- `POST /api/v1/platform/identity/resolutions`
- `POST /api/v1/platform/identity/reviews`
- `POST /api/v1/platform/identity/splits`
- `GET /api/v1/platform/identity/calibration`
- `GET /api/v1/platform/intelligence/quality`
- `GET /api/v1/platform/intelligence/metadata-quality`
- `GET /api/v1/platform/intelligence/claim-conflicts`
- `GET /api/v1/platform/intelligence/calibration/weekly`
- `POST /api/v1/platform/simulations`
- `POST /api/v1/platform/simulations/change-evaluations`
- `POST /api/v1/platform/simulations/scenario-runs`
- `GET /api/v1/platform/jobs/{id}`

`Security`

- `GET /api/v1/security/assets`
- `GET /api/v1/security/findings`
- `GET /api/v1/security/findings/{id}`
- `POST /api/v1/security/findings/{id}:resolve`
- `POST /api/v1/security/findings/{id}:suppress`
- `GET /api/v1/security/policies`
- `POST /api/v1/security/policy-evaluations`
- `GET /api/v1/security/compliance/frameworks`
- `GET /api/v1/security/compliance/frameworks/{id}/report`
- `GET /api/v1/security/access-reviews`
- `POST /api/v1/security/access-reviews`
- `POST /api/v1/security/access-reviews/{id}:start`
- `POST /api/v1/security/access-reviews/{id}/items/{itemId}:decide`
- `GET /api/v1/security/attack-paths`
- `POST /api/v1/security/analyses/attack-paths/jobs`
- `POST /api/v1/security/analyses/blast-radius`
- `POST /api/v1/security/analyses/privilege-escalation`
- `POST /api/v1/security/analyses/toxic-combinations`
- `POST /api/v1/security/analyses/effective-permissions`
- `POST /api/v1/security/analyses/permission-comparisons`
- `POST /api/v1/security/analyses/reverse-access`
- `POST /api/v1/security/analyses/chokepoints`
- `POST /api/v1/security/analyses/peer-groups`
- `GET /api/v1/security/runtime/detections`
- `POST /api/v1/security/runtime/events`
- `GET /api/v1/security/runtime/findings`
- `GET /api/v1/security/threat-intel/feeds`
- `GET /api/v1/security/threat-intel/indicators/{type}/{value}`
- `GET /api/v1/security/remediation/rules`
- `GET /api/v1/security/remediation/executions`

`Org`

- `GET /api/v1/org/expertise/queries`
- `POST /api/v1/org/team-recommendations`
- `POST /api/v1/org/reorg-simulations`
- `GET /api/v1/org/information-flow`
- `GET /api/v1/org/clock-speed`
- `GET /api/v1/org/recommended-connections`
- `GET /api/v1/org/onboarding/{id}/plan`
- `GET /api/v1/org/meetings/insights`
- `GET /api/v1/org/meetings/{id}/analysis`

`Admin`

- `GET /api/v1/admin/health`
- `GET /api/v1/admin/audit`
- `GET /api/v1/admin/providers`
- `POST /api/v1/admin/providers/{name}:configure`
- `POST /api/v1/admin/providers/{name}:test`
- `POST /api/v1/admin/providers/{name}:sync`
- `GET /api/v1/admin/sync-jobs`
- `POST /api/v1/admin/sync-jobs`
- `GET /api/v1/admin/scheduler/jobs`
- `POST /api/v1/admin/scheduler/jobs/{name}:run`
- `GET /api/v1/admin/webhooks`
- `GET /api/v1/admin/notifications`
- `POST /api/v1/admin/telemetry/ingest`

### Endpoint Design Rules

1. Use nouns for primary resources.
   - Prefer `POST /policy-evaluations` over `/policy/evaluate`.

2. Use jobs as a core platform/control-plane primitive.
   - any operation expected to exceed 2 seconds p95 or fan out across more than one provider or source must expose an execution resource
   - provider syncs, graph rebuilds, scans, attack-path analysis, rule discovery, cross-tenant pattern building, and large simulations should return job resources
   - derived report executions should expose both platform job linkage and report-native execution history (`runs`, `attempts`, `events`) so job state does not become the only audit surface

3. Keep shared reasoning separate from vertical views.
   - platform simulation APIs return generic traversal, impact, and contradiction primitives
   - security attack-path or org reorg analysis becomes an application specialization that calls those primitives

4. Keep `/api/v1/graph/*` as temporary aliases only.
   - use deprecation headers and OpenAPI `deprecated: true` once the new platform paths exist

### Permission Model

The namespace split should map cleanly onto capability scopes instead of one growing permission blob.

Recommended initial scopes:

- `platform.graph.read`
- `platform.graph.write`
- `platform.schema.manage`
- `platform.identity.review`
- `platform.simulation.run`
- `platform.jobs.read`
- `security.findings.read`
- `security.findings.manage`
- `security.policies.manage`
- `security.remediation.approve`
- `security.analyses.run`
- `org.expertise.read`
- `org.reorg.run`
- `admin.providers.manage`
- `admin.sync.manage`

### Compatibility And Deprecation Policy

- Every renamed route gets a compatibility alias and a documented successor path.
- If request telemetry or direct operator knowledge confirms there are no consumers, skip the alias and remove the old route immediately.
- Compatibility aliases must emit deprecation headers and a concrete sunset date.
- Removal requires request telemetry showing successor-path adoption above the target threshold.
- The minimum support window should be one full minor release cycle or 90 days, whichever is longer.
- Aliases that still receive material traffic after the window ends require an explicit extension decision, not silent immortality.

### Eventing Model

Platform primitives should emit CloudEvents for downstream applications and automations.

Recommended baseline events:

- `cerebro.platform.claim.created`
- `cerebro.platform.decision.recorded`
- `cerebro.platform.action.executed`
- `cerebro.platform.outcome.recorded`
- `cerebro.platform.identity.merge-reviewed`
- `cerebro.platform.schema.module-registered`
- `cerebro.platform.job.completed`

## 5. Mapping Table

| Current endpoint / concept | Target layer | Target resource / primitive | Action |
| --- | --- | --- | --- |
| `/api/v1/graph/query` | platform | `/api/v1/platform/graph/queries` | rename |
| `/api/v1/platform/graph/diffs` | platform | `/api/v1/platform/graph/diffs` | keep |
| `/api/v1/graph/query/templates` | platform | `/api/v1/platform/graph/templates` | rename |
| `/api/v1/graph/schema` | platform | `/api/v1/platform/schema` | rename |
| `/api/v1/graph/schema/health` | platform | `/api/v1/platform/schema/health` | rename |
| `/api/v1/graph/schema/register` | platform | `/api/v1/platform/schema/modules` | rename |
| `/api/v1/graph/ingest/contracts` | platform | `/api/v1/platform/ingest/contracts` | rename |
| `/api/v1/graph/ingest/health` | platform | `/api/v1/platform/ingest/health` | rename |
| `/api/v1/graph/ingest/dead-letter` | platform | `/api/v1/platform/ingest/dead-letter` | rename |
| `/api/v1/graph/write/observation` | platform | `/api/v1/platform/knowledge/observations` | rename |
| `/api/v1/graph/write/claim` | platform | `/api/v1/platform/knowledge/claims` | rename |
| `/api/v1/graph/write/annotation` | platform | `/api/v1/platform/knowledge/annotations` | rename |
| `/api/v1/graph/write/decision` | platform | `/api/v1/platform/knowledge/decisions` | rename |
| `/api/v1/graph/write/outcome` | platform | `/api/v1/platform/knowledge/outcomes` | rename |
| `/api/v1/graph/actuate/recommendation` | platform | `/api/v1/platform/knowledge/actions` | split |
| `/api/v1/graph/identity/resolve` | platform | `/api/v1/platform/identity/resolutions` | rename |
| `/api/v1/graph/identity/review` | platform | `/api/v1/platform/identity/reviews` | rename |
| `/api/v1/graph/identity/split` | platform | `/api/v1/platform/identity/splits` | rename |
| `/api/v1/graph/identity/calibration` | platform | `/api/v1/platform/identity/calibration` | rename |
| `/api/v1/graph/intelligence/quality` | platform | `/api/v1/platform/intelligence/quality` | rename |
| `/api/v1/graph/intelligence/metadata-quality` | platform | `/api/v1/platform/intelligence/metadata-quality` | rename |
| `/api/v1/graph/intelligence/claim-conflicts` | platform | `/api/v1/platform/intelligence/claim-conflicts` | rename |
| `/api/v1/graph/intelligence/leverage` | platform | `/api/v1/platform/intelligence/leverage` | keep then narrow |
| `/api/v1/graph/intelligence/insights` | platform | `/api/v1/platform/intelligence/insights` | keep then narrow |
| `/api/v1/graph/intelligence/calibration/weekly` | platform | `/api/v1/platform/intelligence/calibration/weekly` | rename |
| `/api/v1/graph/evaluate-change` | platform | `/api/v1/platform/simulations/change-evaluations` | rename |
| `/api/v1/graph/simulate` | platform | `/api/v1/platform/simulations` | rename |
| `/api/v1/impact-analysis` | pending classification | prove domain-neutral first, else move to app intelligence | hold |
| `/api/v1/entities/{id}/cohort` | pending classification | prove domain-neutral first, else move to app intelligence | hold |
| `/api/v1/entities/{id}/outlier-score` | pending classification | prove domain-neutral first, else move to app intelligence | hold |
| `/api/v1/graph/who-knows` | org | `/api/v1/org/expertise/queries` | move |
| `/api/v1/graph/recommend-team` | org | `/api/v1/org/team-recommendations` | move |
| `/api/v1/graph/simulate-reorg` | org | `/api/v1/org/reorg-simulations` | move |
| `/api/v1/org/information-flow` | org | `/api/v1/org/information-flow` | keep |
| `/api/v1/org/clock-speed` | org | `/api/v1/org/clock-speed` | keep |
| `/api/v1/org/recommended-connections` | org | `/api/v1/org/recommended-connections` | keep |
| `/api/v1/org/onboarding/{id}/plan` | org | `/api/v1/org/onboarding/{id}/plan` | keep |
| `/api/v1/org/meeting-insights` | org | `/api/v1/org/meetings/insights` | rename |
| `/api/v1/org/meetings/{id}/analysis` | org | `/api/v1/org/meetings/{id}/analysis` | keep |
| `/api/v1/assets/{table}` | security | `/api/v1/security/assets` | rename and normalize |
| `/api/v1/findings*` | security | `/api/v1/security/findings*` | rename |
| `/api/v1/signals/dashboard` | security | `/api/v1/security/signals/dashboard` | rename |
| `/api/v1/policies` | security | `/api/v1/security/policies` | rename |
| `/api/v1/policies/evaluate` | security | `/api/v1/security/policy-evaluations` | rename |
| `/api/v1/policy/evaluate` | security | alias to policy-evaluations | deprecate |
| `/api/v1/compliance/frameworks*` | security | `/api/v1/security/compliance/frameworks*` | rename |
| `/api/v1/identity/stale-access` | security | `/api/v1/security/identity/stale-access` | rename |
| `/api/v1/identity/report` | security | `/api/v1/security/identity/report` | rename |
| `/api/v1/identity/reviews*` | security | `/api/v1/security/access-reviews*` | rename |
| `/api/v1/graph/access-reviews*` | security | `/api/v1/security/access-reviews*` | deprecate duplicate |
| `/api/v1/attack-paths*` | security | `/api/v1/security/attack-paths*` | rename |
| `/api/v1/graph/attack-paths*` | security | `/api/v1/security/attack-paths*` | deprecate duplicate |
| `/api/v1/graph/blast-radius/*` | security | `/api/v1/security/analyses/blast-radius` | move |
| `/api/v1/graph/cascading-blast-radius/*` | security | `/api/v1/security/analyses/cascading-blast-radius` | move |
| `/api/v1/graph/reverse-access/*` | security | `/api/v1/security/analyses/reverse-access` | move |
| `/api/v1/graph/privilege-escalation/*` | security | `/api/v1/security/analyses/privilege-escalation` | move |
| `/api/v1/graph/toxic-combinations` | security | `/api/v1/security/analyses/toxic-combinations` | move |
| `/api/v1/graph/chokepoints` | security | `/api/v1/security/analyses/chokepoints` | move |
| `/api/v1/graph/peer-groups` | security | `/api/v1/security/analyses/peer-groups` | move |
| `/api/v1/graph/effective-permissions/*` | security | `/api/v1/security/analyses/effective-permissions` | move |
| `/api/v1/graph/compare-permissions` | security | `/api/v1/security/analyses/permission-comparisons` | move |
| `/api/v1/graph/risk-report` | security | `/api/v1/security/risk/report` | move |
| `/api/v1/graph/risk-feedback` | security | `/api/v1/security/risk/feedback` | move |
| `/api/v1/graph/rule-discovery/*` | security | `/api/v1/security/rule-discovery/*` | move |
| `/api/v1/graph/cross-tenant/*` | security | `/api/v1/security/patterns/cross-tenant/*` | move |
| `/api/v1/graph/visualize/*` | security | `/api/v1/security/visualizations/*` | move |
| `/api/v1/runtime/*` | security | `/api/v1/security/runtime/*` | rename |
| `/api/v1/threatintel/*` | security | `/api/v1/security/threat-intel/*` | rename |
| `/api/v1/remediation/*` | security | `/api/v1/security/remediation/*` | rename |
| `/api/v1/lineage/*` | security | `/api/v1/security/lineage/*` | keep application-scoped |
| `/api/v1/incidents*` | security | `/api/v1/security/incidents*` | rename |
| `/api/v1/tickets*` | shared app/service | `/api/v1/security/tickets*` now, later shared workflow service | keep for now |
| `/api/v1/providers/*` | admin | `/api/v1/admin/providers/*` | rename |
| `/api/v1/sync/*` | admin | `/api/v1/admin/sync-jobs*` | split into jobs |
| `/api/v1/scheduler/*` | admin | `/api/v1/admin/scheduler/*` | rename |
| `/api/v1/audit` | admin | `/api/v1/admin/audit` | rename |
| `/api/v1/webhooks*` | admin | `/api/v1/admin/webhooks*` | rename |
| `/api/v1/notifications*` | admin | `/api/v1/admin/notifications*` | rename |
| `/api/v1/telemetry/ingest` | admin | `/api/v1/admin/telemetry/ingest` | rename |
| `/api/v1/rbac/*` | admin | `/api/v1/admin/rbac/*` | rename |

## 6. Migration Plan

### Immediate Changes

- Adopt the namespace model in documentation and OpenAPI terminology now.
- Stop describing shared graph substrate endpoints as "security graph" endpoints.
- Introduce new typed platform endpoints alongside existing `/api/v1/graph/*` handlers.
- Add deprecation headers for duplicate aliases:
  - `/api/v1/policy/evaluate`
  - `/api/v1/graph/access-reviews/*`
  - `/api/v1/graph/attack-paths*`
- Move org-intelligence endpoints out of `/api/v1/graph` first.
  - This is low-risk because it is naming movement with little backward-compatibility dependence compared with findings/policies.
- Add shared response envelopes for new platform endpoints only.
  - Do not mass-rewrite old security endpoints in the same step.

### Medium-Term Refactors

- Introduce `/api/v1/platform/knowledge/*` as the only write path for claim/evidence/decision/action/outcome primitives.
- Convert heavy simulations and analyses into async job resources.
- Treat the hidden-security-bias audit as mandatory substrate work:
  - review canonical node kinds for cloud/security-only assumptions
  - review edge kinds for access- and infra-only assumptions
  - review canonical ID formation for source rules that would break on org/business/document/customer domains
  - review required metadata fields that assume cloud/security collectors
- Split security analytics from graph primitives.
  - attack paths
  - blast radius
  - privilege escalation
  - toxic combinations
  - effective permissions
- Recast findings as security application views over claims, evidence, controls, and outcomes.
- Recast access reviews as security workflow resources built on platform decisions/actions/outcomes.
- Normalize provider sync into control-plane jobs instead of provider-specific verb endpoints.

### Later Cleanups

- Deprecate `/api/v1/graph/*` aliases entirely after telemetry shows migration completion.
- Collapse duplicate attack-path surfaces to one security namespace.
- Decide whether tickets remain security-scoped or become a shared workflow/integration service.
- Introduce module ownership and deprecation policy in the schema registry for application extensions.
- Separate application-specific scoring from platform-wide quality/confidence/freshness services.

### Low-Risk Wins First

- platform wording cleanup in docs and user-facing API descriptions
- org endpoint relocation
- alias/deprecation metadata in OpenAPI
- typed envelopes for newly added platform endpoints
- policy-evaluation alias cleanup

### Risky Changes

- changing finding semantics too early
- flattening access reviews into generic platform workflow APIs before preserving current security UX
- moving provider/sync control plane without explicit job/execution contracts
- over-generalizing attack path and blast radius into vague graph endpoints

### What Should Not Be Changed Yet

- internal package names that still reflect the security-first implementation, unless they are part of a user-facing contract
- existing finding and compliance business logic
- security-specific detection/remediation semantics that have not yet been remapped onto platform claims/actions/outcomes
- Snowflake/storage internals unless needed to support typed platform contracts

## 7. Concrete Schema Proposals

### Response Envelopes

```yaml
SuccessEnvelope:
  type: object
  required: [data, meta]
  additionalProperties: false
  properties:
    data: {}
    meta:
      $ref: '#/components/schemas/ResponseMeta'

ResponseMeta:
  type: object
  required: [request_id, api_version]
  additionalProperties: false
  properties:
    request_id:
      type: string
    api_version:
      type: string
    next_cursor:
      type: string
    has_more:
      type: boolean
    warnings:
      type: array
      items:
        type: string

ErrorResponse:
  type: object
  required: [error]
  additionalProperties: false
  properties:
    error:
      type: object
      required: [code, message, request_id]
      additionalProperties: false
      properties:
        code:
          type: string
        message:
          type: string
        request_id:
          type: string
        retriable:
          type: boolean
        details:
          type: array
          items:
            type: object
            additionalProperties: false
```

### Shared Metadata Objects

```yaml
Provenance:
  type: object
  required: [source_system, source_record_id, observed_at, recorded_at, transaction_from]
  additionalProperties: false
  properties:
    source_system:
      type: string
    source_record_id:
      type: string
    observed_at:
      type: string
      format: date-time
    recorded_at:
      type: string
      format: date-time
    valid_from:
      type: string
      format: date-time
    valid_to:
      type: string
      format: date-time
    transaction_from:
      type: string
      format: date-time
    transaction_to:
      type: string
      format: date-time
    source_schema_url:
      type: string
      format: uri
    producer_fingerprint:
      type: string
    contract_version:
      type: string
    contract_api_version:
      type: string
    confidence:
      type: number
      minimum: 0
      maximum: 1

EntityRef:
  type: object
  required: [id, kind]
  additionalProperties: false
  properties:
    id:
      type: string
    kind:
      type: string
    display_name:
      type: string
```

### Platform Entity And Relationship Records

```yaml
PlatformEntity:
  type: object
  required: [id, kind, category, display_name, provenance]
  additionalProperties: false
  properties:
    id:
      type: string
    kind:
      type: string
    category:
      type: string
      enum: [actor, resource, artifact, event, knowledge, workflow, governance, external]
    display_name:
      type: string
    state:
      type: string
    properties:
      type: object
      additionalProperties: false
    labels:
      type: object
      additionalProperties:
        type: string
    provenance:
      $ref: '#/components/schemas/Provenance'

PlatformRelationship:
  type: object
  required: [id, kind, category, source, target, provenance]
  additionalProperties: false
  properties:
    id:
      type: string
    kind:
      type: string
    category:
      type: string
      enum: [identity, structural, access, dependency, knowledge, workflow, social]
    source:
      $ref: '#/components/schemas/EntityRef'
    target:
      $ref: '#/components/schemas/EntityRef'
    state:
      type: string
    properties:
      type: object
      additionalProperties: false
    provenance:
      $ref: '#/components/schemas/Provenance'
```

### Claim Write Contract

```yaml
CreateClaimRequest:
  type: object
  required: [subject, predicate, status, provenance]
  additionalProperties: false
  properties:
    id:
      type: string
    claim_type:
      type: string
    subject:
      $ref: '#/components/schemas/EntityRef'
    predicate:
      type: string
    object:
      $ref: '#/components/schemas/EntityRef'
    object_value:
      type: string
    status:
      type: string
      enum: [active, disputed, superseded, retracted]
    summary:
      type: string
    evidence_ids:
      type: array
      items:
        type: string
    supporting_claim_ids:
      type: array
      items:
        type: string
    refuting_claim_ids:
      type: array
      items:
        type: string
    source:
      type: object
      additionalProperties: false
      properties:
        id:
          type: string
        name:
          type: string
        type:
          type: string
        url:
          type: string
          format: uri
        trust_tier:
          type: string
        reliability_score:
          type: number
          minimum: 0
          maximum: 1
    provenance:
      $ref: '#/components/schemas/Provenance'

CreateClaimResponse:
  type: object
  required: [claim, links]
  additionalProperties: false
  properties:
    claim:
      type: object
      additionalProperties: false
      properties:
        id:
          type: string
        subject_id:
          type: string
        predicate:
          type: string
        object_id:
          type: string
        object_value:
          type: string
        status:
          type: string
    links:
      type: object
      additionalProperties: false
      properties:
        evidence_ids:
          type: array
          items:
            type: string
        source_id:
          type: string
```

### Graph Query Contract

```yaml
GraphQueryRequest:
  type: object
  required: [mode]
  additionalProperties: false
  properties:
    mode:
      type: string
      enum: [neighbors, paths, subgraph, pattern]
    anchor:
      $ref: '#/components/schemas/EntityRef'
    target:
      $ref: '#/components/schemas/EntityRef'
    direction:
      type: string
      enum: [in, out, both]
    max_depth:
      type: integer
      minimum: 1
      maximum: 12
    limit:
      type: integer
      minimum: 1
      maximum: 500
    kinds:
      type: array
      items:
        type: string
    edge_kinds:
      type: array
      items:
        type: string
    valid_at:
      type: string
      format: date-time
    recorded_at:
      type: string
      format: date-time

GraphQueryResponse:
  type: object
  required: [nodes, relationships]
  additionalProperties: false
  properties:
    nodes:
      type: array
      items:
        $ref: '#/components/schemas/PlatformEntity'
    relationships:
      type: array
      items:
        $ref: '#/components/schemas/PlatformRelationship'
    paths:
      type: array
      items:
        type: object
        additionalProperties: false
```

### Simulation And Job Contracts

```yaml
CreateSimulationRequest:
  type: object
  required: [simulation_type, mutations]
  additionalProperties: false
  properties:
    simulation_type:
      type: string
      enum: [graph_change, scenario, org_reorg, security_attack_path]
    scenario:
      type: string
    mutations:
      type: array
      items:
        type: object
        additionalProperties: false
    valid_at:
      type: string
      format: date-time
    recorded_at:
      type: string
      format: date-time
    async:
      type: boolean

Job:
  type: object
  required: [id, kind, status, submitted_at]
  additionalProperties: false
  properties:
    id:
      type: string
    kind:
      type: string
    status:
      type: string
      enum: [queued, running, succeeded, failed, canceled]
    submitted_at:
      type: string
      format: date-time
    started_at:
      type: string
      format: date-time
    completed_at:
      type: string
      format: date-time
    result_url:
      type: string
    error:
      $ref: '#/components/schemas/ErrorResponse'
```

### Pagination And Async Standards

- new platform list endpoints should use cursor pagination, not offset pagination
- existing security endpoints may keep `limit` and `offset` until clients migrate
- operations expected to exceed 2 seconds or mutate large graph regions should default to async `Job` responses

## 8. Open Questions / Unresolved Risks

- Should `finding` become a first-class platform kind or remain a pure security application resource built from claims and evidence? Recommendation: keep it application-scoped for now.
- Should `ticket` move to a shared workflow service or remain security-scoped until more non-security workflows exist? Recommendation: keep it security-scoped for now.
- Should `lineage` live in platform or security? Today it behaves like a specialized dependency view. Recommendation: keep it in security until broader software-supply-chain or data-lineage applications arrive.
- How much of current risk scoring belongs in platform intelligence versus security application ranking? Recommendation: keep platform scoring focused on confidence, coverage, freshness, contradiction, and calibration; keep risk/severity prioritization application-specific.
- How much internal package renaming is worth doing now? Recommendation: rename user-facing contracts first and defer deep package renames until the API boundary is stable.
- Which existing sync endpoints must become async jobs first? Recommendation: provider sync, graph rebuild, attack-path analysis, cross-tenant pattern build, and scenario simulation.
- How should authorization policy differ across platform versus application routes? This needs an explicit permission model before broad endpoint moves.
