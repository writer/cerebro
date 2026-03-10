# Graph World Model Architecture

This document defines the next bar for Cerebro: a graph that does not just store entities and events, but tracks what is believed, who asserted it, what supports it, what contradicts it, and when Cerebro learned it.

See [GRAPH_REPORT_EXTENSIBILITY_RESEARCH.md](./GRAPH_REPORT_EXTENSIBILITY_RESEARCH.md) for how most org/security dynamics should be surfaced as extensible derived reports over this world model.
See [GRAPH_ASSET_DEEPENING_RESEARCH.md](./GRAPH_ASSET_DEEPENING_RESEARCH.md) for the next asset/entity deepening patterns that should sit on top of this substrate.

## Goal

A world-model graph should be able to answer, for any important fact:

- what is being claimed
- who asserted it
- what supports it
- what contradicts it
- when it became true in the world
- when Cerebro recorded it
- whether it has been corrected, retracted, or superseded

## Core Layers

### 1) Entity Layer

Durable world objects and actors:

- identities: `person`, `user`, `role`, `group`, `service_account`, `identity_alias`
- systems and resources: `service`, `workload`, `database`, `bucket`, `application`, `network`
- operational domains: `pull_request`, `deployment_run`, `pipeline_run`, `check_run`, `meeting`, `document`, `communication_thread`, `incident`
- decision loop: `decision`, `action`, `outcome`

### 2) Knowledge Layer

First-class truth substrate:

- `claim`: one assertion about a subject/predicate/object or subject/predicate/value
- `source`: the origin that asserted a claim
- `evidence`: supporting artifact
- `observation`: lower-level raw observation before or alongside higher-level evidence

Canonical knowledge edges:

- `asserted_by`
- `based_on`
- `supports`
- `refutes`
- `supersedes`
- `contradicts`
- `targets`
- `refers`

### 3) Temporal Layer

Cerebro now needs two time dimensions:

- fact time: `observed_at`, `valid_from`, `valid_to`
- system time: `recorded_at`, `transaction_from`, `transaction_to`

This distinction allows Cerebro to ask both:

- “what was true on March 1, 2026?”
- “what did Cerebro believe on March 1, 2026, based on what it had recorded by then?”

### 4) Derived Report Layer

Not every useful analytic deserves a first-class API noun or substrate primitive.

Org dynamics and security dynamics should usually be exposed as derived reports over the metadata/context graph, for example:

- bus-factor and knowledge-fragility views
- privilege concentration and risky-configuration posture
- coordination bottlenecks, information-flow lag, and reorg impact summaries

These are report surfaces built from entities, edges, claims, evidence, and temporal state. They should only become first-class workflow resources when they need durable IDs, approvals, write-back, or actuation semantics of their own.

## Implemented Foundation

This cycle adds the minimum viable world-model substrate:

- first-class node kinds: `claim`, `source`, `observation`
- first-class edge kinds: `asserted_by`, `supports`, `refutes`, `supersedes`, `contradicts`
- bitemporal metadata normalization in `graph.WriteMetadata`
- bitemporal graph views through `GetAllNodesBitemporal(...)`, `GetOutEdgesBitemporal(...)`, and `SubgraphBitemporal(...)`
- claim write path through `graph.WriteClaim(...)` and `POST /api/v1/platform/knowledge/claims`
- claim read/query path through `graph.QueryClaims(...)`, `graph.GetClaimRecord(...)`, `GET /api/v1/platform/knowledge/claims`, and `GET /api/v1/platform/knowledge/claims/{claim_id}`
- observation write path through `graph.WriteObservation(...)` and `POST /api/v1/platform/knowledge/observations`
- typed artifact reads through `graph.QueryEvidence(...)`, `graph.QueryObservations(...)`, `GET /api/v1/platform/knowledge/evidence`, and `GET /api/v1/platform/knowledge/observations`
- claim adjudication queue and append-only repair writes through `graph.QueryClaimGroups(...)`, `graph.AdjudicateClaimGroup(...)`, `GET /api/v1/platform/knowledge/claim-groups`, `GET /api/v1/platform/knowledge/claim-groups/{group_id}`, and `POST /api/v1/platform/knowledge/claim-groups/{group_id}/adjudications`
- claim reasoning surfaces through `graph.GetClaimTimeline(...)`, `graph.ExplainClaim(...)`, `graph.BuildClaimProofs(...)`, `graph.DiffClaims(...)`, `graph.DiffKnowledgeGraphs(...)`, `GET /api/v1/platform/knowledge/claims/{claim_id}/timeline`, `GET /api/v1/platform/knowledge/claims/{claim_id}/explanation`, `GET /api/v1/platform/knowledge/claims/{claim_id}/proofs`, `GET /api/v1/platform/knowledge/claim-diffs`, and `GET /api/v1/platform/knowledge/diffs`
- typed entity/resource reads through `graph.QueryEntities(...)`, `graph.GetEntityRecord(...)`, `GET /api/v1/platform/entities`, and `GET /api/v1/platform/entities/{entity_id}`
- claim contradiction reporting through `BuildClaimConflictReport(...)` and `GET /api/v1/platform/intelligence/claim-conflicts`
- derived claim state surfaced as typed fields (`supported`, `source_backed`, `sourceless`, `conflicted`, `superseded`) instead of forcing every consumer to traverse raw graph links
- entity support state surfaced as typed fields (`relationships`, `claim_count`, `supported_claim_count`, `conflicted_claim_count`, `evidence_count`, `observation_count`) instead of leaving asset context trapped in raw table rows or one-off reports

## What Still Needs To Be Added

### Relationship Reification

High-value edges should become first-class objects when they have lifecycle, approvals, or evidence:

- ownership
- employment
- contract
- access grant
- dependency
- obligation

### Source Trust Model

`source` should evolve to include:

- trust program / authority domain
- signing or authenticity status
- producer identity
- freshness decay policy
- conflict history and empirical accuracy

### Adjudication Layer

Contradictions should not be silently flattened. Cerebro needs:

- duplicate-entity queues
- claim conflict queues
- merge / split / supersede workflows
- human review records and calibration metrics

Current status:

- duplicate-entity and identity review queues exist
- claim conflict queues now exist as both a report and a typed `claim-group` read surface
- append-only claim adjudication writes now exist through `graph.AdjudicateClaimGroup(...)` and `POST /api/v1/platform/knowledge/claim-groups/{group_id}/adjudications`
- explicit review ownership/SLA resources still need to be added before contradiction repair can be run as a managed workflow

### Module Expansion

The next ontology modules should extend beyond infra/operations into:

- organization: `organization`, `team`, `project`, `capability`
- commerce: `customer`, `vendor`, `product`, `contract`
- geography: `region`, `location`, `facility`
- governance: `policy`, `control`, `risk`
- data / AI: `dataset`, `model`, `experiment`, `publication`

## Build Rules

When adding world-model semantics:

1. Add the node/edge kind and schema registration.
2. Require provenance and both temporal dimensions when the kind represents a durable claim.
3. Add bitemporal tests, not just point-in-time tests.
4. Add contradiction or supportability checks where the new kind can disagree with existing facts.
5. Expose the reasoning surface through an API or tool contract, not just internal helpers.

## Query Standard

A world-model query surface should prefer claim-oriented questions such as:

- all active `claim` nodes about `service:payments`
- contradictory `claim` groups recorded before a given timestamp
- unsupported claims without evidence or source attribution
- claims superseded after a particular incident or decision

Derived report surfaces should then package those lower-level answers into operator views, rather than inventing separate substrate concepts for every org or security dynamic.

That is the standard Cerebro should now optimize for.
