# Graph Asset Deepening Research

This document captures external patterns researched with `gh` CLI and turns them into concrete design rules for deepening Cerebro's asset support.

The goal is not to re-create a CSPM asset inventory inside a graph. The goal is to make platform entities rich enough that security, compliance, and org/report views can all build on the same world-model substrate.

## Current Gap

Cerebro now has:

- typed platform knowledge reads and writes
- typed platform entity reads under `/api/v1/platform/entities`
- canonical graph ontology and schema registration

What is still shallow:

- security assets still largely enter the system as provider/table-shaped records
- entity identity is not yet consistently expressed as one canonical ref plus source aliases
- complex assets are not decomposed into subresources with durable semantics
- asset posture is still mostly a mix of raw properties and downstream findings rather than evidence-backed claims
- summary/support views for assets are not yet modularized

## Research Inputs

### 1) Backstage Catalog Model

Files researched:

- https://github.com/backstage/backstage/blob/master/packages/catalog-model/src/entity/Entity.ts
- https://github.com/backstage/backstage/blob/master/packages/catalog-model/src/entity/ref.ts
- https://github.com/backstage/backstage/blob/master/packages/catalog-model/src/kinds/ResourceEntityV1alpha1.ts
- https://github.com/backstage/backstage/blob/master/packages/catalog-model/src/kinds/relations.ts

Patterns worth adopting:

- every entity has one canonical envelope: `apiVersion`, `kind`, `metadata`, `spec`, `relations`
- canonical refs are normalized and serializable, not ad hoc IDs
- ownership, dependency, parent/child, and part/whole relations are explicit and reusable
- resource entities stay small and typed while richer views are layered on top

Implication for Cerebro:

- every graph entity should eventually expose a canonical entity ref independent of source-specific IDs
- entity reads should keep identity, metadata, and relation summaries separate from raw properties
- `owner`, `depends_on`, `part_of`, `located_in`, and `managed_by` should be treated as reusable platform relations, not product-local conventions

### 2) DataHub Asset Summaries + Ownership Aspect

Files researched:

- https://github.com/datahub-project/datahub/blob/master/docs/features/feature-guides/custom-asset-summaries.md
- https://github.com/datahub-project/datahub/blob/master/metadata-models/src/main/pegasus/com/linkedin/settings/asset/AssetSummarySettings.pdl
- https://github.com/datahub-project/datahub/blob/master/metadata-models/src/main/pegasus/com/linkedin/common/Ownership.pdl

Patterns worth adopting:

- summary pages are curated modules over an asset, not special asset types
- ownership is a typed aspect, not a free-form string stuffed into properties
- high-value logical assets get first-class summaries that combine docs, links, ownership, and related assets

Implication for Cerebro:

- asset summaries should be built as report/section compositions over entity + claim + evidence context
- ownership should converge on typed claims and typed relations instead of loose property fields
- the asset page model should support pluggable modules such as ownership, posture, lineage, risky config, support evidence, links, and operational context

### 3) OpenMetadata Entity Schemas

Files researched:

- https://github.com/open-metadata/OpenMetadata/blob/main/openmetadata-spec/src/main/resources/json/schema/entity/data/table.json
- https://github.com/open-metadata/OpenMetadata/blob/main/openmetadata-spec/src/main/resources/json/schema/type/entityReference.json

Patterns worth adopting:

- asset types are defined by strict schemas with enums and nested typed objects
- references to other entities are typed, not bare strings without semantics
- asset richness comes from structured metadata, not one giant `additionalProperties` blob

Implication for Cerebro:

- entity kinds should accumulate kind-specific profile fragments with explicit fields and enums
- cross-entity references should become typed summaries instead of raw IDs in arbitrary properties
- asset deepening should prefer schema-backed facets over dumping more provider JSON into `properties`

### 4) Cartography Resource + Composite Node Pattern

Files researched:

- https://github.com/cartography-cncf/cartography/blob/master/cartography/models/aws/ec2/instances.py
- https://github.com/cartography-cncf/cartography/blob/master/cartography/models/aws/s3/bucket.py
- https://github.com/cartography-cncf/cartography/blob/master/cartography/models/aws/s3/policy_statement.py

Patterns worth adopting:

- each provider resource has a base node schema plus explicit relationships to account/container nodes
- composite schemas add focused property sets without overwriting the base resource record
- subresources like policy statements become separate nodes when they have their own semantics

Implication for Cerebro:

- deep asset support should use composable profile fragments, not one ever-growing node payload
- assets like `bucket`, `database`, `service`, and `network` need attached support fragments such as encryption, exposure, logging, policy, backup, and runtime posture
- rules, policy statements, ports, endpoints, columns, and bindings should become subresource nodes when they drive analysis or explanation

## Design Rules For Cerebro

### 1) Canonical Entity Ref First

Every entity should converge on a canonical ref shape:

- `kind`
- `namespace` or provider scope
- stable canonical name
- source aliases / external refs

Current raw source IDs should remain as aliases, not as the only durable identity.

### 2) Base Entity + Facet Fragments

Deep assets should be modeled as:

- base entity record
- relation summaries
- knowledge support summaries
- typed facet fragments

Examples of facet fragments:

- ownership
- exposure
- encryption
- logging/audit
- network reachability
- backup/recovery
- runtime posture
- policy posture
- data sensitivity
- deployment/runtime lineage

These should be queryable and schema-backed, and then reusable in report sections.

### 3) Subresource Promotion Rule

Promote a nested provider construct into its own node when it has one of these properties:

- has independent lifecycle
- can be linked to multiple parents
- drives security/risk explanation
- needs evidence/provenance of its own
- shows up in recommendations or remediation workflows

Examples:

- bucket policy statements
- security group rules
- IAM inline policy documents
- database tables/columns
- service endpoints
- deployment bindings
- secrets versions

### 4) Support Must Be Evidence-Backed

Risky-configuration posture should not live only as raw properties.

Prefer:

- entity properties for raw observed configuration
- observations for low-level collected facts
- evidence for artifacts and scans
- claims for normalized posture statements

That gives the platform a way to answer:

- what is risky
- who says so
- what raw evidence supports it
- when it changed

### 5) Asset Summaries Are Report Views

Asset pages should be built from report modules over the entity graph, not from bespoke per-asset endpoint trees.

Candidate built-in summary modules:

- identity and ownership
- topology and dependencies
- risky configuration posture
- evidence/support coverage
- change timeline
- linked findings and remediations
- docs and external links
- runtime and deployment context

## Recommended Next Implementation Tracks

### Track A: Canonical Entity Identity

Exit criteria:

- canonical entity ref on all typed entity reads
- source alias list on entities
- explicit external reference objects

### Track B: Asset Facet Registry

Exit criteria:

- schema-backed facet definitions for high-value resource kinds
- typed facet summaries on entity detail
- compatibility checks for facet evolution

### Track C: Subresource Deepening

Exit criteria:

- at least one fully modeled asset family with promoted subresources
- example: `bucket` plus policy statements, logging config, encryption config, and public-access controls

### Track D: Support And Posture Claims

Exit criteria:

- risky configurations expressed as claims with evidence links
- entity detail shows which claims are active, supported, disputed, or stale

### Track E: Asset Summary Modules

Exit criteria:

- extensible report modules for entity summary pages
- no new bespoke asset-summary endpoints

## Immediate Conclusion

The right next move for asset deepening is:

1. keep expanding `/api/v1/platform/entities` as the canonical typed read surface
2. add canonical refs and external refs
3. add facet fragments for high-value resource kinds
4. promote subresources where posture/explanation depends on them
5. express risky configurations as evidence-backed claims

That keeps the graph honest: assets stay entities, support stays in the knowledge layer, and UI/report richness stays in derived modules rather than becoming another pile of special-case APIs.
