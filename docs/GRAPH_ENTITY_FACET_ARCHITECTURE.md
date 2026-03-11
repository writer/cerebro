# Graph Entity Facet Architecture

This document describes the platform-level entity model that now sits between raw graph nodes and report/UI asset views.

The goal is to keep entity reads durable and typed while pushing richer presentation into report modules instead of bespoke asset endpoint trees.

## Core Model

Typed entity reads under `/api/v1/platform/entities*` now separate:

- canonical platform identity: `canonical_ref`
- source-native identity: `external_refs`
- alias context: `aliases`
- graph context: `relationships`, `links`
- knowledge context: `knowledge`
- asset deepening modules: `facets`
- promoted support modules: `subresources`
- normalized posture/support state: `posture`

This keeps the entity record small enough to stay reusable while making it rich enough for report composition.

## Canonical Identity

Every entity should expose one canonical ref with:

- `id`
- `kind`
- `namespace`
- `name`
- `provider`
- `account`
- `region`

Rules:

- `canonical_ref` is the platform identity, not the raw provider ID.
- `external_refs` retain provider-native identity such as ARNs, resource IDs, and source URLs.
- `aliases` capture explicit alternate identity records like `identity_alias -> alias_of`.

This mirrors the catalog/entity-ref pattern from Backstage while preserving graph-native IDs internally.

## Facet Contracts

Facets are schema-backed fragments materialized on entity detail.

Current built-in facets:

- `ownership`
- `exposure`
- `data_sensitivity`
- `bucket_public_access`
- `bucket_encryption`
- `bucket_logging`
- `bucket_versioning`

Facet rules:

- facets are not raw provider blobs
- facets must advertise stable IDs, schema names, and schema URLs
- facet fields should come from raw properties, graph relationships, and normalized claims
- new facets should be additive and backward-compatible

Facet registry surface:

- `GET /api/v1/platform/entities/facets`
- `GET /api/v1/platform/entities/facets/{facet_id}`

This registry is the contract surface for generated docs, compatibility checks, and downstream report/UI composition. Handlers should not be the only place facet shape exists.

Facet assessment values should stay coarse and durable:

- `pass`
- `warn`
- `fail`
- `info`
- `unknown`

## Posture Model

Risk posture should not live only in `properties`.

Use:

- `properties` for raw observed configuration
- `observations` for low-level collected facts
- `evidence` for attached artifacts and scans
- `claims` for normalized posture statements

Entity detail exposes a `posture` block that summarizes active posture claims and their support/dispute state.

Current posture-oriented predicates include:

- `public_access`
- `internet_exposed`
- `encrypted`
- `default_encryption_enabled`
- `access_logging_enabled`
- `versioning_enabled`
- `backup_enabled`
- `contains_sensitive_data`
- `data_classification`

## Report Boundary

The richer asset view should be a report, not a new subtree of asset-specific APIs.

Current report surface:

- `GET /api/v1/platform/intelligence/entity-summary`
- `POST /api/v1/platform/intelligence/reports/entity-summary/runs`

The `entity-summary` report composes:

- `overview`
- `topology`
- `facets`
- `subresources`
- `posture`
- `support`

This keeps asset pages aligned with the existing report registry, run lifecycle, snapshot lineage, and stream/event model.

## Promotion Rule

Promote a nested asset construct into its own node only when at least one is true:

- it has an independent lifecycle
- it needs provenance/evidence of its own
- it appears in explanations or remediation actions
- it can be linked from multiple parents

Likely next promotions:

- bucket policy statements
- bucket public-access-block state
- bucket encryption config
- bucket logging config
- bucket versioning config
- security group rules
- service endpoints
- database tables/columns
- secret versions

The first family is now implemented for `bucket` through promoted configuration nodes linked back to the parent bucket with `configures`. Those promoted nodes can carry their own observations, claims, evidence, and explanation paths.

## Current Deepening Pattern

The storage-family pattern now looks like:

- base entity: `bucket`
- facet modules: `bucket_public_access`, `bucket_encryption`, `bucket_logging`, `bucket_versioning`
- promoted subresources:
  - `bucket_policy_statement`
  - `bucket_public_access_block`
  - `bucket_encryption_config`
  - `bucket_logging_config`
  - `bucket_versioning_config`
- normalized posture claims on the bucket supported by the promoted subresource claims

This is the pattern to reuse for `database`, `service`, `instance`, and network-boundary families rather than inventing family-specific endpoint trees.

## Next Tracks

1. Reuse the same promotion + claim-normalization pattern for `database`, `service`, and compute families.
2. Add more specific support edges where `configures` is too coarse for enforcement/protection semantics.
3. Move normalization lifecycle into inspectable jobs/executions with emitted lifecycle events.
4. Add entity-summary module overlays for docs/links, timeline, remediation, and benchmark context.
