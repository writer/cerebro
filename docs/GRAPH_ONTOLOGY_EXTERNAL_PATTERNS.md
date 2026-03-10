# Graph Ontology External Patterns

This document captures design patterns researched with `gh` CLI from external projects and maps them into Cerebro graph ontology decisions.

## Projects Reviewed

- OpenLineage (`OpenLineage/OpenLineage`)
- DataHub (`datahub-project/datahub`)
- OpenMetadata (`open-metadata/OpenMetadata`)
- Backstage Catalog (`backstage/backstage`)
- CloudEvents (`cloudevents/spec`)

## Reusable Patterns

### 1) Facet-level provenance + schema pointers (OpenLineage)

References:

- https://github.com/OpenLineage/OpenLineage/blob/main/spec/OpenLineage.md
- https://github.com/OpenLineage/OpenLineage/blob/main/spec/OpenLineage.json
- https://github.com/OpenLineage/OpenLineage/blob/main/spec/facets/NominalTimeRunFacet.json

Observed pattern:

- Metadata facets include immutable provenance fields (`_producer`) and schema pointers (`_schemaURL`).
- Temporal metadata is typed explicitly using `format: date-time`.

Cerebro application:

- Enforce metadata profile timestamp keys per kind (`observed_at`, `valid_from`, `valid_to`).
- Keep metadata contracts explicit and auto-documented per node kind.

### 2) Immutable, versioned metadata aspects (DataHub)

References:

- https://github.com/datahub-project/datahub/blob/master/docs/what/aspect.md
- https://github.com/datahub-project/datahub/blob/master/docs/advanced/aspect-versioning.md

Observed pattern:

- Metadata updates are immutable/versioned by default.
- Aspect-specific evolution is decoupled to reduce lockstep schema churn.

Cerebro application:

- Treat node kind metadata profiles as versioned schema contracts.
- Emit compatibility warnings when required metadata keys or enum contracts tighten.

### 3) Strict relationship references (OpenMetadata)

Reference:

- https://github.com/open-metadata/OpenMetadata/blob/main/openmetadata-spec/src/main/resources/json/schema/type/entityReference.json

Observed pattern:

- Relationship references have strongly typed required fields and `additionalProperties: false`.

Cerebro application:

- Keep explicit per-kind relationship allowlists.
- Prefer explicit metadata-profile keys over unconstrained free-form metadata for core kinds.

### 4) Envelope + kind-specific validation (Backstage)

References:

- https://github.com/backstage/backstage/blob/master/packages/catalog-model/src/schema/Entity.schema.json
- https://github.com/backstage/backstage/blob/master/packages/catalog-model/src/validation/entityKindSchemaValidator.ts

Observed pattern:

- A shared entity envelope enforces `apiVersion`, `kind`, and `metadata`.
- Kind-specific validation is strict, but kind mismatch can be treated as a soft routing miss.

Cerebro application:

- Keep generic graph writes permissive enough for routing while strict validation applies once kind is resolved.
- Use per-kind `NodeMetadataProfile` for metadata constraints instead of one global policy.

### 5) Required event context attributes (CloudEvents)

Reference:

- https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md

Observed pattern:

- Events require core attributes (`id`, `source`, `specversion`, `type`) and strongly constrained naming.

Cerebro application:

- Require core metadata keys on profiled kinds (`source_system`, `source_event_id`, `observed_at`, `valid_from`).
- Track missing required keys as first-class schema issues.

### 6) Machine-readable schema catalog generation (google-cloudevents)

References:

- https://github.com/googleapis/google-cloudevents/blob/main/README.md
- https://github.com/googleapis/google-cloudevents/blob/main/jsonschema/catalog.json
- https://github.com/googleapis/google-cloudevents/blob/main/scripts/gen.sh

Observed pattern:

- Keep a human-readable catalog and machine-readable JSON schema catalog in sync from one generation entrypoint.
- Validate generated schemas continuously in CI.

Cerebro application:

- Generate both markdown and machine-readable CloudEvents contract artifacts from one script.
- Treat generated JSON contracts as first-class API/automation inputs.

## Implemented in Cerebro (This Cycle)

- Added `NodeMetadataProfile` to `NodeKindDefinition`.
- Added schema issue codes for missing metadata keys, invalid metadata enums, and invalid metadata timestamps.
- Added metadata profile validation to schema registry node validation.
- Added metadata profiles and enum contracts for operational/decision-intelligence kinds.
- Added `BuildGraphMetadataQualityReport(...)` and API endpoint `GET /api/v1/platform/intelligence/metadata-quality`.
- Extended ontology autogen output to include node metadata profile matrices.
- Added CloudEvents autogen catalog (`docs/CLOUDEVENTS_AUTOGEN.md`) with envelope and template-derived mapping contracts.
- Added machine-readable contract catalog (`docs/CLOUDEVENTS_CONTRACTS.json`) with generated per-mapping data schemas.
- Added mapping config versioning (`apiVersion`, `contractVersion`) and runtime contract validation before writes.
- Added compatibility checker script (`scripts/check_cloudevents_contract_compat/main.go`) for required-key and enum-tightening changes.
- Added API endpoint `GET /api/v1/graph/ingest/contracts` to expose generated contracts at runtime.
- Added mapper metadata enrichment pointers (`source_schema_url`, `producer_fingerprint`, `contract_version`, `contract_api_version`).
- Added first-class world-model ontology nodes (`claim`, `source`, `observation`) and contradiction/support edges.
- Added bitemporal write metadata (`recorded_at`, `transaction_from`, `transaction_to`) plus bitemporal graph views.
- Added claim writeback and contradiction intelligence endpoints (`POST /api/v1/platform/knowledge/claims`, `GET /api/v1/platform/intelligence/claim-conflicts`).

## Next Moves

1. Add CI gate for metadata-profile coverage on high-volume kinds (threshold-based failure).
2. Add explicit enum normalization maps per source domain in mappings (`dataEnums` + coercion maps).
3. Add JSON Schema draft-level validation for generated mapping data schemas in CI (Ajv or equivalent).
4. Add relationship reification for ownership, employment, contracts, and access grants so high-value edges gain lifecycle + evidence semantics.
5. Add human adjudication queues for contradictory claims, duplicate entities, and source-trust calibration.
