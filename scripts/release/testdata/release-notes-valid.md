# Cerebro v1.2.3

## Compatibility
API, event, and storage contracts remain compatible with the previous stable release.

## Migrations
No data migration is required. Existing stores can start this version directly.

## Configuration
No configuration keys changed. Existing runtime configuration remains valid.

## Content packs
The bundled content packs remain compatible with this runtime and schema set.

## Rollback
Restore the previous image digest and configuration revision. No reverse migration is required.

## Runtime contract
The runtime deploy contract remains at cerebro.runtime-deploy-contract/v1.

## Smoke evidence
The canary passed readiness, graph health, source health, and version checks: https://example.invalid/smoke/123

## Supported versions
This release supports the documented Postgres, NATS, and Neo4j versions in the hosting guide.
