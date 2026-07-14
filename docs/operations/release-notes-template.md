# Cerebro vX.Y.Z

Complete every section before starting the Stable Release workflow. Write `None` plus the reason when a section has no operator action.

## Compatibility

Record API, event, storage, configuration, and content-pack compatibility with the previous stable release.

## Migrations

List required migrations, execution order, expected duration, and downgrade limits.

## Configuration

List added, removed, renamed, or behavior-changing configuration keys and defaults.

## Content packs

List content-pack version requirements, rebuild requirements, and known compatibility limits.

## Rollback

Name the previous image digest and configuration revision. State whether a reverse data migration is safe.

## Runtime contract

Record the runtime contract schema version and any consumer action.

## Smoke evidence

Link the successful canary or production smoke receipt used by the stable workflow.

## Supported versions

List supported runtime profiles and backing-service versions for this release.
