# CLI Reference

Build first with `make build`, then run `./bin/cerebro`.

```bash
make build
./bin/cerebro version
```

Top-level commands are `serve`, `version`, `source`, `source-runtime`, `append-log`, `finding-rule`, `graph`, `orchestrator`, `vulndb`, `closeout`, and `deploy`.

Agent onboarding is a Makefile workflow around the CLI and HTTP API:

```bash
make agent-onboard PLAN=examples/onboarding/cerebro-onboarding.yaml
make agent-onboard-e2e
```

## Server And Version

```bash
./bin/cerebro serve
./bin/cerebro version
```

## Deploy Preflight

```bash
./bin/cerebro deploy preflight
./bin/cerebro deploy preflight --format text
```

`deploy preflight` emits a redacted readiness receipt. The JSON output includes the selected runtime profile, enabled capabilities, required backing services, required secret variable names, operator actions, and pass/fail checks. Store the receipt with deployment records; keep concrete secret values, hostnames, schedules, and tenant assignments in the deployment system.

## Source Catalog And Previews

Source config is passed as `key=value` pairs.

```bash
./bin/cerebro source list
./bin/cerebro source check github owner=writer repo=cerebro
./bin/cerebro source discover github owner=writer repo=cerebro
./bin/cerebro source read github owner=writer repo=cerebro per_page=1
```

## Source Runtimes

Source runtime persistence requires Postgres. Sync also requires NATS JetStream.

```bash
./bin/cerebro source-runtime list
./bin/cerebro source-runtime bootstrap env=SOURCE_RUNTIMES_JSON
./bin/cerebro source-runtime put example-github github tenant_id=example owner=writer repo=cerebro
./bin/cerebro source-runtime get example-github
./bin/cerebro source-runtime sync example-github page_limit=1
```

See [Source runtime guide](../domains/source-runtime-guide.md) for store setup, secrets, sync behavior, and recovery.

## Append Log Recovery

Exhausted JetStream publishes are recorded in Postgres when the state store is configured. List pending records without requiring JetStream to be healthy:

```bash
./bin/cerebro append-log dead-letters stats
./bin/cerebro append-log dead-letters list
./bin/cerebro append-log dead-letters list subject=sec.findings.v1.recorded status=pending limit=20
```

Replay one record after the append-log path is healthy, or discard it after investigation:

```bash
./bin/cerebro append-log dead-letters replay <dead-letter-id> actor=oncall@example.com reason=INC-1234
./bin/cerebro append-log dead-letters discard <dead-letter-id> actor=oncall@example.com reason=INC-1234
```

`replay` claims the record before publishing. `list` reports the claim owner,
lease expiry, attempt count, and last bounded replay error category without
exposing the claim token. A second operator cannot replay or discard the record
until the active claim completes or expires.

Replay and discard commit the status transition and actor/action/reason audit
row in one Postgres transaction.

Dead-letter IDs are deterministic for the subject, event ID, and payload. A
replayed or discarded record stays terminal if the same event exhausts again.

Delete terminal records before a retention cutoff in audited, resumable batches:

```bash
./bin/cerebro append-log dead-letters cleanup terminal_before=2026-06-01T00:00:00Z actor=oncall@example.com reason=CHG-1234 limit=100
./bin/cerebro append-log dead-letters cleanup actor=oncall@example.com reason=scheduled-retention limit=100
```

`cleanup` only deletes replayed or discarded records. When `has_more` is true,
run the command again with the returned `next_after_id` as `after_id`.
When `terminal_before` is omitted, the command uses the configured terminal
retention period.

## Finding Rules

```bash
./bin/cerebro finding-rule new identity-example source_id=okta event_kinds=okta.user name="Example identity rule" dry_run=true
./bin/cerebro finding-rule graph-evaluate <rule-id> tenant_id=example limit=10
```

## Graph Operations

Graph inspection and ingest require Neo4j or Aura. Runtime-backed graph operations also need the configured source runtime stores.

```bash
./bin/cerebro graph counts
./bin/cerebro graph relation-counts
./bin/cerebro graph neighborhood <root-urn> limit=10
./bin/cerebro graph paths limit=10
./bin/cerebro graph integrity
./bin/cerebro graph health
./bin/cerebro graph ingest github tenant_id=example owner=writer repo=cerebro page_limit=1
./bin/cerebro graph ingest-runtime example-github page_limit=1
./bin/cerebro graph ingest-run <run-id>
./bin/cerebro graph ingest-runs runtime_id=example-github
./bin/cerebro graph rebuild example-github dry_run=true mode=replay
```

See [Graph operations](../domains/graph-operations.md) for health checks, ingest, rebuilds, query safety, and troubleshooting.
