# CLI Reference

Build first with `make build`, then run `./bin/cerebro`.

```bash
make build
./bin/cerebro version
```

Top-level commands are `serve`, `version`, `source`, `source-runtime`, `finding-rule`, `graph`, `orchestrator`, `vulndb`, `closeout`, and `deploy`.

## Server And Version

```bash
./bin/cerebro serve
./bin/cerebro version
```

## Deploy Preflight

```bash
./bin/cerebro deploy preflight
```

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

See [Source runtime guide](SOURCE_RUNTIME_GUIDE.md) for store setup, secrets, sync behavior, and recovery.

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

See [Graph operations](GRAPH_OPERATIONS.md) for health checks, ingest, rebuilds, query safety, and troubleshooting.
