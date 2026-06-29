# Cerebro Quick Reference

This quick reference covers the current bootstrap service. Historical Snowflake, scheduler, webhook, and Cedar-runtime examples have been removed.

## Build And Run

```bash
make serve-dev
```

Durable local stack:

```bash
docker compose pull
docker compose up -d
```

Plain Compose initializes the local Postgres volume with the compose-file password. The onboarding Make targets use `tmp/local-postgres-password`. Before switching from plain Compose to `make agent-onboard-e2e` or `make github-business-demo`, run `docker compose down -v` to recreate local volumes, or run the Make target with `CEREBRO_LOCAL_POSTGRES_PASSWORD=cerebro` to reuse that volume. `docker compose down -v` deletes local stack data.

End-to-end local walkthrough: [`docs/start/getting-started.md`](getting-started.md).
Coding agent handoff: [`docs/start/agent-onboarding.md`](agent-onboarding.md).

First security onboarding run:

```bash
make secure-business-demo
```

First real GitHub-backed run:

```bash
export GITHUB_OWNER=<owner>
export GITHUB_REPO=<repo>
export GITHUB_TOKEN=<token>
make github-business-demo
```

Health and source catalog:

```bash
export CEREBRO_API_KEY=local-dev-key
curl -sS http://127.0.0.1:8080/health
curl -sS --oauth2-bearer "$CEREBRO_API_KEY" http://127.0.0.1:8080/sources
```

## Configuration

```bash
export CEREBRO_HTTP_ADDR=:8080
export CEREBRO_APPEND_LOG_DRIVER=jetstream
export CEREBRO_JETSTREAM_URL=nats://127.0.0.1:4222
export CEREBRO_JETSTREAM_STREAM_NAME=CEREBRO_EVENTS
export CEREBRO_STATE_STORE_DRIVER=postgres
export CEREBRO_POSTGRES_DSN='postgres://127.0.0.1:5432/cerebro?sslmode=disable'
export CEREBRO_GRAPH_STORE_DRIVER=neo4j
export CEREBRO_NEO4J_URI=bolt://127.0.0.1:7687
export CEREBRO_NEO4J_USERNAME=neo4j
export CEREBRO_NEO4J_PASSWORD='local-password'
```

API auth and rate limiting are enabled by default outside acknowledged dev mode. Configure credentials for shared deployments:

```bash
export CEREBRO_API_KEYS='secret-key:principal:tenant_id'
```

## CLI

```bash
./bin/cerebro version
./bin/cerebro source list
./bin/cerebro source check github owner=writer repo=cerebro
./bin/cerebro source discover github owner=writer repo=cerebro
./bin/cerebro source read github owner=writer repo=cerebro per_page=1
```

## MCP

```bash
make serve-dev
droid mcp add cerebro-local http://127.0.0.1:8080/api/v1/mcp --type http \
  --header "Authorization: Bearer local-dev-key"
```

Ask the agent to call `cerebro.sources.read` with `source_id=github` and `config={"owner":"writer","repo":"cerebro","per_page":"5"}` for a live, store-free first answer.

Runtime-backed commands require Postgres and, for sync/replay, JetStream:

```bash
./bin/cerebro source-runtime put local-github github tenant_id=local owner=writer repo=cerebro
./bin/cerebro source-runtime get local-github
./bin/cerebro source-runtime sync local-github page_limit=1
```

Graph operations require Neo4j:

```bash
./bin/cerebro graph counts
./bin/cerebro graph neighborhood <root-urn> limit=10
./bin/cerebro graph ingest-runtime local-github page_limit=1
```

## Validation

```bash
make test
make check
make verify
make readme-check
make docs-drift-check
make oss-audit
make agent-onboard-test
make agent-onboard-e2e
```

Focused targets:

```bash
make finding-rule-test
make workflow-e2e-test
make workflow-replay-test
```
