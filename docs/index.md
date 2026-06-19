# Cerebro Documentation

Cerebro is an operations data platform for cloud, SaaS, identity, workflow, finding, compliance, and graph signals.

The current `main` branch is centered on a Go bootstrap service with JSON HTTP and Connect APIs, built-in source integrations, source runtime sync, finding and report workflows, compliance-control coverage, append-log replay, MCP access, device-authenticated telemetry, and optional graph projection/query tooling.

## Mental Model

```text
CLI / JSON HTTP / Connect / MCP clients
              |
              v
      Bootstrap service
   (cmd/cerebro, internal/bootstrap)
              |
              +--> Source registry, preview, and runtime sync
              +--> Claim, finding, report, workflow, and graph services
              +--> Optional MCP OAuth and device-auth services
              |
              +--> Optional append log: NATS JetStream
              +--> Optional state store: Postgres
              +--> Optional graph store: Neo4j/Aura
```

With no external drivers configured, the server can still start and serve lightweight routes such as `/health`, `/healthz`, `/livez`, `/openapi.yaml`, and `/sources`. Durable runtime, claim, finding, report, replay, and graph operations require their corresponding stores.

## First Run

```bash
make doctor
make serve-dev
```

Then check the server:

```bash
curl -sS http://127.0.0.1:8080/health
curl -sS http://127.0.0.1:8080/sources
```

For a durable local stack:

```bash
docker compose up --build
```

## Main Docs

| Need | Document |
| --- | --- |
| Short command reference | [Quick reference](QUICKREF.md) |
| Local end-to-end walkthrough | [Getting started](GETTING_STARTED.md) |
| Runtime shape and dependency boundaries | [Architecture](ARCHITECTURE.md) |
| Runtime configuration | [Configuration variables](CONFIG_ENV_VARS.md) |
| Hosting and operations | [Hosting](HOSTING.md), [cloud deployment](CLOUD_DEPLOYMENT.md), [deployment examples](DEPLOYMENT_EXAMPLES.md), [operations runbook](OPERATIONS_RUNBOOK.md), and [troubleshooting](TROUBLESHOOTING.md) |
| API contracts | [API reference](API_REFERENCE.md), [generated API contracts](API_CONTRACTS_AUTOGEN.md), `../api/openapi.yaml`, and `../proto/cerebro/v1/bootstrap.proto` |
| CLI usage | [CLI reference](CLI_REFERENCE.md) |
| Built-in source integrations | [Source catalog](SOURCES.md) |
| Source runtime sync | [Source runtime guide](SOURCE_RUNTIME_GUIDE.md) |
| Graph operations | [Graph operations](GRAPH_OPERATIONS.md) |
| Compliance control coverage | [Compliance controls](COMPLIANCE_CONTROLS.md) |
| Policies | [Policies](POLICIES.md) |
| MCP setup | [MCP native Droid setup](MCP_DROID_SETUP.md) |
| Endpoint telemetry | [Endpoint security platform integration](ENDPOINT_SECURITY_PLATFORM_INTEGRATION.md) |
| Release artifacts | [Release contract](RELEASE_CONTRACT.md) |
| Contribution rules | [Development](DEVELOPMENT.md) and [non-goals](NON_GOALS.md) |

## Source Of Truth

Treat `cmd/cerebro`, `internal/bootstrap`, `internal/config`, `api/openapi.yaml`, `proto/cerebro/v1/bootstrap.proto`, `sources/*/catalog.yaml`, and the Makefile as the current runtime source of truth. Some older docs may describe broader architecture ideas and should be verified against the current bootstrap implementation before use.
