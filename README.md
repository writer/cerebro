# Cerebro

**Operations data platform for cloud, SaaS, identity, workflow, finding, compliance, and graph signals.**

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Cerebro ingests operational and security signals, turns them into source runtime events, claims, findings, reports, workflow events, compliance evidence, and graph context, then exposes that substrate through a Go CLI, JSON HTTP, Connect RPC, SDK helpers, and MCP.

## Start Here

```bash
git clone https://github.com/writer/cerebro.git
cd cerebro

make doctor
make serve-dev
```

By default, the local server listens on `:8080`.

```bash
curl -sS http://127.0.0.1:8080/health
curl -sS http://127.0.0.1:8080/sources
```

Run focused tests while iterating, then use CI-parity validation before broad PRs:

```bash
make test
make verify
```

For a durable local stack with NATS JetStream, Postgres, Neo4j, and the local bearer key `local-dev-key`:

```bash
docker compose up --build
```

## What Is In This Repo

- A Go bootstrap service built around `net/http`, Connect RPC, and `cmd/cerebro`.
- Built-in source integrations for cloud, SaaS, identity, endpoint, vulnerability, compliance, and workflow signals.
- Source runtime sync, append-log replay, claim/finding/report workflows, compliance control coverage, and optional graph projection/query tooling.
- Optional MCP, graph-agent, and device-authenticated telemetry surfaces.
- Policy catalogs, generated detection catalogs, SDK helpers, OpenAPI/Connect contracts, release artifacts, and local validation tooling.

## Choose A Path

| Goal | Start here |
| --- | --- |
| Get the shortest runnable path | [Quick reference](docs/QUICKREF.md) |
| Walk through a local end-to-end flow | [Getting started](docs/GETTING_STARTED.md) |
| Understand runtime shape and stores | [Architecture](docs/ARCHITECTURE.md) |
| Configure auth, tenancy, stores, MCP, or device auth | [Configuration variables](docs/CONFIG_ENV_VARS.md) and [.env.example](.env.example) |
| Host or operate Cerebro | [Hosting](docs/HOSTING.md), [cloud deployment](docs/CLOUD_DEPLOYMENT.md), [deployment examples](docs/DEPLOYMENT_EXAMPLES.md), and [operations runbook](docs/OPERATIONS_RUNBOOK.md) |
| Explore JSON HTTP or Connect APIs | [API reference](docs/API_REFERENCE.md), `api/openapi.yaml`, and `proto/cerebro/v1/bootstrap.proto` |
| Use the CLI | [CLI reference](docs/CLI_REFERENCE.md) |
| Browse built-in integrations | [Source catalog](docs/SOURCES.md) |
| Use SDK helpers | [Python SDK](sdk/python/README.md), [TypeScript SDK](sdk/typescript/README.md), and `sources/sdk` |
| Persist and sync source runtimes | [Source runtime guide](docs/SOURCE_RUNTIME_GUIDE.md) |
| Work on graph behavior | [Graph operations](docs/GRAPH_OPERATIONS.md) |
| Integrate MCP clients | [MCP native Droid setup](docs/MCP_DROID_SETUP.md) |
| Integrate endpoint telemetry | [Endpoint security platform integration](docs/ENDPOINT_SECURITY_PLATFORM_INTEGRATION.md) |
| Author policies, control mappings, or finding rules | [Policies](docs/POLICIES.md), [compliance controls](docs/COMPLIANCE_CONTROLS.md), `policies/`, and `internal/findings` |
| Contribute code or docs | [Development](docs/DEVELOPMENT.md), [non-goals](docs/NON_GOALS.md), and the Makefile |

## Optional Docs Site

The Markdown docs work directly on GitHub. To browse them as a local site:

```bash
python3 -m pip install mkdocs
mkdocs serve
```

The site entry point is [docs/index.md](docs/index.md), and `mkdocs.yml` defines the navigation.

## Runtime Boundaries

This public repository is authoritative for runtime behavior, CLI/API contracts, source catalogs, configuration semantics, and release artifacts. Environment-specific deployment details, stack configuration, account wiring, hostnames, and rollout procedures intentionally live outside this public repo.

The handoff to deployment repositories is the release payload: container images plus `cerebro-runtime-contract.json`. Treat that contract as the bridge between public runtime releases and environment-specific promotion/deploy automation.

Volatile details should stay in their source-of-truth files and be linked from here: configuration variables in `docs/CONFIG_ENV_VARS.md`, API shape in `api/openapi.yaml`, source capabilities in `sources/*/catalog.yaml`, and release/deploy handoff data in `cerebro-runtime-contract.json`.

See [Non-goals](docs/NON_GOALS.md) before changing storage shape, Source CDK boundaries, graph/Cypher behavior, findings workflow contracts, action/runtime response semantics, platform/security namespace boundaries, or public product language.

## Common Commands

```bash
make build          # compile ./bin/cerebro
make serve-dev      # run the local server with acknowledged dev-mode opt-out
make test           # go test ./...
make check          # build, tests, lint, proto lint, structural checks, arch tests
make verify         # CI-parity local verification
make readme-check   # README and docs drift checks
make docs-drift-check
make oss-audit      # public repository hygiene scan
```

Top-level commands are `serve`, `version`, `source`, `source-runtime`, `finding-rule`, `graph`, `orchestrator`, `vulndb`, `closeout`, and `deploy`.

For compliance-control work, run `make control-index-check`, `make policy-rule-check`, and `make detection-catalog-check`. Control extension packs are documented in [Compliance controls](docs/COMPLIANCE_CONTROLS.md) and use `--init-extension`, `--extension`, `--profile`, `--output`, and `--write` workflows.

## Stack

| Component | Technology |
| --- | --- |
| Language | Go 1.26+ (`go1.26.4` toolchain) |
| HTTP server | Go `net/http` `ServeMux` |
| RPC | Connect |
| CLI | Standard Go CLI under `cmd/cerebro` |
| Append log | NATS JetStream |
| State store | Postgres |
| Graph store | Neo4j/Aura |
| Validation | `go test`, `golangci-lint`, Buf, Spectral, catalog checks, policy-rule checks, control-index checks, README drift checks, OSS audit, custom structural linters, arch tests |

## License

Apache 2.0; see [LICENSE](LICENSE).
