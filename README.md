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
- Source runtime sync, append-log replay, claim/finding/report workflows, compliance control coverage, and optional graph projection, query, and action tooling.
- Optional MCP, graph-agent, and device-authenticated telemetry surfaces.
- Policy and FindingRule YAML DSL catalogs, generated detection catalogs, SDK helpers, OpenAPI/Connect contracts, release artifacts, and local validation tooling.

## Choose A Path

| Goal | Start here |
| --- | --- |
| Get the shortest runnable path | [Quick reference](docs/start/quick-reference.md) |
| Walk through a local end-to-end flow | [Getting started](docs/start/getting-started.md) |
| Understand runtime shape and stores | [Architecture](docs/reference/architecture.md) |
| Configure auth, tenancy, stores, MCP, or device auth | [Configuration variables](docs/reference/config-env-vars.md) and [.env.example](.env.example) |
| Host or operate Cerebro | [Hosting](docs/operations/hosting.md), [runtime profiles](docs/operations/runtime-profiles.md), [deployment readiness](docs/operations/deployment-readiness.md), [cloud deployment](docs/operations/cloud-deployment.md), [deployment examples](docs/operations/deployment-examples.md), and [operations runbook](docs/operations/operations-runbook.md) |
| Explore JSON HTTP or Connect APIs | [API reference](docs/reference/api-reference.md), `api/openapi.yaml`, and `proto/cerebro/v1/bootstrap.proto` |
| Use the CLI | [CLI reference](docs/reference/cli.md) |
| Browse built-in integrations | [Source catalog](docs/reference/sources.md) |
| Use SDK helpers | [Python SDK](sdk/python/README.md), [TypeScript SDK](sdk/typescript/README.md), and `sources/sdk` |
| Persist and sync source runtimes | [Source runtime guide](docs/domains/source-runtime-guide.md) |
| Work on graph behavior | [Graph operations](docs/domains/graph-operations.md) |
| Design persona-specific graph views | [Persona view lenses](docs/domains/persona-view-lenses.md) |
| Integrate MCP clients | [MCP native Droid setup](docs/domains/mcp-droid-setup.md) |
| Integrate endpoint telemetry | [Endpoint security platform integration](docs/domains/endpoint-security-platform-integration.md) |
| Author policies, control mappings, or finding rules | [Policies](docs/domains/policies.md), [compliance controls](docs/domains/compliance-controls.md), `policies/`, `internal/findingdsl`, and `internal/findings` |
| Contribute code or docs | [Development](docs/engineering/development.md), [non-goals](docs/engineering/non-goals.md), and the Makefile |

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

Volatile details should stay in their source-of-truth files and be linked from here: configuration variables in `docs/reference/config-env-vars.md`, API shape in `api/openapi.yaml`, source capabilities in `sources/*/catalog.yaml`, and release/deploy handoff data in `cerebro-runtime-contract.json`.

See [Non-goals](docs/engineering/non-goals.md) before changing storage shape, Source CDK boundaries, graph/Cypher behavior, findings workflow contracts, action/runtime response semantics, platform/security namespace boundaries, or public product language.

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
cerebro deploy preflight  # emit a redacted deployment readiness receipt
```

Top-level commands are `serve`, `version`, `source`, `source-runtime`, `finding-rule`, `graph`, `orchestrator`, `vulndb`, `closeout`, and `deploy`.

For policy or compliance-control work, run `make finding-dsl-check`, `make policy-rule-check`, `make detection-catalog-check`, and `make control-index-check` as applicable. Control extension packs are documented in [Compliance controls](docs/domains/compliance-controls.md) and use `--init-extension`, `--extension`, `--profile`, `--output`, and `--write` workflows.

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
