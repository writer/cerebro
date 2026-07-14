# Cerebro

**Agent-readable security and compliance context.**

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Cerebro is Writer's public Go runtime for turning security, identity, cloud, SaaS, workflow, policy, and compliance data into evidence-backed context that coding agents and automation can query. It is a source integration, evidence, findings, controls, and graph runtime exposed through a CLI, JSON HTTP API, Connect RPC, MCP, and SDK helpers.

Cerebro is not an end-user web UI, SIEM, SOAR, CSPM replacement, LLM host, or data warehouse. It is the runtime and contract layer that lets agents ask grounded questions such as:

- What evidence exists for this repo, asset, identity, control, or workflow?
- Which policies, controls, findings, approvals, and owners apply?
- What changed, what is risky, and what should be fixed first?
- Which connected systems, identities, and resources explain the risk?
- Is a proposed action supported by current evidence?

## How The Runtime Works

Cerebro has two useful operating shapes:

1. **Live source preview:** run the Go server and call source tools directly. This path can read provider data through the source service without Postgres, NATS, or Neo4j.
2. **Durable evidence runtime:** add NATS JetStream, Postgres, and Neo4j/Aura to persist source runtime syncs, append-log events, findings, reports, and graph projections.

The same source contracts, API contracts, policy catalogs, and validation tools are used in both shapes. Routes that need a configured durable store fail closed when that store is absent.

## Quick Start

```bash
git clone https://github.com/writer/cerebro.git
cd cerebro

make doctor
make serve-dev
```

The local development server listens on `:8080` by default.

```bash
curl -sS http://127.0.0.1:8080/health
curl -sS http://127.0.0.1:8080/sources
```

Build the binary directly when you want to run the CLI:

```bash
make build
./bin/cerebro version
./bin/cerebro source list
```

## Give A Coding Agent Context

Start Cerebro, connect an MCP client to the local MCP endpoint, then let the agent read live source data through Cerebro.

```bash
make serve-dev
droid mcp add cerebro-local http://127.0.0.1:8080/api/v1/mcp --type http \
  --header "Authorization: Bearer local-dev-key"
```

Example agent instruction:

```text
Use Cerebro as security and compliance context for this repo.
Call cerebro.sources.read with source_id=github and config
{"owner":"<owner>","repo":"<repo>","per_page":"5"}, then summarize the
evidence, risks, controls, and follow-up questions that apply before this can
ship.

Do not commit provider credentials, customer names, tenant-specific hostnames,
account IDs, or live secret values.
```

The MCP source tools, `cerebro.sources.list`, `cerebro.sources.check`, `cerebro.sources.discover`, and `cerebro.sources.read`, call the same source service used by the HTTP and CLI surfaces. For durable graph and evidence context, run `make github-business-demo` with `GITHUB_OWNER`, `GITHUB_REPO`, and `GITHUB_TOKEN`, then hand `tmp/onboarding/github-receipt.json` to the agent.

See [Agent onboarding](docs/start/agent-onboarding.md), [MCP native Droid setup](docs/domains/mcp-droid-setup.md), and [Agent platform contract](docs/domains/agent-platform-contract.md).

## Durable Local Stack

Use Docker Compose when you need the durable runtime locally.

```bash
docker compose pull
docker compose up -d
```

The compose stack runs Cerebro with NATS JetStream, Postgres, Neo4j, and the local bearer key `local-dev-key`. Configuration lives in `.env.example` and `docs/reference/config-env-vars.md`.

Plain Compose initializes the local Postgres volume with the compose-file password. The onboarding Make targets use `tmp/local-postgres-password`. If you switch between those modes, recreate local volumes with `docker compose down -v` or run the Make target with an explicit local Postgres password that matches the existing volume. `docker compose down -v` deletes local stack data.

## What Is In This Repo

- `cmd/cerebro`: the main Go binary. It defaults to `serve` and also exposes source, runtime, graph, finding, closeout, deploy, and orchestration commands.
- `internal/bootstrap`: HTTP, Connect RPC, MCP, auth, rate-limit, and route wiring for the runtime.
- `internal/sourcecdk`, `internal/sourceregistry`, and `sources/`: the source contract and built-in source catalog for cloud, SaaS, identity, endpoint, vulnerability, workflow, and compliance signals.
- `internal/appendlog`, `internal/sourceprojection`, `internal/findings`, and graph packages: durable event, runtime sync, finding, report, and graph workflows.
- `policies/`, `internal/findingdsl`, and `internal/findings`: policy, control mapping, finding rule, and detection catalogs.
- `api/openapi.yaml` and `proto/cerebro/v1/bootstrap.proto`: JSON HTTP and Connect RPC contracts.
- `sdk/python/README.md`, `sdk/typescript/README.md`, and `sdk/go/cerebroapi`: SDK helper packages.
- `docs/`, `scripts/`, and `tools/`: operating guides, validation checks, generators, and repository-specific guardrails.

## Main Surfaces

| Surface | Use it for | Start here |
| --- | --- | --- |
| CLI | Local development, source checks, runtime syncs, graph operations, finding rules, deploy preflights | `./bin/cerebro --help`, [CLI reference](docs/reference/cli.md) |
| JSON HTTP | Simple service integrations and local smoke checks | [API reference](docs/reference/api-reference.md), `api/openapi.yaml` |
| Connect RPC | Typed service clients and generated contracts | `proto/cerebro/v1/bootstrap.proto` |
| MCP | Agent-readable source, policy, graph, and evidence context | `POST /api/v1/mcp`, `docs/domains/mcp-droid-setup.md` |
| SDK helpers | Client helper packages for generated API surfaces | `sdk/python/README.md`, `sdk/typescript/README.md`, `sdk/go/cerebroapi` |

Top-level commands are `serve`, `version`, `source`, `source-runtime`, `append-log`, `finding-rule`, `graph`, `orchestrator`, `vulndb`, `closeout`, and `deploy`.

## Choose A Path

| Goal | Start here |
| --- | --- |
| Get the shortest runnable path | [Quick reference](docs/start/quick-reference.md) |
| Walk through a local end-to-end flow | [Getting started](docs/start/getting-started.md) |
| Hand setup to a coding agent | [Agent onboarding](docs/start/agent-onboarding.md) |
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

## Runtime Boundaries

This public repository is authoritative for runtime behavior, CLI/API contracts, source catalogs, configuration semantics, validation checks, and release artifacts. Environment-specific deployment details, stack configuration, account wiring, hostnames, and rollout procedures intentionally live outside this public repo.

The deployment handoff is the release payload: container images plus `cerebro-runtime-contract.json`. Treat that contract as the bridge between public runtime releases and environment-specific promotion and deployment automation.

Volatile details should stay in their source-of-truth files and be linked from here: configuration variables in `docs/reference/config-env-vars.md`, API shape in `api/openapi.yaml`, source capabilities in `sources/*/catalog.yaml`, and release/deploy handoff data in `cerebro-runtime-contract.json`.

Read [Non-goals](docs/engineering/non-goals.md) before changing storage shape, Source CDK boundaries, graph/Cypher behavior, findings workflow contracts, action/runtime response semantics, platform/security namespace boundaries, or public product language.

## Common Commands

```bash
make build                    # compile ./bin/cerebro
make serve-dev                # run the local server with acknowledged dev-mode opt-out
make test                     # run Go tests
make check                    # build, tests, lint, proto lint, structural checks, and arch tests
make verify                   # CI-parity local verification
make readme-check             # README formatting and drift checks
make docs-drift-check         # documentation drift checks
make oss-audit                # public repository hygiene scan
make sdk-test                 # SDK tests and type checks
make secure-business-demo     # run local security onboarding and write a receipt
make github-business-demo     # seed durable graph context from a real GitHub repo
make agent-onboard            # run an onboarding plan and write a redacted receipt
make agent-onboard-e2e        # run the Docker-backed local onboarding workflow
make finding-dsl-check        # validate finding DSL definitions
make policy-rule-check        # validate policy rule catalog behavior
make detection-catalog-check  # validate generated detection catalogs
make control-index-check      # validate compliance control index output
cerebro deploy preflight      # emit a redacted deployment readiness receipt
```

Control extension packs are documented in [Compliance controls](docs/domains/compliance-controls.md) and use `--init-extension`, `--extension`, `--profile`, `--output`, and `--write` workflows.

## Optional Docs Site

The Markdown docs work directly on GitHub. To browse them as a local site:

```bash
python3 -m pip install mkdocs
mkdocs serve
```

The site entry point is [docs/index.md](docs/index.md), and `mkdocs.yml` defines the navigation.

## Stack

| Component | Technology |
| --- | --- |
| Language | Go 1.26+ with `go1.26.5` toolchain |
| HTTP server | Go `net/http` `ServeMux` |
| RPC | Connect |
| CLI | Standard Go CLI under `cmd/cerebro` |
| MCP | HTTP MCP endpoint at `/api/v1/mcp` |
| Append log | NATS JetStream |
| State store | Postgres |
| Graph store | Neo4j/Aura |
| Validation | `go test`, `golangci-lint`, Buf, Spectral, catalog checks, policy-rule checks, control-index checks, README drift checks, OSS audit, custom structural linters, and arch tests |

## License

Apache 2.0; see [LICENSE](LICENSE).
