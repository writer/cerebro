# Cerebro

**Compliance superpowers for coding agents.**

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Cerebro turns security, identity, cloud, SaaS, workflow, policy, and compliance signals into evidence-backed context that coding agents can query through a Go CLI, JSON HTTP, Connect RPC, SDK helpers, and MCP.

Use it to help agents answer:

- Can this change ship?
- Which controls, policies, findings, or approvals apply?
- What evidence already exists?
- What remediation or next action is safe to propose?
- Which systems, identities, and risks are connected?

## Give Your Coding Agent Compliance Context

The fastest path is to start Cerebro, add it to your agent over MCP, and let the agent read live source data before any stores are configured:

```bash
make serve-dev
droid mcp add cerebro-local http://127.0.0.1:8080/api/v1/mcp --type http \
  --header "Authorization: Bearer local-dev-key"
```

```text
Use Cerebro as compliance context for this repo.
Call cerebro.sources.read with source_id=github and config
{"owner":"<owner>","repo":"<repo>","per_page":"5"}, then tell me what
evidence exists and what security or compliance context applies before this
can ship.

Do not commit provider credentials, customer names, tenant-specific hostnames,
account IDs, or live secret values.
```

The MCP source tools (`cerebro.sources.list/check/discover/read`) hit live providers through the existing source service and do not require Postgres, NATS, or Neo4j. For durable evidence and graph context, run `make github-business-demo` with `GITHUB_OWNER`, `GITHUB_REPO`, and `GITHUB_TOKEN`, then hand `tmp/onboarding/github-receipt.json` to the agent.

For a live agent integration, connect your MCP client to `POST /api/v1/mcp` and expose Cerebro as the source for policy memory, compliance evidence, graph context, and safe action planning. See [Agent onboarding](docs/start/agent-onboarding.md), [MCP native Droid setup](docs/domains/mcp-droid-setup.md), and [Agent platform contract](docs/domains/agent-platform-contract.md).

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
docker compose pull
docker compose up -d
```

Plain Compose initializes the local Postgres volume with the compose-file password. The onboarding Make targets use `tmp/local-postgres-password`. Before switching from plain Compose to `make agent-onboard-e2e` or `make github-business-demo`, run `docker compose down -v` to recreate local volumes, or run the Make target with `CEREBRO_LOCAL_POSTGRES_PASSWORD=cerebro` to reuse that volume. `docker compose down -v` deletes local stack data.

## What Is In This Repo

- A Go bootstrap service built around `net/http`, Connect RPC, and `cmd/cerebro`.
- Built-in source integrations for cloud, SaaS, identity, endpoint, vulnerability, compliance, and workflow signals.
- Source runtime sync, append-log replay, claim/finding/report workflows, compliance control coverage, and optional graph projection, query, and action tooling.
- Optional MCP, graph-agent, and device-authenticated telemetry surfaces for agent-readable evidence and control context.
- Policy and FindingRule YAML DSL catalogs, generated detection catalogs, SDK helpers, OpenAPI/Connect contracts, release artifacts, and local validation tooling.

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
make secure-business-demo  # run local security onboarding and write a receipt
make github-business-demo  # seed durable graph context from a real GitHub repo
make agent-onboard  # run an onboarding plan and write a redacted receipt
make agent-onboard-e2e  # run the Docker-backed local onboarding workflow
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
