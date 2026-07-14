# Cerebro Documentation

Cerebro gives coding agents compliance superpowers.

The current `main` branch is centered on a Go bootstrap service that turns security, identity, cloud, SaaS, workflow, policy, and compliance signals into evidence-backed context. Agents and operators can query that context through JSON HTTP, Connect APIs, CLI workflows, SDK helpers, MCP access, and optional graph projection/query tooling.

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

With no external drivers configured, the server can still start and serve lightweight routes such as `/health`, `/healthz`, `/livez`, `/openapi.yaml`, `/sources`, and stateless MCP source previews. Durable runtime, claim, finding, report, replay, and graph operations require their corresponding stores.

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
docker compose pull
docker compose up -d
```

Plain Compose initializes the local Postgres volume with the compose-file password. The onboarding Make targets use `tmp/local-postgres-password`. Before switching from plain Compose to `make agent-onboard-e2e` or `make github-business-demo`, run `docker compose down -v` to recreate local volumes, or run the Make target with `CEREBRO_LOCAL_POSTGRES_PASSWORD=cerebro` to reuse that volume. `docker compose down -v` deletes local stack data.

## Agent Compliance Quickstart

Start Cerebro and connect it to your coding agent over MCP:

```bash
make serve-dev
droid mcp add cerebro-local http://127.0.0.1:8080/api/v1/mcp --type http \
  --header "Authorization: Bearer local-dev-key"
```

```text
Use Cerebro as compliance context for this repo.
Call cerebro.sources.read for source_id=github with config owner=<owner>,
repo=<repo>, and per_page=5. Summarize the live evidence and the security
or compliance context that applies before this can ship.
```

For durable evidence and graph context, run `make github-business-demo` with `GITHUB_OWNER`, `GITHUB_REPO`, and `GITHUB_TOKEN`, then give `tmp/onboarding/github-receipt.json` to the agent. For hosted integrations, connect an MCP client to `POST /api/v1/mcp` so agents can query policy memory, compliance evidence, graph context, and safe action-planning contracts.

## Main Docs

| Need | Document |
| --- | --- |
| Short command reference | [Quick reference](start/quick-reference.md) |
| Local end-to-end walkthrough | [Getting started](start/getting-started.md) |
| Coding agent setup handoff | [Agent onboarding](start/agent-onboarding.md) |
| Runtime shape and dependency boundaries | [Architecture](reference/architecture.md) |
| Runtime configuration | [Configuration variables](reference/config-env-vars.md) |
| Hosting and operations | [Hosting](operations/hosting.md), [runtime profiles](operations/runtime-profiles.md), [deployment readiness](operations/deployment-readiness.md), [cloud deployment](operations/cloud-deployment.md), [deployment examples](operations/deployment-examples.md), [operations runbook](operations/operations-runbook.md), [append-log dead-letter data policy](operations/append-log-dead-letter-policy.md), and [troubleshooting](operations/troubleshooting.md) |
| API contracts | [API reference](reference/api-reference.md), [generated API contracts](reference/api-contracts.md), `../api/openapi.yaml`, and `../proto/cerebro/v1/bootstrap.proto` |
| CLI usage | [CLI reference](reference/cli.md) |
| Built-in source integrations | [Source catalog](reference/sources.md) |
| Source runtime sync | [Source runtime guide](domains/source-runtime-guide.md) |
| Graph operations | [Graph operations](domains/graph-operations.md) |
| Persona-specific graph views | [Persona view lenses](domains/persona-view-lenses.md) |
| GRC architecture | [GRC architecture](domains/grc-architecture.md) |
| Compliance control coverage | [Compliance controls](domains/compliance-controls.md) |
| Policies | [Policies](domains/policies.md) |
| Security operations | [Security operations](domains/security-operations.md) |
| Aperio integration | [Aperio integration contract](domains/aperio-integration-contract.md) |
| Source health and coverage | [Source health and coverage](domains/source-health-and-coverage.md) |
| Agent platform services | [Agent platform services](domains/agent-platform-services.md) |
| Risk planning, graph provenance, and query cache | [Risk, graph, and cache](domains/risk-graph-and-cache.md) |
| Findings platform | [Findings platform architecture](domains/findings-platform-architecture.md) |
| Finding candidate operations | [Finding candidate operations](domains/finding-candidate-operations.md) |
| Policy rule extensions | [Policy rule extensions](domains/policy-rule-extensions.md) |
| MCP setup | [MCP native Droid setup](domains/mcp-droid-setup.md) |
| Endpoint telemetry | [Endpoint security platform integration](domains/endpoint-security-platform-integration.md) |
| Release artifacts | [Release contract](operations/release-contract.md) |
| Contribution rules | [Development](engineering/development.md) and [non-goals](engineering/non-goals.md) |

## Source Of Truth

Treat `cmd/cerebro`, `internal/bootstrap`, `internal/config`, `api/openapi.yaml`, `proto/cerebro/v1/bootstrap.proto`, `sources/*/catalog.yaml`, and the Makefile as the current runtime source of truth. Some older docs may describe broader architecture ideas and should be verified against the current bootstrap implementation before use.
