# Cerebro

**Operations data platform for cloud, SaaS, identity, workflow, finding, and graph signals.**

Cerebro is Writer's original operations platform repository. The current `main` branch is centered on a Go bootstrap service with Connect and JSON HTTP APIs, built-in source integrations, source runtime sync, finding and report workflows, append-log replay, and optional graph projection/query tooling.

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## Current capabilities

- **Bootstrap API service** — `net/http` plus Connect RPC handlers for health, sources, runtimes, claims, findings, reports, workflow events, and graph queries.
- **Source previews and runtime sync** — built-in sources can be checked, discovered, read, persisted as source runtimes, synced through an append log, and projected into state/graph stores when configured.
- **Finding workflows** — built-in finding rules can evaluate source runtime events, persist evidence/evaluation runs, and drive finding lifecycle actions.
- **Report runs** — report definitions can be listed and executed with durable run retrieval when a state store is configured.
- **Workflow event replay** — knowledge decisions, actions, and outcomes can be written and replayed through append-log-backed projections.
- **Graph operations** — Neo4j/Aura-backed graph counts, neighborhoods, path summaries, integrity checks, source ingest, runtime ingest, and ingest run status, plus isolated dry-run rebuilds.
- **Policy catalog** — JSON policy definitions under `policies/` for cloud, identity, GitHub, Kubernetes, SaaS, runtime, vulnerability, compliance, and business-operation checks.

Cerebro has historical and forward-looking docs in `docs/`. For current runtime behavior, treat `cmd/cerebro`, `internal/config`, `internal/bootstrap`, `proto/cerebro/v1/bootstrap.proto`, and the Makefile as the source of truth.

---

## Architecture

```text
CLI / JSON HTTP / Connect clients
              |
              v
      Bootstrap service
   (cmd/cerebro, internal/bootstrap)
              |
              +--> Source registry, preview, and runtime sync
              +--> Claim, finding, report, workflow, and graph services
              |
              +--> Optional append log: NATS JetStream
              +--> Optional state store: Postgres
              +--> Optional graph store: Neo4j/Aura
```

External dependency drivers are opt-in. With no external drivers configured, the server can start and serve lightweight routes such as `/health`, `/healthz`, and `/sources`. Durable runtime, claim, finding, report, replay, and graph operations require their corresponding stores.

---

## Quick start

### Prerequisites

- Go 1.26+; this repo pins toolchain `go1.26.2`.
- Optional: NATS JetStream for append-log-backed sync/replay.
- Optional: Postgres for durable source runtime, claim, finding, evidence, evaluation, and report state.
- Optional: Neo4j or AuraDB for graph projection/query operations.

### Build and verify

```bash
git clone https://github.com/writer/cerebro.git
cd cerebro

make build
make test
make verify
```

### Run locally

```bash
make serve
# or
./bin/cerebro serve
```

By default, Cerebro listens on `:8080`.

```bash
curl -sS http://127.0.0.1:8080/health
curl -sS http://127.0.0.1:8080/sources
```

---

## Configuration

The bootstrap binary currently reads these environment variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `CEREBRO_HTTP_ADDR` | HTTP listen address | `:8080` |
| `CEREBRO_SHUTDOWN_TIMEOUT` | graceful shutdown timeout | `10s` |
| `CEREBRO_API_AUTH_ENABLED` | require bearer/API-key auth for non-public routes | `false` |
| `CEREBRO_API_KEYS` | comma-separated `key[:principal[:tenant_id]]` entries | unset |
| `CEREBRO_ALLOWED_TENANTS` | optional tenant allowlist for unscoped API keys | unset |
| `CEREBRO_APPEND_LOG_DRIVER` | append-log driver; supported value: `jetstream` | unset |
| `CEREBRO_JETSTREAM_URL` | NATS URL for JetStream | unset |
| `CEREBRO_JETSTREAM_SUBJECT_PREFIX` | JetStream subject prefix | `events` |
| `CEREBRO_STATE_STORE_DRIVER` | state-store driver; supported value: `postgres` | unset |
| `CEREBRO_POSTGRES_DSN` | Postgres DSN | unset |
| `CEREBRO_GRAPH_STORE_DRIVER` | graph-store driver; supported value: `neo4j` | unset |
| `CEREBRO_NEO4J_URI` | Neo4j/Aura connection URI | unset |
| `CEREBRO_NEO4J_USERNAME` | Neo4j/Aura username | unset |
| `CEREBRO_NEO4J_PASSWORD` | Neo4j/Aura password | unset |
| `CEREBRO_NEO4J_DATABASE` | optional Neo4j database name; empty uses the server default | unset |

Driver selection is inferred when a driver-specific setting is present. For example, `CEREBRO_POSTGRES_DSN` selects the Postgres state store, and `CEREBRO_NEO4J_URI` selects the Neo4j graph store.

Enable `CEREBRO_API_AUTH_ENABLED=true` in shared or production deployments. API keys can be scoped to a tenant with `key:principal:tenant_id`; requests that provide a different `tenant_id` are rejected before service logic runs.

Example durable local configuration:

```bash
export CEREBRO_APPEND_LOG_DRIVER=jetstream
export CEREBRO_JETSTREAM_URL=nats://127.0.0.1:4222
export CEREBRO_STATE_STORE_DRIVER=postgres
export CEREBRO_POSTGRES_DSN='postgres://127.0.0.1:5432/cerebro?sslmode=disable'
export CEREBRO_GRAPH_STORE_DRIVER=neo4j
export CEREBRO_NEO4J_URI=bolt://127.0.0.1:7687
export CEREBRO_NEO4J_USERNAME=neo4j
export CEREBRO_NEO4J_PASSWORD='local-password'
```

---

## Dependencies by operation

| Operation | Required backing dependencies |
| --- | --- |
| `serve`, `/health`, `/sources`, source `check/discover/read` | none beyond provider-specific source config/auth |
| `source-runtime put/get` | Postgres state store |
| `source-runtime sync` | Postgres state store + NATS JetStream append log |
| Claim, finding, evidence, evaluation, and report run persistence | Postgres state store |
| Workflow replay | NATS JetStream append log plus configured projection stores |
| Graph query/ingest operations | Neo4j/Aura graph store; runtime-backed graph operations also need Postgres and/or JetStream |
| Graph rebuild dry-runs | Postgres state store; replay mode also needs NATS JetStream append log |

---

## CLI

Build first with `make build`, then run `./bin/cerebro`.

```bash
# Server and version
./bin/cerebro serve
./bin/cerebro version

# Source catalog and previews
./bin/cerebro source list
./bin/cerebro source check github owner=writer repo=cerebro
./bin/cerebro source discover github owner=writer repo=cerebro
./bin/cerebro source read github owner=writer repo=cerebro per_page=1

# Source runtimes require configured stores
./bin/cerebro source-runtime put writer-github github tenant_id=writer owner=writer repo=cerebro
./bin/cerebro source-runtime get writer-github
./bin/cerebro source-runtime sync writer-github page_limit=1

# Finding rule scaffolding
./bin/cerebro finding-rule new identity-example source_id=okta event_kinds=okta.user name="Example identity rule" dry_run=true

# Graph inspection and ingest require a configured graph store
./bin/cerebro graph counts
./bin/cerebro graph neighborhood <root-urn> limit=10
./bin/cerebro graph paths limit=10
./bin/cerebro graph integrity
./bin/cerebro graph ingest github tenant_id=writer owner=writer repo=cerebro page_limit=1
./bin/cerebro graph ingest-runtime writer-github page_limit=1
./bin/cerebro graph ingest-run <run-id>
./bin/cerebro graph ingest-runs runtime_id=writer-github
./bin/cerebro graph rebuild writer-github dry_run=true mode=replay
```

Top-level commands are `serve`, `version`, `source`, `source-runtime`, `finding-rule`, and `graph`.

---

## Built-in sources

| Source ID | Description | Emitted kinds / families |
| --- | --- | --- |
| `aws` | AWS IAM inventory and CloudTrail source | `aws.access_key`, `aws.cloudtrail`, `aws.iam_*`, `aws.resource_exposure` |
| `azure` | Azure Entra ID, RBAC, activity, and audit source | `azure.activity_log`, `azure.directory_audit`, `azure.user`, `azure.group`, `azure.*assignment`, `azure.resource_exposure` |
| `gcp` | GCP IAM, Cloud Identity, service-account, and audit source | `gcp.audit`, `gcp.group`, `gcp.iam_role_assignment`, `gcp.service_account*`, `gcp.resource_exposure` |
| `github` | GitHub audit, Dependabot, and pull request source | `github.audit`, `github.dependabot_alert`, `github.pull_request` |
| `google_workspace` | Google Workspace Directory and Admin audit source | `google_workspace.audit`, `google_workspace.group`, `google_workspace.group_member`, `google_workspace.role_assignment`, `google_workspace.user` |
| `okta` | Okta audit, identity inventory, app, group, assignment, and admin role source | `okta.audit`, `okta.admin_role`, `okta.app_assignment`, `okta.application`, `okta.group`, `okta.group_membership`, `okta.user` |
| `sdk` | Generic SDK push source for onboarded applications | validates pushed integration config; preview reads are empty |

Source-specific configuration is passed as `key=value` pairs in CLI calls or query parameters in HTTP calls. Required keys vary by source and family.

---

## HTTP and Connect API surface

Connect RPC procedures are served under `/cerebro.v1.BootstrapService/{Method}`. The server also registers JSON HTTP routes:

| Route | Purpose |
| --- | --- |
| `GET /health`, `GET /healthz` | service and dependency health |
| `GET /sources` | list registered sources |
| `GET /sources/{sourceID}/check` | validate source configuration |
| `GET /sources/{sourceID}/discover` | discover source collections |
| `GET /sources/{sourceID}/read` | preview source events |
| `PUT /source-runtimes/{runtimeID}` | create/update a source runtime |
| `GET /source-runtimes/{runtimeID}` | load a source runtime |
| `POST /source-runtimes/{runtimeID}/sync` | sync a source runtime |
| `GET /source-runtimes/{runtimeID}/claims` | list runtime claims |
| `POST /source-runtimes/{runtimeID}/claims` | write runtime claims |
| `GET /source-runtimes/{runtimeID}/findings` | list runtime findings |
| `GET /source-runtimes/{runtimeID}/finding-evidence` | list runtime finding evidence |
| `GET /source-runtimes/{runtimeID}/finding-evaluation-runs` | list runtime finding evaluation runs |
| `POST /source-runtimes/{runtimeID}/finding-rules/evaluate` | evaluate finding rules |
| `POST /source-runtimes/{runtimeID}/findings/evaluate` | evaluate findings |
| `GET /finding-rules` | list built-in finding rules |
| `GET /findings/{findingID}` | get finding details |
| `POST /findings/{findingID}/resolve` | resolve a finding |
| `POST /findings/{findingID}/suppress` | suppress a finding |
| `PUT /findings/{findingID}/assign` | assign a finding |
| `PUT /findings/{findingID}/due` | set a finding due date |
| `POST /findings/{findingID}/notes` | add a finding note |
| `POST /findings/{findingID}/tickets` | link a ticket |
| `GET /finding-evidence/{evidenceID}` | get finding evidence |
| `GET /finding-evaluation-runs/{runID}` | get evaluation run details |
| `GET /reports` | list report definitions |
| `POST /reports/{reportID}/runs` | run a report |
| `GET /report-runs/{runID}` | get a report run |
| `POST /platform/knowledge/decisions` | write a knowledge decision |
| `POST /platform/knowledge/actions` | write a workflow action |
| `POST /graph/actuate/recommendation` | write an action through the graph actuation route |
| `POST /graph/write/outcome` | write a workflow outcome |
| `POST /platform/workflow/replay` | replay workflow events |
| `GET /graph/neighborhood` | query graph neighborhood |

---

## Policies

Policy definitions live under `policies/` as JSON files. The catalog includes cloud posture, identity governance, GitHub, Kubernetes, M365, Okta, runtime, vulnerability, compliance, and business-operation checks.

Useful directories include `policies/aws/`, `policies/azure/`, `policies/gcp/`, `policies/github/`, `policies/identity/`, `policies/kubernetes/`, `policies/okta/`, `policies/runtime/`, and `policies/vulnerability/`.

---

## Development

```bash
make build          # compile ./bin/cerebro
make serve          # build and run the server
make test           # go test ./...
make lint           # golangci-lint over app packages
make proto-lint     # buf lint
make check          # build, tests, lint, proto lint, structural checks, arch tests
make verify         # CI-parity local verification
make clean          # remove bin/
```

Focused validation and utility targets include `make workflow-e2e-test`, `make workflow-replay-test`, `make finding-rule-test`, `make graph-rebuild-dryrun`, `make workflow-replay`, and `make workflow-neighborhood`.

---

## Documentation

Some files in `docs/` describe broader or historical architecture and may be ahead of or behind the current bootstrap implementation. Useful entry points:

| Document | Notes |
| --- | --- |
| [API contracts](docs/API_CONTRACTS_AUTOGEN.md) | current bootstrap HTTP and Connect contract reference |
| [CloudEvents](docs/CLOUDEVENTS_AUTOGEN.md) | generated event contract reference |
| [Graph ontology](docs/GRAPH_ONTOLOGY_AUTOGEN.md) | generated graph ontology reference |
| [Graph report contracts](docs/GRAPH_REPORT_CONTRACTS_AUTOGEN.md) | generated graph/report contract reference |
| [Policies](docs/POLICIES.md) | policy catalog and authoring notes |
| [Packages](docs/PACKAGES.md) | package overview; verify against current code before relying on details |
| [Development](docs/DEVELOPMENT.md) | development notes; verify commands against the Makefile |

---

## Stack

| Component | Technology |
| --- | --- |
| Language | Go 1.26+ (`go1.26.2` toolchain) |
| HTTP server | Go `net/http` `ServeMux` |
| RPC | Connect |
| CLI | Standard Go CLI under `cmd/cerebro` |
| Append log | NATS JetStream |
| State store | Postgres |
| Graph store | Neo4j/Aura |
| Source integrations | AWS, Azure, GCP, GitHub, Google Workspace, Okta, SDK |
| Validation | `go test`, `golangci-lint`, Buf, custom structural linters, arch tests |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
