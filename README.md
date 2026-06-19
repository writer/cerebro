# Cerebro

**Operations data platform for cloud, SaaS, identity, workflow, finding, and graph signals.**

Cerebro is Writer's original operations platform repository. The current `main` branch is centered on a Go bootstrap service with Connect and JSON HTTP APIs, built-in source integrations, source runtime sync, finding and report workflows, compliance-control coverage, append-log replay, MCP access, device-authenticated telemetry, and optional graph projection/query tooling.

In practical terms, Cerebro ingests source and runtime signals, turns them into claims, findings, reports, workflow events, compliance evidence, and graph context, then exposes that substrate through the CLI, JSON HTTP, Connect RPC, SDK helpers, and MCP.

[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## Current capabilities

- **Bootstrap API service** — `net/http` plus Connect RPC handlers for health, source, runtime, claim, finding, candidate, report, workflow, MCP, device, and graph routes.
- **Source previews and runtime sync** — built-in sources can be checked, discovered, read, bootstrapped from config, persisted as source runtimes, synced through an append log, and projected into state/graph stores when configured.
- **Panopticon security operations ingest** — first-class `panopticon` source runtimes read curated cases by default from the Panopticon API, with explicit alert and IOC families available for evidence and enrichment.
- **Finding workflows** — built-in finding rules can evaluate source runtime events, produce candidates, persist evidence/evaluation runs, promote or reject candidates, and drive finding lifecycle actions.
- **Report runs** — report definitions can be listed and executed with durable run retrieval when a state store is configured.
- **Workflow event replay** — knowledge decisions, actions, and outcomes can be written and replayed through append-log-backed projections.
- **Graph operations** — Neo4j/Aura-backed graph counts, relation counts, neighborhoods, path summaries, impact queries, graph health, source/runtime ingest, ingest run status, repair/cleanup helpers, and isolated dry-run rebuilds.
- **MCP and graph-agent surfaces** — an authenticated MCP endpoint, optional OAuth 2.1 authorization-server flow for MCP clients, and an optional graph agent LLM adapter.
- **Device telemetry surface** — optional first-party device enrollment, token, telemetry ingest, and device vulnerability finding routes.
- **Policy and compliance catalogs** — JSON policy definitions under `policies/`, generated detection catalogs, compliance control profiles, coverage indexes, evidence/posture packet helpers, and extension packs for custom control frameworks.

Cerebro has historical and forward-looking docs in `docs/`. For current runtime behavior, treat `cmd/cerebro`, `internal/config`, `internal/bootstrap`, `proto/cerebro/v1/bootstrap.proto`, and the Makefile as the source of truth.

---

## Public boundaries and non-goals

Cerebro exposes JSON HTTP, Connect RPC, CLI, and release artifacts. This repository does not ship an end-user web console, a SIEM/CSPM/CNAPP/EDR/SOAR replacement, an endpoint sensor, a plugin marketplace, a general-purpose graph database product, autonomous remediation, or a cloud-specific control plane.

### Cross-repo contract

This public repository is authoritative for runtime behavior, CLI/API contracts, source catalogs, configuration semantics, and release artifacts. Environment-specific deployment details, stack configuration, account wiring, hostnames, and rollout procedures intentionally live outside this public repo.

The handoff to deployment repositories is the release payload: container images plus `cerebro-runtime-contract.json`. Treat that contract as the bridge between public runtime releases and environment-specific promotion/deploy automation.

Volatile details should stay in their source-of-truth files and be linked from here: configuration variables in `docs/CONFIG_ENV_VARS.md`, API shape in `api/openapi.yaml`, source capabilities in `sources/*/catalog.yaml`, and release/deploy handoff data in `cerebro-runtime-contract.json`.

See [Non-goals](docs/NON_GOALS.md) before changing storage shape, Source CDK boundaries, graph/Cypher behavior, findings workflow contracts, action/runtime response semantics, platform/security namespace boundaries, or public product language.

Panopticon integration uses canonical event archives and supported SDK claim writes. EvidenceCAS data stays pointer-only (`evidencecas://` URI plus digest/Merkle metadata) and Cerebro does not provide a legacy claims-NDJSON importer.

---

## Architecture

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

External dependency drivers are opt-in. With no external drivers configured, the server can start and serve lightweight routes such as `/health`, `/healthz`, `/livez`, and `/sources`. `/health` is the dependency-aware readiness check; `/healthz` and `/livez` are liveness-only checks. Durable runtime, claim, finding, report, replay, and graph operations require their corresponding stores.

---

## Quick start

### Prerequisites

- Go 1.26+; this repo pins toolchain `go1.26.4`.
- Optional: NATS JetStream for append-log-backed sync/replay.
- Optional: Postgres for durable source runtime, claim, finding, evidence, evaluation, and report state.
- Optional: Neo4j or AuraDB for graph projection/query operations.

### First run

```bash
git clone https://github.com/writer/cerebro.git
cd cerebro

make doctor
make serve-dev
```

By default, Cerebro listens on `:8080`.

In another shell:

```bash
curl -sS http://127.0.0.1:8080/health
curl -sS http://127.0.0.1:8080/sources
```

Run focused tests while iterating, then use CI-parity validation before broad PRs:

```bash
make test
make verify
```

### Durable local stack

```bash
docker compose up --build
```

The compose stack starts Cerebro with NATS JetStream, Postgres, Neo4j, and a local-only bearer key (`local-dev-key`) using service-local `CEREBRO_*` environment variables. For a standalone environment template, start from `.env.example`.

---

## Choose your path

| Goal | Start here | Notes |
| --- | --- | --- |
| Run the lightweight server | `make serve-dev` | Starts the API without external stores using an acknowledged local-only auth/rate-limit opt-out; useful for health, source catalog, and OpenAPI checks. |
| Run the durable local stack | `docker compose up --build` | Starts Cerebro with NATS JetStream, Postgres, Neo4j, and the local bearer key `local-dev-key`. |
| Host Cerebro | `docs/HOSTING.md`, `docs/CLOUD_DEPLOYMENT.md`, `docs/DEPLOYMENT_EXAMPLES.md`, and `docs/OPERATIONS_RUNBOOK.md` | Deployment guidance, AWS/GCP/Azure Pulumi templates, example platform shapes, health checks, operations, and rollout. |
| Preserve production headroom | `docs/HEADROOM.md`, `docs/OBSERVABILITY.md`, and `make load-smoke` | Capacity SLOs, saturation alerts, autoscaling signals, wide-event incident queries, and bounded live load smoke checks. |
| Try a local end-to-end path | `docs/GETTING_STARTED.md` | Creates an SDK source runtime, writes a synthetic claim, and reads it back. |
| Explore the API | `GET /openapi.yaml` or `api/openapi.yaml` | JSON HTTP routes are generated and checked against the OpenAPI contract. |
| Call the Connect API | `proto/cerebro/v1/bootstrap.proto` and `gen/cerebro/v1` | Connect RPCs are served under `/cerebro.v1.BootstrapService/{Method}`. |
| Use SDK helpers | `sdk/python/README.md`, `sdk/typescript/README.md`, and `sources/sdk` | Maintained helpers target current bootstrap routes; the historical Agent SDK gateway is retired. |
| Map compliance controls and evidence coverage | `docs/COMPLIANCE_CONTROLS.md`, `make control-index-check`, and `go run ./tools/controlindex --init-extension ...` | Built-in profiles cover SOC 2, ISO, CIS, PCI, DORA, FedRAMP, NIS2, CMMC, CJIS, NIST CSF, privacy, and AI governance scopes. Control extension packs scaffold custom `extension.yaml`, `controls.yaml`, and `profiles.yaml` files, then `--extension`, `--profile`, `--output`, and `--write` generate filtered coverage packets. |
| Ingest Panopticon cases | `sources/panopticon`, source runtime config, and `sdk/python/examples/panopticon_push_claims.py` | API runtimes read curated `case` events by default; explicit `alert` and `ioc` families are available when raw signal evidence or IOC enrichment is needed. |
| Preview a source | `./bin/cerebro source check/discover/read ...` | Source config is passed as `key=value` pairs or HTTP query parameters. |
| Persist and sync a runtime | `docs/SOURCE_RUNTIME_GUIDE.md` and `source-runtime put/get/list/sync` | Requires Postgres; sync also requires JetStream. |
| Work on graph behavior | `docs/GRAPH_OPERATIONS.md` and `graph counts/health/ingest-runtime` | Requires Neo4j/Aura and, for runtime-backed operations, the configured runtime stores. |
| Configure auth and tenancy | `docs/AUTH_TENANCY.md` | Covers API keys, structured credentials, tenant scoping, proxy origin, and rotation. |
| Consume release artifacts | `docs/RELEASE_CONTRACT.md` | Covers image tags, runtime deploy contracts, source manifests, and artifact verification. |
| Troubleshoot operations | `docs/TROUBLESHOOTING.md` | Symptom-to-cause recipes for health, auth, source sync, graph, and MCP OAuth. |
| Integrate MCP clients | `docs/MCP_DROID_SETUP.md` and `/api/v1/mcp` | Covers stateless Streamable HTTP, OAuth discovery, and compatibility checks. |
| Shape agent-facing platform contracts | `docs/AGENT_PLATFORM_CONTRACT.md` and `internal/agentplatform` | Cerebro-native runtime, eval, capability, execution, replay, connector, and knowledge principles. |
| Integrate endpoint telemetry | `docs/ENDPOINT_SECURITY_PLATFORM_INTEGRATION.md` | Covers device-authenticated telemetry, trusted endpoint claims, and trust-gate evidence. |
| Author policies, control mappings, or finding rules | `policies/`, `docs/COMPLIANCE_CONTROLS.md`, `internal/compliance`, `internal/findings`, and catalog checks | Run the relevant catalog, policy-rule, control-index, detection-catalog, and finding-rule checks before opening a PR. |
| Contribute code or docs | `docs/DEVELOPMENT.md`, `docs/NON_GOALS.md`, and the Makefile | Prefer focused `make` targets while iterating; use `make verify` for broad PR preflight. |

---

## Configuration

The bootstrap binary currently reads core, auth, store, graph-agent, MCP OAuth, device-auth, and source-config environment variables through `internal/config`. Start from `.env.example` for a local template, and use `docs/CONFIG_ENV_VARS.md` as the expanded configuration reference.

Core runtime and store variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `CEREBRO_HTTP_ADDR` | HTTP listen address | `:8080` |
| `CEREBRO_SHUTDOWN_TIMEOUT` | graceful shutdown timeout | `10s` |
| `CEREBRO_IMAGE_TAG` | image tag exported by release/deploy tooling | unset |
| `CEREBRO_API_AUTH_ENABLED` | require bearer/API-key auth for non-public routes | `true` outside acknowledged dev mode |
| `CEREBRO_API_KEYS` | comma-separated `key[:principal[:tenant_id]]` entries | unset |
| `CEREBRO_API_CREDENTIALS_JSON` | structured bearer credentials with scopes and tenant metadata | unset |
| `CEREBRO_ALLOWED_TENANTS` | optional tenant allowlist for unscoped API keys | unset |
| `CEREBRO_CAPABILITY_TOKEN_SECRETS` | comma-separated HMAC secrets for capability-token auth | unset |
| `CEREBRO_CAPABILITY_TOKEN_AUDIENCE` | expected capability-token audience | `cerebro-api` |
| `CEREBRO_PUBLIC_ORIGIN` | canonical external origin for DPoP and proxy-aware URL reconstruction | request host |
| `CEREBRO_TRUSTED_PROXY_CIDRS` | comma-separated trusted proxy/load-balancer CIDRs for forwarded headers | unset |
| `CEREBRO_TRUSTED_PROXY_COUNT` | trusted trailing `X-Forwarded-For` hops | `0` |
| `CEREBRO_RATE_LIMIT_ENABLED` | enable global API rate limiting | `true` outside acknowledged dev mode |
| `CEREBRO_RATE_LIMIT_RPS` | global API rate-limit refill rate | `100` |
| `CEREBRO_RATE_LIMIT_BURST` | global API rate-limit burst size | `150` |
| `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BASE_URL` | access-approvals base URL for provider-backed graph actions and reconciliation | unset |
| `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN` | bearer token for access-approvals graph action create/read calls; supports `_FILE` | unset |
| `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_TIMEOUT` | access-approvals graph action request timeout | `10s` |
| `CEREBRO_APPEND_LOG_DRIVER` | append-log driver; supported value: `jetstream` | unset |
| `CEREBRO_JETSTREAM_URL` | NATS URL for JetStream | unset |
| `CEREBRO_JETSTREAM_SUBJECT_PREFIX` | JetStream subject prefix | `events` |
| `CEREBRO_STATE_STORE_DRIVER` | state-store driver; supported value: `postgres` | unset |
| `CEREBRO_POSTGRES_DSN` | Postgres DSN | unset |
| `CEREBRO_CACHE_MODE` | optional query-cache driver; supported: `off`, `memory`, `redis`, `valkey` | inferred from `CEREBRO_CACHE_URL`, otherwise `off` |
| `CEREBRO_CACHE_URL` | Redis/Valkey URL for shared GRC query caching | unset |
| `CEREBRO_CACHE_NAMESPACE` | cache key namespace, useful per environment | `cerebro` |
| `CEREBRO_CACHE_DEFAULT_TTL` | default fresh TTL for cacheable GRC reads | `30s` |
| `CEREBRO_CACHE_STALE_TTL` | stale-if-error window for cacheable GRC reads | `5m` |
| `CEREBRO_CACHE_MAX_PAYLOAD_BYTES` | maximum response payload eligible for caching | `1048576` |
| `CEREBRO_CONNECTOR_CREDENTIAL_KEY` | high-entropy key used to seal Cerebro-managed connector credentials in the state store | unset |
| `CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY` | RSA private key used to decrypt browser-submitted connector credentials; all replicas must share the same key | unset |
| `CEREBRO_GRAPH_STORE_DRIVER` | graph-store driver; supported value: `neo4j` | unset |
| `CEREBRO_NEO4J_URI` | Neo4j/Aura connection URI | unset |
| `CEREBRO_NEO4J_USERNAME` | Neo4j/Aura username | unset |
| `CEREBRO_NEO4J_PASSWORD` | Neo4j/Aura password | unset |
| `CEREBRO_NEO4J_DATABASE` | optional Neo4j database name; empty uses the server default | unset |

Advanced config families include:

| Variable family | Purpose |
| --- | --- |
| `source-runtime bootstrap env=<env-var>`, `CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST`, `CEREBRO_AWS_ASSUME_ROLE_ARNS` | bootstrap source runtimes and allow `env:` source config references |
| `CEREBRO_GRAPH_AGENT_LLM_*`, `CEREBRO_OPENROUTER_API_KEY` | optional graph-agent LLM provider/model settings |
| `CEREBRO_MCP_OAUTH_*` | optional OAuth 2.1 authorization-server surface for MCP clients |
| `CEREBRO_DEVICE_AUTH_*` | optional first-party device enrollment, token, DPoP, attestation, and telemetry controls |

Driver selection is inferred when a driver-specific setting is present. For example, `CEREBRO_POSTGRES_DSN` selects the Postgres state store, and `CEREBRO_NEO4J_URI` selects the Neo4j graph store.

API auth and rate limiting are enabled by default outside acknowledged dev mode. API keys can be scoped to a tenant with `key:principal:tenant_id`; requests that provide a different `tenant_id` are rejected before service logic runs.

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
| Connector library and credentialed connector creation | Postgres state store; credentialed creation also requires `CEREBRO_CONNECTOR_CREDENTIAL_KEY` and shared `CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY` |
| `source-runtime put/get` | Postgres state store |
| `source-runtime sync` | Postgres state store + NATS JetStream append log |
| Claim, finding, evidence, evaluation, and report run persistence | Postgres state store |
| Workflow replay | NATS JetStream append log plus configured projection stores |
| Graph query/ingest operations | Neo4j/Aura graph store; runtime-backed graph operations also need Postgres and/or JetStream |
| Graph rebuild dry-runs | Postgres state store; replay mode also needs NATS JetStream append log |
| MCP endpoint | API auth; OAuth mode additionally requires Postgres, public origin, client/upstream config, and capability-token secrets |
| Device-auth telemetry | API auth, device-auth signing keys, and a device-auth-capable state store |

---

## CLI

Build first with `make build`, then run `./bin/cerebro`.

```bash
# Server and version
./bin/cerebro serve
./bin/cerebro version

# Deploy preflight receipt
./bin/cerebro deploy preflight

# Source catalog and previews
./bin/cerebro source list
./bin/cerebro source check github owner=writer repo=cerebro
./bin/cerebro source discover github owner=writer repo=cerebro
./bin/cerebro source read github owner=writer repo=cerebro per_page=1

# Source runtimes require configured stores
./bin/cerebro source-runtime list
./bin/cerebro source-runtime bootstrap env=SOURCE_RUNTIMES_JSON
./bin/cerebro source-runtime put example-github github tenant_id=example owner=writer repo=cerebro
./bin/cerebro source-runtime get example-github
./bin/cerebro source-runtime sync example-github page_limit=1

# Finding rule scaffolding and graph-backed evaluation
./bin/cerebro finding-rule new identity-example source_id=okta event_kinds=okta.user name="Example identity rule" dry_run=true
./bin/cerebro finding-rule graph-evaluate <rule-id> tenant_id=example limit=10

# Graph inspection and ingest require a configured graph store
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

Top-level commands are `serve`, `version`, `source`, `source-runtime`, `finding-rule`, `graph`, `orchestrator`, `vulndb`, `closeout`, and `deploy`.

---

## Built-in sources

| Source ID | Description | Emitted kinds / families |
| --- | --- | --- |
| `anthropic` | Anthropic organization governance source | organization, users, invites, workspaces and members, API keys, service accounts, federation, external keys, usage/cost reports, rate/spend limits, compliance activity |
| `archetype` | Archetype repository vulnerability scan source | scans, vulnerabilities |
| `aurelius` | SaaS/business-operation export source | configured catalog families |
| `auth0` | Auth0 Management API source | users, roles, audit events |
| `aws` | AWS IAM, cloud, workload, network exposure, and CloudTrail source | access keys, IAM users/groups/roles/trust, EC2, ECS, EKS, Lambda, public endpoints, resource exposure, CloudTrail |
| `azure` | Azure Entra ID, RBAC, activity, and audit source | activity logs, directory audit, users, groups, role/app assignments, service principals, credentials, resource exposure |
| `backstage` | Backstage catalog source | components |
| `cerebro` | Cerebro product access telemetry source backed by structured NDJSON archives | API access audit events |
| `cloudflare` | Cloudflare account and network source | accounts, members, roles, zones, DNS records, Gateway rules, Workers scripts |
| `cosmo` | Cosmo workflow and message source | messages, survey feedback, configured families |
| `duo` | Duo identity and MFA source | users, groups, endpoints, phones, tokens, WebAuthn credentials |
| `email_domain_health` | Email domain authentication posture source (SPF, DKIM, DMARC, MX, MTA-STS) | health |
| `evidence_cas` | EvidenceCAS content-addressed evidence reference source | object manifests |
| `gcp` | GCP IAM, Cloud Identity, service-account, and audit source | audit, groups, IAM role assignments, service accounts, resource exposure |
| `github` | GitHub audit, repository, Dependabot, and pull request source | audit, repository, Dependabot alerts, pull requests; repository and optional org-inventory audit-log freshness probes |
| `google_workspace` | Google Workspace Directory and Admin audit source | audit, groups, group members, role assignments, users |
| `grc` | Governance/risk/compliance source | configured GRC families |
| `kandji` | Kandji device/application/vulnerability source | devices, applications, vulnerabilities |
| `kolide` | Kolide device posture source | configured catalog families |
| `kubernetes` | Kubernetes inventory source | clusters, namespaces, pods, containers, service accounts, workloads, workload identity bindings |
| `okta` | Okta audit, identity inventory, app, group, authenticator, assignment, and admin role source | audit, users, groups, applications, assignments, admin roles, authenticators, threat insight |
| `openai` | OpenAI organization governance source | audit logs, users, invites, groups, roles, projects, project access, service accounts, API keys, usage/costs, retention, spend alerts, certificates, rate limits, model/tool permissions |
| `pagerduty` | PagerDuty incident management source | users, teams, services, schedules, escalation policies, integrations, vendors |
| `panopticon` | Panopticon security operations API source | cases by default; alerts and IOCs explicitly |
| `sdk` | Generic SDK push source for onboarded applications | validates pushed integration config; optional declared inventory URN discovery; preview reads are empty |
| `sentinelone` | SentinelOne endpoint posture and threat source | agents, threats, activities, applications, exclusions, groups, sites |
| `security_tooling_map` | Security tooling inventory source | configured tooling-map families |
| `slack` | Slack workspace source | teams, users, channels, user groups |
| `tailscale` | Tailscale network source | tailnets, users, devices, groups, tags, services, grants |
| `trivy` | Trivy report source | image scans, image packages, image vulnerabilities, fixes |
| `trusted_endpoint` | Trusted Endpoint posture, AI trust, GRC evidence, and trust-gate source | metadata-only endpoint posture, AI risk, evidence, findings, and action outcomes |
| `vulnview` | Vulnerability and attack-surface source | sites, scans, vulnerabilities, assets, DNS alerts |

Source-specific configuration is passed as `key=value` pairs in CLI calls or query parameters in HTTP calls. Required keys vary by source and family.

---

## HTTP and Connect API surface

Connect RPC procedures are served under `/cerebro.v1.BootstrapService/{Method}`. JSON HTTP is described by `api/openapi.yaml` and is served by the binary at `GET /openapi.yaml`.

Major route groups include:

- Public health and metadata: `/health` readiness, `/healthz` and `/livez` liveness, `/openapi.yaml`, OAuth protected-resource/authorization-server metadata.
- Source catalog and previews: `/sources`, `/sources/{sourceID}/check`, `/discover`, `/read`.
- Source runtime operations: `/source-runtimes`, runtime `sync`, claims, findings, candidates, evidence, evaluation runs, and graph ingest runs.
- Finding and candidate lifecycle: `/finding-rules`, `/findings/*`, `/finding-candidates/*`, `/finding-evidence/*`, `/finding-evaluation-runs/*`.
- Reports and workflow events: `/reports`, `/report-runs`, `/platform/knowledge/*`, `/platform/workflow/replay`.
- Graph platform APIs: `/platform/graph/neighborhood`, impact, attack paths, crown-jewel rankings, AWS public endpoint insights, ingest health, and ingest run retrieval.
- MCP: `/api/v1/mcp` over GET/POST.
- Device auth and telemetry when enabled: `/platform/devices/*`, `/platform/telemetry/ingest`, and `/.well-known/device-jwks.json`.

When auth is enabled, only health/OpenAPI and OAuth/device metadata-style routes are public; platform, source, finding, report, graph, MCP, and device mutation routes require appropriate authentication and scopes.

---

## SDK helpers

Maintained SDK helpers live directly under `sdk/python` and `sdk/typescript`. They target the current bootstrap API surface for source runtime setup, claim writes, graph neighborhoods, and integration examples such as Jira posture onboarding and Panopticon push-claim onboarding.

These helpers are separate from the retired historical Agent SDK gateway. Future SDK methods should start from the current HTTP/OpenAPI or Connect contracts, then add generated or hand-maintained helpers after the runtime route exists.

Useful checks:

```bash
make sdk-test
cd sdk/python && python3 -m unittest discover -s tests
cd sdk/typescript && npm test
```

---

## Policies

Policy definitions live under `policies/` as JSON files. The catalog includes cloud posture, identity governance, GitHub, Kubernetes, M365, Okta, runtime, vulnerability, compliance, and business-operation checks.

Useful directories include `policies/aws/`, `policies/azure/`, `policies/gcp/`, `policies/github/`, `policies/identity/`, `policies/kubernetes/`, `policies/okta/`, `policies/runtime/`, and `policies/vulnerability/`.

Compliance control metadata lives under `internal/compliance/`. `internal/compliance/control_families.yaml` is the built-in control catalog, `internal/compliance/control_profiles.yaml` defines reusable audit scopes, and `internal/compliance/control_coverage_index.yaml` is generated by `make control-index-generate`. Use `docs/COMPLIANCE_CONTROLS.md` for custom framework authoring, extension pack scaffolding with `--init-extension`, and filtered coverage generation with `--extension` and `--profile`.

---

## Development

```bash
make build          # compile ./bin/cerebro
make serve-dev      # build and run local server with acknowledged dev-mode opt-out
make test           # go test ./...
make lint           # golangci-lint over app packages
make proto-lint     # buf lint
make check          # build, tests, lint, proto lint, structural checks, arch tests
make verify         # CI-parity local verification
make doctor         # check required local developer tools
make release-smoke  # validate GoReleaser config
make docker-smoke   # build the runtime Dockerfile locally
make readme-check   # README drift checks
make docs-drift-check  # generated docs drift checks
make oss-audit      # public repository hygiene scan
make clean          # remove bin/
```

Focused validation and utility targets include `make openapi-check`, `make openapi-lint`, `make catalog-check`, `make policy-rule-check`, `make control-index-check`, `make detection-catalog-check`, `make workflow-e2e-test`, `make workflow-replay-test`, `make finding-rule-test`, `make graph-rebuild-dryrun`, `make workflow-replay`, and `make workflow-neighborhood`.

Public-facing docs, config, or example changes should run:

```bash
make oss-audit
```

Choose validators by change type:

| Change type | Minimum local validation |
| --- | --- |
| README-only | `make readme-check` and `make oss-audit` |
| Go runtime/API change | `make test` plus focused package tests |
| OpenAPI route or handler change | `make openapi-check openapi-lint` |
| Proto change | `make proto-lint` and generated contract checks when applicable |
| Source catalog or policy change | `make catalog-check policy-rule-check detection-catalog-check` |
| Compliance control/profile/scaffold change | `make catalog-check policy-rule-check control-index-check detection-catalog-check` |
| Public docs/config/examples | `make docs-drift-check` when generated docs are touched, plus `make oss-audit` |
| Broad PR preflight | `make verify` |

### README freshness

The README is maintained by `make readme-check`, which is part of CI and local changed-path validation. It compares the built-in source table with `internal/sourceregistry`, top-level CLI commands with `cmd/cerebro`, the documented Go toolchain with `go.mod`, selected config names with `internal/config` and `.env.example`, and README anchors for compliance control extension workflows. When a public capability, source, CLI command, config family, or control-index workflow changes, update the README and extend `scripts/readme_check.py` with the new source-of-truth assertion.

---

## Release and deploy artifacts

Releases are tag-driven (`vMAJOR.MINOR.PATCH[-PRERELEASE]`). The release workflow runs the same verify shards as CI, publishes GoReleaser binaries, builds multi-arch runtime images at `ghcr.io/writer/cerebro:<tag>`, signs images and runtime deploy contracts with cosign, and uploads `cerebro-runtime-contract.json` plus its signature/certificate to the GitHub release.

`cmd/sourcedeploy` renders source deployment fragments and the runtime deploy contract from `sources/*/deploy.yaml` manifests:

```bash
go run ./cmd/sourcedeploy -env <env> -tenant <tenant> -format yaml
go run ./cmd/sourcedeploy -env <env> -tenant <tenant> -format contract-json -image-tag vX.Y.Z
```

If release-promotion secrets are configured, release publishes can dispatch downstream deployment proposal workflows. The repository still treats deployments as explicit, validated, and reviewable.

---

## Documentation

Some files in `docs/` describe broader or historical architecture and may be ahead of or behind the current bootstrap implementation. Useful entry points:

| Document | Notes |
| --- | --- |
| [Getting started](docs/GETTING_STARTED.md) | local durable stack plus SDK source runtime and claim-write walkthrough |
| [API contracts](docs/API_CONTRACTS_AUTOGEN.md) | current bootstrap HTTP and Connect contract reference |
| [API reference](docs/API_REFERENCE.md) | OpenAPI-oriented route reference |
| [Configuration](docs/CONFIGURATION.md) | configuration and deployment notes |
| [Hosting](docs/HOSTING.md) | hosting guide for containers, backing stores, proxy/TLS, operations, and rollout |
| [Cloud deployment](docs/CLOUD_DEPLOYMENT.md) | AWS, GCP, Azure, and Pulumi template guidance |
| [Deployment examples](docs/DEPLOYMENT_EXAMPLES.md) | portable examples for Docker Compose, Kubernetes, ECS-style tasks, systemd, and scheduled jobs |
| [Operations runbook](docs/OPERATIONS_RUNBOOK.md) | startup, health, dependency, rollout, rollback, and incident triage guidance |
| [Observability](docs/OBSERVABILITY.md) | OTEL, structured span logs, trace propagation, error capture, and verification |
| [Source runtime guide](docs/SOURCE_RUNTIME_GUIDE.md) | source preview, runtime persistence, sync, secrets, health, and scheduling |
| [Auth and tenancy](docs/AUTH_TENANCY.md) | API keys, structured credentials, tenant scoping, public origin, proxy trust, and rotation |
| [Graph operations](docs/GRAPH_OPERATIONS.md) | graph health, ingest, rebuild, cleanup, query safety, and troubleshooting |
| [Compliance controls](docs/COMPLIANCE_CONTROLS.md) | control catalog schema, profiles, extension packs, coverage resolution, posture, and evidence packets |
| [Release contract](docs/RELEASE_CONTRACT.md) | release artifacts, runtime deploy contract schema, source manifests, and verification |
| [PR landing](docs/PR_LANDING.md) | merge ordering, Droid review gates, and branch deletion safety |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | symptom-driven cookbook for health, auth, source runtime, graph, MCP, and device-auth issues |
| [MCP native Droid setup](docs/MCP_DROID_SETUP.md) | native Droid MCP setup, OAuth flow, transport compatibility, and troubleshooting |
| [DevEx codegen catalog](docs/DEVEX_CODEGEN_AUTOGEN.md) | generated surface map for OpenAPI, proto, and detection catalog checks |
| [Endpoint security platform integration](docs/ENDPOINT_SECURITY_PLATFORM_INTEGRATION.md) | trusted-endpoint, secheck, Security/Kairos, identity, telemetry, and trust-gate integration contract |
| [Non-goals](docs/NON_GOALS.md) | what Cerebro intentionally does not try to do, with rationale and enforcement pointers |
| [Policies](docs/POLICIES.md) | policy catalog and authoring notes |
| [Packages](docs/PACKAGES.md) | package overview; verify against current code before relying on details |
| [Development](docs/DEVELOPMENT.md) | development notes; verify commands against the Makefile |

---

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
| Source integrations | Built-in source registry under `sources/`; see the Built-in sources table above for the checked list |
| Validation | `go test`, `golangci-lint`, Buf, Spectral, catalog checks, policy-rule checks, control-index checks, README drift checks, OSS audit, custom structural linters, arch tests |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
