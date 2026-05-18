# cerebro

## What this codebase does

Cerebro is Writer's Go security operations platform for cloud/SaaS source ingestion, graph projection/query, finding evaluation, workflow knowledge, report generation, and a bootstrap HTTP/Connect API. The server entrypoint is `cmd/cerebro`; the request surface, auth middleware, and OpenAPI-backed handlers are in `internal/bootstrap`.

## Auth shape

- API auth is configured in `internal/config` and enforced by `authMiddleware`, `authConnectInterceptor`, and tenant helpers in `internal/bootstrap/auth.go`.
- Tenant-scoped API keys must be checked against explicit `tenant_id` fields, tenant-bearing URNs, runtime/findings/report records loaded by ID, and graph ingest/workflow operations that otherwise default to global scope.
- `/health`, `/healthz`, and `/openapi.yaml` are intentionally public; most `/platform/*`, `/source-runtimes/*`, `/findings/*`, `/reports/*`, and Connect RPC paths are protected when `CEREBRO_API_AUTH_ENABLED=true`.

## Threat model

Highest impact attackers try to bypass API auth, cross tenant boundaries via bare durable IDs or tenant-bearing URNs, enumerate graph/finding/report data, or trigger source sync and workflow writes for another tenant. Findings that combine tenant confusion with read/write access to graph projections, findings, source runtimes, report results, or workflow events are higher priority than generic validation nits.

## Project-specific patterns to flag

- New handlers in `internal/bootstrap/app.go` that call services by ID without `authorize*Tenant` checks.
- Proto/JSON request fields that carry tenant scope indirectly, especially maps, metadata, `root_urn`, `decision_id`, `target_ids`, `evidence_ids`, and `action_ids`.
- Source runtime and graph ingest paths in `internal/sourceruntime`, `internal/graphingest`, `internal/graphstore`, and `internal/sourceprojection` where empty tenant IDs can become global or unrestricted.
- Finding/report/claim list and get paths in `internal/findings`, `internal/reports`, and `internal/claims` that must preserve tenant/runtime scoping.
- Source integrations under `sources/*` that emit events or entities with tenant IDs derived from provider configuration.

## Known false-positives

- Tests and fixtures under `**/*_test.go` and `sources/*/testdata/**` use synthetic credentials and tenants.
- Generated or contract-governed files such as `api/openapi.yaml`, `api/spec_embed.go`, and `docs/*_AUTOGEN.md` should be correlated back to source handlers.
- Static policy fixtures under `policies/**` are data inputs rather than executable code.
- Local development paths, embedded fixture secrets, and redacted source runtime configs are intentional unless they flow into production logs or persisted plaintext secrets.
