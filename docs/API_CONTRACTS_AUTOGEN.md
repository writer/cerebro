# HTTP API Contracts

Generated-by-hand snapshot for the current bootstrap service. Source of truth: `api/openapi.yaml` and `proto/cerebro/v1/bootstrap.proto`.

- HTTP operations: **68** across **66** paths.
- Connect RPCs: **38**.
- Public unauthenticated routes when auth is enabled: `/health`, `/healthz`, `/livez`, `/openapi.yaml`.
- Preferred shared platform namespace: `/platform/*`.
- Legacy `/graph/*` compatibility aliases have been removed; use `/platform/graph/*`.

## Current route families

| Family | Routes |
| --- | --- |
| Health/contracts | `/health` readiness, `/healthz` and `/livez` liveness, `/openapi.yaml` |
| Sources | `/sources`, `/sources/{sourceID}/check`, `/sources/{sourceID}/discover`, `/sources/{sourceID}/read` |
| Source runtimes | `/source-runtimes/{runtimeID}`, `/source-runtimes/{runtimeID}/sync`, `/source-runtimes/{runtimeID}/graph-ingest-runs` |
| Claims/findings | `/source-runtimes/{runtimeID}/claims`, `/source-runtimes/{runtimeID}/findings`, finding lifecycle routes |
| Reports | `/reports`, `/reports/{reportID}/runs`, `/report-runs/{runID}` |
| Platform knowledge | `/platform/knowledge/decisions`, `/platform/knowledge/actions`, `/platform/knowledge/outcomes` |
| Platform workflow | `/platform/workflow/replay` |
| Platform graph | `/platform/graph/neighborhood`, `/platform/graph/ingest-health`, `/platform/graph/ingest-runs*` |
