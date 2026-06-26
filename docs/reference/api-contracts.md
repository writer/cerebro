# HTTP API Contracts

Generated-by-hand snapshot for the current bootstrap service. Source of truth: `api/openapi.yaml` and `proto/cerebro/v1/bootstrap.proto`.

- HTTP operations: **138** across **129** paths.
- Connect RPCs: **38**.
- Public unauthenticated routes when auth is enabled: `/health`, `/healthz`, `/livez`, `/openapi.yaml`, A2A Agent Card metadata, OAuth metadata/authorization endpoints, `/.well-known/device-jwks.json`, `/platform/devices/enroll`, and `/platform/devices/token`.
- Preferred shared platform namespace: `/platform/*`.
- Legacy `/graph/*` compatibility aliases have been removed; use `/platform/graph/*`.

## Current route families

| Family | Routes |
| --- | --- |
| Health/contracts | `/health` readiness, `/healthz` and `/livez` liveness, `/metrics`, `/openapi.yaml` |
| A2A/agent platform contracts | `/.well-known/agent-card.json`, `/.well-known/agent.json`, `/api/v1/a2a`, `/api/v1/agent-platform/*`, `/api/v1/event-subscriptions/contract`, `/api/v1/idempotency-contract` |
| OAuth/device bootstrap | `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, `/oauth/authorize`, `/oauth/callback`, `/oauth/token`, `/oauth/revoke`, `/oauth/register`, `/.well-known/device-jwks.json`, `/platform/devices/enroll`, `/platform/devices/token` |
| Sources | `/sources`, `/sources/{sourceID}/check`, `/sources/{sourceID}/discover`, `/sources/{sourceID}/read` |
| Source runtimes | `/source-runtimes/{runtimeID}`, `/source-runtimes/{runtimeID}/sync`, `/source-runtimes/{runtimeID}/graph-ingest-runs` |
| Claims/findings | `/source-runtimes/{runtimeID}/claims`, `/source-runtimes/{runtimeID}/findings`, finding lifecycle routes |
| Reports | `/reports`, `/reports/{reportID}/runs`, `/report-runs/{runID}` |
| GRC/compliance | `/grc/dashboard`, `/grc/program-readiness`, `/grc/findings`, `/grc/controls`, `/grc/evidence`, `/grc/control-archetypes`, `/grc/control-profiles`, `/grc/control-coverage`, `/grc/control-packs*`, `/grc/audit-packets/{packetID}` |
| Platform knowledge | `/platform/knowledge/decisions`, `/platform/knowledge/actions`, `/platform/knowledge/outcomes` |
| Platform workflow | `/platform/workflow/replay` |
| Platform graph | `/platform/graph/neighborhood`, `/platform/graph/ingest-health`, `/platform/graph/ingest-runs*` |
| Platform jobs | `/platform/jobs`, `/platform/jobs/{jobID}`, `/platform/jobs/{jobID}/events`, `/platform/jobs/{jobID}/cancel` |
| Runtime response | `/platform/runtime-response/capabilities`, `/platform/runtime-response/actions`, `/platform/runtime-response/blocklist*` |
