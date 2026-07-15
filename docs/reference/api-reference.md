# API Reference

The current bootstrap API exposes both Connect RPCs and JSON HTTP routes.

- Connect contract: `proto/cerebro/v1/bootstrap.proto`.
- JSON HTTP contract: `api/openapi.yaml`.
- Embedded contract endpoint: `GET /openapi.yaml`.

## Authentication

Set `CEREBRO_API_AUTH_ENABLED=true` and pass `Authorization: Bearer <key>` or `X-Cerebro-API-Key: <key>` for all non-public routes. API-key entries can bind a tenant with `key:principal:tenant_id`; cross-tenant `tenant_id` requests are rejected.

## Public routes

- `GET /health` - dependency-aware readiness; returns unavailable when configured dependencies are degraded.
- `GET /healthz` - liveness-only process check.
- `GET /livez` - liveness-only process check.
- `GET /openapi.yaml`
- `GET /.well-known/agent-card.json` and `GET /.well-known/agent.json` - public Agent2Agent discovery metadata.
- `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-authorization-server` - MCP OAuth metadata.
- `GET /oauth/authorize`, `GET /oauth/callback`, `POST /oauth/token`, `POST /oauth/revoke`, and `POST /oauth/register` - OAuth authorization-server endpoints.
- `GET /.well-known/device-jwks.json` - public device-token signing keys.
- `POST /platform/devices/enroll` and `POST /platform/devices/token` - unauthenticated device bootstrap/token exchange routes; requests are validated with bootstrap tokens, refresh tokens, DPoP, and rate limits.

## Preferred platform routes

- `POST /api/v1/a2a`
- `GET /api/v1/agent-platform/contract`
- `GET /api/v1/agent-platform/capabilities`
- `GET /api/v1/agent-platform/security-control-plane`
- `GET /api/v1/event-subscriptions/contract`
- `GET /api/v1/idempotency-contract`
- `POST /platform/knowledge/decisions`
- `POST /platform/knowledge/actions`
- `POST /platform/knowledge/actions/recommendation`
- `POST /platform/knowledge/outcomes`
- `POST /platform/workflow/replay`
- `GET /platform/graph/neighborhood`
- `GET /platform/graph/effective-access-paths`
- `POST /platform/graph/actions`
- `GET /platform/graph/ingest-health`
- `GET /platform/graph/ingest-runs`
- `GET /platform/graph/ingest-runs/{runID}`
- `GET /metrics` - Prometheus-compatible process/API metrics; authenticated when API auth is enabled.
- `POST /platform/jobs`
- `GET /platform/jobs`
- `GET /platform/jobs/{jobID}`
- `GET /platform/jobs/{jobID}/events`
- `POST /platform/jobs/{jobID}/cancel`
- `GET /platform/runtime-response/capabilities`
- `POST /platform/runtime-response/actions`
- `GET /platform/runtime-response/blocklist`
- `POST /platform/runtime-response/blocklist/{entryID}/revoke`

Runtime response capabilities include locally executable blocklist actions plus external workflow actions owned by
Aperio, such as `google_workspace.revoke_oauth_grant`, `slack.revoke_app_install`, and
`github.revoke_oauth_app`. External Aperio actions are advertised with provider, target type, required context key,
dry-run, and approval metadata; they remain proposal workflows through `aperio.propose_cerebro_response` rather than
direct Cerebro runtime mutations.
- `GET /grc/control-archetypes`
- `GET /grc/control-profiles`
- `GET /grc/control-coverage`
- `POST /grc/control-packs/preview`
- `POST /grc/control-packs`

Legacy `/graph/*` aliases have been removed; use `/platform/graph/*` routes instead.

## Public Idempotency Contract

Use `Idempotency-Key` for retried mutating API requests and outbound webhook delivery dedupe. The canonical machine-readable contract is `GET /api/v1/idempotency-contract`; it documents route scope, replay behavior, 409 conflict semantics, and the 255-byte key limit. Keys are opaque client-generated values and must not contain secrets, tenant names, hostnames, or resource identifiers.

## A2A And Webhook Contracts

`GET /.well-known/agent-card.json` publishes public-safe A2A discovery metadata. Authenticated A2A JSON-RPC calls use `POST /api/v1/a2a`; `SendMessage` returns contract discovery content by default, or creates a durable `agent-evidence-packet` task when message or request metadata sets `skillId` to `agent-evidence-packet`. `GetTask` and `ListTasks` read those tenant-scoped A2A work tasks from the platform job store. Streaming, cancellation, and push methods still return A2A-style unsupported-operation errors until backed by replayable runtime adapters.

`GET /api/v1/event-subscriptions/contract` documents outbound HTTPS webhook trigger families, delivery headers, signing schemes, retries, dead-letter behavior, and webhook delivery idempotency. Subscription metadata remains tenant-scoped and event-type allow-listed.

`POST /platform/append-log/dead-letters/{deadLetterID}/force-purge` deletes one explicitly identified pending recovery record. It requires an authenticated admin credential allowed for the supplied `tenant_id`, derives the audit actor from that credential, requires a concrete `reason`, rejects terminal records and active replay claims, and never returns the replayable event envelope.
