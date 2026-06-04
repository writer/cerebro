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
- `GET /.well-known/oauth-protected-resource` and `GET /.well-known/oauth-authorization-server` - MCP OAuth metadata.
- `GET /oauth/authorize`, `GET /oauth/callback`, `POST /oauth/token`, `POST /oauth/revoke`, and `POST /oauth/register` - OAuth authorization-server endpoints.
- `GET /.well-known/device-jwks.json` - public device-token signing keys.
- `POST /platform/devices/enroll` and `POST /platform/devices/token` - unauthenticated device bootstrap/token exchange routes; requests are validated with bootstrap tokens, refresh tokens, DPoP, and rate limits.

## Preferred platform routes

- `POST /platform/knowledge/decisions`
- `POST /platform/knowledge/actions`
- `POST /platform/knowledge/actions/recommendation`
- `POST /platform/knowledge/outcomes`
- `POST /platform/workflow/replay`
- `GET /platform/graph/neighborhood`
- `GET /platform/graph/ingest-health`
- `GET /platform/graph/ingest-runs`
- `GET /platform/graph/ingest-runs/{runID}`

Legacy `/graph/*` aliases have been removed; use `/platform/graph/*` routes instead.
