# API Reference

The current bootstrap API exposes both Connect RPCs and JSON HTTP routes.

- Connect contract: `proto/cerebro/v1/bootstrap.proto`.
- JSON HTTP contract: `api/openapi.yaml`.
- Embedded contract endpoint: `GET /openapi.yaml`.

## Authentication

Set `CEREBRO_API_AUTH_ENABLED=true` and pass `Authorization: Bearer <key>` or `X-Cerebro-API-Key: <key>` for all non-public routes. API-key entries can bind a tenant with `key:principal:tenant_id`; cross-tenant `tenant_id` requests are rejected.

## Public routes

- `GET /health`
- `GET /healthz`
- `GET /openapi.yaml`

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

Legacy `/graph/*` aliases remain for compatibility and emit deprecation headers.
