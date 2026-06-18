# Configuration

Cerebro `main` uses a small bootstrap configuration surface.

For end-to-end hosting guidance, including container deployment, reverse proxy settings, backing stores, health checks, secrets, and rollout operations, see [`docs/HOSTING.md`](./HOSTING.md).

## Minimal local configuration

No external stores are required for `/health`, `/healthz`, `/livez`, `/openapi.yaml`, `/sources`, and source preview routes that do not need provider credentials. API auth and rate limiting are enabled by default outside acknowledged dev mode. `/health` reports dependency-aware readiness; `/healthz` and `/livez` are liveness-only.

```bash
make serve-dev
curl -sS http://127.0.0.1:8080/health
```

## Production baseline

```bash
export CEREBRO_API_AUTH_ENABLED=true
export CEREBRO_API_KEYS='<random-key>:cerebro-service:<tenant-id>'
export CEREBRO_ALLOWED_TENANTS='<tenant-id>'
export CEREBRO_APPEND_LOG_DRIVER=jetstream
export CEREBRO_JETSTREAM_URL='nats://nats.example.com:4222'
export CEREBRO_STATE_STORE_DRIVER=postgres
export CEREBRO_POSTGRES_DSN='<postgres-dsn-with-tls>'
export CEREBRO_GRAPH_STORE_DRIVER=neo4j
export CEREBRO_NEO4J_URI='neo4j+s://example.databases.neo4j.io'
export CEREBRO_NEO4J_USERNAME='neo4j'
export CEREBRO_NEO4J_PASSWORD='<secret>'
```

Provider-backed graph actions are optional. To enable access-approvals backed identity actions such as `identity.okta.suspend_user` and `identity.okta.unsuspend_user`, configure `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BASE_URL`, `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN` or `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN_FILE`, and grant callers the `cerebro.graph_actions.write` scope. When device auth is enabled, Cerebro also wires the first-party `endpoint.cerebro.revoke_device` action through the same graph action surface. `POST /platform/graph/actions` requires an eligible `finding_id`; the target is derived from the finding unless an explicit target assertion matches the finding identity or Cerebro device. `POST /platform/graph/actions/reconcile` refreshes a linked provider action status back into the finding lifecycle.

Graph action support is catalog-driven. Add or review supported actions in `internal/graphactions/action_catalog.yaml`, regenerate the Go registry with `make graph-action-generate`, and keep `make graph-action-check` green. Non-Okta providers should implement an `internal/graphactions.ActionProvider` adapter so execution and reconciliation keep the same finding eligibility, target validation, idempotency, workflow-event, and external-reference safeguards.

See `docs/CONFIG_ENV_VARS.md` for the full current variable list.
