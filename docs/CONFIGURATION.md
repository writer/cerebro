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

Provider-backed graph actions are optional. To enable `POST /platform/graph/actions` for access-approvals backed identity actions such as `identity.okta.suspend_user` and `identity.okta.unsuspend_user`, configure `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BASE_URL`, `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN` or `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN_FILE`, and grant callers the `cerebro.graph_actions.write` scope.

See `docs/CONFIG_ENV_VARS.md` for the full current variable list.
