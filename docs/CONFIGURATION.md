# Configuration

Cerebro `main` uses a small bootstrap configuration surface.

## Minimal local configuration

No external stores are required for `/health`, `/healthz`, `/openapi.yaml`, `/sources`, and source preview routes that do not need provider credentials.

```bash
make serve
curl -sS http://127.0.0.1:8080/health
```

## Production baseline

```bash
export CEREBRO_API_AUTH_ENABLED=true
export CEREBRO_API_KEYS='<random-key>:cerebro-service:writer'
export CEREBRO_ALLOWED_TENANTS='writer'
export CEREBRO_APPEND_LOG_DRIVER=jetstream
export CEREBRO_JETSTREAM_URL='nats://nats:4222'
export CEREBRO_STATE_STORE_DRIVER=postgres
export CEREBRO_POSTGRES_DSN='postgres://user:pass@postgres:5432/cerebro?sslmode=require'
export CEREBRO_GRAPH_STORE_DRIVER=neo4j
export CEREBRO_NEO4J_URI='neo4j+s://example.databases.neo4j.io'
export CEREBRO_NEO4J_USERNAME='neo4j'
export CEREBRO_NEO4J_PASSWORD='<secret>'
```

See `docs/CONFIG_ENV_VARS.md` for the full current variable list.
