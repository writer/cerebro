# Configuration Environment Variables

Current bootstrap configuration is loaded by `internal/config`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CEREBRO_HTTP_ADDR` | `:8080` | HTTP listen address. |
| `CEREBRO_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown timeout. |
| `CEREBRO_API_AUTH_ENABLED` | `false` | Require bearer/API-key authentication for non-public routes. |
| `CEREBRO_API_KEYS` | unset | Comma-separated `key[:principal[:tenant_id]]` entries. Required when auth is enabled. |
| `CEREBRO_ALLOWED_TENANTS` | unset | Optional comma-separated tenant allowlist for unscoped API keys. |
| `CEREBRO_APPEND_LOG_DRIVER` | inferred | Append-log driver. Supported: `jetstream`. |
| `CEREBRO_JETSTREAM_URL` | unset | NATS JetStream URL. Setting this infers `jetstream`. |
| `CEREBRO_JETSTREAM_SUBJECT_PREFIX` | `events` | Subject prefix for append-log events. |
| `CEREBRO_STATE_STORE_DRIVER` | inferred | State-store driver. Supported: `postgres`. |
| `CEREBRO_POSTGRES_DSN` | unset | Postgres connection string. Setting this infers `postgres`. |
| `CEREBRO_GRAPH_STORE_DRIVER` | inferred | Graph-store driver. Supported: `neo4j`. |
| `CEREBRO_NEO4J_URI` | unset | Neo4j/Aura URI. Setting this infers `neo4j`. |
| `CEREBRO_NEO4J_USERNAME` | unset | Neo4j/Aura username. |
| `CEREBRO_NEO4J_PASSWORD` | unset | Neo4j/Aura password. |
| `CEREBRO_NEO4J_DATABASE` | unset | Optional Neo4j database name. |

`CEREBRO_KUZU_PATH` is rejected. Kuzu is no longer a supported graph backend.
