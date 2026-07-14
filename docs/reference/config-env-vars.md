# Configuration Environment Variables

Current bootstrap configuration is loaded by `internal/config`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CEREBRO_HTTP_ADDR` | `:8080` | HTTP listen address. |
| `CEREBRO_SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown timeout. |
| `CEREBRO_API_AUTH_ENABLED` | `true` outside acknowledged dev mode | Require bearer/API-key authentication for non-public routes. |
| `CEREBRO_API_KEYS` | unset | Comma-separated `key[:principal[:tenant_id]]` entries. Required when auth is enabled. |
| `CEREBRO_API_CREDENTIALS_JSON` | unset | JSON array of structured API credentials with explicit `key` or `key_sha256`, principal metadata, `tenant_id` or `allowed_tenants`, and optional `scopes` and `roles`. Store as a secret. |
| `CEREBRO_ALLOWED_TENANTS` | unset | Optional comma-separated tenant allowlist for unscoped API keys. |
| `CEREBRO_PUBLIC_ORIGIN` | request host | Canonical external origin, for example `https://cerebro.example.com`, used for DPoP `htu` and public URL reconstruction. Must not include a path, query, or fragment. |
| `CEREBRO_TRUSTED_PROXY_CIDRS` | unset | Optional comma-separated CIDRs whose forwarded headers are trusted. Set this explicitly in production to the load-balancer/proxy network. |
| `CEREBRO_TRUSTED_PROXY_COUNT` | `0` | Optional count of trusted trailing `X-Forwarded-For` hops. Use `1` for a single ALB/proxy hop. |
| `CEREBRO_RATE_LIMIT_ENABLED` | `true` outside acknowledged dev mode | Enable global API rate limiting. |
| `CEREBRO_RATE_LIMIT_RPS` | `100` | Global API rate-limit refill rate. |
| `CEREBRO_RATE_LIMIT_BURST` | `150` | Global API rate-limit burst size. |
| `CEREBRO_RATE_LIMIT_EXEMPT_PATHS` | liveness, metrics, and well-known metadata paths | Optional comma-separated path prefixes that bypass rate limiting. |
| `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BASE_URL` | unset | Base URL for the access-approvals service. Required for access-approvals backed graph actions and reconciliation such as `identity.okta.suspend_user`. |
| `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN` | unset | Bearer token Cerebro uses to call access-approvals graph action create/read endpoints. Supports `_FILE` via `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_BEARER_TOKEN_FILE`. |
| `CEREBRO_GRAPH_ACTIONS_ACCESS_APPROVALS_TIMEOUT` | `10s` | HTTP timeout for access-approvals graph action requests. |
| `CEREBRO_APPEND_LOG_DRIVER` | inferred | Append-log driver. Supported: `jetstream`. |
| `CEREBRO_JETSTREAM_URL` | unset | NATS JetStream URL. Setting this infers `jetstream`. |
| `CEREBRO_JETSTREAM_STREAM_NAME` | unset | Optional stream name for publish and replay readiness checks. Set this when one logical append-log stream is expected. |
| `CEREBRO_JETSTREAM_SUBJECT_PREFIX` | `events` | Subject prefix for append-log events. |
| `CEREBRO_JETSTREAM_DRAIN_TIMEOUT` | NATS default | Optional timeout for graceful NATS connection drain during shutdown. |
| `CEREBRO_JETSTREAM_PUBLISH_MAX_IN_FLIGHT` | unlimited | Optional per-process bulkhead for concurrent JetStream publishes. |
| `CEREBRO_JETSTREAM_PUBLISH_FINDINGS_MAX_IN_FLIGHT` | unlimited | Optional per-process bulkhead for `sec.findings.v1.*` publishes. |
| `CEREBRO_JETSTREAM_PUBLISH_RETRY_ATTEMPTS` | `10` | Optional maximum outer publish attempts for retryable JetStream publish errors. |
| `CEREBRO_JETSTREAM_PUBLISH_RETRY_INITIAL_BACKOFF` | `250ms` | Optional first outer publish retry backoff. |
| `CEREBRO_JETSTREAM_PUBLISH_RETRY_MAX_BACKOFF` | `5s` | Optional cap for outer publish retry backoff. |
| `CEREBRO_JETSTREAM_PUBLISH_ATTEMPT_TIMEOUT` | `30s` | Optional timeout for each outer publish attempt. |
| `CEREBRO_JETSTREAM_PUBLISH_RETRY_MAX_ELAPSED` | `90s` | Optional total outer publish retry budget. Set above expected NATS restore time in environments with large streams. |
| `CEREBRO_JETSTREAM_PUBLISH_CLIENT_RETRY_ATTEMPTS` | `5` | Optional NATS client retry attempts inside each outer publish attempt. |
| `CEREBRO_JETSTREAM_PUBLISH_CLIENT_RETRY_WAIT` | `500ms` | Optional NATS client retry wait inside each outer publish attempt. |
| `CEREBRO_JETSTREAM_RUNTIME_INDEX_ENABLED` | `true` | Enables the per-runtime append-log replay index (schema, population job, and read path). Set `false` to disable it. |
| `CEREBRO_STATE_STORE_DRIVER` | inferred | State-store driver. Supported: `postgres`. |
| `CEREBRO_POSTGRES_DSN` | unset | Postgres connection string. Setting this infers `postgres`. |
| `CEREBRO_CONNECTOR_CREDENTIAL_KEY` | unset | High-entropy key used to seal Cerebro-managed connector credentials before storing them in Postgres. Supports `_FILE` via `CEREBRO_CONNECTOR_CREDENTIAL_KEY_FILE`. |
| `CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY` | unset | RSA private key used to decrypt browser-submitted connector credential envelopes. All replicas must share the same key. Supports `_FILE` via `CEREBRO_CONNECTOR_CREDENTIAL_TRANSIT_PRIVATE_KEY_FILE`. |
| `CEREBRO_CONTENT_PACK_ROOT` | unset | Directory containing signed content-pack directories. Set with the allowlist path and tenant ID to activate external declarative content. |
| `CEREBRO_CONTENT_PACK_ALLOWLIST_PATH` | unset | JSON allowlist granting exact pack IDs, versions, digests, and signing keys. Required when a content-pack root is set. |
| `CEREBRO_CONTENT_PACK_TENANT_ID` | unset | Tenant grant selected from the content-pack allowlist. Required when a content-pack root is set; never emitted as a metric label. |
| `CEREBRO_CONTENT_PACK_KERNEL_VERSION` | `1.0.0` | Kernel compatibility version used for signed pack range checks. |
| `CEREBRO_POSTGRES_MAX_OPEN_CONNS` | Go default | Optional `database/sql` maximum open connections. |
| `CEREBRO_POSTGRES_MAX_IDLE_CONNS` | Go default | Optional `database/sql` maximum idle connections. |
| `CEREBRO_POSTGRES_CONN_MAX_LIFETIME` | Go default | Optional maximum lifetime for pooled Postgres connections. |
| `CEREBRO_POSTGRES_CONN_MAX_IDLE_TIME` | Go default | Optional maximum idle time for pooled Postgres connections. |
| `CEREBRO_CACHE_MODE` | inferred | Optional query-cache driver. Supported: `off`, `memory`, `redis`, `valkey`. |
| `CEREBRO_CACHE_URL` | unset | Redis/Valkey URL. Setting this infers `redis` unless `CEREBRO_CACHE_MODE` is set. |
| `CEREBRO_CACHE_NAMESPACE` | `cerebro` | Cache key namespace. Use a distinct value per environment. |
| `CEREBRO_CACHE_DEFAULT_TTL` | `30s` | Default fresh TTL for cacheable GRC read responses. |
| `CEREBRO_CACHE_STALE_TTL` | `5m` | Additional stale-if-error window for cacheable GRC read responses. |
| `CEREBRO_CACHE_MAX_PAYLOAD_BYTES` | `1048576` | Maximum response payload size eligible for caching. |
| `CEREBRO_CACHE_ENABLED` | unset | Compatibility boolean. `false` forces `off`; `true` with no mode selects `redis`. |
| `CEREBRO_GRAPH_STORE_DRIVER` | inferred | Graph-store driver. Supported: `neo4j`. |
| `CEREBRO_NEO4J_URI` | unset | Neo4j/Aura URI. Setting this infers `neo4j`. |
| `CEREBRO_NEO4J_USERNAME` | unset | Neo4j/Aura username. |
| `CEREBRO_NEO4J_PASSWORD` | unset | Neo4j/Aura password. |
| `CEREBRO_NEO4J_DATABASE` | unset | Optional Neo4j database name. |
| `CEREBRO_NEO4J_QUERY_TIMEOUT` | unset | Optional timeout applied to Neo4j read transactions. |

`CEREBRO_KUZU_PATH` is rejected. Kuzu is no longer a supported graph backend.
