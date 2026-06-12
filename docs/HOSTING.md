# Hosting Cerebro

This guide describes how to host the Cerebro bootstrap service using public, environment-agnostic primitives. It intentionally does not document any account, registry, hostname, network, secret, tenant, rollout, or infrastructure details from a specific deployment.

Use it with:

- [`README.md`](../README.md) for the current runtime overview and quick start.
- [`docs/CONFIGURATION.md`](./CONFIGURATION.md) for a short configuration baseline.
- [`docs/CONFIG_ENV_VARS.md`](./CONFIG_ENV_VARS.md) for the current environment variable reference.
- [`api/openapi.yaml`](../api/openapi.yaml) for the JSON HTTP route contract.
- [`proto/cerebro/v1/bootstrap.proto`](../proto/cerebro/v1/bootstrap.proto) for the Connect RPC contract.

## What you host

Cerebro runs as a single Go HTTP service. The same `cerebro` binary exposes:

- liveness and readiness routes,
- JSON HTTP APIs,
- Connect RPC handlers,
- source catalog and source runtime routes,
- claim, finding, report, workflow, and graph routes,
- an optional MCP endpoint,
- optional MCP OAuth support,
- optional device-authenticated telemetry routes,
- CLI commands that use the same configuration surface.

The public container entrypoint is:

```text
/usr/local/bin/cerebro serve
```

By default the service listens on `:8080`. Override that with `CEREBRO_HTTP_ADDR`.

## Hosting profiles

Choose the smallest profile that matches the operations you need.

| Profile | Dependencies | Good for | Not enough for |
| --- | --- | --- | --- |
| Lightweight API | none beyond the binary/container | `/health`, `/healthz`, `/livez`, `/openapi.yaml`, `/sources`, and source previews that do not need provider credentials | durable runtimes, claims, findings, workflow replay, graph operations |
| Durable API | Postgres | persisted source runtimes, claims, finding state, evidence, evaluations, and report runs | append-log replay and graph projection |
| Durable sync | Postgres plus NATS JetStream | runtime sync, append-log-backed workflows, replayable events | graph queries and graph ingest |
| Graph-enabled | Postgres, NATS JetStream, and Neo4j or Aura | full local or production-like operation, including graph ingest and graph queries | an end-user web console, which this repo does not ship |

Routes that require a missing dependency should fail closed instead of silently falling back to in-memory behavior. There is no production SQLite or in-memory persistence mode.

## Deployment options

### Local Docker Compose

For local durable evaluation:

```bash
docker compose up --build
curl -sS http://127.0.0.1:8080/health
curl -sS http://127.0.0.1:8080/sources
```

The checked-in compose file starts:

- Cerebro on port `8080`,
- NATS JetStream on `4222`,
- Postgres on `5432`,
- Neo4j on `7474` and `7687`,
- persistent Docker volumes for all backing stores.

Local compose is a convenient development stack. Do not copy its credentials, open ports, password choices, or network exposure into a shared environment.

### Container image on a platform

For a hosted environment, publish the Cerebro image to your registry and run one or more instances behind a load balancer or reverse proxy. The platform should provide:

- container image rollout and rollback,
- secret injection,
- network policy or security group controls,
- TLS termination,
- health checks,
- restart policy,
- logs and metrics collection,
- persistent managed backing services.

The runtime image should run as a non-root user and expose only the HTTP port needed by the service. The checked-in Dockerfiles already set the entrypoint and health check. Your platform only needs to pass the required environment variables and route traffic to the configured HTTP address.

### Generic orchestrator example

The following Kubernetes-shaped example is intentionally generic. Replace the image, secret names, hostnames, labels, and resource sizing with values owned by your environment.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cerebro
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cerebro
  template:
    metadata:
      labels:
        app: cerebro
    spec:
      containers:
        - name: cerebro
          image: registry.example.com/cerebro:VERSION
          args: ["serve"]
          ports:
            - containerPort: 8080
          env:
            - name: CEREBRO_HTTP_ADDR
              value: ":8080"
            - name: CEREBRO_API_AUTH_ENABLED
              value: "true"
            - name: CEREBRO_PUBLIC_ORIGIN
              value: "https://cerebro.example.com"
            - name: CEREBRO_TRUSTED_PROXY_CIDRS
              value: "10.0.0.0/8"
            - name: CEREBRO_TRUSTED_PROXY_COUNT
              value: "1"
            - name: CEREBRO_APPEND_LOG_DRIVER
              value: "jetstream"
            - name: CEREBRO_STATE_STORE_DRIVER
              value: "postgres"
            - name: CEREBRO_GRAPH_STORE_DRIVER
              value: "neo4j"
          envFrom:
            - secretRef:
                name: cerebro-secrets
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
            periodSeconds: 10
            timeoutSeconds: 5
          livenessProbe:
            httpGet:
              path: /livez
              port: 8080
            periodSeconds: 30
            timeoutSeconds: 5
```

Use your orchestrator's equivalent primitives if you run on ECS, Nomad, systemd, a PaaS, or another scheduler. The hosting contract is the same: run the container, inject configuration, attach backing stores, expose HTTP through a trusted TLS boundary, and monitor health.

## Required network shape

```text
Clients
  |
  v
TLS load balancer or reverse proxy
  |
  v
Cerebro HTTP service
  |
  +--> Postgres, when durable state is needed
  +--> NATS JetStream, when append-log sync or replay is needed
  +--> Neo4j or Aura, when graph projection or graph queries are needed
  +--> Source provider APIs, when configured source runtimes sync external systems
```

Only the load balancer or reverse proxy should be internet-facing in a hosted deployment. The backing stores should be reachable only from Cerebro and administrative break-glass paths.

## Configuration checklist

Start with `.env.example`, then map each value into your platform's config and secret system.

### Core service

| Variable | Guidance |
| --- | --- |
| `CEREBRO_HTTP_ADDR` | Bind address for the service. `:8080` is the common container value. |
| `CEREBRO_SHUTDOWN_TIMEOUT` | Graceful shutdown budget. Set it long enough for in-flight requests to finish during rollouts. |
| `CEREBRO_IMAGE_TAG` | Optional release metadata exported by your release pipeline. |

### Authentication and tenancy

| Variable | Guidance |
| --- | --- |
| `CEREBRO_API_AUTH_ENABLED` | Set to `true` for any shared, hosted, or production-like environment. |
| `CEREBRO_API_KEYS` | Simple bearer/API-key credentials. Store as a secret, not in a config file. |
| `CEREBRO_API_CREDENTIALS_JSON` | Structured credentials with principal, tenant, and scope metadata. Store as a secret. |
| `CEREBRO_ALLOWED_TENANTS` | Optional allowlist for unscoped credentials. |
| `CEREBRO_CAPABILITY_TOKEN_SECRETS` | HMAC secrets for capability-token auth. Required by MCP OAuth mode. |
| `CEREBRO_CAPABILITY_TOKEN_AUDIENCE` | Expected audience for capability tokens. |

Use tenant-scoped credentials where possible. Rotate credentials through your secret manager and restart or roll the service when changed.

### Public origin and proxy trust

| Variable | Guidance |
| --- | --- |
| `CEREBRO_PUBLIC_ORIGIN` | Canonical external origin, such as `https://cerebro.example.com`. Do not include a path, query, or fragment. |
| `CEREBRO_TRUSTED_PROXY_CIDRS` | CIDRs for load balancers or reverse proxies whose forwarded headers may be trusted. Set explicitly in hosted environments. |
| `CEREBRO_TRUSTED_PROXY_COUNT` | Number of trusted trailing `X-Forwarded-For` hops. Use `1` for a single proxy hop. |

Cerebro uses these values for proxy-aware URL reconstruction and DPoP `htu` validation. Do not trust forwarded headers from arbitrary clients.

### Append log

| Variable | Guidance |
| --- | --- |
| `CEREBRO_APPEND_LOG_DRIVER` | Set to `jetstream` when append-log behavior is required. |
| `CEREBRO_JETSTREAM_URL` | NATS URL. Setting this can infer the driver. Store credentials in the URL only if your secret manager handles it safely. |
| `CEREBRO_JETSTREAM_SUBJECT_PREFIX` | Subject prefix. Use a stable, environment-specific prefix if multiple logical deployments share a NATS cluster. |
| `CEREBRO_JETSTREAM_DRAIN_TIMEOUT` | Optional graceful drain timeout for shutdown. |

NATS JetStream should have durable storage, retention appropriate for replay needs, and monitoring for stream health, consumer lag, and disk pressure.

### State store

| Variable | Guidance |
| --- | --- |
| `CEREBRO_STATE_STORE_DRIVER` | Set to `postgres` when durable state is required. |
| `CEREBRO_POSTGRES_DSN` | Postgres DSN. Store as a secret and use TLS for networked databases. |
| `CEREBRO_POSTGRES_MAX_OPEN_CONNS` | Optional connection pool cap. Size with database limits and replica count in mind. |
| `CEREBRO_POSTGRES_MAX_IDLE_CONNS` | Optional idle pool cap. |
| `CEREBRO_POSTGRES_CONN_MAX_LIFETIME` | Optional connection lifetime. Useful with managed database proxies or load balancers. |
| `CEREBRO_POSTGRES_CONN_MAX_IDLE_TIME` | Optional idle lifetime. |

Use managed Postgres or an operationally equivalent deployment for shared environments. Enable backups, point-in-time recovery where available, maintenance windows, and least-privilege credentials.

### Graph store

| Variable | Guidance |
| --- | --- |
| `CEREBRO_GRAPH_STORE_DRIVER` | Set to `neo4j` when graph operations are required. |
| `CEREBRO_NEO4J_URI` | Neo4j or Aura URI. Use encrypted schemes where supported by your graph service. |
| `CEREBRO_NEO4J_USERNAME` | Graph database user. |
| `CEREBRO_NEO4J_PASSWORD` | Graph database password. Store as a secret. |
| `CEREBRO_NEO4J_DATABASE` | Optional database name. Leave unset to use the server default. |
| `CEREBRO_NEO4J_QUERY_TIMEOUT` | Optional timeout for read transactions. |

Monitor graph ingest health, query latency, index health, and storage growth. Keep graph credentials scoped to the required database.

### Source runtime secrets

Source integrations can require provider credentials. Keep provider tokens, API keys, cloud role bindings, and source-specific secrets outside checked-in config.

Use:

- secret manager references,
- orchestrator-injected environment variables,
- `CEREBRO_SOURCE_CONFIG_ENV_ALLOWLIST` to permit only approved `env:` references,
- `CEREBRO_AWS_ASSUME_ROLE_ARNS` only when a source needs a constrained role allowlist.

Do not place live provider tokens in runtime JSON checked into source control.

### Optional MCP OAuth

MCP OAuth mode adds an authorization-server surface for MCP clients. It requires:

- `CEREBRO_API_AUTH_ENABLED=true`,
- `CEREBRO_PUBLIC_ORIGIN`,
- Postgres state store configuration,
- `CEREBRO_CAPABILITY_TOKEN_SECRETS`,
- the relevant `CEREBRO_MCP_OAUTH_*` settings documented in the config reference.

Keep MCP client metadata, upstream OAuth metadata, and signing or HMAC material in your secret system.

### Optional device auth

Device-authenticated telemetry is intended for first-party fleet agents. If enabled, configure:

- API auth,
- signing key JSON,
- issuer and audience values,
- current key ID,
- DPoP and token lifetimes,
- attestation settings when required,
- a device-auth-capable state store.

Device auth should be exposed only through the same TLS and trusted-proxy boundary as the rest of the API.

## Secrets handling

Never commit live secrets to this repository or to deployment manifests. Treat the following as secrets:

- API keys and structured API credential JSON,
- Postgres DSNs with credentials,
- NATS URLs with credentials,
- Neo4j usernames and passwords,
- provider API tokens,
- OAuth client secrets,
- capability-token HMAC secrets,
- device-auth signing keys,
- cloud role or service-account credentials.

Recommended practices:

1. Store secrets in a managed secret store or orchestrator secret object.
2. Inject them as environment variables at runtime.
3. Limit read access to the service identity that runs Cerebro.
4. Rotate credentials on a schedule and after suspected exposure.
5. Keep examples in docs and manifests placeholder-only.

## Reverse proxy and TLS

Cerebro serves plain HTTP inside the container. Terminate TLS at a load balancer, ingress controller, service mesh, or reverse proxy.

Minimum proxy requirements:

- forward the original host and scheme,
- set `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` only at the trusted proxy boundary,
- strip inbound forwarded headers from untrusted clients before adding your own,
- route all Cerebro paths to the same service unless you intentionally split public and private ingress,
- preserve request bodies for JSON HTTP, Connect, and MCP traffic,
- support long enough request timeouts for sync, graph, and report operations used by your clients.

Set:

```bash
export CEREBRO_PUBLIC_ORIGIN='https://cerebro.example.com'
export CEREBRO_TRUSTED_PROXY_CIDRS='10.0.0.0/8'
export CEREBRO_TRUSTED_PROXY_COUNT='1'
```

Use CIDRs and hop counts that match your actual proxy topology.

## Health checks

Cerebro exposes three health-style routes:

| Route | Purpose | Use |
| --- | --- | --- |
| `/livez` | liveness-only check | container liveness probe |
| `/healthz` | liveness-only alias | platforms that standardize on `healthz` |
| `/health` | dependency-aware readiness | load balancer readiness and rollout gates |

Use `/livez` or `/healthz` to decide whether the process should be restarted. Use `/health` to decide whether the instance should receive traffic.

Example:

```bash
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/health
```

If you intentionally run the lightweight profile without stores, validate the expected `/health` behavior before using it as a hard rollout gate.

## Background work and scheduled sync

Cerebro source runtime sync and graph ingest can be driven by the same runtime image through CLI commands or API calls. A common hosting pattern is:

- run the API service continuously,
- run scheduled sync or ingest jobs as separate tasks using the same image tag,
- use the same secret and config source where appropriate,
- give jobs separate resource limits and retry policies from the API,
- avoid concurrent sync for the same cursor-sensitive runtime unless the runtime and backing stores are known to handle it safely.

Examples of operations that may be scheduled by your platform:

```bash
cerebro source-runtime sync <runtime-id> page_limit=100
cerebro graph ingest-runtime <runtime-id> page_limit=100
cerebro graph rebuild <runtime-id> dry_run=true mode=replay
```

Keep runtime IDs, tenant IDs, source credentials, and schedules in your deployment system, not in public docs.

## Persistence and backup

For local compose, Docker volumes are enough for development. For hosted environments:

### Postgres

- use durable storage,
- enable automated backups,
- test restore procedures,
- use TLS for network access,
- restrict access to the service identity and operators,
- monitor connection saturation, disk, CPU, replication lag, and slow queries.

### NATS JetStream

- use persistent storage for streams,
- size storage for expected event volume and retention,
- monitor stream health, consumer lag, disk usage, and dropped messages,
- document retention behavior because it affects replay windows.

### Neo4j or Aura

- use managed backups or snapshots where available,
- monitor database availability, storage, index health, query latency, and ingest failures,
- plan graph rebuild procedures for schema or projection changes.

## Observability

At minimum, collect:

- process restarts and container exit codes,
- liveness and readiness results,
- HTTP request rate, latency, and status codes,
- authentication failures,
- Postgres connection pool metrics and query errors,
- NATS connection, stream, and consumer health,
- graph query and ingest errors,
- source runtime sync duration, page counts, and cursor advancement,
- finding and report workflow failures,
- resource saturation for CPU, memory, disk, and network.

Logs should be structured or consistently parsed by your platform. Do not log secrets, provider tokens, bearer tokens, full credential JSON, or sensitive source payloads.

## Security baseline

Use this baseline for any shared deployment:

1. Set `CEREBRO_API_AUTH_ENABLED=true`.
2. Use tenant-scoped credentials where possible.
3. Store all secrets in a secret manager or orchestrator secret.
4. Terminate TLS before traffic reaches Cerebro.
5. Set `CEREBRO_PUBLIC_ORIGIN` to the canonical HTTPS origin.
6. Set explicit trusted proxy CIDRs and trusted proxy count.
7. Restrict inbound network access to intended clients and operators.
8. Restrict backing-store access to Cerebro and administrative paths.
9. Use least-privilege provider credentials for source runtimes.
10. Monitor auth failures, denied tenant access, dependency errors, and unusual sync volume.
11. Keep `/metrics`, if exposed, behind the same auth and network controls as other operational surfaces.
12. Run public-facing docs, config, and example changes through the repository OSS audit before publishing.

## Rollout checklist

Before first traffic:

1. Build or select an immutable image tag.
2. Confirm the image starts with `cerebro serve`.
3. Configure `CEREBRO_HTTP_ADDR`.
4. Configure API auth and tenant scoping.
5. Configure public origin and trusted proxy settings.
6. Configure Postgres if durable state is required.
7. Configure NATS JetStream if sync or replay is required.
8. Configure Neo4j or Aura if graph operations are required.
9. Configure source runtime secrets and allowlists.
10. Wire liveness to `/livez` or `/healthz`.
11. Wire readiness to `/health`.
12. Verify `/openapi.yaml` is reachable from an authorized network path.
13. Run a low-risk source preview or source runtime check.
14. Verify logs and metrics reach your observability platform.
15. Document rollback as image tag revert plus config revert.

During rollout:

1. Start with a small replica count.
2. Wait for readiness before sending traffic.
3. Watch 4xx and 5xx rates separately.
4. Watch dependency health, especially Postgres connections and NATS stream health.
5. Check source runtime sync progress before increasing schedule frequency.
6. Check graph ingest errors before enabling graph-dependent workflows broadly.

After rollout:

1. Save the exact image tag and config version in your deployment records.
2. Confirm backups are active for every durable store.
3. Confirm alerts exist for service down, readiness failure, high 5xx rate, auth anomaly, Postgres connection saturation, JetStream lag, and graph ingest failure.
4. Run a restore or rebuild drill on a non-production environment.

## Upgrade and rollback

Treat the container image plus environment variables as the release unit.

Upgrade:

1. Read the release notes or change summary for config and contract changes.
2. Deploy the new image to a small percentage or a staging environment.
3. Verify `/livez`, `/health`, API smoke checks, and representative source or graph operations.
4. Roll the remaining instances.
5. Keep the previous image tag available until the new version is stable.

Rollback:

1. Revert to the previous image tag.
2. Revert any config changes that were coupled to the new version.
3. Confirm readiness and key operations.
4. Check whether any background jobs need to be paused or replayed.

If a release includes storage or event-shape changes, follow the migration notes for that release. Do not assume arbitrary downgrade safety for persistent data.

## Public release handoff

This repository intentionally stops at public runtime artifacts and contracts. Environment-specific deployment repositories or platforms should own:

- cloud accounts and regions,
- registry paths,
- hostnames and DNS,
- private network topology,
- secret names and secret paths,
- operational schedules,
- alert thresholds,
- approval gates,
- customer or tenant assignments,
- rollout procedures.

The public handoff is:

- the container image,
- the binary behavior,
- `cerebro-runtime-contract.json` when produced by release tooling,
- API and proto contracts,
- the documented environment variable surface.

Keep concrete deployment values out of public documentation unless they are intentionally generic examples.

## Troubleshooting

### The process starts but readiness fails

Check:

- `/livez` to confirm the process is alive,
- `/health` response body for dependency status,
- Postgres DSN and network access,
- NATS URL, credentials, and stream availability,
- Neo4j URI, credentials, and database name,
- whether the selected hosting profile expects those dependencies.

### Authenticated requests return unauthorized

Check:

- `CEREBRO_API_AUTH_ENABLED`,
- bearer token formatting,
- API key or credential JSON secret injection,
- tenant scoping on the credential,
- whether the route is public or protected,
- proxy behavior that might strip `Authorization` headers.

### Public URLs or DPoP validation are wrong

Check:

- `CEREBRO_PUBLIC_ORIGIN`,
- trusted proxy CIDRs,
- trusted proxy hop count,
- whether the reverse proxy strips untrusted forwarded headers,
- whether the proxy forwards `X-Forwarded-Proto` and `X-Forwarded-Host`.

### Source sync does not advance

Check:

- source runtime configuration,
- provider credentials,
- source-specific rate limits,
- Postgres availability,
- NATS JetStream availability,
- whether another job is syncing the same runtime,
- logs for validation errors or cursor write failures.

### Graph routes fail

Check:

- `CEREBRO_GRAPH_STORE_DRIVER=neo4j`,
- Neo4j URI, username, password, and database,
- graph database network access,
- graph query timeout,
- whether prerequisite source runtime data exists,
- ingest run status for the runtime.

### MCP OAuth fails

Check:

- API auth is enabled,
- public origin is configured,
- Postgres is configured,
- capability-token secrets are configured,
- MCP OAuth client and upstream settings are present,
- proxy forwarded headers match the public origin.
