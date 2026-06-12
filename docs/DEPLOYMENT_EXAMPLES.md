# Deployment Examples

This guide gives portable deployment patterns for OSS users. All names, hosts, images, secrets, tenants, networks, and sizing values are placeholders. Replace them with values from your own environment.

Use it with:

- [`docs/HOSTING.md`](./HOSTING.md) for the hosting contract.
- [`docs/OPERATIONS_RUNBOOK.md`](./OPERATIONS_RUNBOOK.md) for rollout and operations.
- [`docs/AUTH_TENANCY.md`](./AUTH_TENANCY.md) for auth and proxy-aware origin settings.
- [`.env.example`](../.env.example) for a local environment template.

## Runtime contract

Cerebro runs the same way across platforms:

```text
cerebro serve
```

Container images expose port `8080` by default and include a liveness health check against `/livez`. The runtime is configured with environment variables, and durable features are enabled by configuring Postgres, NATS JetStream, and Neo4j or Aura.

## Minimal local server

Use this profile when you want to explore public metadata routes, OpenAPI, and source catalog behavior without backing stores.

```bash
make build
CEREBRO_HTTP_ADDR=:8080 ./bin/cerebro serve
```

Check:

```bash
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/sources
```

This profile is not enough for persisted source runtimes, claims, findings, reports, workflow replay, or graph operations.

## Durable local Docker Compose

Use the checked-in compose stack for local durable testing:

```bash
docker compose up --build
```

It starts:

- Cerebro,
- NATS JetStream,
- Postgres,
- Neo4j,
- Docker volumes for local persistence.

Do not copy local compose credentials into a shared deployment.

## Production-like environment variables

Use placeholders like these as the shape of your platform config:

```bash
CEREBRO_HTTP_ADDR=:8080
CEREBRO_SHUTDOWN_TIMEOUT=10s

CEREBRO_API_AUTH_ENABLED=true
CEREBRO_API_KEYS=<random-api-key>:<principal>:<tenant-id>
CEREBRO_ALLOWED_TENANTS=<tenant-id>

CEREBRO_PUBLIC_ORIGIN=https://cerebro.example.com
CEREBRO_TRUSTED_PROXY_CIDRS=10.0.0.0/8
CEREBRO_TRUSTED_PROXY_COUNT=1

CEREBRO_APPEND_LOG_DRIVER=jetstream
CEREBRO_JETSTREAM_URL=nats://nats.example.com:4222
CEREBRO_JETSTREAM_SUBJECT_PREFIX=events

CEREBRO_STATE_STORE_DRIVER=postgres
CEREBRO_POSTGRES_DSN=<postgres-dsn-with-tls>

CEREBRO_GRAPH_STORE_DRIVER=neo4j
CEREBRO_NEO4J_URI=neo4j+s://graph.example.com
CEREBRO_NEO4J_USERNAME=<neo4j-user>
CEREBRO_NEO4J_PASSWORD=<neo4j-password>
```

Store secret-bearing values in your secret manager or orchestrator secret system. Do not commit them.

## Kubernetes deployment

This is a generic shape, not a complete production chart.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cerebro
  labels:
    app: cerebro
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
          image: ghcr.io/writer/cerebro:vX.Y.Z
          args: ["serve"]
          ports:
            - name: http
              containerPort: 8080
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
              port: http
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          livenessProbe:
            httpGet:
              path: /livez
              port: http
            periodSeconds: 30
            timeoutSeconds: 5
            failureThreshold: 3
          resources:
            requests:
              cpu: "250m"
              memory: "512Mi"
            limits:
              cpu: "1000m"
              memory: "1Gi"
```

Example service:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: cerebro
spec:
  selector:
    app: cerebro
  ports:
    - name: http
      port: 80
      targetPort: http
```

Example ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cerebro
spec:
  tls:
    - hosts:
        - cerebro.example.com
      secretName: cerebro-tls
  rules:
    - host: cerebro.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: cerebro
                port:
                  name: http
```

Make sure your ingress strips untrusted incoming forwarded headers and sets the forwarded headers Cerebro expects.

## Kubernetes secret shape

Example only:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cerebro-secrets
type: Opaque
stringData:
  CEREBRO_API_KEYS: "<random-api-key>:<principal>:<tenant-id>"
  CEREBRO_POSTGRES_DSN: "<postgres-dsn-with-tls>"
  CEREBRO_JETSTREAM_URL: "nats://nats.example.com:4222"
  CEREBRO_NEO4J_URI: "neo4j+s://graph.example.com"
  CEREBRO_NEO4J_USERNAME: "<neo4j-user>"
  CEREBRO_NEO4J_PASSWORD: "<neo4j-password>"
```

Prefer external secret operators or your cloud secret manager for real deployments.

## ECS-style task shape

The same config maps to ECS, Nomad, or similar schedulers:

```json
{
  "family": "cerebro",
  "containerDefinitions": [
    {
      "name": "cerebro",
      "image": "ghcr.io/writer/cerebro:vX.Y.Z",
      "command": ["serve"],
      "portMappings": [
        {"containerPort": 8080, "protocol": "tcp"}
      ],
      "environment": [
        {"name": "CEREBRO_HTTP_ADDR", "value": ":8080"},
        {"name": "CEREBRO_API_AUTH_ENABLED", "value": "true"},
        {"name": "CEREBRO_PUBLIC_ORIGIN", "value": "https://cerebro.example.com"},
        {"name": "CEREBRO_TRUSTED_PROXY_CIDRS", "value": "10.0.0.0/8"},
        {"name": "CEREBRO_TRUSTED_PROXY_COUNT", "value": "1"},
        {"name": "CEREBRO_APPEND_LOG_DRIVER", "value": "jetstream"},
        {"name": "CEREBRO_STATE_STORE_DRIVER", "value": "postgres"},
        {"name": "CEREBRO_GRAPH_STORE_DRIVER", "value": "neo4j"}
      ],
      "secrets": [
        {"name": "CEREBRO_API_KEYS", "valueFrom": "<secret-ref>"},
        {"name": "CEREBRO_POSTGRES_DSN", "valueFrom": "<secret-ref>"},
        {"name": "CEREBRO_JETSTREAM_URL", "valueFrom": "<secret-ref>"},
        {"name": "CEREBRO_NEO4J_URI", "valueFrom": "<secret-ref>"},
        {"name": "CEREBRO_NEO4J_USERNAME", "valueFrom": "<secret-ref>"},
        {"name": "CEREBRO_NEO4J_PASSWORD", "valueFrom": "<secret-ref>"}
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -qO- http://127.0.0.1:8080/livez >/dev/null || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 20
      }
    }
  ]
}
```

## systemd service

For a single host or VM:

```ini
[Unit]
Description=Cerebro
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cerebro
Group=cerebro
EnvironmentFile=/etc/cerebro/cerebro.env
ExecStart=/usr/local/bin/cerebro serve
Restart=on-failure
RestartSec=5s
KillSignal=SIGTERM
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
```

Pair this with a reverse proxy that terminates TLS and forwards to `127.0.0.1:8080`.

## Background sync job examples

Use the same image for scheduled work. Keep these separate from the API deployment so retries, concurrency, and resources can be tuned independently.

Kubernetes CronJob shape:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cerebro-sync-example
spec:
  schedule: "*/15 * * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: sync
              image: ghcr.io/writer/cerebro:vX.Y.Z
              command: ["cerebro"]
              args: ["source-runtime", "sync", "<runtime-id>", "page_limit=100"]
              envFrom:
                - secretRef:
                    name: cerebro-secrets
```

Graph ingest job shape:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cerebro-graph-ingest-example
spec:
  schedule: "*/30 * * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: graph-ingest
              image: ghcr.io/writer/cerebro:vX.Y.Z
              command: ["cerebro"]
              args: ["graph", "ingest-runtime", "<runtime-id>", "page_limit=100"]
              envFrom:
                - secretRef:
                    name: cerebro-secrets
```

Use `concurrencyPolicy: Forbid` or your scheduler's equivalent for cursor-sensitive runtimes.

## Reverse proxy checklist

1. Terminate TLS before Cerebro.
2. Set `CEREBRO_PUBLIC_ORIGIN` to the external HTTPS origin.
3. Strip inbound `X-Forwarded-*` headers from untrusted clients.
4. Add `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` at the trusted proxy.
5. Set `CEREBRO_TRUSTED_PROXY_CIDRS` to the proxy or load balancer networks.
6. Set `CEREBRO_TRUSTED_PROXY_COUNT` to the number of trusted trailing hops.
7. Preserve `Authorization` and `DPoP` headers.
8. Allow request bodies for JSON HTTP, Connect, and MCP routes.

## Managed services checklist

### Postgres

- TLS required for networked deployments.
- Automated backups enabled.
- Restore tested.
- Connection pool sized for replica count.
- Credentials scoped to the Cerebro database.

### NATS JetStream

- Persistent storage enabled.
- Retention matches replay needs.
- Stream and consumer lag monitored.
- Storage pressure alerted.

### Neo4j or Aura

- Encrypted URI where supported.
- Database backups or snapshots enabled.
- Query latency and ingest failures monitored.
- Credentials scoped to the target database.
