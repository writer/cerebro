# Cerebro Pulumi Templates

These Pulumi templates deploy the public Cerebro runtime on AWS, Google Cloud, or Azure using environment-agnostic defaults. They intentionally use placeholder names and caller-owned configuration only. Do not put live account IDs, hostnames, tenant names, source schedules, provider tokens, or secret values in this directory.

The templates deploy the Cerebro API container and wire any backing services you provide through cloud-native secret mechanisms:

- AWS: ECS Fargate service behind an Application Load Balancer.
- GCP: Cloud Run v2 service.
- Azure: Azure Container Apps service.

Postgres, NATS JetStream, and Neo4j/Aura are configured by passing DSNs and URLs as Pulumi secrets. You can use managed services, self-hosted services, or third-party services as long as the Cerebro container can reach them.

## Runtime Profiles

| Profile | Required template config | Cerebro features |
| --- | --- | --- |
| Lightweight API | image, cloud, region/location | `/livez`, `/health`, `/openapi.yaml`, `/sources`, and provider-free source previews |
| Durable API | `cerebro:postgresDsn` | persisted runtimes, claims, findings, reports, OAuth, and device-auth state |
| Durable sync | `cerebro:postgresDsn`, `cerebro:jetstreamUrl` | source runtime sync and append-log-backed replay |
| Graph-enabled | `cerebro:postgresDsn`, `cerebro:jetstreamUrl`, `cerebro:neo4jUri`, `cerebro:neo4jUsername`, `cerebro:neo4jPassword` | graph ingest, graph queries, graph health, and graph-agent workflows |

## Install

```bash
cd deploy/pulumi
uv sync
```

Use a local Pulumi backend for previews when you do not want to touch Pulumi Cloud:

```bash
export PULUMI_BACKEND_URL="file://$PWD/.pulumi-state"
export PULUMI_CONFIG_PASSPHRASE="local-preview-only"
```

## Preview Without Deploying

Each checked-in example stack is intentionally lightweight and unauthenticated so it can be previewed without live secrets. Do not deploy these exact stack files to a shared environment.

```bash
pulumi preview --stack aws --refresh=false
pulumi preview --stack gcp --refresh=false
pulumi preview --stack azure --refresh=false
```

For real deployments, set a release image, enable API auth, and provide secrets first:

```bash
pulumi config set cerebro:image ghcr.io/writer/cerebro:vX.Y.Z
pulumi config set cerebro:apiAuthEnabled true
pulumi config set --secret cerebro:apiKeys '<random-key>:<principal>:<tenant-id>'
pulumi config set --secret cerebro:postgresDsn '<postgres-dsn-with-tls>'
pulumi config set --secret cerebro:jetstreamUrl '<nats-url>'
pulumi config set --secret cerebro:neo4jUri '<neo4j-or-aura-uri>'
pulumi config set --secret cerebro:neo4jUsername '<neo4j-user>'
pulumi config set --secret cerebro:neo4jPassword '<neo4j-password>'
```

## Cloud Selection

Set `cerebro:cloud` to one of:

- `aws`
- `gcp`
- `azure`

The shared config keys are the same across clouds:

| Key | Default | Notes |
| --- | --- | --- |
| `cerebro:name` | `cerebro` | Resource name prefix. Use lowercase letters, numbers, and hyphens. |
| `cerebro:image` | required | Runtime image, usually `ghcr.io/writer/cerebro:<release-tag>` or a cloud-registry mirror. |
| `cerebro:containerPort` | `8080` | Container port. |
| `cerebro:minReplicas` | `1` | Minimum running replicas where supported. |
| `cerebro:maxReplicas` | `1` | Maximum replicas where supported. Raise carefully because backing stores and source cursors need matching capacity. |
| `cerebro:cpu` | `1` | vCPU count for GCP/Azure; AWS converts this to ECS CPU units. |
| `cerebro:memoryMiB` | `2048` | Container memory. |
| `cerebro:publicOrigin` | unset | Set to the external HTTPS origin for shared deployments. |
| `cerebro:trustedProxyCIDRs` | unset | Comma-separated trusted proxy CIDRs. |
| `cerebro:trustedProxyCount` | `1` | Trusted trailing `X-Forwarded-For` hops. |
| `cerebro:apiAuthEnabled` | `true` | Keep true outside local or validation-only stacks. |
| `cerebro:apiKeys` | unset | Secret API key entries. Required when API auth is enabled unless using structured credentials. |
| `cerebro:apiCredentialsJson` | unset | Secret structured credential JSON. Alternative to simple API keys. |
| `cerebro:allowedTenants` | unset | Optional tenant allowlist. |
| `cerebro:postgresDsn` | unset | Secret Postgres DSN. Enables the Postgres state store. |
| `cerebro:jetstreamUrl` | unset | Secret NATS URL. Enables JetStream append log. |
| `cerebro:neo4jUri` | unset | Secret Neo4j/Aura URI. Enables Neo4j graph store when username/password are also set. |
| `cerebro:neo4jUsername` | unset | Secret graph username. |
| `cerebro:neo4jPassword` | unset | Secret graph password. |
| `cerebro:connectorCredentialKey` | unset | Secret key for Cerebro-managed connector credentials. |
| `cerebro:connectorTransitPrivateKey` | unset | Secret shared RSA private key for browser-submitted connector credentials. |
| `cerebro:capabilityTokenSecrets` | unset | Secret HMAC material for capability-token auth. |
| `cerebro:extraEnv` | `{}` | Non-secret environment variable map. |
| `cerebro:extraSecrets` | `{}` | Secret environment variable map. |

Cloud-specific keys:

| Cloud | Keys |
| --- | --- |
| AWS | `cerebro:awsRegion`, `cerebro:awsAvailabilityZones`, `cerebro:awsVpcCidr`, `cerebro:awsPublicSubnetCidrs`, `cerebro:awsAssignPublicIp`, `cerebro:awsSkipCredentialsValidation` |
| GCP | `cerebro:gcpProject`, `cerebro:gcpRegion`, `cerebro:gcpIngress`, `cerebro:gcpAllowUnauthenticated` |
| Azure | `cerebro:azureLocation`, `cerebro:azureResourceGroupName`, `cerebro:azureExternalIngress` |

## Production Notes

These templates are a portable starting point, not a replacement for your organization's deployment controls.

- Put the service behind TLS and set `cerebro:publicOrigin` to the HTTPS origin clients use.
- Strip untrusted inbound forwarded headers at the edge and set `cerebro:trustedProxyCIDRs` to your real proxy or load-balancer network.
- Keep API auth enabled and store credentials as Pulumi secrets or in your cloud secret manager.
- Use private networking for Postgres, NATS JetStream, Neo4j/Aura, Redis/Valkey, and source-provider egress where available.
- Run scheduled source sync and graph ingest jobs separately from the API service so retries, concurrency, and capacity can be tuned independently.
- Preview every stack with `--refresh=false` before review, then run a normal preview with real credentials before `pulumi up`.
