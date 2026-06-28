# Cerebro Pulumi Templates

These Pulumi templates deploy the public Cerebro runtime on AWS, Google Cloud, or Azure using environment-agnostic defaults. They intentionally use placeholder names and caller-owned configuration only. Do not put live account IDs, hostnames, tenant names, source schedules, provider tokens, or secret values in this directory.

Use these templates with [`docs/operations/runtime-profiles.md`](../../docs/operations/runtime-profiles.md) and [`docs/operations/deployment-readiness.md`](../../docs/operations/deployment-readiness.md). The templates wire the API service and scheduled job runners; the deployment environment owns backing stores, schedules, secret paths, approval gates, and rollback records.

The stack entrypoint creates one reusable `CerebroService` component. That component chooses a provider-specific child component from the shared `cerebro:cloud` config:

- AWS: ECS Fargate service behind an Application Load Balancer, with optional ACM HTTPS, private subnets, NAT, and EventBridge Scheduler jobs.
- GCP: Cloud Run v2 service, with optional service account, VPC connector, Cloud Run Jobs, and Cloud Scheduler triggers.
- Azure: Azure Container Apps service, with optional system identity, Key Vault-backed secrets, and scheduled Container Apps Jobs.

Postgres, NATS JetStream, Neo4j/Aura, and Redis/Valkey are wired by DSN/URL secrets. You can provide those secrets through Pulumi-created cloud secrets or by referencing existing cloud secret manager entries.

## Runtime Profiles

| Profile | Required template config | Cerebro features |
| --- | --- | --- |
| Lightweight API | image, cloud, region/location | `/livez`, `/health`, `/openapi.yaml`, `/sources`, and provider-free source previews |
| Durable API | `CEREBRO_POSTGRES_DSN` via `cerebro:postgresDsn` or `cerebro:existingSecretRefs` | persisted runtimes, claims, findings, reports, OAuth, and device-auth state |
| Durable sync | Postgres plus `CEREBRO_JETSTREAM_URL` | source runtime sync and append-log-backed replay |
| Graph-enabled | Postgres, JetStream, `CEREBRO_NEO4J_URI`, `CEREBRO_NEO4J_USERNAME`, `CEREBRO_NEO4J_PASSWORD` | graph ingest, graph queries, graph health, and graph-agent workflows |

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

Each checked-in example stack is explicitly marked `cerebro:deploymentProfile=preview` and intentionally keeps auth disabled so the resource graph can be previewed without live secrets. Do not deploy these exact stack files to a shared environment.

```bash
pulumi preview --stack aws --refresh=false
pulumi preview --stack gcp --refresh=false
pulumi preview --stack azure --refresh=false
```

If your workstation has no active provider auth, use dummy provider environment variables for preview-only validation with `--refresh=false`; do not use those values for deployment.

For real deployments, set a release image, enable production guardrails, enable auth or an authenticated edge, and provide secrets first:

```bash
pulumi config set cerebro:deploymentProfile production
pulumi config set cerebro:image ghcr.io/writer/cerebro:vX.Y.Z
pulumi config set cerebro:apiAuthEnabled true
pulumi config set cerebro:publicOrigin https://cerebro.example.com
pulumi config set --secret cerebro:apiKeys '<random-key>:<principal>:<tenant-id>'
pulumi config set --secret cerebro:postgresDsn '<postgres-dsn-with-tls>'
pulumi config set --secret cerebro:jetstreamUrl '<nats-url>'
pulumi config set --secret cerebro:neo4jUri '<neo4j-or-aura-uri>'
pulumi config set --secret cerebro:neo4jUsername '<neo4j-user>'
pulumi config set --secret cerebro:neo4jPassword '<neo4j-password>'
```

## Guardrails

Production stacks fail preview/update unless unsafe settings are fixed or explicitly overridden with a justification. The guardrails cover:

- API authentication disabled without `cerebro:edgeAuthManaged=true`.
- mutable `:latest` or untagged container images.
- non-HTTPS `cerebro:publicOrigin`.
- public ingress without API auth, edge auth, restricted ingress CIDRs, or IAM-only access.
- AWS public load balancers without `cerebro:awsCertificateArn` or an upstream edge declaration.

Temporary exceptions require both:

```bash
pulumi config set cerebro:allowUnsafeProduction true
pulumi config set cerebro:unsafeProductionJustification '<why this is acceptable and time-bounded>'
```

## Cloud Selection

Set `cerebro:cloud` to one of:

- `aws`
- `gcp`
- `azure`

The shared config keys are the same across clouds:

| Key | Default | Notes |
| --- | --- | --- |
| `cerebro:deploymentProfile` | `preview` | Set `production` for shared environments. |
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
| `cerebro:ingressCidrs` | `["0.0.0.0/0"]` | Applied to AWS ALB ingress; use cloud edge controls for GCP/Azure CIDR filtering. |
| `cerebro:edgeAuthManaged` | `false` | Set true when an upstream edge owns authentication and forwarded-header hygiene. |
| `cerebro:apiAuthEnabled` | `true` | Keep true outside local or validation-only stacks unless an authenticated edge owns access. |
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
| `cerebro:extraSecrets` | `{}` | Secret environment variable map created by the template. |
| `cerebro:existingSecretRefs` | `{}` | Existing provider-native secret refs keyed by environment variable name. |
| `cerebro:scheduledJobs` | `[]` | Optional scheduled jobs that run the same image with a command override. |

Cloud-specific keys:

| Cloud | Keys |
| --- | --- |
| AWS | `cerebro:awsRegion`, `cerebro:awsAvailabilityZones`, `cerebro:awsVpcCidr`, `cerebro:awsPublicSubnetCidrs`, `cerebro:awsPrivateSubnetCidrs`, `cerebro:awsEnablePrivateSubnets`, `cerebro:awsEnableNatGateway`, `cerebro:awsAssignPublicIp`, `cerebro:awsCertificateArn`, `cerebro:awsRedirectHttpToHttps`, `cerebro:awsLogRetentionDays`, `cerebro:awsSkipCredentialsValidation` |
| GCP | `cerebro:gcpProject`, `cerebro:gcpRegion`, `cerebro:gcpIngress`, `cerebro:gcpAllowUnauthenticated`, `cerebro:gcpServiceAccountEmail`, `cerebro:gcpSchedulerServiceAccountEmail`, `cerebro:gcpVpcConnector` |
| Azure | `cerebro:azureLocation`, `cerebro:azureResourceGroupName`, `cerebro:azureExternalIngress`, `cerebro:azureEnableSystemIdentity` |

## Existing Secrets

Use `existingSecretRefs` when your environment already manages secret material. The keys are Cerebro environment variables; each value is cloud-specific metadata.

AWS Secrets Manager:

```bash
pulumi config set --path 'cerebro:existingSecretRefs.CEREBRO_POSTGRES_DSN.awsArn' \
  'arn:aws:secretsmanager:us-east-1:111122223333:secret:cerebro/postgres'
```

GCP Secret Manager:

```bash
pulumi config set --path 'cerebro:existingSecretRefs.CEREBRO_POSTGRES_DSN.gcpSecret' \
  'projects/example-project/secrets/cerebro-postgres-dsn'
pulumi config set --path 'cerebro:existingSecretRefs.CEREBRO_POSTGRES_DSN.gcpVersion' latest
```

Azure Key Vault:

```bash
pulumi config set --path 'cerebro:existingSecretRefs.CEREBRO_POSTGRES_DSN.azureSecretName' \
  cerebro-postgres-dsn
pulumi config set --path 'cerebro:existingSecretRefs.CEREBRO_POSTGRES_DSN.azureKeyVaultUrl' \
  'https://example-vault.vault.azure.net/secrets/cerebro-postgres-dsn'
```

For Azure Key Vault refs, grant the Container App system identity access to the referenced secrets.

## Scheduled Jobs

Scheduled jobs run the same image with a command override. Keep runtime IDs, tenant assignments, provider credentials, and cadence in your private deployment config, not in generic docs.

```bash
pulumi config set --path 'cerebro:scheduledJobs[0].name' sync-example
pulumi config set --path 'cerebro:scheduledJobs[0].schedule' 'rate(15 minutes)'
pulumi config set --path 'cerebro:scheduledJobs[0].command[0]' source-runtime
pulumi config set --path 'cerebro:scheduledJobs[0].command[1]' sync
pulumi config set --path 'cerebro:scheduledJobs[0].command[2]' '<runtime-id>'
pulumi config set --path 'cerebro:scheduledJobs[0].command[3]' page_limit=100
```

Scheduler shapes:

| Cloud | Template shape |
| --- | --- |
| AWS | EventBridge Scheduler launching the ECS task definition with container command overrides |
| GCP | Cloud Run Job plus optional Cloud Scheduler HTTP trigger when `cerebro:gcpSchedulerServiceAccountEmail` is set |
| Azure | Container Apps Job with a schedule trigger |

AWS schedules use EventBridge Scheduler expressions such as `rate(15 minutes)` or `cron(...)`. GCP and Azure schedules use cron expressions.

## Optional Dependency Modules

The base component intentionally deploys the API service and job runners only. Dependency modules remain opt-in through provider-managed services or third-party services:

- Postgres: provide `CEREBRO_POSTGRES_DSN` via `cerebro:postgresDsn` or `existingSecretRefs`.
- NATS JetStream: provide `CEREBRO_JETSTREAM_URL`.
- Neo4j/Aura: provide `CEREBRO_NEO4J_URI`, username, and password.
- Redis/Valkey: set `cerebro:extraEnv.CEREBRO_CACHE_MODE=redis` and provide `CEREBRO_CACHE_URL` through `extraSecrets` or `existingSecretRefs`.
- Private connectivity: use `awsEnablePrivateSubnets`, `awsEnableNatGateway`, `gcpVpcConnector`, or a network-integrated Azure Container Apps environment adapted in your deployment repo.
- Identity/logging: use `gcpServiceAccountEmail`, Azure system identity, AWS task roles, and your cloud logging controls.

## Production Notes

These templates are a portable starting point, not a replacement for your organization's deployment controls.

- Put the service behind TLS and set `cerebro:publicOrigin` to the HTTPS origin clients use.
- Strip untrusted inbound forwarded headers at the edge and set `cerebro:trustedProxyCIDRs` to your real proxy or load-balancer network.
- Keep API auth enabled or document the authenticated edge that owns access.
- Use private networking for Postgres, NATS JetStream, Neo4j/Aura, Redis/Valkey, and source-provider egress where available.
- Run scheduled source sync and graph ingest jobs separately from the API service so retries, concurrency, and capacity can be tuned independently.
- Preview every stack with `--refresh=false` before review, then run a normal preview with real credentials before `pulumi up`.
