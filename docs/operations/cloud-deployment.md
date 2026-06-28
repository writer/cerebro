# Cloud Deployment

This guide explains how to deploy Cerebro on AWS, Google Cloud, or Azure without depending on any private deployment topology. All names, regions, projects, subscriptions, hostnames, tenant IDs, schedules, secrets, and sizing values are examples. Replace them with values owned by your environment.

Use it with:

- [`docs/operations/hosting.md`](hosting.md) for the runtime hosting contract.
- [`docs/operations/runtime-profiles.md`](runtime-profiles.md) for profile-specific dependencies, config, and checks.
- [`docs/operations/deployment-readiness.md`](deployment-readiness.md) for rollout gates and the preflight receipt.
- [`docs/reference/config-env-vars.md`](../reference/config-env-vars.md) for all supported environment variables.
- [`docs/operations/operations-runbook.md`](operations-runbook.md) for health checks, rollout, rollback, and incident handling.
- [`deploy/pulumi`](../../deploy/pulumi) for validated Pulumi templates.

## Deployment Contract

Cerebro is one HTTP container plus optional backing services:

```text
TLS edge or load balancer
  |
  v
Cerebro API container
  |
  +--> Postgres, when durable state is enabled
  +--> NATS JetStream, when append-log sync or replay is enabled
  +--> Neo4j or Aura, when graph projection and graph queries are enabled
  +--> source provider APIs, when source runtimes sync external systems
```

The container runs:

```text
/usr/local/bin/cerebro serve
```

It listens on `:8080` by default. Use `/livez` for process liveness and `/health` for dependency-aware readiness.

## Pulumi Component Model

The templates in [`deploy/pulumi`](../../deploy/pulumi) use one shared `CerebroService` component and choose a cloud backend with `cerebro:cloud`:

| Cloud | Component target | What it creates |
| --- | --- | --- |
| AWS | ECS Fargate plus Application Load Balancer | VPC, public subnets, optional private subnets/NAT, ALB, optional ACM HTTPS, ECS cluster, task definition, service, logs, IAM, optional Secrets Manager entries, and optional EventBridge Scheduler jobs |
| GCP | Cloud Run v2 | Cloud Run service, optional service account, optional VPC connector, optional Secret Manager entries, optional Cloud Run Jobs, and optional Cloud Scheduler triggers |
| Azure | Azure Container Apps | Resource group, Container Apps managed environment, Container App, optional system identity, Container App secrets, Key Vault-backed secret refs, and optional scheduled Container Apps Jobs |

The templates do not create a private organization-specific control plane, source runtime rollout catalog, DNS zones, managed Postgres clusters, NATS clusters, or Neo4j/Aura instances. They wire the API service and job runners to those dependencies when you provide DSNs, URLs, or existing secret references.

Install:

```bash
cd deploy/pulumi
uv sync
```

Preview locally without deploying:

```bash
export PULUMI_BACKEND_URL="file://$PWD/.pulumi-state"
export PULUMI_CONFIG_PASSPHRASE="local-preview-only"

pulumi stack init aws || true
pulumi stack init gcp || true
pulumi stack init azure || true

pulumi preview --stack aws --refresh=false
pulumi preview --stack gcp --refresh=false
pulumi preview --stack azure --refresh=false
```

If your workstation has no active provider auth, use dummy provider environment variables only for preview-only validation with `--refresh=false`; never use dummy credentials for deployment.

The checked-in stacks are preview-only examples with `cerebro:deploymentProfile=preview` and `cerebro:apiAuthEnabled=false`. Do not deploy them to a shared environment as-is.

## Production Guardrails

Set production mode before any shared deployment:

```bash
pulumi config set cerebro:deploymentProfile production
```

Production mode fails preview/update when the stack has common unsafe settings:

- API auth disabled without `cerebro:edgeAuthManaged=true`.
- mutable `:latest` or untagged images.
- non-HTTPS public origin.
- public ingress without API auth, edge auth, restricted ingress CIDRs, or IAM-only access.
- AWS public ALB without `cerebro:awsCertificateArn` or an upstream edge declaration.

Temporary exceptions must be explicit and justified:

```bash
pulumi config set cerebro:allowUnsafeProduction true
pulumi config set cerebro:unsafeProductionJustification '<why this is acceptable and time-bounded>'
```

## Common Production Config

Set a real image, enable auth or declare an authenticated edge, and set the public origin:

```bash
pulumi config set cerebro:image ghcr.io/writer/cerebro:vX.Y.Z
pulumi config set cerebro:apiAuthEnabled true
pulumi config set cerebro:publicOrigin https://cerebro.example.com
pulumi config set cerebro:trustedProxyCIDRs 10.0.0.0/8
pulumi config set cerebro:trustedProxyCount 1
pulumi config set --secret cerebro:apiKeys '<random-key>:<principal>:<tenant-id>'
```

Enable durable state with a Pulumi-created cloud secret:

```bash
pulumi config set --secret cerebro:postgresDsn '<postgres-dsn-with-tls>'
```

Or reference an existing provider-native secret instead:

```bash
pulumi config set --path 'cerebro:existingSecretRefs.CEREBRO_POSTGRES_DSN.awsArn' \
  'arn:aws:secretsmanager:us-east-1:111122223333:secret:cerebro/postgres'

pulumi config set --path 'cerebro:existingSecretRefs.CEREBRO_POSTGRES_DSN.gcpSecret' \
  'projects/example-project/secrets/cerebro-postgres-dsn'

pulumi config set --path 'cerebro:existingSecretRefs.CEREBRO_POSTGRES_DSN.azureSecretName' \
  cerebro-postgres-dsn
pulumi config set --path 'cerebro:existingSecretRefs.CEREBRO_POSTGRES_DSN.azureKeyVaultUrl' \
  'https://example-vault.vault.azure.net/secrets/cerebro-postgres-dsn'
```

Enable append-log-backed source sync and replay:

```bash
pulumi config set --secret cerebro:jetstreamUrl '<nats-jetstream-url>'
```

Enable graph projection and graph queries:

```bash
pulumi config set --secret cerebro:neo4jUri '<neo4j-or-aura-uri>'
pulumi config set --secret cerebro:neo4jUsername '<neo4j-user>'
pulumi config set --secret cerebro:neo4jPassword '<neo4j-password>'
```

Optional connector-credential and capability-token secrets:

```bash
pulumi config set --secret cerebro:connectorCredentialKey '<high-entropy-key>'
pulumi config set --secret cerebro:connectorTransitPrivateKey '<rsa-private-key-pem>'
pulumi config set --secret cerebro:capabilityTokenSecrets '<hmac-secret-1>,<hmac-secret-2>'
```

For Redis/Valkey or other optional dependency URLs:

```bash
pulumi config set --path 'cerebro:extraEnv.CEREBRO_CACHE_MODE' redis
pulumi config set --secret --path 'cerebro:extraSecrets.CEREBRO_CACHE_URL' '<redis-or-valkey-url>'
```

## AWS

The AWS component deploys the Cerebro API on ECS Fargate behind an Application Load Balancer.

Example setup:

```bash
cd deploy/pulumi
export PULUMI_BACKEND_URL="file://$PWD/.pulumi-state"
export PULUMI_CONFIG_PASSPHRASE="local-preview-only"

pulumi stack select aws --create
pulumi config set cerebro:cloud aws
pulumi config set cerebro:deploymentProfile production
pulumi config set cerebro:name cerebro-prod
pulumi config set cerebro:awsRegion us-east-1
pulumi config set --path 'cerebro:awsAvailabilityZones[0]' us-east-1a
pulumi config set --path 'cerebro:awsAvailabilityZones[1]' us-east-1b
pulumi config set cerebro:image '<account>.dkr.ecr.us-east-1.amazonaws.com/cerebro:vX.Y.Z'
pulumi config set cerebro:awsCertificateArn '<acm-certificate-arn>'
```

Recommended AWS hardening before `pulumi up`:

- Mirror the public image to ECR or an approved registry.
- Set `cerebro:awsCertificateArn` so the ALB serves HTTPS; HTTP redirects to HTTPS by default.
- Restrict ALB ingress with `cerebro:ingressCidrs` or place the service behind a private edge.
- Set `cerebro:awsEnablePrivateSubnets=true` and `cerebro:awsEnableNatGateway=true` when tasks should run in private subnets with outbound internet access.
- Use RDS or Aurora PostgreSQL with TLS, backups, and least-privilege credentials.
- Use managed or self-hosted NATS JetStream with persistent storage.
- Use Neo4j Aura or an operated Neo4j deployment with encrypted connections.
- Store runtime secrets in Secrets Manager through Pulumi secrets, `existingSecretRefs`, or your secret-import pipeline.

Preview:

```bash
AWS_PROFILE=<profile> pulumi preview --stack aws --refresh=false
```

Deploy only after reviewing the preview:

```bash
AWS_PROFILE=<profile> pulumi up --stack aws
```

## Google Cloud

The GCP component deploys the Cerebro API on Cloud Run v2.

Example setup:

```bash
cd deploy/pulumi
export PULUMI_BACKEND_URL="file://$PWD/.pulumi-state"
export PULUMI_CONFIG_PASSPHRASE="local-preview-only"

pulumi stack select gcp --create
pulumi config set cerebro:cloud gcp
pulumi config set cerebro:deploymentProfile production
pulumi config set cerebro:name cerebro-prod
pulumi config set cerebro:gcpProject example-project
pulumi config set cerebro:gcpRegion us-central1
pulumi config set cerebro:image 'us-central1-docker.pkg.dev/example-project/cerebro/cerebro:vX.Y.Z'
pulumi config set cerebro:gcpAllowUnauthenticated false
```

Recommended GCP hardening before `pulumi up`:

- Mirror the public image to Artifact Registry.
- Use Cloud SQL for PostgreSQL or another operated Postgres endpoint with TLS.
- Use managed NATS or run NATS JetStream on GKE or another persistent platform.
- Use Neo4j Aura or an operated Neo4j deployment with encrypted connections.
- Set `cerebro:gcpAllowUnauthenticated=false` when an authenticated edge or IAM invoker policy owns access.
- Set `cerebro:gcpServiceAccountEmail` to a least-privilege Cloud Run service account.
- Set `cerebro:gcpVpcConnector` when private dependencies require Serverless VPC Access.
- Store runtime secrets in Secret Manager through Pulumi secrets, `existingSecretRefs`, or your secret-import pipeline.

Preview:

```bash
gcloud auth application-default login
pulumi preview --stack gcp --refresh=false
```

Deploy only after reviewing the preview:

```bash
pulumi up --stack gcp
```

## Azure

The Azure component deploys the Cerebro API on Azure Container Apps.

Example setup:

```bash
cd deploy/pulumi
export PULUMI_BACKEND_URL="file://$PWD/.pulumi-state"
export PULUMI_CONFIG_PASSPHRASE="local-preview-only"

pulumi stack select azure --create
pulumi config set cerebro:cloud azure
pulumi config set cerebro:deploymentProfile production
pulumi config set cerebro:name cerebro-prod
pulumi config set cerebro:azureLocation eastus
pulumi config set cerebro:azureResourceGroupName cerebro-prod-rg
pulumi config set cerebro:image 'example.azurecr.io/cerebro:vX.Y.Z'
```

Recommended Azure hardening before `pulumi up`:

- Mirror the public image to Azure Container Registry.
- Use Azure Database for PostgreSQL Flexible Server or another operated Postgres endpoint with TLS.
- Use managed NATS or run NATS JetStream on AKS or another persistent platform.
- Use Neo4j Aura or an operated Neo4j deployment with encrypted connections.
- Put Container Apps in a network-integrated environment when dependencies are private.
- Put Azure Front Door, Application Gateway, or another TLS edge in front of the app for shared deployments.
- Use `cerebro:azureEnableSystemIdentity=true` or Key Vault-backed `existingSecretRefs` when the app needs managed identity.
- Store runtime secrets as Container App secrets, Key Vault references, or your secret-import pipeline.

Preview:

```bash
az login
pulumi preview --stack azure --refresh=false
```

Deploy only after reviewing the preview:

```bash
pulumi up --stack azure
```

## Background Jobs

The API service should stay separate from scheduled source sync and graph ingest jobs. Use the same Cerebro image and secret set, but schedule commands independently:

```bash
cerebro source-runtime sync <runtime-id> page_limit=100
cerebro graph ingest-runtime <runtime-id> page_limit=100
```

Configure jobs with `cerebro:scheduledJobs`:

```bash
pulumi config set --path 'cerebro:scheduledJobs[0].name' sync-example
pulumi config set --path 'cerebro:scheduledJobs[0].schedule' 'rate(15 minutes)'
pulumi config set --path 'cerebro:scheduledJobs[0].command[0]' source-runtime
pulumi config set --path 'cerebro:scheduledJobs[0].command[1]' sync
pulumi config set --path 'cerebro:scheduledJobs[0].command[2]' '<runtime-id>'
pulumi config set --path 'cerebro:scheduledJobs[0].command[3]' page_limit=100
```

Common scheduler mappings:

| Cloud | Scheduler shape |
| --- | --- |
| AWS | EventBridge Scheduler launching the ECS task definition with container command overrides |
| GCP | Cloud Run Job plus optional Cloud Scheduler trigger when `cerebro:gcpSchedulerServiceAccountEmail` is set |
| Azure | Container Apps Job with a schedule trigger |

Keep runtime IDs, tenant assignments, provider credentials, and cadence in your deployment repository or scheduler config. Do not publish live schedules in generic docs.

## Validation

Before opening a deployment PR:

```bash
cd deploy/pulumi
uv sync
uv run python -m py_compile __main__.py components.py runtime.py aws_stack.py gcp_stack.py azure_stack.py
uv run pytest -q
pulumi preview --stack <aws|gcp|azure> --refresh=false
```

The templates should be validated with `pulumi preview --refresh=false` for all three example stacks and with placeholder secret config for durable/graph-enabled previews. Do not run `pulumi up` during template validation.

After deploying to a real environment, verify:

```bash
cerebro deploy preflight
curl -fsS https://cerebro.example.com/livez
curl -fsS https://cerebro.example.com/health
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  https://cerebro.example.com/sources
```

For durable or graph-enabled deployments, also run the checks in [`docs/operations/operations-runbook.md`](operations-runbook.md).
