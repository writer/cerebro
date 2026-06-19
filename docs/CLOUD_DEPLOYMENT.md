# Cloud Deployment

This guide explains how to deploy Cerebro on AWS, Google Cloud, or Azure without depending on any private deployment topology. All names, regions, projects, subscriptions, hostnames, tenant IDs, schedules, secrets, and sizing values are examples. Replace them with values owned by your environment.

Use it with:

- [`docs/HOSTING.md`](./HOSTING.md) for the runtime hosting contract.
- [`docs/CONFIG_ENV_VARS.md`](./CONFIG_ENV_VARS.md) for all supported environment variables.
- [`docs/OPERATIONS_RUNBOOK.md`](./OPERATIONS_RUNBOOK.md) for health checks, rollout, rollback, and incident handling.
- [`deploy/pulumi`](../deploy/pulumi) for validated Pulumi templates.

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

## Pulumi Templates

The templates in [`deploy/pulumi`](../deploy/pulumi) use one shared configuration model and choose a cloud backend with `cerebro:cloud`:

| Cloud | Template target | What it creates |
| --- | --- | --- |
| AWS | ECS Fargate plus Application Load Balancer | VPC, public subnets, ALB, ECS cluster, task definition, service, logs, IAM, and optional Secrets Manager entries |
| GCP | Cloud Run v2 | Cloud Run service, optional public invoker binding, and optional Secret Manager entries |
| Azure | Azure Container Apps | Resource group, Container Apps managed environment, Container App, ingress, and Container App secrets |

The templates do not create a private organization-specific control plane, source runtime schedules, DNS zones, certificates, Postgres clusters, NATS clusters, or Neo4j/Aura instances. They wire the API service to those dependencies when you provide their DSNs or URLs as Pulumi secrets.

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

The checked-in stacks are preview-only examples with `cerebro:apiAuthEnabled=false`. Do not deploy them to a shared environment as-is.

## Common Production Config

Set a real image and enable auth before any shared deployment:

```bash
pulumi config set cerebro:image ghcr.io/writer/cerebro:vX.Y.Z
pulumi config set cerebro:apiAuthEnabled true
pulumi config set cerebro:publicOrigin https://cerebro.example.com
pulumi config set cerebro:trustedProxyCIDRs 10.0.0.0/8
pulumi config set cerebro:trustedProxyCount 1
pulumi config set --secret cerebro:apiKeys '<random-key>:<principal>:<tenant-id>'
```

Enable durable state:

```bash
pulumi config set --secret cerebro:postgresDsn '<postgres-dsn-with-tls>'
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

For any additional non-secret runtime variable, use:

```bash
pulumi config set --path 'cerebro:extraEnv.CEREBRO_CACHE_MODE' redis
```

For any additional secret runtime variable, use:

```bash
pulumi config set --secret --path 'cerebro:extraSecrets.CEREBRO_CACHE_URL' '<redis-or-valkey-url>'
```

## AWS

The AWS template deploys the Cerebro API on ECS Fargate behind an Application Load Balancer.

Example setup:

```bash
cd deploy/pulumi
export PULUMI_BACKEND_URL="file://$PWD/.pulumi-state"
export PULUMI_CONFIG_PASSPHRASE="local-preview-only"

pulumi stack select aws --create
pulumi config set cerebro:cloud aws
pulumi config set cerebro:name cerebro-prod
pulumi config set cerebro:awsRegion us-east-1
pulumi config set --path 'cerebro:awsAvailabilityZones[0]' us-east-1a
pulumi config set --path 'cerebro:awsAvailabilityZones[1]' us-east-1b
pulumi config set cerebro:image '<account>.dkr.ecr.us-east-1.amazonaws.com/cerebro:vX.Y.Z'
```

Recommended AWS hardening before `pulumi up`:

- Mirror the public image to ECR or an approved registry.
- Put tasks in private subnets with controlled egress for shared environments.
- Terminate TLS with ACM on the load balancer or an upstream edge.
- Use RDS or Aurora PostgreSQL with TLS, backups, and least-privilege credentials.
- Use managed or self-hosted NATS JetStream with persistent storage.
- Use Neo4j Aura or an operated Neo4j deployment with encrypted connections.
- Restrict ALB ingress CIDRs or place the service behind a private edge when appropriate.
- Store runtime secrets in Secrets Manager through Pulumi secrets or your secret-import pipeline.

Preview:

```bash
AWS_PROFILE=<profile> pulumi preview --stack aws --refresh=false
```

Deploy only after reviewing the preview:

```bash
AWS_PROFILE=<profile> pulumi up --stack aws
```

## Google Cloud

The GCP template deploys the Cerebro API on Cloud Run v2.

Example setup:

```bash
cd deploy/pulumi
export PULUMI_BACKEND_URL="file://$PWD/.pulumi-state"
export PULUMI_CONFIG_PASSPHRASE="local-preview-only"

pulumi stack select gcp --create
pulumi config set cerebro:cloud gcp
pulumi config set cerebro:name cerebro-prod
pulumi config set cerebro:gcpProject example-project
pulumi config set cerebro:gcpRegion us-central1
pulumi config set cerebro:image 'us-central1-docker.pkg.dev/example-project/cerebro/cerebro:vX.Y.Z'
```

Recommended GCP hardening before `pulumi up`:

- Mirror the public image to Artifact Registry.
- Use Cloud SQL for PostgreSQL or another operated Postgres endpoint with TLS.
- Use managed NATS or run NATS JetStream on GKE or another persistent platform.
- Use Neo4j Aura or an operated Neo4j deployment with encrypted connections.
- Set `cerebro:gcpAllowUnauthenticated=false` when an authenticated edge or IAM invoker policy owns access.
- Use Serverless VPC Access or equivalent private connectivity for private dependencies.
- Store runtime secrets in Secret Manager through Pulumi secrets or your secret-import pipeline.

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

The Azure template deploys the Cerebro API on Azure Container Apps.

Example setup:

```bash
cd deploy/pulumi
export PULUMI_BACKEND_URL="file://$PWD/.pulumi-state"
export PULUMI_CONFIG_PASSPHRASE="local-preview-only"

pulumi stack select azure --create
pulumi config set cerebro:cloud azure
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
- Store runtime secrets as Container App secrets through Pulumi secrets or your secret-import pipeline.

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

Common scheduler mappings:

| Cloud | Scheduler shape |
| --- | --- |
| AWS | EventBridge Scheduler or EventBridge rule launching an ECS Fargate task |
| GCP | Cloud Scheduler triggering a Cloud Run Job or Workflows step |
| Azure | Container Apps Job with a schedule trigger |

Keep runtime IDs, tenant assignments, provider credentials, and cadence in your deployment repository or scheduler config. Do not publish live schedules in generic docs.

## Validation

Before opening a deployment PR:

```bash
cd deploy/pulumi
uv sync
uv run python -m py_compile __main__.py runtime.py aws_stack.py gcp_stack.py azure_stack.py
pulumi preview --stack <aws|gcp|azure> --refresh=false
```

The templates were validated locally with `pulumi preview --refresh=false` for all three example stacks and with placeholder secret config for durable/graph-enabled previews. No `pulumi up` was run.

After deploying to a real environment, verify:

```bash
curl -fsS https://cerebro.example.com/livez
curl -fsS https://cerebro.example.com/health
curl -fsS -H "Authorization: Bearer ${CEREBRO_API_KEY}" \
  https://cerebro.example.com/sources
```

For durable or graph-enabled deployments, also run the checks in [`docs/OPERATIONS_RUNBOOK.md`](./OPERATIONS_RUNBOOK.md).
