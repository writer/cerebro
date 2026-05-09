# Cerebro Infrastructure

Pulumi infrastructure for Writer's internal Cerebro runtime.

## AWS runtime

`infra/aws` deploys a private ECS Fargate API service and optional scheduled orchestrator tasks. The stack provisions or wires:

- ECR repository references and explicit image tags
- VPC networking, security groups, private subnets, and internal ALB
- ACM certificate attachment and WAF rules
- ECS cluster, task definitions, service, task IAM, and EventBridge orchestrator schedules
- RDS Postgres for state
- NATS JetStream for the append log
- Neo4j/Aura for graph projections
- KMS keys, CloudWatch logs/alarms, ALB access logs, and optional Tailscale routing
- Infisical/AWS Secrets Manager boundaries for runtime secrets
- S3 source IAM scopes for configured source runtimes

## GCP runtime support

`infra/gcp` configures Workload Identity Federation so approved AWS ECS task roles can impersonate a GCP scanner service account without long-lived service account keys.

## Stacks

| Stack | Purpose |
| --- | --- |
| `sec-dev` | Security development runtime, including Okta source runtime schedules. |
| `go-prod` | Production runtime. |
| `gcp-dev` | Development GCP WIF/scanner IAM. |
| `gcp-prod` | Production GCP WIF/scanner IAM. |

## Install

```bash
cd infra
uv sync
```

## Preview

```bash
cd infra/aws
uv run pulumi preview --stack sec-dev
uv run pulumi preview --stack go-prod

cd ../gcp
uv run pulumi preview --stack gcp-dev
uv run pulumi preview --stack gcp-prod
```

## Deploy

Prefer the GitHub Actions workflow for reviewed deployments. For emergency/manual operations, use the same stack names locally after verifying credentials and Pulumi organization access.

```bash
cd infra/aws
uv run pulumi up --stack sec-dev
uv run pulumi up --stack go-prod
```

## Important config

| Key | Required | Description |
| --- | --- | --- |
| `cerebro:ecrBaseUri` | Yes | ECR repository base URI for the runtime image. |
| `cerebro:imageTag` | Yes | Explicit runtime image tag. |
| `cerebro:environment` | Yes | Runtime environment name. |
| `cerebro:useExistingVpc` | Usually | Use pre-existing Writer VPC/subnets. |
| `cerebro:apiMaxInstances` | Yes | Must remain `1` until runtime cursor locking supports multiple API tasks. |
| `cerebro:sourceRuntimes` | Optional | Declarative source runtime definitions. |
| `cerebro:orchestratorEnabled` | Optional | Enables scheduled ECS orchestrator tasks. |
| `cerebro:apiKeys` | Shared envs | Pulumi-encrypted API key set. |
| `cerebro:neo4jAura*` | Graph envs | Neo4j/Aura instance and credential settings. |
| `cerebro:s3Sources` | S3-backed sources | IAM scope for S3 source runtimes. |
| `cerebro:enableInfisicalSyncRole` | Shared envs | Allows Infisical-managed secret sync. |
| `cerebro:enableTailscale` | Internal access | Enables Tailscale subnet routing. |

## Outputs

Common AWS outputs include `api_url`, `alb_dns_name`, `ecs_cluster_name`, `ecs_service_name`, `postgres_endpoint`, `postgres_secret_name`, `nats_url`, `jetstream_stream_name`, Neo4j/Aura connection outputs, ECR repository outputs, WAF ARN, and optional Tailscale/Infisical outputs.

## Deployment boundaries

Image promotion is intentionally explicit and reviewable. Update the stack's `cerebro:imageTag`; do not add automatic cross-repository deployment linkage.

Keep stack files free of plaintext secrets. Use Pulumi encrypted values and external secret imports instead.
