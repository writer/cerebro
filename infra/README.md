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

### Go-prod source-role trust rollout

When a go-prod deploy is blocked by source runtime role trust drift:

1. Land the IAM trust change in the owning GitOps repository (`aws-account-automation`) and wait for its main deployment workflow to finish.
2. Verify the scan roles trust the task roles before starting a Cerebro rollout:

   ```bash
   cd infra
   uv run python scripts/verify_aws_scan_role_trust.py \
     --stack-file aws/Pulumi.go-prod.yaml \
     --profile-by-account 009160076449=writer-prod \
     --profile-by-account 381491964434=writer-devops \
     --profile-by-account 944130631940=cerebro-sec-dev
   ```

3. Dispatch the `Infrastructure Deploy` workflow for `go-prod`.
4. Confirm ECS settles on the intended task definition and the API reports ready:

   ```bash
   aws ecs describe-services \
     --profile writer-sec-prod-us1 \
     --cluster cerebro-go-production-cluster \
     --services cerebro-go-production-api

   curl -fsS https://cerebro.adm.prod.writer.com/health
   ```

5. Run graph health after rollout:

   ```bash
   cd infra
   uv run python scripts/verify_graph_health_ecs.py \
     --stack-file aws/Pulumi.go-prod.yaml \
     --wait-timeout-seconds 3600 \
     --graph-command-retry-seconds 3600 \
     --allow-transient-source-failures
   ```

## Important config

| Key | Required | Description |
| --- | --- | --- |
| `cerebro:ecrBaseUri` | Yes | ECR repository base URI for the runtime image. |
| `cerebro:imageTag` | Yes | Explicit runtime image tag. |
| `cerebro:environment` | Yes | Runtime environment name. |
| `cerebro:useExistingVpc` | Usually | Use pre-existing Writer VPC/subnets. |
| `cerebro:apiMaxInstances` | Yes | Defaults to `1`. May be raised above 1 only when `cerebro:imageTag >= v2.1.25` (carries cross-task source-runtime cursor locking, writer/cerebro PR #554). |
| `cerebro:sourceRuntimes` | Optional | Declarative source runtime definitions. |
| `cerebro:orchestratorEnabled` | Optional | Enables scheduled ECS orchestrator tasks. |
| `cerebro:apiKeys` | Shared envs | Pulumi-encrypted API key set. |
| `cerebro:publicOrigin` | Optional | Canonical external API origin. Defaults to `https://<cerebro:domain>` and is exported as `CEREBRO_PUBLIC_ORIGIN`. |
| `cerebro:trustedProxyCIDRs` | Optional | CIDRs whose forwarded headers are trusted. Defaults to the runtime VPC CIDR for internal ALB stacks and is exported as `CEREBRO_TRUSTED_PROXY_CIDRS`. |
| `cerebro:trustedProxyCount` | Optional | Trusted trailing `X-Forwarded-For` hops. Defaults to `1` when trusted proxy CIDRs are configured. |
| `cerebro:neo4jAura*` | Graph envs | Neo4j/Aura instance and credential settings. |
| `cerebro:s3Sources` | S3-backed sources | IAM scope for S3 source runtimes. |
| `cerebro:enableInfisicalSyncRole` | Shared envs | Allows Infisical-managed secret sync. |
| `cerebro:enableTailscale` | Internal access | Enables Tailscale subnet routing. |

## Outputs

Common AWS outputs include `api_url`, `alb_dns_name`, `ecs_cluster_name`, `ecs_service_name`, `postgres_endpoint`, `postgres_secret_name`, `nats_url`, `jetstream_stream_name`, Neo4j/Aura connection outputs, ECR repository outputs, WAF ARN, and optional Tailscale/Infisical outputs.

## Deployment boundaries

Image promotion is intentionally explicit and reviewable. Update the stack's `cerebro:imageTag`; do not add automatic cross-repository deployment linkage.

Keep stack files free of plaintext secrets. Use Pulumi encrypted values and external secret imports instead.
