# Cerebro

WriterInternal Cerebro owns the internal deployment surface for the current Cerebro runtime. It keeps environment-specific infrastructure, stack configuration, image promotion, and deployment workflows in one place without renaming the repository or wiring automatic cross-repository promotion.

This repository is intentionally narrow: it deploys and operates Cerebro for Writer environments. Product/runtime source code, UI console work, automation workflows, and historical v1 design notes should not be reintroduced here.

## Current responsibilities

- **AWS runtime stacks** in `infra/aws` for `sec-dev` and `go-prod`.
- **GCP Workload Identity Federation** in `infra/gcp` for AWS-to-GCP scanner access.
- **Container image mirroring** from GHCR to environment ECR repositories using pinned image tags from Pulumi stack config.
- **Private runtime networking**: VPC/subnets, internal ALB, ACM certificates, WAF, Tailscale access, and CloudWatch logging.
- **Runtime dependencies**: RDS Postgres for current state, NATS JetStream for the append log, and Neo4j/Aura for graph projections.
- **Secret boundaries**: Infisical sync role, AWS Secrets Manager imports, and Pulumi-encrypted stack values.
- **Source runtime bootstrap**: declarative source runtime definitions and the ECS/EventBridge orchestrator schedules that execute them.

## Non-goals

- No repository rename.
- No automatic repository-to-repository release linkage.
- No application source code beyond deployment-specific IAM/config shims.
- No stale v1 platform docs or old provider tree.
- No `cerebro-web` or `cerebro-automation` ownership in this repo.

## Repository layout

| Path | Purpose |
| --- | --- |
| `.github/workflows/ci.yml` | Mirrors the pinned Cerebro image tag from GHCR into the target ECR repository. |
| `.github/workflows/infra-deploy.yml` | Runs Pulumi previews on PRs and deploys selected stacks. |
| `infra/aws` | AWS Pulumi program for ECS, ALB, WAF, Postgres, NATS, Neo4j/Aura, ECR, KMS, Tailscale, and source runtime bootstrap. |
| `infra/aws/Pulumi.sec-dev.yaml` | sec-dev stack configuration and source runtime schedules. |
| `infra/aws/Pulumi.go-prod.yaml` | go-prod stack configuration. |
| `infra/gcp` | GCP Pulumi program for Workload Identity Federation and scanner IAM. |
| `renovate.json` | Dependency maintenance for the infrastructure workspace. |

## Operating model

Image versions are explicit. Change `cerebro:imageTag` in the relevant Pulumi stack file, open a normal PR, review the image mirror/preview results, and then merge or dispatch the deployment workflow. Do not add an automatic promotion workflow between repositories; deployment remains an intentional infrastructure change.

The AWS runtime has historically been singleton: `cerebro:apiMaxInstances` defaulted to `1` because source-runtime cursor advances were not cross-task safe. Starting with `cerebro:imageTag >= v2.1.25` the API serializes cursor advances behind the same postgres lease the orchestrator already uses (writer/cerebro PR #554), so `apiMaxInstances` may be raised. Stack validation rejects `apiMaxInstances > 1` on older image tags. The orchestrator still runs as scheduled ECS tasks through EventBridge rather than as a second long-running API service.

## Local workflow

Prerequisites:

- Python 3.11+
- `uv`
- Pulumi CLI and access to the `writer-ai` Pulumi organization
- AWS/GCP credentials for the stack being previewed

Install dependencies:

```bash
cd infra
uv sync
```

Preview AWS changes:

```bash
cd infra/aws
uv run pulumi preview --stack sec-dev
uv run pulumi preview --stack go-prod
```

Preview GCP changes:

```bash
cd infra/gcp
uv run pulumi preview --stack gcp-dev
uv run pulumi preview --stack gcp-prod
```

## Key AWS config

| Key | Purpose |
| --- | --- |
| `cerebro:ecrBaseUri` | ECR repository base URI. |
| `cerebro:imageTag` | Explicit runtime image tag to deploy. |
| `cerebro:useExistingVpc`, `cerebro:vpcId`, subnet IDs | Place runtime into an existing Writer VPC. |
| `cerebro:apiCpu`, `cerebro:apiMemory`, `cerebro:apiMinInstances`, `cerebro:apiMaxInstances` | ECS API sizing. |
| `cerebro:postgres*` | RDS Postgres sizing, backups, deletion protection, and multi-AZ behavior. |
| `cerebro:natsCpu`, `cerebro:natsMemory`, `cerebro:jetstream*` | NATS JetStream runtime settings. |
| `cerebro:neo4jAura*` | Neo4j/Aura graph projection settings. |
| `cerebro:apiAuthEnabled`, `cerebro:apiKeys`, `cerebro:allowedTenants` | Runtime API authentication controls. |
| `cerebro:sourceRuntimes` | Declarative source runtime bootstrap definitions. |
| `cerebro:orchestrator*` | EventBridge schedule and ECS task settings for source runtime sync. |
| `cerebro:s3Sources` | IAM read scope for S3-backed source runtimes. |
| `cerebro:enableInfisicalSyncRole`, `cerebro:externalSecretsPrefix` | External secret import boundary. |
| `cerebro:enableTailscale`, `cerebro:tailscaleAdvertiseRoutes` | Tailscale subnet router settings. |

## CI and deployment

- Pull requests preview AWS and GCP Pulumi changes.
- Pull requests also mirror the `sec-dev` image tag to ECR when the referenced GHCR image exists.
- Merges to `main` mirror the `go-prod` image tag to prod ECR and run the `go-prod` Pulumi deployment.
- `workflow_dispatch` supports manual stack deployment for `sec-dev`, `go-prod`, `gcp-dev`, and `gcp-prod`.

## Security notes

- Never commit plaintext credentials, tokens, API keys, or service-specific secrets.
- Keep Pulumi secrets encrypted in stack config.
- Use Infisical or AWS Secrets Manager imports for runtime secrets.
- Keep ALBs internal unless there is an explicit reviewed reason to expose one.
- Preserve least-privilege S3 source IAM scopes in `cerebro:s3Sources`.
