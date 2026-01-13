# Cerebro Infrastructure

Pulumi infrastructure for deploying Cerebro on AWS.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                              VPC                                 │
│  ┌──────────────────────┐    ┌──────────────────────┐          │
│  │   Public Subnets     │    │   Private Subnets    │          │
│  │  ┌────────────────┐  │    │  ┌────────────────┐  │          │
│  │  │      ALB       │──│────│──│   ECS Fargate  │  │          │
│  │  └────────────────┘  │    │  │   (Cerebro)    │  │          │
│  │         │            │    │  └────────────────┘  │          │
│  │         │ WAF        │    │         │            │          │
│  └─────────│────────────┘    └─────────│────────────┘          │
│            │                           │                        │
└────────────│───────────────────────────│────────────────────────┘
             │                           │
        Internet                    Snowflake
                                   (External)
```

## Components

- **VPC**: Public/private subnets across 2 AZs, NAT gateway
- **ECS Fargate**: Go API server with auto-scaling (2-10 instances)
- **ALB**: Application Load Balancer with health checks
- **WAF**: Rate limiting + AWS managed rules (SQLi, XSS, bad inputs)
- **Secrets Manager**: Snowflake credentials, API keys
- **CloudWatch**: Logs, metrics, dashboard, alarms

## Prerequisites

1. AWS CLI configured with appropriate credentials
2. Pulumi CLI installed (`brew install pulumi`)
3. Python 3.11+

## Quick Start

```bash
# Install dependencies
cd infra
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create stack
pulumi stack init production

# Set required config
pulumi config set cerebro:containerImage <ECR_IMAGE_URI>
pulumi config set --secret cerebro:snowflakeConnectionString "user:pass@account/DB/SCHEMA"

# Optional: AI agents
pulumi config set --secret cerebro:anthropicApiKey "sk-ant-..."

# Optional: Notifications
pulumi config set --secret cerebro:slackWebhookUrl "https://hooks.slack.com/..."

# Preview changes
pulumi preview

# Deploy
pulumi up
```

## Configuration

| Key | Required | Description |
|-----|----------|-------------|
| `containerImage` | Yes | ECR image URI |
| `snowflakeConnectionString` | Yes | Snowflake connection string |
| `environment` | No | Environment name (default: production) |
| `domain` | No | Custom domain for HTTPS |
| `apiCpu` | No | CPU units (default: 1024) |
| `apiMemory` | No | Memory MB (default: 2048) |
| `apiMinInstances` | No | Min instances (default: 2) |
| `apiMaxInstances` | No | Max instances (default: 10) |
| `enableWaf` | No | Enable WAF (default: true) |
| `albInternal` | No | Internal ALB only (default: true) |

## Outputs

After deployment, Pulumi exports:

- `api_url` - API endpoint URL
- `alb_dns_name` - ALB DNS name
- `ecs_cluster_name` - ECS cluster name
- `secrets_arn` - Secrets Manager ARN

## CI/CD

See `.github/workflows/infra-deploy.yml` for automated deployment.

## Cost Estimate

Approximate monthly cost (us-east-1):

| Resource | Cost |
|----------|------|
| ECS Fargate (2x 1vCPU/2GB) | ~$60 |
| ALB | ~$20 |
| NAT Gateway | ~$35 |
| WAF | ~$10 |
| CloudWatch | ~$5 |
| **Total** | **~$130/mo** |

Note: Snowflake costs are separate and depend on usage.
