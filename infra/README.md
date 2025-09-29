# Cerebro Infrastructure as Code

Production-ready infrastructure for deploying Cerebro using Pulumi.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Internet                                 │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │   CloudFront    │  (CDN - Optional)
                    │   /ALB/NLB      │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
    ┌─────────▼─────────┐       ┌──────────▼──────────┐
    │   API Servers     │       │   Flower (Monitor)  │
    │  (ECS/GKE/K8s)    │       │   (Optional)        │
    │  - Autoscaling    │       └─────────────────────┘
    │  - Health Checks  │
    └─────────┬─────────┘
              │
    ┌─────────┴──────────────────────────────┐
    │                                         │
┌───▼────────────┐              ┌────────────▼─────┐
│  Celery Workers│              │   Celery Beat    │
│  (ECS/GKE)     │              │   (Single)       │
│  - Autoscaling │              │   - Digest Sched │
│  - Queue: 4    │              └──────────────────┘
└───┬────────────┘
    │
    └─────────────┬──────────────┬────────────────┐
                  │              │                │
         ┌────────▼────────┐ ┌──▼────────┐  ┌───▼────────┐
         │   PostgreSQL    │ │   Redis   │  │    KMS     │
         │   (RDS/SQL)     │ │(ElastiCache)│  │ (AWS/GCP) │
         │  - Multi-AZ     │ │ - Cluster │  │           │
         │  - Read Replica │ │ - Persist │  │           │
         └────────┬────────┘ └───────────┘  └────────────┘
                  │
         ┌────────▼────────┐
         │  Secrets Mgr    │
         │  (AWS/GCP)      │
         │  - DB creds     │
         │  - API keys     │
         └─────────────────┘
```

## Cloud Provider Options

### AWS (Recommended for US customers)
- **Compute**: ECS Fargate (serverless containers)
- **Database**: RDS PostgreSQL (Multi-AZ)
- **Cache**: ElastiCache Redis (Cluster mode)
- **Secrets**: AWS Secrets Manager
- **KMS**: AWS KMS
- **Load Balancer**: Application Load Balancer
- **CDN**: CloudFront
- **Monitoring**: CloudWatch + X-Ray

### GCP (Recommended for European customers)
- **Compute**: Cloud Run / GKE Autopilot
- **Database**: Cloud SQL PostgreSQL (HA)
- **Cache**: Memorystore Redis
- **Secrets**: Secret Manager
- **KMS**: Cloud KMS
- **Load Balancer**: Cloud Load Balancing
- **CDN**: Cloud CDN
- **Monitoring**: Cloud Logging + Cloud Monitoring

## Directory Structure

```
infra/
├── README.md                    # This file
├── Pulumi.yaml                  # Pulumi project config
├── requirements.txt             # Python dependencies
├── __main__.py                  # Main Pulumi program
├── aws/
│   ├── __init__.py
│   ├── networking.py            # VPC, subnets, security groups
│   ├── database.py              # RDS PostgreSQL
│   ├── cache.py                 # ElastiCache Redis
│   ├── compute.py               # ECS Fargate services
│   ├── secrets.py               # Secrets Manager
│   ├── kms.py                   # KMS keys
│   ├── monitoring.py            # CloudWatch, alarms
│   └── load_balancer.py         # ALB configuration
├── gcp/
│   ├── __init__.py
│   ├── networking.py            # VPC, subnets, firewall rules
│   ├── database.py              # Cloud SQL
│   ├── cache.py                 # Memorystore
│   ├── compute.py               # Cloud Run / GKE
│   ├── secrets.py               # Secret Manager
│   ├── kms.py                   # Cloud KMS
│   ├── monitoring.py            # Cloud Monitoring
│   └── load_balancer.py         # Load Balancing
├── kubernetes/
│   ├── api-deployment.yaml      # API server deployment
│   ├── worker-deployment.yaml   # Celery workers
│   ├── beat-deployment.yaml     # Celery beat
│   ├── flower-deployment.yaml   # Flower monitoring
│   ├── ingress.yaml             # Ingress controller
│   └── hpa.yaml                 # Horizontal Pod Autoscaler
└── config/
    ├── dev.yaml                 # Development config
    ├── staging.yaml             # Staging config
    └── prod.yaml                # Production config
```

## Prerequisites

### Install Dependencies

```bash
# Install Pulumi
curl -fsSL https://get.pulumi.com | sh

# Install Python dependencies
cd infra
pip install -r requirements.txt

# Configure cloud credentials
# AWS
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx

# OR GCP
export GOOGLE_CREDENTIALS=$(cat path/to/service-account.json)
export GOOGLE_PROJECT=your-project-id
```

### Initialize Pulumi Stack

```bash
# Create new stack
pulumi stack init prod

# Configure stack
pulumi config set aws:region us-east-1
pulumi config set cerebro:environment production
pulumi config set cerebro:domain cerebro.example.com
pulumi config set --secret cerebro:secretKey $(openssl rand -base64 32)
```

## Deployment

### Quick Start

```bash
cd infra

# Preview changes
pulumi preview

# Deploy infrastructure
pulumi up

# Get outputs
pulumi stack output apiUrl
pulumi stack output dbEndpoint
```

### Full Deployment Steps

#### 1. Deploy Networking Layer
```bash
pulumi up --target-dependents urn:pulumi:prod::cerebro::aws:ec2/vpc:Vpc::cerebro-vpc
```

#### 2. Deploy Database & Cache
```bash
pulumi up --target-dependents urn:pulumi:prod::cerebro::aws:rds/instance:Instance::cerebro-db
pulumi up --target-dependents urn:pulumi:prod::cerebro::aws:elasticache/cluster:Cluster::cerebro-redis
```

#### 3. Run Migrations
```bash
# Connect to bastion or use AWS Systems Manager Session Manager
aws ecs run-task \
  --cluster cerebro-cluster \
  --task-definition cerebro-migration \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx]}"
```

#### 4. Deploy Application
```bash
pulumi up
```

## Configuration

### Environment Variables

All secrets are stored in AWS Secrets Manager / GCP Secret Manager:

- `CEREBRO_SECRET_KEY` - JWT signing key
- `CEREBRO_DB_PASSWORD` - Database password
- `CEREBRO_REDIS_PASSWORD` - Redis password
- `ANTHROPIC_API_KEY` - Claude API key
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` - For AWS provider access
- `GOOGLE_APPLICATION_CREDENTIALS` - For GCP provider access

### Scaling Configuration

**API Servers**:
- Min: 2 instances
- Max: 20 instances
- Target CPU: 70%
- Target Memory: 80%

**Celery Workers**:
- Min: 2 instances
- Max: 50 instances
- Target Queue Depth: 100 messages
- Scale up: Add 1 worker per 100 messages
- Scale down: Remove 1 worker when queue < 50 messages

**Celery Beat**:
- Fixed: 1 instance (leader election via Redis)

### Database Configuration

**PostgreSQL (RDS)**:
- Instance: db.r6g.xlarge (4 vCPU, 32GB RAM)
- Storage: 500GB gp3 (16,000 IOPS)
- Multi-AZ: Yes
- Backup retention: 30 days
- Read replicas: 2 (for analytics queries)
- Connection pooling: PgBouncer (100 connections)

**Redis (ElastiCache)**:
- Instance: cache.r6g.large (2 vCPU, 13GB RAM)
- Cluster mode: Enabled (3 shards, 2 replicas each)
- Persistence: AOF enabled (every 1 second)
- Backup retention: 7 days

## Cost Estimation

### AWS (us-east-1, monthly)

| Resource | Configuration | Monthly Cost |
|----------|--------------|--------------|
| ECS Fargate (API) | 2-20 tasks @ 2 vCPU, 4GB | $150-$1,500 |
| ECS Fargate (Workers) | 2-50 tasks @ 1 vCPU, 2GB | $75-$1,875 |
| RDS PostgreSQL | db.r6g.xlarge Multi-AZ | $650 |
| RDS Read Replicas | 2x db.r6g.large | $600 |
| ElastiCache Redis | cache.r6g.large cluster | $350 |
| Application Load Balancer | 1x ALB | $25 |
| NAT Gateway | 2x NAT (Multi-AZ) | $90 |
| Data Transfer | 1TB out | $90 |
| CloudWatch Logs | 50GB | $25 |
| Secrets Manager | 10 secrets | $4 |
| KMS | 1 key | $1 |
| **Total (baseline)** | | **~$2,060/mo** |
| **Total (scaled up)** | | **~$5,340/mo** |

### GCP (us-central1, monthly)

| Resource | Configuration | Monthly Cost |
|----------|--------------|--------------|
| Cloud Run (API) | 2-20 instances @ 2 vCPU, 4GB | $120-$1,200 |
| GKE Autopilot (Workers) | 2-50 pods @ 1 vCPU, 2GB | $60-$1,500 |
| Cloud SQL | db-highmem-4 HA | $580 |
| Cloud SQL Replicas | 2x db-highmem-2 | $520 |
| Memorystore Redis | M3 tier (5GB) | $280 |
| Cloud Load Balancing | Standard tier | $20 |
| Cloud NAT | 2x NAT | $88 |
| Egress | 1TB | $120 |
| Cloud Logging | 50GB | $25 |
| Secret Manager | 10 secrets | $0.36 |
| Cloud KMS | 1 key | $0.06 |
| **Total (baseline)** | | **~$1,813/mo** |
| **Total (scaled up)** | | **~$4,353/mo** |

## Monitoring & Observability

### Metrics
- **API**: Request rate, latency (p50, p95, p99), error rate
- **Workers**: Queue depth, task processing time, task success/failure rate
- **Database**: Connections, CPU, memory, disk I/O, replication lag
- **Redis**: Memory usage, evictions, hit rate
- **Encryption**: Cache hit rate, KMS API calls, decryption failures

### Alarms
- API error rate > 5%
- API p99 latency > 2s
- Worker queue depth > 1000
- Database CPU > 80%
- Database connections > 90% of max
- Redis memory > 80%
- Encryption cache evictions > 100/min
- KMS API errors > 10/min

### Logs
- Structured JSON logs to CloudWatch / Cloud Logging
- Log retention: 30 days
- Audit logs (decryption): 1 year retention

## Disaster Recovery

### Backup Strategy
- **Database**: Automated daily backups (30 days retention)
- **Point-in-time recovery**: Last 35 days
- **Redis**: AOF persistence + daily snapshots (7 days)
- **Application state**: Stateless (no backups needed)

### Recovery Procedures

**Database Failure** (RTO: 5 minutes, RPO: 1 minute):
1. Automatic failover to standby (Multi-AZ)
2. Promote read replica if needed
3. Update DNS to point to new primary

**Redis Failure** (RTO: 10 minutes, RPO: 1 second):
1. Automatic failover to replica
2. Restore from AOF if needed
3. Workers will retry failed tasks

**Region Failure** (RTO: 1 hour, RPO: 5 minutes):
1. Deploy to secondary region using Pulumi
2. Restore database from latest backup
3. Update DNS to point to new region

## Security

### Network Security
- **VPC**: Private subnets for database, cache, workers
- **Security Groups**: Least privilege (only required ports)
- **NAT Gateway**: Outbound internet for workers (AWS API calls)
- **No public IPs**: Only ALB/Load Balancer has public IP

### Application Security
- **TLS**: ALB terminates TLS 1.3
- **Secrets**: All secrets in Secrets Manager (encrypted at rest)
- **KMS**: Envelope encryption with customer-managed keys
- **IAM Roles**: Service-specific roles with minimal permissions
- **Rate Limiting**: Enabled (100/min default, 10/min for configs)

### Compliance
- **Encryption at rest**: Database, Redis, S3, Secrets Manager
- **Encryption in transit**: TLS everywhere
- **Audit logs**: All decryption operations logged
- **Access logs**: ALB logs to S3

## Maintenance

### Updates
```bash
# Update infrastructure
pulumi up

# Update application (rolling deployment)
pulumi up --target cerebro-api-service

# Update database (blue/green deployment)
# 1. Create new RDS instance
# 2. Replicate data
# 3. Switch traffic
# 4. Decommission old instance
```

### Rollback
```bash
# Rollback to previous version
pulumi stack select prod
pulumi history  # List deployment history
pulumi cancel   # Cancel in-progress deployment
pulumi refresh  # Sync state
pulumi up --target urn:pulumi:...  # Deploy specific version
```

## Troubleshooting

### Common Issues

**Migrations failing**:
```bash
# Run migration task manually
aws ecs run-task --cluster cerebro-cluster --task-definition cerebro-migration

# Check logs
aws logs tail /ecs/cerebro-migration --follow
```

**Workers not processing tasks**:
```bash
# Check Redis connection
aws elasticache describe-cache-clusters --cache-cluster-id cerebro-redis

# Check worker logs
aws logs tail /ecs/cerebro-worker --follow

# Check queue depth
celery -A cerebro.tasks.celery_app inspect stats
```

**High latency**:
```bash
# Check database performance
aws rds describe-db-instances --db-instance-identifier cerebro-db

# Check read replica lag
aws cloudwatch get-metric-statistics --namespace AWS/RDS --metric-name ReplicaLag

# Scale up API servers
pulumi config set cerebro:apiMinInstances 5
pulumi up
```

## Next Steps

1. Review and customize `config/prod.yaml`
2. Set up DNS (Route 53 / Cloud DNS)
3. Configure SSL certificate (ACM / Certificate Manager)
4. Deploy monitoring dashboards (Grafana)
5. Set up alerting (PagerDuty / Opsgenie)
6. Run load tests
7. Perform security audit
8. Document runbooks

## Support

For issues or questions:
- GitHub: https://github.com/haasonsaas/cerebro/issues
- Docs: [Deployment Guide](../docs/developer-guide/DEPLOYMENT.md)