# Cerebro Infrastructure - Quick Start

## 🚀 Quick Deploy (5 minutes)

### AWS Deployment

```bash
# 1. Install Pulumi
curl -fsSL https://get.pulumi.com | sh

# 2. Navigate to infra directory
cd infra

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Configure AWS credentials
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
export AWS_REGION=us-east-1

# 5. Initialize Pulumi stack
pulumi login  # Or: pulumi login --local for local state
pulumi stack init prod

# 6. Configure required settings
pulumi config set aws:region us-east-1
pulumi config set cerebro:environment production
pulumi config set cerebro:domain cerebro.example.com
pulumi config set --secret cerebro:secretKey $(openssl rand -base64 32)
pulumi config set --secret cerebro:dbPassword $(openssl rand -base64 32)
pulumi config set --secret cerebro:redisPassword $(openssl rand -base64 24)

# 7. Deploy!
pulumi up

# 8. Get outputs
pulumi stack output apiUrl
pulumi stack output dbEndpoint
```

## 📦 What Gets Deployed

### Core Infrastructure
- ✅ **VPC** with public/private subnets across 2 AZs
- ✅ **RDS PostgreSQL** (db.r6g.xlarge, Multi-AZ, encrypted)
- ✅ **ElastiCache Redis** (cache.r6g.large, cluster mode, encrypted)
- ✅ **Application Load Balancer** (HTTPS with ACM certificate)
- ✅ **ECS Fargate** services:
  - API servers (2-20 instances, autoscaling)
  - Celery workers (2-50 instances, autoscaling)
  - Celery Beat (1 instance, scheduler)
  - Flower (1 instance, monitoring UI)

### Security & Secrets
- ✅ **KMS** customer-managed encryption key
- ✅ **Secrets Manager** for credentials
- ✅ **Security Groups** (least privilege)
- ✅ **NAT Gateways** for private subnet internet access
- ✅ **TLS 1.3** on ALB

### Monitoring
- ✅ **CloudWatch** logs and metrics
- ✅ **Alarms** for critical thresholds
- ✅ **X-Ray** tracing (optional)

## 🎯 Production Configuration

### Recommended Settings

**Small/Startup** (< 10 users, <1000 findings/day):
```bash
pulumi config set cerebro:apiMinInstances 2
pulumi config set cerebro:apiMaxInstances 5
pulumi config set cerebro:workerMinInstances 2
pulumi config set cerebro:workerMaxInstances 10
pulumi config set cerebro:dbInstanceClass db.t4g.large
pulumi config set cerebro:redisNodeType cache.t4g.micro
# Est. cost: ~$400/month
```

**Medium** (10-100 users, 1000-10000 findings/day):
```bash
pulumi config set cerebro:apiMinInstances 2
pulumi config set cerebro:apiMaxInstances 10
pulumi config set cerebro:workerMinInstances 2
pulumi config set cerebro:workerMaxInstances 20
pulumi config set cerebro:dbInstanceClass db.r6g.large
pulumi config set cerebro:redisNodeType cache.r6g.large
# Est. cost: ~$1,200/month
```

**Large/Enterprise** (100+ users, 10000+ findings/day):
```bash
pulumi config set cerebro:apiMinInstances 4
pulumi config set cerebro:apiMaxInstances 20
pulumi config set cerebro:workerMinInstances 4
pulumi config set cerebro:workerMaxInstances 50
pulumi config set cerebro:dbInstanceClass db.r6g.xlarge
pulumi config set cerebro:redisNodeType cache.r6g.large
pulumi config set cerebro:enableReadReplicas true
pulumi config set cerebro:readReplicaCount 2
# Est. cost: ~$2,500/month
```

## 🔧 Post-Deployment

### 1. Run Database Migrations

```bash
# Get database endpoint
DB_ENDPOINT=$(pulumi stack output dbEndpoint)

# SSH to bastion or use AWS Systems Manager
aws ecs run-task \
  --cluster cerebro-prod-cluster \
  --task-definition cerebro-migration \
  --launch-type FARGATE

# Or manually:
export DATABASE_URL="postgresql://cerebro:PASSWORD@$DB_ENDPOINT/cerebro"
alembic upgrade head
```

### 2. Configure DNS

```bash
# Get ALB DNS name
ALB_DNS=$(pulumi stack output alb_dns_name)

# Create CNAME record:
# cerebro.example.com -> $ALB_DNS

# Or use Route 53 alias
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890 \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "cerebro.example.com",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "...",
          "DNSName": "'"$ALB_DNS"'",
          "EvaluateTargetHealth": true
        }
      }
    }]
  }'
```

### 3. Create Admin User

```bash
# Connect to API container
aws ecs execute-command \
  --cluster cerebro-prod-cluster \
  --task TASK_ID \
  --container cerebro-api \
  --command "/bin/bash" \
  --interactive

# Inside container:
python -m cerebro.cli.main create-user \
  --username admin \
  --email admin@example.com \
  --password "$(openssl rand -base64 16)"
```

### 4. Verify Health

```bash
# Check API health
curl https://cerebro.example.com/health

# Check encryption service
curl https://cerebro.example.com/health/encryption

# Check Celery
curl https://cerebro.example.com/health/celery
```

## 📊 Monitoring

### Access Flower (Celery Monitoring)

```bash
FLOWER_URL=$(pulumi stack output flower_url)
echo "Flower UI: $FLOWER_URL"

# Open in browser (requires VPN or security group update)
```

### CloudWatch Dashboards

```bash
# View in AWS Console
open "https://console.aws.amazon.com/cloudwatch/home?region=$AWS_REGION#dashboards:"
```

### View Logs

```bash
# API logs
aws logs tail /ecs/cerebro-api --follow

# Worker logs
aws logs tail /ecs/cerebro-worker --follow

# Beat logs
aws logs tail /ecs/cerebro-beat --follow
```

## 🔄 Updates & Rollbacks

### Update Infrastructure

```bash
# Update configuration
pulumi config set cerebro:apiMaxInstances 30

# Preview changes
pulumi preview

# Apply changes
pulumi up
```

### Update Application

```bash
# Build new image
docker build -t cerebro:v2.0.0 .

# Push to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin $ECR_REPO
docker tag cerebro:v2.0.0 $ECR_REPO:v2.0.0
docker push $ECR_REPO:v2.0.0

# Update task definition (Pulumi will handle rolling update)
pulumi up
```

### Rollback

```bash
# View deployment history
pulumi history

# Rollback to previous state
pulumi stack select prod
pulumi cancel  # If deployment is in progress
pulumi refresh
pulumi up --target urn:pulumi:prod::cerebro::...  # Specific version
```

## 💰 Cost Optimization

### Dev/Staging Environment

```bash
# Use smaller instances for non-production
pulumi stack init staging
pulumi config set cerebro:enableMultiAz false
pulumi config set cerebro:enableReadReplicas false
pulumi config set cerebro:dbInstanceClass db.t4g.medium
pulumi config set cerebro:apiMaxInstances 3
pulumi config set cerebro:workerMaxInstances 5
pulumi up

# Est. savings: ~70% vs production
```

### Scheduled Scaling

```bash
# Scale down during off-hours (9 PM - 6 AM)
aws application-autoscaling put-scheduled-action \
  --service-namespace ecs \
  --scalable-dimension ecs:service:DesiredCount \
  --resource-id service/cerebro-prod/api \
  --scheduled-action-name scale-down-evening \
  --schedule "cron(0 21 * * ? *)" \
  --scalable-target-action MinCapacity=1,MaxCapacity=2
```

## 🧹 Cleanup

### Destroy Everything

```bash
# ⚠️  WARNING: This will delete ALL resources including databases!

# Backup database first
aws rds create-db-snapshot \
  --db-instance-identifier cerebro-prod \
  --db-snapshot-identifier cerebro-final-backup-$(date +%Y%m%d)

# Destroy infrastructure
pulumi destroy

# Remove stack
pulumi stack rm prod
```

## 🆘 Troubleshooting

### Common Issues

**"No space left on device"**:
```bash
# Increase ECS task storage
# Update task definition ephemeral_storage to 50GB
```

**"Connection timeout"**:
```bash
# Check security groups
aws ec2 describe-security-groups --group-ids sg-xxx

# Check NAT gateway
aws ec2 describe-nat-gateways
```

**"Rate limiting errors"**:
```bash
# Increase rate limits
pulumi config set cerebro:apiMaxInstances 10
pulumi up
```

## 📚 Next Steps

1. Set up CI/CD pipeline (GitHub Actions / GitLab CI)
2. Configure custom domain and SSL certificate
3. Set up monitoring dashboards (Grafana)
4. Configure alerting (PagerDuty / Opsgenie)
5. Run load tests (Locust / k6)
6. Security audit (AWS Security Hub)
7. Compliance checks (CIS benchmarks)

## 🔗 Resources

- [Full Documentation](README.md)
- [AWS Architecture](https://docs.aws.amazon.com/architecture/)
- [Pulumi Docs](https://www.pulumi.com/docs/)
- [Cerebro GitHub](https://github.com/WriterInternal/cerebro)