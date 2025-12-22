# Cerebro Infrastructure - GCP Quick Start

## 🚀 Quick Deploy on GCP (5 minutes)

### Prerequisites

```bash
# 1. Install Pulumi
curl -fsSL https://get.pulumi.com | sh

# 2. Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL

# 3. Authenticate with GCP
gcloud auth login
gcloud auth application-default login
```

### Deployment Steps

```bash
# 1. Navigate to infra directory
cd infra

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Set GCP project
export GCP_PROJECT=your-project-id
gcloud config set project $GCP_PROJECT

# 4. Enable required APIs
gcloud services enable \
  compute.googleapis.com \
  sqladmin.googleapis.com \
  redis.googleapis.com \
  run.googleapis.com \
  cloudkms.googleapis.com \
  secretmanager.googleapis.com \
  monitoring.googleapis.com \
  cloudtasks.googleapis.com

# 5. Initialize Pulumi stack
pulumi login  # Or: pulumi login --local for local state
pulumi stack init gcp-prod

# 6. Configure required settings
pulumi config set gcp:project $GCP_PROJECT
pulumi config set gcp:region us-central1
pulumi config set cerebro:environment production
pulumi config set cerebro:domain cerebro.example.com
pulumi config set --secret cerebro:secretKey $(openssl rand -base64 32)
pulumi config set --secret cerebro:dbPassword $(openssl rand -base64 32)
pulumi config set --secret cerebro:redisPassword $(openssl rand -base64 24)

# 7. Use GCP main program
cp __main_gcp__.py __main__.py

# 8. Deploy!
pulumi up

# 9. Get outputs
pulumi stack output apiUrl
pulumi stack output loadBalancerIp
```

## 📦 What Gets Deployed

### Core Infrastructure
- ✅ **VPC** with private subnets and Cloud NAT
- ✅ **Cloud SQL PostgreSQL** (db-custom-4-16384, Regional HA, KMS encrypted)
- ✅ **Memorystore Redis** (5GB, Standard HA, encrypted)
- ✅ **Cloud Load Balancing** (Global HTTPS with Google-managed SSL)
- ✅ **Cloud Run** services:
  - API servers (2-20 instances, autoscaling)
  - Workers (1-50 instances, autoscaling)
- ✅ **Cloud Tasks** queues for Celery

### Security & Secrets
- ✅ **Cloud KMS** customer-managed encryption keys with auto-rotation
- ✅ **Secret Manager** for credentials with KMS encryption
- ✅ **VPC Service Controls** for data exfiltration prevention
- ✅ **Private VPC connections** for all services
- ✅ **TLS 1.3** on Load Balancer

### Monitoring
- ✅ **Cloud Monitoring** uptime checks and alerts
- ✅ **Custom dashboards** for metrics visualization
- ✅ **Email notifications** for critical alerts
- ✅ **Cloud Logging** for all services

## 🎯 Environment Sizing

### Small/Startup (< 10 users, <1000 findings/day)

```bash
pulumi config set cerebro:apiMinInstances 1
pulumi config set cerebro:apiMaxInstances 5
pulumi config set cerebro:workerMinInstances 1
pulumi config set cerebro:workerMaxInstances 10
pulumi config set cerebro:dbTier db-custom-2-8192  # 2 vCPU, 8GB RAM
pulumi config set cerebro:redisMemoryGb 1
pulumi config set cerebro:enableMultiAz false
# Est. cost: ~$300/month
```

### Medium (10-100 users, 1000-10000 findings/day)

```bash
pulumi config set cerebro:apiMinInstances 2
pulumi config set cerebro:apiMaxInstances 10
pulumi config set cerebro:workerMinInstances 2
pulumi config set cerebro:workerMaxInstances 20
pulumi config set cerebro:dbTier db-custom-4-16384  # 4 vCPU, 16GB RAM
pulumi config set cerebro:redisMemoryGb 5
pulumi config set cerebro:enableMultiAz true
# Est. cost: ~$1,000/month
```

### Large/Enterprise (100+ users, 10000+ findings/day)

```bash
pulumi config set cerebro:apiMinInstances 4
pulumi config set cerebro:apiMaxInstances 20
pulumi config set cerebro:workerMinInstances 4
pulumi config set cerebro:workerMaxInstances 50
pulumi config set cerebro:dbTier db-custom-8-32768  # 8 vCPU, 32GB RAM
pulumi config set cerebro:redisMemoryGb 10
pulumi config set cerebro:enableMultiAz true
pulumi config set cerebro:enableReadReplicas true
pulumi config set cerebro:readReplicaCount 2
# Est. cost: ~$2,200/month
```

## 🔧 Post-Deployment

### 1. Run Database Migrations

```bash
# Get database connection
DB_CONNECTION=$(pulumi stack output dbConnectionName)

# Run migration via Cloud Run job
gcloud run jobs create cerebro-migration \
  --image $CONTAINER_IMAGE \
  --command "alembic" \
  --args "upgrade,head" \
  --set-env-vars DATABASE_CONNECTION_NAME=$DB_CONNECTION \
  --set-cloudsql-instances $DB_CONNECTION

gcloud run jobs execute cerebro-migration
```

### 2. Configure DNS

```bash
# Get load balancer IP
LB_IP=$(pulumi stack output loadBalancerIp)

# Create A record in Cloud DNS
gcloud dns record-sets create cerebro.example.com \
  --zone=your-zone \
  --type=A \
  --ttl=300 \
  --rrdatas=$LB_IP

# Or use external DNS provider
# Create A record: cerebro.example.com -> $LB_IP
```

### 3. Create Admin User

```bash
# Get API service name
API_SERVICE=$(pulumi stack output apiServiceUrl | cut -d'/' -f3 | cut -d'.' -f1)

# Run command in Cloud Run
gcloud run services execute $API_SERVICE \
  --command "python -m cerebro.cli.main create-user \
    --username admin \
    --email admin@example.com \
    --password $(openssl rand -base64 16)"
```

### 4. Verify Health

```bash
# Check API health
curl https://cerebro.example.com/health

# Check Cloud SQL connection
gcloud sql connect $(pulumi stack output dbConnectionName | cut -d':' -f3)

# Check Redis
gcloud redis instances describe cerebro-production-redis --region=us-central1
```

## 📊 Monitoring

### Access Cloud Console

```bash
# Monitoring dashboard
open "https://console.cloud.google.com/monitoring/dashboards?project=$GCP_PROJECT"

# Cloud Run services
open "https://console.cloud.google.com/run?project=$GCP_PROJECT"

# Cloud SQL instances
open "https://console.cloud.google.com/sql/instances?project=$GCP_PROJECT"

# Logs Explorer
open "https://console.cloud.google.com/logs/query?project=$GCP_PROJECT"
```

### View Logs

```bash
# API logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=cerebro-production-api" --limit=50

# Worker logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=cerebro-production-worker" --limit=50

# Database logs
gcloud logging read "resource.type=cloudsql_database" --limit=50
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
# Build and push new image
docker build -t gcr.io/$GCP_PROJECT/cerebro:v2.0.0 .
docker push gcr.io/$GCP_PROJECT/cerebro:v2.0.0

# Update config
pulumi config set cerebro:containerImage gcr.io/$GCP_PROJECT/cerebro:v2.0.0

# Deploy (Cloud Run will handle rolling update)
pulumi up
```

### Rollback

```bash
# View deployment history
pulumi history

# Rollback to previous state
pulumi stack select gcp-prod
pulumi cancel  # If deployment is in progress
pulumi refresh
```

## 💰 Cost Optimization

### Dev/Staging Environment

```bash
# Use smaller instances for non-production
pulumi stack init gcp-staging
pulumi config set cerebro:enableMultiAz false
pulumi config set cerebro:enableReadReplicas false
pulumi config set cerebro:dbTier db-custom-1-3840
pulumi config set cerebro:apiMaxInstances 3
pulumi config set cerebro:workerMaxInstances 5
pulumi up

# Est. savings: ~60% vs production
```

### Use Committed Use Discounts

```bash
# Purchase 1-year or 3-year commitments for Cloud SQL and Compute
# Savings: up to 57% for 3-year commitments
gcloud compute commitments create cerebro-commitment \
  --plan=TWELVE_MONTH \
  --resources=vcpu=4,memory=16
```

## 🧹 Cleanup

### Destroy Everything

```bash
# ⚠️  WARNING: This will delete ALL resources including databases!

# Backup database first
gcloud sql backups create \
  --instance=$(pulumi stack output dbConnectionName | cut -d':' -f3)

# Destroy infrastructure
pulumi destroy

# Remove stack
pulumi stack rm gcp-prod
```

## 🆘 Troubleshooting

### Common Issues

**"Permission denied"**:
```bash
# Ensure all required APIs are enabled
gcloud services list --enabled

# Check IAM permissions
gcloud projects get-iam-policy $GCP_PROJECT
```

**"Cloud SQL connection failed"**:
```bash
# Check VPC peering
gcloud services vpc-peerings list --service=servicenetworking.googleapis.com

# Verify Cloud SQL proxy
gcloud sql connect [INSTANCE_NAME] --user=cerebro
```

**"Cloud Run service errors"**:
```bash
# Check service logs
gcloud run services logs read cerebro-production-api --limit=50

# Check IAM bindings
gcloud run services get-iam-policy cerebro-production-api
```

## 📚 Next Steps

1. Set up Cloud Build for CI/CD
2. Configure Binary Authorization for container signing
3. Enable VPC Service Controls for data perimeter
4. Set up Cloud Armor for DDoS protection
5. Configure Workload Identity for GKE (if migrating from Cloud Run)
6. Enable Cloud Audit Logs for compliance
7. Set up Forseti or Security Command Center

## 🔗 Resources

- [Full Documentation](README.md)
- [GCP Architecture Center](https://cloud.google.com/architecture)
- [Pulumi GCP Provider](https://www.pulumi.com/registry/packages/gcp/)
- [Cerebro GitHub](https://github.com/WriterInternal/cerebro)