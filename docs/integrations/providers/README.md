# Provider Setup Guide

## AWS

### Prerequisites
- AWS account with programmatic access
- IAM permissions for security services

### 1. Create IAM Policy

Create a custom IAM policy with read-only access to security-relevant services:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:GetBucket*",
        "s3:GetObject*",
        "s3:ListBucket*",
        "iam:Get*",
        "iam:List*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "guardduty:Get*",
        "guardduty:List*",
        "securityhub:Get*",
        "securityhub:List*",
        "config:Describe*",
        "config:Get*",
        "organizations:Describe*",
        "organizations:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

### 2. Create Service Account

```bash
# Create IAM user
aws iam create-user --user-name cerebro-collector

# Attach policy
aws iam attach-user-policy \
  --user-name cerebro-collector \
  --policy-arn arn:aws:iam::ACCOUNT:policy/CerebroSecurityReadOnly

# Create access keys
aws iam create-access-key --user-name cerebro-collector
```

### 3. Configure Environment

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"

# Verify access
aws sts get-caller-identity
```

### 4. Test Collection

```bash
# Test AWS provider
cerebro query "SELECT instance_id, state FROM aws_ec2_instance LIMIT 5"

# Full collection test
make cli-collect ORG="Test Org" PROVIDER=aws
```

## GitHub

### Prerequisites
- GitHub organization or personal account
- Admin access for comprehensive security scanning

### 1. Create Personal Access Token

Go to GitHub Settings → Developer settings → Personal access tokens

**Required Scopes:**
- `repo` - Repository access
- `admin:org` - Organization data
- `user` - User information
- `security_events` - Vulnerability alerts
- `admin:public_key` - Deploy keys

### 2. GitHub App (Recommended for Organizations)

Create a GitHub App for better rate limits and permissions:

```bash
# App permissions needed:
# - Repository: Read
# - Organization: Read
# - Members: Read
# - Security events: Read
# - Vulnerability alerts: Read
```

### 3. Configure Environment

```bash
# For Personal Access Token
export GITHUB_TOKEN="ghp_..."

# For GitHub App
export GITHUB_APP_ID="123456"
export GITHUB_APP_PRIVATE_KEY_PATH="/path/to/private-key.pem"
export GITHUB_APP_INSTALLATION_ID="12345678"
```

### 4. Test Collection

```bash
# Test GitHub provider
cerebro query "SELECT name, visibility FROM github_repository LIMIT 10"

# Test vulnerability scanning
cerebro query "SELECT repository, severity FROM github_vulnerability_alert WHERE severity = 'high'"

# Full collection test
make cli-collect ORG="Test Org" PROVIDER=github
```

### 5. Organization Setup

```bash
# Create organization in Cerebro
cerebro org create --name "My GitHub Org"

# Add GitHub account
curl -X POST http://localhost:8000/api/v1/accounts \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "org_id": "ORG_ID",
    "provider": "github", 
    "external_id": "my-github-org",
    "display_name": "My GitHub Organization"
  }'
```

## Google Cloud Platform

### Prerequisites
- GCP project with billing enabled
- Project owner or editor permissions

### 1. Enable Required APIs

```bash
gcloud services enable \
  compute.googleapis.com \
  storage-api.googleapis.com \
  iam.googleapis.com \
  cloudresourcemanager.googleapis.com \
  container.googleapis.com \
  dns.googleapis.com
```

### 2. Create Service Account

```bash
# Create service account
gcloud iam service-accounts create cerebro-collector \
  --description="Cerebro security data collector" \
  --display-name="Cerebro Collector"

# Grant required roles
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:cerebro-collector@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/viewer"

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:cerebro-collector@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/security.securityReviewer"

# Create and download key
gcloud iam service-accounts keys create cerebro-gcp-key.json \
  --iam-account=cerebro-collector@PROJECT_ID.iam.gserviceaccount.com
```

### 3. Configure Environment

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/cerebro-gcp-key.json"
export GOOGLE_CLOUD_PROJECT="your-project-id"

# Verify access
gcloud auth application-default print-access-token
```

### 4. Test Collection

```bash
# Test GCP provider  
cerebro query "SELECT name, status FROM gcp_compute_instance LIMIT 5"

# Test IAM data
cerebro query "SELECT name, email FROM gcp_iam_user WHERE deleted = false"

# Full collection test
make cli-collect ORG="Test Org" PROVIDER=gcp
```

## 🔐 Okta Setup

### Prerequisites
- Okta admin account
- Super Admin or Read-Only Admin permissions

### 1. Create API Token

1. Sign in to Okta Admin Console
2. Go to Security → API → Tokens
3. Click "Create Token"
4. Name: "Cerebro Security Collector"
5. Copy the token (shown only once)

### 2. Configure Environment

```bash
export OKTA_DOMAIN="your-domain.okta.com"
export OKTA_API_TOKEN="00..."
```

### 3. Test Collection

```bash
# Test Okta provider
cerebro query "SELECT username, status FROM okta_user WHERE status = 'ACTIVE' LIMIT 10"

# Test MFA status
cerebro query "SELECT username, mfa_enrolled FROM okta_user WHERE mfa_enrolled = false"

# Full collection test  
make cli-collect ORG="Test Org" PROVIDER=okta
```

## 📧 Google Workspace Setup

### Prerequisites
- Google Workspace admin account
- Super Admin privileges

### 1. Enable Admin SDK API

1. Go to Google Cloud Console
2. Enable Admin SDK API
3. Create OAuth 2.0 credentials or service account

### 2. Configure Service Account

```bash
# Create service account with domain-wide delegation
gcloud iam service-accounts create cerebro-workspace \
  --description="Cerebro Workspace collector" \
  --display-name="Cerebro Workspace"

# Enable domain-wide delegation in Google Admin Console
```

### 3. Configure Environment

```bash
export GOOGLE_WORKSPACE_DOMAIN="company.com"
export GOOGLE_WORKSPACE_ADMIN_EMAIL="admin@company.com"
export GOOGLE_WORKSPACE_CREDENTIALS_PATH="/path/to/workspace-key.json"
```

### 4. Test Collection

```bash
# Test Workspace provider
cerebro query "SELECT email, suspended FROM google_workspace_user LIMIT 10"

# Full collection test
make cli-collect ORG="Test Org" PROVIDER=google_workspace
```

## 🔧 Multi-Provider Configuration

### Environment File Setup

Create a comprehensive `.env` file:

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost/cerebro
REDIS_URL=redis://localhost:6379/0

# AWS
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1

# GitHub  
GITHUB_TOKEN=ghp_...

# GCP
GOOGLE_APPLICATION_CREDENTIALS=/path/to/gcp-key.json
GOOGLE_CLOUD_PROJECT=my-project

# Okta
OKTA_DOMAIN=mycompany.okta.com
OKTA_API_TOKEN=00...

# Google Workspace
GOOGLE_WORKSPACE_DOMAIN=company.com
GOOGLE_WORKSPACE_ADMIN_EMAIL=admin@company.com
GOOGLE_WORKSPACE_CREDENTIALS_PATH=/path/to/workspace-key.json

# Security
SECRET_KEY=your-256-bit-secret-here
```

### Test All Providers

```bash
# Test authentication for all providers
make providers-test

# Collect from all providers
make cli-collect ORG="My Company" PROVIDER="aws github gcp okta"
```

## 🚨 Security Best Practices

### Credential Management
- Store credentials in environment variables, not code
- Use least-privilege access principles
- Rotate credentials regularly
- Monitor credential usage

### Network Security
- Whitelist Cerebro IP addresses in provider firewalls
- Use VPC endpoints where available (AWS)
- Enable audit logging for all API access

### Access Control
- Create dedicated service accounts for Cerebro
- Avoid using personal accounts for automation
- Document all permissions granted
- Regular access reviews

## 📊 Monitoring & Troubleshooting

### Collection Status

```bash
# Check provider status
curl http://localhost:8000/api/v1/collectors/providers

# Monitor collection tasks
curl http://localhost:8000/api/v1/collectors/tasks/TASK_ID
```

### Common Issues

**AWS Permission Errors**
```bash
# Test specific permissions
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT:user/cerebro-collector \
  --action-names ec2:DescribeInstances
```

**GitHub Rate Limits**
```bash
# Check rate limit status
curl -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/rate_limit
```

**GCP Authentication Issues**
```bash
# Test service account
gcloud auth activate-service-account \
  --key-file=$GOOGLE_APPLICATION_CREDENTIALS

gcloud auth list
```

This guide ensures secure and reliable provider integration with Cerebro's security monitoring platform.
