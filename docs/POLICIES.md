# Cerebro Security Policies

## Overview

Cerebro uses a Cedar-style policy engine to evaluate cloud assets against security best practices. Policies are defined as JSON files and organized by cloud provider.

## Policy Structure

### Basic Policy

```json
{
    "id": "unique-policy-identifier",
    "name": "Human Readable Name",
    "description": "Detailed description of what this policy checks",
    "effect": "forbid",
    "conditions": ["field != expected_value"],
    "severity": "critical",
    "tags": ["compliance-framework", "category", "resource-type"]
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier (kebab-case recommended) |
| `name` | string | Yes | Human-readable policy name |
| `description` | string | Yes | What the policy checks and why it matters |
| `effect` | string | Yes | `permit` or `forbid` |
| `conditions` | array | Yes | Condition expressions to evaluate |
| `severity` | string | Yes | `critical`, `high`, `medium`, `low` |
| `tags` | array | No | Tags for categorization and compliance mapping |
| `principal` | string | No | Principal pattern for access control |
| `action` | string | No | Action pattern for access control |
| `resource` | string | No | Resource pattern for access control |

### Severity Levels

| Level | Description | Example |
|-------|-------------|---------|
| `critical` | Immediate security risk, public exposure | Public S3 bucket, no encryption |
| `high` | Significant risk requiring prompt attention | No MFA, overly permissive IAM |
| `medium` | Security best practice violation | Missing logging, weak configs |
| `low` | Minor improvement opportunity | Naming conventions, tagging |

---

## Condition Syntax

### Equality Check
```json
"conditions": ["field == value"]
```
Matches when field equals value. Typically used with `effect: permit`.

### Inequality Check (Violation Detection)
```json
"conditions": ["field != expected_value"]
```
Flags violation when field doesn't match expected value. Used with `effect: forbid`.

### Multiple Conditions
```json
"conditions": [
    "encryption_enabled != true",
    "versioning_status != Enabled"
]
```
All conditions are evaluated. Any true condition triggers a finding.

### Boolean Fields
```json
"conditions": ["mfa_active != true"]
```

### String Fields
```json
"conditions": ["status != Enabled"]
```

### Null Checks
```json
"conditions": ["encryption_type == null"]
```

---

## Policy Organization

### Directory Structure

```
policies/
├── aws/
│   ├── s3/
│   │   ├── public-access.json
│   │   ├── encryption.json
│   │   └── versioning.json
│   ├── iam/
│   │   ├── mfa-required.json
│   │   ├── access-key-rotation.json
│   │   └── root-account.json
│   ├── ec2/
│   │   ├── public-ip.json
│   │   └── imdsv2.json
│   └── rds/
│       ├── encryption.json
│       └── public-access.json
├── gcp/
│   ├── storage/
│   │   └── public-access.json
│   ├── compute/
│   │   └── external-ip.json
│   └── iam/
│       └── service-account-keys.json
├── azure/
│   ├── storage/
│   │   └── https-only.json
│   └── compute/
│       └── managed-identity.json
└── kubernetes/
    ├── pods/
    │   ├── privileged-containers.json
    │   └── host-network.json
    └── rbac/
        └── cluster-admin.json
```

---

## AWS Policies

### S3 Bucket Policies

#### S3 Public Access Block
```json
{
    "id": "aws-s3-bucket-no-public-access",
    "name": "S3 Bucket Public Access Block",
    "description": "S3 buckets should have public access blocked at the bucket level",
    "effect": "forbid",
    "conditions": [
        "block_public_acls != true"
    ],
    "severity": "critical",
    "tags": ["cis-aws-2.1.5", "security", "s3", "data-protection"]
}
```

#### S3 Encryption at Rest
```json
{
    "id": "aws-s3-bucket-encryption",
    "name": "S3 Bucket Encryption",
    "description": "S3 buckets should have server-side encryption enabled",
    "effect": "forbid",
    "conditions": [
        "server_side_encryption_configuration == null"
    ],
    "severity": "high",
    "tags": ["cis-aws-2.1.1", "security", "s3", "encryption"]
}
```

#### S3 Versioning
```json
{
    "id": "aws-s3-bucket-versioning",
    "name": "S3 Bucket Versioning",
    "description": "S3 buckets should have versioning enabled for data protection",
    "effect": "forbid",
    "conditions": [
        "versioning_status != Enabled"
    ],
    "severity": "medium",
    "tags": ["security", "s3", "data-protection", "backup"]
}
```

#### S3 Logging
```json
{
    "id": "aws-s3-bucket-logging",
    "name": "S3 Bucket Access Logging",
    "description": "S3 buckets should have access logging enabled",
    "effect": "forbid",
    "conditions": [
        "logging_target_bucket == null"
    ],
    "severity": "medium",
    "tags": ["cis-aws-2.1.3", "security", "s3", "logging", "audit"]
}
```

### IAM Policies

#### IAM User MFA
```json
{
    "id": "aws-iam-user-mfa",
    "name": "IAM User MFA",
    "description": "IAM users should have MFA enabled",
    "effect": "forbid",
    "conditions": [
        "mfa_active != true"
    ],
    "severity": "critical",
    "tags": ["cis-aws-1.5", "security", "iam", "authentication"]
}
```

#### IAM Access Key Rotation
```json
{
    "id": "aws-iam-access-key-rotation",
    "name": "IAM Access Key Rotation",
    "description": "IAM access keys should be rotated within 90 days",
    "effect": "forbid",
    "conditions": [
        "access_key_1_last_rotated_days > 90"
    ],
    "severity": "high",
    "tags": ["cis-aws-1.12", "security", "iam", "credentials"]
}
```

#### IAM Root Account Usage
```json
{
    "id": "aws-iam-no-root-access-key",
    "name": "No Root Access Keys",
    "description": "Root account should not have access keys",
    "effect": "forbid",
    "conditions": [
        "user == root",
        "access_key_1_active == true"
    ],
    "severity": "critical",
    "tags": ["cis-aws-1.4", "security", "iam", "root"]
}
```

### EC2 Policies

#### EC2 Public IP
```json
{
    "id": "aws-ec2-no-public-ip",
    "name": "EC2 No Public IP",
    "description": "EC2 instances should not have public IP addresses",
    "effect": "forbid",
    "conditions": [
        "public_ip_address != null"
    ],
    "severity": "high",
    "tags": ["security", "ec2", "network"]
}
```

#### EC2 IMDSv2
```json
{
    "id": "aws-ec2-imdsv2",
    "name": "EC2 IMDSv2 Required",
    "description": "EC2 instances should require IMDSv2",
    "effect": "forbid",
    "conditions": [
        "metadata_options_http_tokens != required"
    ],
    "severity": "high",
    "tags": ["security", "ec2", "ssrf-protection"]
}
```

### RDS Policies

#### RDS Encryption
```json
{
    "id": "aws-rds-encryption",
    "name": "RDS Encryption at Rest",
    "description": "RDS instances should have encryption enabled",
    "effect": "forbid",
    "conditions": [
        "storage_encrypted != true"
    ],
    "severity": "critical",
    "tags": ["cis-aws-2.3.1", "security", "rds", "encryption"]
}
```

#### RDS Public Access
```json
{
    "id": "aws-rds-no-public-access",
    "name": "RDS No Public Access",
    "description": "RDS instances should not be publicly accessible",
    "effect": "forbid",
    "conditions": [
        "publicly_accessible == true"
    ],
    "severity": "critical",
    "tags": ["security", "rds", "network"]
}
```

---

## GCP Policies

### Cloud Storage

#### Storage Public Access
```json
{
    "id": "gcp-storage-no-public-access",
    "name": "Cloud Storage No Public Access",
    "description": "Cloud Storage buckets should not allow public access",
    "effect": "forbid",
    "conditions": [
        "iam_policy_public == true"
    ],
    "severity": "critical",
    "tags": ["cis-gcp-5.1", "security", "storage", "data-protection"]
}
```

#### Storage Uniform Access
```json
{
    "id": "gcp-storage-uniform-access",
    "name": "Cloud Storage Uniform Bucket-Level Access",
    "description": "Cloud Storage buckets should use uniform bucket-level access",
    "effect": "forbid",
    "conditions": [
        "uniform_bucket_level_access_enabled != true"
    ],
    "severity": "medium",
    "tags": ["security", "storage", "access-control"]
}
```

### Compute Engine

#### Compute External IP
```json
{
    "id": "gcp-compute-no-external-ip",
    "name": "Compute No External IP",
    "description": "Compute instances should not have external IP addresses",
    "effect": "forbid",
    "conditions": [
        "network_interfaces_access_configs != null"
    ],
    "severity": "high",
    "tags": ["security", "compute", "network"]
}
```

### IAM

#### Service Account Keys
```json
{
    "id": "gcp-iam-no-user-managed-keys",
    "name": "No User-Managed Service Account Keys",
    "description": "Service accounts should not have user-managed keys",
    "effect": "forbid",
    "conditions": [
        "keys_count > 0"
    ],
    "severity": "high",
    "tags": ["cis-gcp-1.4", "security", "iam", "credentials"]
}
```

---

## Azure Policies

### Storage Account

#### Storage HTTPS Only
```json
{
    "id": "azure-storage-https-only",
    "name": "Storage Account HTTPS Only",
    "description": "Storage accounts should only allow HTTPS traffic",
    "effect": "forbid",
    "conditions": [
        "enable_https_traffic_only != true"
    ],
    "severity": "high",
    "tags": ["cis-azure-3.1", "security", "storage", "encryption"]
}
```

#### Storage Public Access
```json
{
    "id": "azure-storage-no-public-access",
    "name": "Storage No Public Blob Access",
    "description": "Storage accounts should not allow public blob access",
    "effect": "forbid",
    "conditions": [
        "allow_blob_public_access == true"
    ],
    "severity": "critical",
    "tags": ["security", "storage", "data-protection"]
}
```

### Virtual Machines

#### VM Managed Identity
```json
{
    "id": "azure-vm-managed-identity",
    "name": "VM Managed Identity",
    "description": "Virtual machines should use managed identity",
    "effect": "forbid",
    "conditions": [
        "identity_type == null"
    ],
    "severity": "medium",
    "tags": ["security", "vm", "identity"]
}
```

---

## Kubernetes Policies

### Pod Security

#### Privileged Containers
```json
{
    "id": "k8s-pod-no-privileged",
    "name": "No Privileged Containers",
    "description": "Pods should not run privileged containers",
    "effect": "forbid",
    "conditions": [
        "spec_containers_security_context_privileged == true"
    ],
    "severity": "critical",
    "tags": ["cis-k8s-5.2.1", "security", "pods", "container-security"]
}
```

#### Host Network
```json
{
    "id": "k8s-pod-no-host-network",
    "name": "No Host Network",
    "description": "Pods should not use host network",
    "effect": "forbid",
    "conditions": [
        "spec_host_network == true"
    ],
    "severity": "high",
    "tags": ["cis-k8s-5.2.4", "security", "pods", "network"]
}
```

#### Host PID
```json
{
    "id": "k8s-pod-no-host-pid",
    "name": "No Host PID",
    "description": "Pods should not share host PID namespace",
    "effect": "forbid",
    "conditions": [
        "spec_host_pid == true"
    ],
    "severity": "high",
    "tags": ["cis-k8s-5.2.2", "security", "pods", "isolation"]
}
```

#### Root User
```json
{
    "id": "k8s-pod-no-root",
    "name": "No Root User",
    "description": "Pods should not run as root",
    "effect": "forbid",
    "conditions": [
        "spec_containers_security_context_run_as_non_root != true"
    ],
    "severity": "high",
    "tags": ["cis-k8s-5.2.6", "security", "pods", "user"]
}
```

### RBAC

#### Cluster Admin
```json
{
    "id": "k8s-rbac-no-wildcard",
    "name": "No Wildcard Permissions",
    "description": "RBAC roles should not use wildcard permissions",
    "effect": "forbid",
    "conditions": [
        "rules_verbs_contains == *",
        "rules_resources_contains == *"
    ],
    "severity": "critical",
    "tags": ["cis-k8s-5.1.1", "security", "rbac", "access-control"]
}
```

---

## Compliance Mapping

### CIS AWS Foundations Benchmark

| Control ID | Policy ID | Description |
|------------|-----------|-------------|
| 1.4 | aws-iam-no-root-access-key | No root access keys |
| 1.5 | aws-iam-user-mfa | MFA enabled for all users |
| 1.12 | aws-iam-access-key-rotation | Access key rotation |
| 2.1.1 | aws-s3-bucket-encryption | S3 encryption |
| 2.1.3 | aws-s3-bucket-logging | S3 access logging |
| 2.1.5 | aws-s3-bucket-no-public-access | S3 public access block |
| 2.3.1 | aws-rds-encryption | RDS encryption |

### SOC 2 Mapping

| Trust Criteria | Policy IDs |
|----------------|------------|
| CC6.1 - Logical Access | aws-iam-user-mfa, aws-iam-access-key-rotation |
| CC6.6 - Encryption | aws-s3-bucket-encryption, aws-rds-encryption |
| CC6.7 - Data Protection | aws-s3-bucket-no-public-access, aws-rds-no-public-access |
| CC7.2 - Monitoring | aws-s3-bucket-logging |

---

## Creating Custom Policies

### Step 1: Identify the Table

```bash
# List available tables
cerebro query "SHOW TABLES"

# Examine table schema
cerebro query "DESCRIBE TABLE aws_s3_buckets"

# Sample data
cerebro query "SELECT * FROM aws_s3_buckets LIMIT 5"
```

### Step 2: Identify the Condition

```bash
# Find field values
cerebro query "SELECT DISTINCT versioning_status FROM aws_s3_buckets"
```

### Step 3: Create Policy File

```json
{
    "id": "custom-check-name",
    "name": "Custom Check Name",
    "description": "Description of what this checks",
    "effect": "forbid",
    "conditions": ["field != expected"],
    "severity": "medium",
    "tags": ["custom", "category"]
}
```

### Step 4: Test Policy

```bash
# Validate syntax
cerebro policy validate

# Test against sample asset
cerebro policy test custom-check-name sample-asset.json
```

### Step 5: Deploy

Place the policy file in the appropriate `policies/` subdirectory and restart Cerebro.

---

## Best Practices

1. **Use descriptive IDs** - Include provider, service, and check name
2. **Write clear descriptions** - Explain why the check matters
3. **Map to compliance** - Use tags to link to compliance frameworks
4. **Start with high severity** - Address critical issues first
5. **Test before deploying** - Validate policies against real data
6. **Document exceptions** - Use suppression with justification
7. **Review regularly** - Update policies as best practices evolve
