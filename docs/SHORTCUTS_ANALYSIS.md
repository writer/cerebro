# Shortcuts and Gaps Analysis

**Generated:** 2026-01-13  
**Status:** Active investigation

---

## Critical Gaps Identified

### 1. ~~Limited Scan Tables~~ (FIXED)

Expanded `defaultScanTables()` to include 40+ tables covering IAM, S3, EC2, RDS, Lambda, ELB, KMS, CloudTrail, CloudWatch, GuardDuty, EKS, ECR, Secrets Manager, SNS, SQS, DynamoDB, Redshift, ElastiCache, OpenSearch, API Gateway, CloudFront, CodeBuild, and ECS.

---

### 2. Policy → Asset Table Mapping Missing

**Issue:** No explicit mapping between policies and the asset tables they require.

**Example:** Policy `aws-rds-encryption-enabled` needs `aws_rds_db_instances` table, but this isn't enforced.

**Impact:** Policies might evaluate against wrong tables or find no assets.

**Fix Needed:** Add table requirement metadata to policies or create mapping in code.

---

### 3. ~~Compliance Report Not Showing Asset Counts~~ (FIXED)

Enhanced `generateComplianceReport` to include:
- `FailCount` per control (number of findings)
- `total_findings` in response
- `data_warning` when asset data is stale

---

### 4. ~~Asset Data Freshness Not Enforced~~ (FIXED)

Added freshness check to `runScheduledScan()` - warns if asset data is >24h old before scanning.

---

### 5. ~~Missing Multi-Cloud Policy Coverage~~ (FIXED)

Added GCP and Azure tables to `defaultScanTables()`:
- GCP: compute_instances, firewalls, iam_service_accounts, storage_buckets, sql_instances, container_clusters
- Azure: virtual_machines, storage_accounts, sql_servers, network_security_groups, ad_users, ad_service_principals

---

### 6. Findings Store Not Persisted on Restart

**Location:** `internal/findings/store.go`

**Issue:** In-memory store loses all findings on restart unless Snowflake is connected.

**Impact:** Development/testing loses findings between runs.

---

### 7. No Policy Validation Against Available Tables

**Issue:** Policies can reference asset types that don't exist in Snowflake.

**Example:** If a sync run fails for `aws_lambda_functions`, policies for Lambda will find 0 assets silently.

---

## Medium Priority Gaps

### 8. Rate Limiting on Scan Endpoints

**Issue:** `/api/v1/findings/scan` can trigger expensive full scans with no rate limiting.

---

### 9. No Incremental Scanning

**Issue:** Every scan re-evaluates all assets. Should track last scan time per table and only scan new/modified assets.

---

### 10. Compliance Score Calculation

**Issue:** Score is just `passing / total * 100`. Doesn't weight controls by severity or importance.

---

## Resolved Shortcuts

- [x] Policy IDs in frameworks.go that don't exist (fixed: mapped to correct IDs)
- [x] Duplicate policy engine in legacy sync package (deleted)
- [x] Missing asset API endpoints (added)
- [x] Asset data health check - validates tables exist in Snowflake
1. **Expand default scan tables** to cover all security-relevant asset tables
- [x] Compliance report asset counts - now includes fail counts per control and data warning
- [x] Multi-cloud scan tables - added GCP and Azure to default scan
- [x] Asset data health check - validates tables exist in Snowflake

---

## Recommended Immediate Fixes

1. **Expand default scan tables** to cover all security-relevant asset tables
2. **Add freshness check** before scans
3. **Enhance compliance report** with asset counts and evidence
4. **Create policy→table mapping** for validation

