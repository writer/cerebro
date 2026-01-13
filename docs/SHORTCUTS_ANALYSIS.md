# Shortcuts and Gaps Analysis

**Generated:** 2026-01-13  
**Status:** Active investigation

---

## Critical Gaps Identified

### 1. ~~Limited Scan Tables~~ (FIXED)

Expanded `defaultScanTables()` to include 40+ tables covering IAM, S3, EC2, RDS, Lambda, ELB, KMS, CloudTrail, CloudWatch, GuardDuty, EKS, ECR, Secrets Manager, SNS, SQS, DynamoDB, Redshift, ElastiCache, OpenSearch, API Gateway, CloudFront, CodeBuild, and ECS.

---

### 2. Policy → CloudQuery Table Mapping Missing

**Issue:** No explicit mapping between policies and the CloudQuery tables they require.

**Example:** Policy `aws-rds-encryption-enabled` needs `aws_rds_db_instances` table, but this isn't enforced.

**Impact:** Policies might evaluate against wrong tables or find no assets.

**Fix Needed:** Add table requirement metadata to policies or create mapping in code.

---

### 3. ~~Compliance Report Not Showing Asset Counts~~ (FIXED)

Enhanced `generateComplianceReport` to include:
- `FailCount` per control (number of findings)
- `total_findings` in response
- `data_warning` when CloudQuery data is stale

---

### 4. ~~CloudQuery Data Freshness Not Enforced~~ (FIXED)

Added freshness check to `runScheduledScan()` - warns if CloudQuery data is >24h old before scanning.

---

### 5. Missing Multi-Cloud Policy Coverage

**Issue:** Compliance frameworks reference GCP/Azure policies that map to the correct IDs, but:
- GCP/Azure tables may not be populated
- No scan schedule for GCP/Azure tables

---

### 6. Findings Store Not Persisted on Restart

**Location:** `internal/findings/store.go`

**Issue:** In-memory store loses all findings on restart unless Snowflake is connected.

**Impact:** Development/testing loses findings between runs.

---

### 7. No Policy Validation Against Available Tables

**Issue:** Policies can reference asset types that don't exist in Snowflake.

**Example:** If CloudQuery sync fails for `aws_lambda_functions`, policies for Lambda will find 0 assets silently.

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
- [x] Duplicate policy engine in cloudquery package (deleted)
- [x] Missing CloudQuery API endpoints (added)
- [x] Limited scan tables - expanded to 40+ tables covering all AWS services
- [x] Data freshness check - added to runScheduledScan()
- [x] Compliance report asset counts - now includes fail counts per control and data warning

---

## Recommended Immediate Fixes

1. **Expand default scan tables** to cover all security-relevant CloudQuery tables
2. **Add freshness check** before scans
3. **Enhance compliance report** with asset counts and evidence
4. **Create policy→table mapping** for validation

