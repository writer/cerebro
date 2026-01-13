package cloudquery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/writerinternal/cerebro/internal/snowflake"
)

// PolicyExecutor executes CloudQuery-style SQL policies against Snowflake
type PolicyExecutor struct {
	client   *snowflake.Client
	policies map[string]*SQLPolicy
	mu       sync.RWMutex
}

// SQLPolicy represents a CloudQuery-compatible SQL-based policy
type SQLPolicy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Framework   string            `json:"framework"` // cis_v3.0.0, pci_dss_v3.2.1, etc.
	CheckID     string            `json:"check_id"`
	Provider    string            `json:"provider"` // aws, gcp, azure, k8s
	Service     string            `json:"service"`  // iam, s3, ec2, etc.
	Severity    string            `json:"severity"`
	SQL         string            `json:"sql"`
	Tags        []string          `json:"tags"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references"`
	Metadata    map[string]string `json:"metadata"`
}

// PolicyResult represents the result of a policy check
type PolicyResult struct {
	Framework   string    `json:"framework"`
	CheckID     string    `json:"check_id"`
	Title       string    `json:"title"`
	AccountID   string    `json:"account_id"`
	ResourceID  string    `json:"resource_id"`
	Status      string    `json:"status"` // pass, fail
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// PolicySummary aggregates results by framework/check
type PolicySummary struct {
	Framework    string    `json:"framework"`
	CheckID      string    `json:"check_id"`
	Title        string    `json:"title"`
	TotalChecked int       `json:"total_checked"`
	Passed       int       `json:"passed"`
	Failed       int       `json:"failed"`
	PassRate     float64   `json:"pass_rate"`
	LastRun      time.Time `json:"last_run"`
}

// NewPolicyExecutor creates a new policy executor
func NewPolicyExecutor(client *snowflake.Client) *PolicyExecutor {
	return &PolicyExecutor{
		client:   client,
		policies: make(map[string]*SQLPolicy),
	}
}

// RegisterPolicy adds a SQL policy to the executor
func (pe *PolicyExecutor) RegisterPolicy(policy *SQLPolicy) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.policies[policy.ID] = policy
}

// RegisterBuiltinPolicies loads CloudQuery-compatible policies
func (pe *PolicyExecutor) RegisterBuiltinPolicies() {
	// CIS AWS 1.4 - Root user no access keys
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "cis-aws-1.4",
		Name:        "Root User No Access Keys",
		Description: "Ensure no root user access key exists",
		Framework:   "cis_v3.0.0",
		CheckID:     "1.4",
		Provider:    "aws",
		Service:     "iam",
		Severity:    "critical",
		SQL: `
SELECT
    'cis_v3.0.0' AS framework,
    '1.4' AS check_id,
    'Ensure no root user access key exists' AS title,
    account_id,
    '<root_account>' AS resource_id,
    CASE WHEN 
        account_access_keys_present > 0
    THEN 'fail' ELSE 'pass' END AS status
FROM aws_iam_credential_reports
WHERE user = '<root_account>'`,
		Tags:        []string{"iam", "root", "access-keys", "cis"},
		Remediation: "Delete root access keys via AWS CLI: aws iam delete-access-key --user-name root --access-key-id <key-id>",
	})

	// CIS AWS 1.5 - MFA enabled for root
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "cis-aws-1.5",
		Name:        "MFA Enabled for Root",
		Description: "Ensure MFA is enabled for the root user",
		Framework:   "cis_v3.0.0",
		CheckID:     "1.5",
		Provider:    "aws",
		Service:     "iam",
		Severity:    "critical",
		SQL: `
SELECT
    'cis_v3.0.0' AS framework,
    '1.5' AS check_id,
    'Ensure MFA is enabled for the root user' AS title,
    account_id,
    '<root_account>' AS resource_id,
    CASE WHEN 
        mfa_active = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_iam_credential_reports
WHERE user = '<root_account>'`,
		Tags:        []string{"iam", "root", "mfa", "cis"},
		Remediation: "Enable MFA for root user via AWS Console: IAM > Security credentials > Activate MFA",
	})

	// CIS AWS 1.16 - No star policies
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "cis-aws-1.16",
		Name:        "IAM No Star Policies",
		Description: "IAM policies should not allow full '*' administrative privileges",
		Framework:   "cis_v3.0.0",
		CheckID:     "1.16",
		Provider:    "aws",
		Service:     "iam",
		Severity:    "high",
		SQL: `
WITH policy_statements AS (
    SELECT
        p.id,
        p.arn,
        p.account_id,
        stmt.value AS statement
    FROM aws_iam_policies p,
    LATERAL FLATTEN(PARSE_JSON(p.document):Statement) stmt
    WHERE p.arn NOT LIKE 'arn:aws:iam::aws:policy%'
),
violations AS (
    SELECT
        id,
        COUNT(*) AS violations
    FROM policy_statements,
    LATERAL FLATTEN(
        CASE WHEN IS_ARRAY(statement:Resource) 
             THEN statement:Resource 
             ELSE ARRAY_CONSTRUCT(statement:Resource) END
    ) res,
    LATERAL FLATTEN(
        CASE WHEN IS_ARRAY(statement:Action) 
             THEN statement:Action 
             ELSE ARRAY_CONSTRUCT(statement:Action) END
    ) act
    WHERE statement:Effect = 'Allow'
      AND res.value = '*'
      AND (act.value = '*' OR act.value = '*:*')
    GROUP BY id
)
SELECT DISTINCT
    'cis_v3.0.0' AS framework,
    '1.16' AS check_id,
    'IAM policies should not allow full * administrative privileges' AS title,
    p.account_id,
    p.arn AS resource_id,
    CASE WHEN v.id IS NOT NULL AND v.violations > 0
    THEN 'fail' ELSE 'pass' END AS status
FROM aws_iam_policies p
LEFT JOIN violations v ON v.id = p.id
WHERE p.arn NOT LIKE 'arn:aws:iam::aws:policy%'`,
		Tags:        []string{"iam", "least-privilege", "cis"},
		Remediation: "Replace wildcard (*) permissions with specific actions and resources.",
	})

	// CIS AWS 2.1.1 - S3 deny HTTP requests
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "cis-aws-2.1.1",
		Name:        "S3 Deny HTTP Requests",
		Description: "Ensure S3 Bucket Policy is set to deny HTTP requests",
		Framework:   "cis_v3.0.0",
		CheckID:     "2.1.1",
		Provider:    "aws",
		Service:     "s3",
		Severity:    "medium",
		SQL: `
WITH bucket_policies AS (
    SELECT
        b.arn,
        b.account_id,
        b.name,
        bp.policy
    FROM aws_s3_buckets b
    LEFT JOIN aws_s3_bucket_policies bp ON bp._cq_parent_id = b._cq_id
),
ssl_enforcement AS (
    SELECT
        arn,
        CASE WHEN policy IS NULL THEN FALSE
        ELSE EXISTS (
            SELECT 1 FROM (
                SELECT stmt.value AS statement
                FROM TABLE(FLATTEN(PARSE_JSON(policy):Statement)) stmt
            ) s
            WHERE s.statement:Effect = 'Deny'
              AND s.statement:Condition:Bool:"aws:SecureTransport" = 'false'
        ) END AS has_ssl_enforcement
    FROM bucket_policies
)
SELECT
    'cis_v3.0.0' AS framework,
    '2.1.1' AS check_id,
    'Ensure S3 Bucket Policy is set to deny HTTP requests' AS title,
    bp.account_id,
    bp.arn AS resource_id,
    CASE WHEN se.has_ssl_enforcement = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM bucket_policies bp
LEFT JOIN ssl_enforcement se ON se.arn = bp.arn`,
		Tags:        []string{"s3", "encryption", "https", "cis"},
		Remediation: "Add bucket policy requiring aws:SecureTransport condition.",
	})

	// CIS AWS 2.1.4 - S3 public access blocks
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "cis-aws-2.1.4",
		Name:        "S3 Account Level Public Access Blocks",
		Description: "S3 Block Public Access setting should be enabled",
		Framework:   "cis_v3.0.0",
		CheckID:     "2.1.4",
		Provider:    "aws",
		Service:     "s3",
		Severity:    "high",
		SQL: `
SELECT
    'cis_v3.0.0' AS framework,
    '2.1.4' AS check_id,
    'S3 Block Public Access setting should be enabled' AS title,
    a.account_id,
    a.account_id AS resource_id,
    CASE WHEN
        s.config_exists IS DISTINCT FROM TRUE
        OR s.block_public_acls IS DISTINCT FROM TRUE
        OR s.block_public_policy IS DISTINCT FROM TRUE
        OR s.ignore_public_acls IS DISTINCT FROM TRUE
        OR s.restrict_public_buckets IS DISTINCT FROM TRUE
    THEN 'fail' ELSE 'pass' END AS status
FROM aws_iam_accounts a
LEFT JOIN aws_s3_accounts s ON a.account_id = s.account_id`,
		Tags:        []string{"s3", "public-access", "cis"},
		Remediation: "Enable S3 Block Public Access at account level via AWS Console or CLI.",
	})

	// CIS AWS 3.1 - CloudTrail enabled in all regions
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "cis-aws-3.1",
		Name:        "CloudTrail Enabled All Regions",
		Description: "Ensure CloudTrail is enabled in all regions",
		Framework:   "cis_v3.0.0",
		CheckID:     "3.1",
		Provider:    "aws",
		Service:     "cloudtrail",
		Severity:    "high",
		SQL: `
SELECT
    'cis_v3.0.0' AS framework,
    '3.1' AS check_id,
    'Ensure CloudTrail is enabled in all regions' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN 
        is_multi_region_trail = TRUE AND status:IsLogging = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_cloudtrail_trails
WHERE is_organization_trail = FALSE`,
		Tags:        []string{"cloudtrail", "logging", "cis"},
		Remediation: "Enable multi-region CloudTrail: aws cloudtrail create-trail --name <name> --is-multi-region-trail",
	})

	// CIS AWS 4.1 - VPC Flow Logs enabled
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "cis-aws-3.7",
		Name:        "VPC Flow Logs Enabled",
		Description: "Ensure VPC flow logging is enabled in all VPCs",
		Framework:   "cis_v3.0.0",
		CheckID:     "3.7",
		Provider:    "aws",
		Service:     "vpc",
		Severity:    "medium",
		SQL: `
WITH vpc_flow_logs AS (
    SELECT DISTINCT resource_id FROM aws_ec2_flow_logs
)
SELECT
    'cis_v3.0.0' AS framework,
    '3.7' AS check_id,
    'Ensure VPC flow logging is enabled in all VPCs' AS title,
    v.account_id,
    v.arn AS resource_id,
    CASE WHEN fl.resource_id IS NOT NULL
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_ec2_vpcs v
LEFT JOIN vpc_flow_logs fl ON fl.resource_id = v.id`,
		Tags:        []string{"vpc", "flow-logs", "logging", "cis"},
		Remediation: "Enable VPC Flow Logs: aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id>",
	})

	// CIS AWS 5.1 - Security groups no unrestricted SSH
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "cis-aws-5.2",
		Name:        "Security Group No Unrestricted SSH",
		Description: "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
		Framework:   "cis_v3.0.0",
		CheckID:     "5.2",
		Provider:    "aws",
		Service:     "ec2",
		Severity:    "high",
		SQL: `
SELECT
    'cis_v3.0.0' AS framework,
    '5.2' AS check_id,
    'Ensure no security groups allow ingress from 0.0.0.0/0 to port 22' AS title,
    sg.account_id,
    sg.arn AS resource_id,
    CASE WHEN EXISTS (
        SELECT 1 FROM aws_ec2_security_group_ip_permissions sgp
        WHERE sgp._cq_parent_id = sg._cq_id
          AND (sgp.ip_protocol = '-1' OR (sgp.from_port <= 22 AND sgp.to_port >= 22))
          AND EXISTS (
              SELECT 1 FROM aws_ec2_security_group_ip_ranges ipr
              WHERE ipr._cq_parent_id = sgp._cq_id
                AND ipr.cidr_ip = '0.0.0.0/0'
          )
    ) THEN 'fail' ELSE 'pass' END AS status
FROM aws_ec2_security_groups sg`,
		Tags:        []string{"security-groups", "ssh", "network", "cis"},
		Remediation: "Remove or restrict 0.0.0.0/0 ingress rules for port 22.",
	})

	// AWS RDS public access
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "cis-aws-2.3.3",
		Name:        "RDS No Public Access",
		Description: "RDS DB instances should prohibit public access",
		Framework:   "cis_v3.0.0",
		CheckID:     "2.3.3",
		Provider:    "aws",
		Service:     "rds",
		Severity:    "critical",
		SQL: `
SELECT
    'cis_v3.0.0' AS framework,
    '2.3.3' AS check_id,
    'RDS DB instances should prohibit public access' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN publicly_accessible = TRUE
    THEN 'fail' ELSE 'pass' END AS status
FROM aws_rds_instances`,
		Tags:        []string{"rds", "database", "public-access", "cis"},
		Remediation: "Modify RDS instance to disable public accessibility.",
	})

	// EBS encryption
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "cis-aws-2.2.1",
		Name:        "EBS Encryption Enabled",
		Description: "Ensure EBS volume encryption is enabled",
		Framework:   "cis_v3.0.0",
		CheckID:     "2.2.1",
		Provider:    "aws",
		Service:     "ec2",
		Severity:    "high",
		SQL: `
SELECT
    'cis_v3.0.0' AS framework,
    '2.2.1' AS check_id,
    'Ensure EBS volume encryption is enabled' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN encrypted = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_ec2_ebs_volumes`,
		Tags:        []string{"ebs", "encryption", "storage", "cis"},
		Remediation: "Enable EBS encryption by default or encrypt individual volumes.",
	})

	// KMS key rotation
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "cis-aws-3.6",
		Name:        "KMS Key Rotation Enabled",
		Description: "Ensure rotation for customer created CMKs is enabled",
		Framework:   "cis_v3.0.0",
		CheckID:     "3.6",
		Provider:    "aws",
		Service:     "kms",
		Severity:    "medium",
		SQL: `
SELECT
    'cis_v3.0.0' AS framework,
    '3.6' AS check_id,
    'Ensure rotation for customer created CMKs is enabled' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN key_rotation_enabled = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_kms_keys
WHERE key_manager = 'CUSTOMER'
  AND key_state = 'Enabled'`,
		Tags:        []string{"kms", "encryption", "key-rotation", "cis"},
		Remediation: "Enable key rotation: aws kms enable-key-rotation --key-id <key-id>",
	})
}

// ExecutePolicy runs a single policy and returns results
func (pe *PolicyExecutor) ExecutePolicy(ctx context.Context, policyID string) ([]PolicyResult, error) {
	pe.mu.RLock()
	policy, ok := pe.policies[policyID]
	pe.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}

	return pe.runSQL(ctx, policy.SQL)
}

// ExecuteFramework runs all policies for a framework
func (pe *PolicyExecutor) ExecuteFramework(ctx context.Context, framework string) ([]PolicyResult, error) {
	pe.mu.RLock()
	var policies []*SQLPolicy
	for _, p := range pe.policies {
		if p.Framework == framework {
			policies = append(policies, p)
		}
	}
	pe.mu.RUnlock()

	var allResults []PolicyResult
	for _, policy := range policies {
		results, err := pe.runSQL(ctx, policy.SQL)
		if err != nil {
			continue // Log but continue
		}
		allResults = append(allResults, results...)
	}

	return allResults, nil
}

// ExecuteAll runs all registered policies
func (pe *PolicyExecutor) ExecuteAll(ctx context.Context) ([]PolicyResult, error) {
	pe.mu.RLock()
	policies := make([]*SQLPolicy, 0, len(pe.policies))
	for _, p := range pe.policies {
		policies = append(policies, p)
	}
	pe.mu.RUnlock()

	var allResults []PolicyResult
	for _, policy := range policies {
		results, err := pe.runSQL(ctx, policy.SQL)
		if err != nil {
			continue
		}
		allResults = append(allResults, results...)
	}

	return allResults, nil
}

// GetSummary returns aggregated results by check
func (pe *PolicyExecutor) GetSummary(results []PolicyResult) []PolicySummary {
	summaryMap := make(map[string]*PolicySummary)

	for _, r := range results {
		key := fmt.Sprintf("%s:%s", r.Framework, r.CheckID)
		if _, ok := summaryMap[key]; !ok {
			summaryMap[key] = &PolicySummary{
				Framework: r.Framework,
				CheckID:   r.CheckID,
				Title:     r.Title,
				LastRun:   time.Now(),
			}
		}

		s := summaryMap[key]
		s.TotalChecked++
		if r.Status == "pass" {
			s.Passed++
		} else {
			s.Failed++
		}
	}

	var summaries []PolicySummary
	for _, s := range summaryMap {
		if s.TotalChecked > 0 {
			s.PassRate = float64(s.Passed) / float64(s.TotalChecked) * 100
		}
		summaries = append(summaries, *s)
	}

	return summaries
}

// ListPolicies returns all registered policies
func (pe *PolicyExecutor) ListPolicies() []*SQLPolicy {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	policies := make([]*SQLPolicy, 0, len(pe.policies))
	for _, p := range pe.policies {
		policies = append(policies, p)
	}
	return policies
}

// ListFrameworks returns unique frameworks
func (pe *PolicyExecutor) ListFrameworks() []string {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	frameworks := make(map[string]bool)
	for _, p := range pe.policies {
		frameworks[p.Framework] = true
	}

	result := make([]string, 0, len(frameworks))
	for f := range frameworks {
		result = append(result, f)
	}
	return result
}

func (pe *PolicyExecutor) runSQL(ctx context.Context, query string) ([]PolicyResult, error) {
	rows, err := pe.client.DB().QueryContext(ctx, strings.TrimSpace(query))
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var results []PolicyResult
	for rows.Next() {
		var r PolicyResult
		if err := rows.Scan(&r.Framework, &r.CheckID, &r.Title, &r.AccountID, &r.ResourceID, &r.Status); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		r.EvaluatedAt = time.Now()
		results = append(results, r)
	}

	return results, rows.Err()
}

// SaveResults persists policy results to Snowflake
func (pe *PolicyExecutor) SaveResults(ctx context.Context, results []PolicyResult) error {
	if len(results) == 0 {
		return nil
	}

	tx, err := pe.client.DB().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO policy_results (framework, check_id, title, account_id, resource_id, status, evaluated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range results {
		if _, err := stmt.ExecContext(ctx, r.Framework, r.CheckID, r.Title, r.AccountID, r.ResourceID, r.Status, r.EvaluatedAt); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ResultsToJSON converts results to JSON for API responses
func ResultsToJSON(results []PolicyResult) ([]byte, error) {
	return json.Marshal(results)
}

// SummaryToJSON converts summary to JSON for API responses
func SummaryToJSON(summary []PolicySummary) ([]byte, error) {
	return json.Marshal(summary)
}

// Helper to ensure table exists
func (pe *PolicyExecutor) EnsureResultsTable(ctx context.Context) error {
	_, err := pe.client.DB().ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS policy_results (
			id VARCHAR DEFAULT UUID_STRING(),
			framework VARCHAR,
			check_id VARCHAR,
			title VARCHAR,
			account_id VARCHAR,
			resource_id VARCHAR,
			status VARCHAR,
			evaluated_at TIMESTAMP_NTZ,
			_cq_sync_time TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
			PRIMARY KEY (id)
		)
	`)
	return err
}
