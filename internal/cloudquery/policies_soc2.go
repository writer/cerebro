package cloudquery

// RegisterSOC2Policies adds SOC 2 Trust Services Criteria compliance policies
func (pe *PolicyExecutor) RegisterSOC2Policies() {
	// CC6.1 - Logical and Physical Access Controls
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "soc2-cc6.1-mfa",
		Name:        "MFA for Console Access",
		Description: "The entity implements logical access security measures to protect against threats",
		Framework:   "soc2",
		CheckID:     "CC6.1",
		Provider:    "aws",
		Service:     "iam",
		Severity:    "high",
		SQL: `
SELECT
    'soc2' AS framework,
    'CC6.1' AS check_id,
    'IAM users with console access should have MFA enabled' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN 
        password_enabled = TRUE AND mfa_active = FALSE
    THEN 'fail' ELSE 'pass' END AS status
FROM aws_iam_credential_reports
WHERE user != '<root_account>'`,
		Tags:        []string{"iam", "mfa", "access-control", "soc2"},
		Remediation: "Enable MFA for all IAM users with console access.",
	})

	// CC6.1 - Access keys rotation
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "soc2-cc6.1-keys",
		Name:        "Access Key Rotation",
		Description: "Access keys should be rotated regularly",
		Framework:   "soc2",
		CheckID:     "CC6.1",
		Provider:    "aws",
		Service:     "iam",
		Severity:    "medium",
		SQL: `
SELECT
    'soc2' AS framework,
    'CC6.1' AS check_id,
    'IAM access keys should be rotated within 90 days' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN 
        access_key_1_active = TRUE 
        AND DATEDIFF(day, access_key_1_last_rotated, CURRENT_TIMESTAMP()) > 90
    THEN 'fail' ELSE 'pass' END AS status
FROM aws_iam_credential_reports
WHERE access_key_1_active = TRUE`,
		Tags:        []string{"iam", "access-keys", "rotation", "soc2"},
		Remediation: "Rotate IAM access keys at least every 90 days.",
	})

	// CC6.6 - Encryption in Transit
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "soc2-cc6.6-s3",
		Name:        "S3 Encryption in Transit",
		Description: "The entity implements controls to protect data in transit",
		Framework:   "soc2",
		CheckID:     "CC6.6",
		Provider:    "aws",
		Service:     "s3",
		Severity:    "high",
		SQL: `
SELECT
    'soc2' AS framework,
    'CC6.6' AS check_id,
    'S3 buckets should enforce SSL/TLS' AS title,
    b.account_id,
    b.arn AS resource_id,
    CASE WHEN bp.policy IS NOT NULL 
         AND bp.policy LIKE '%aws:SecureTransport%'
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_s3_buckets b
LEFT JOIN aws_s3_bucket_policies bp ON bp._cq_parent_id = b._cq_id`,
		Tags:        []string{"s3", "encryption", "transit", "soc2"},
		Remediation: "Add bucket policy requiring aws:SecureTransport condition.",
	})

	// CC6.7 - Encryption at Rest
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "soc2-cc6.7-ebs",
		Name:        "EBS Encryption at Rest",
		Description: "The entity restricts the transmission of confidential data at rest",
		Framework:   "soc2",
		CheckID:     "CC6.7",
		Provider:    "aws",
		Service:     "ec2",
		Severity:    "high",
		SQL: `
SELECT
    'soc2' AS framework,
    'CC6.7' AS check_id,
    'EBS volumes should be encrypted' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN encrypted = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_ec2_ebs_volumes`,
		Tags:        []string{"ebs", "encryption", "storage", "soc2"},
		Remediation: "Enable EBS encryption by default or encrypt individual volumes.",
	})

	// CC6.7 - RDS Encryption
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "soc2-cc6.7-rds",
		Name:        "RDS Encryption at Rest",
		Description: "RDS instances should be encrypted at rest",
		Framework:   "soc2",
		CheckID:     "CC6.7",
		Provider:    "aws",
		Service:     "rds",
		Severity:    "high",
		SQL: `
SELECT
    'soc2' AS framework,
    'CC6.7' AS check_id,
    'RDS instances should be encrypted' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN storage_encrypted = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_rds_instances`,
		Tags:        []string{"rds", "encryption", "storage", "soc2"},
		Remediation: "Enable encryption for RDS instances.",
	})

	// CC7.2 - Monitoring for Security Events
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "soc2-cc7.2-cloudtrail",
		Name:        "CloudTrail Logging",
		Description: "The entity monitors system components for anomalies",
		Framework:   "soc2",
		CheckID:     "CC7.2",
		Provider:    "aws",
		Service:     "cloudtrail",
		Severity:    "high",
		SQL: `
SELECT
    'soc2' AS framework,
    'CC7.2' AS check_id,
    'CloudTrail should be enabled with log file validation' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN 
        status:IsLogging = TRUE 
        AND log_file_validation_enabled = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_cloudtrail_trails
WHERE is_multi_region_trail = TRUE`,
		Tags:        []string{"cloudtrail", "logging", "monitoring", "soc2"},
		Remediation: "Enable CloudTrail with log file validation.",
	})

	// CC7.2 - GuardDuty
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "soc2-cc7.2-guardduty",
		Name:        "GuardDuty Enabled",
		Description: "GuardDuty should be enabled for threat detection",
		Framework:   "soc2",
		CheckID:     "CC7.2",
		Provider:    "aws",
		Service:     "guardduty",
		Severity:    "high",
		SQL: `
SELECT
    'soc2' AS framework,
    'CC7.2' AS check_id,
    'GuardDuty should be enabled' AS title,
    account_id,
    detector_id AS resource_id,
    CASE WHEN status = 'ENABLED'
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_guardduty_detectors`,
		Tags:        []string{"guardduty", "threat-detection", "monitoring", "soc2"},
		Remediation: "Enable GuardDuty in all regions.",
	})

	// CC7.3 - Incident Response
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "soc2-cc7.3-securityhub",
		Name:        "Security Hub Enabled",
		Description: "The entity evaluates and manages security events",
		Framework:   "soc2",
		CheckID:     "CC7.3",
		Provider:    "aws",
		Service:     "securityhub",
		Severity:    "medium",
		SQL: `
SELECT
    'soc2' AS framework,
    'CC7.3' AS check_id,
    'Security Hub should be enabled' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN hub_arn IS NOT NULL
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_securityhub_hubs`,
		Tags:        []string{"securityhub", "incident-response", "monitoring", "soc2"},
		Remediation: "Enable AWS Security Hub for centralized security findings.",
	})

	// CC8.1 - Change Management
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "soc2-cc8.1-config",
		Name:        "AWS Config Enabled",
		Description: "The entity authorizes, designs, develops, configures changes",
		Framework:   "soc2",
		CheckID:     "CC8.1",
		Provider:    "aws",
		Service:     "config",
		Severity:    "medium",
		SQL: `
SELECT DISTINCT
    'soc2' AS framework,
    'CC8.1' AS check_id,
    'AWS Config should be enabled for change tracking' AS title,
    recorder.account_id,
    recorder.account_id AS resource_id,
    CASE WHEN recorder.recording = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_config_configuration_recorders recorder`,
		Tags:        []string{"config", "change-management", "compliance", "soc2"},
		Remediation: "Enable AWS Config to track configuration changes.",
	})

	// A1.2 - Availability
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "soc2-a1.2-rds-multiaz",
		Name:        "RDS Multi-AZ",
		Description: "The entity authorizes processes, and implements controls for availability",
		Framework:   "soc2",
		CheckID:     "A1.2",
		Provider:    "aws",
		Service:     "rds",
		Severity:    "medium",
		SQL: `
SELECT
    'soc2' AS framework,
    'A1.2' AS check_id,
    'RDS instances should have Multi-AZ enabled' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN multi_az = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_rds_instances
WHERE db_instance_status = 'available'`,
		Tags:        []string{"rds", "availability", "multi-az", "soc2"},
		Remediation: "Enable Multi-AZ for RDS instances in production.",
	})

	// A1.2 - Backup
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "soc2-a1.2-backup",
		Name:        "RDS Automated Backups",
		Description: "Automated backups should be enabled for data recovery",
		Framework:   "soc2",
		CheckID:     "A1.2",
		Provider:    "aws",
		Service:     "rds",
		Severity:    "high",
		SQL: `
SELECT
    'soc2' AS framework,
    'A1.2' AS check_id,
    'RDS instances should have automated backups enabled' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN backup_retention_period > 0
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_rds_instances`,
		Tags:        []string{"rds", "backup", "recovery", "soc2"},
		Remediation: "Enable automated backups with appropriate retention period.",
	})
}
