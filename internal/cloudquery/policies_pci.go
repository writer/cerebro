package cloudquery

// RegisterPCIDSSPolicies adds PCI-DSS v3.2.1 compliance policies
func (pe *PolicyExecutor) RegisterPCIDSSPolicies() {
	// PCI-DSS 1.2.1 - Restrict inbound/outbound traffic
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "pci-dss-1.2.1",
		Name:        "Restrict Inbound/Outbound Traffic",
		Description: "Restrict inbound and outbound traffic to that which is necessary",
		Framework:   "pci_dss_v3.2.1",
		CheckID:     "1.2.1",
		Provider:    "aws",
		Service:     "ec2",
		Severity:    "high",
		SQL: `
SELECT
    'pci_dss_v3.2.1' AS framework,
    '1.2.1' AS check_id,
    'Security groups should restrict inbound traffic' AS title,
    sg.account_id,
    sg.arn AS resource_id,
    CASE WHEN EXISTS (
        SELECT 1 FROM aws_ec2_security_group_ip_permissions sgp
        WHERE sgp._cq_parent_id = sg._cq_id
          AND sgp.ip_protocol = '-1'
          AND EXISTS (
              SELECT 1 FROM aws_ec2_security_group_ip_ranges ipr
              WHERE ipr._cq_parent_id = sgp._cq_id
                AND ipr.cidr_ip = '0.0.0.0/0'
          )
    ) THEN 'fail' ELSE 'pass' END AS status
FROM aws_ec2_security_groups sg`,
		Tags:        []string{"network", "firewall", "pci-dss"},
		Remediation: "Review and restrict security group rules to only necessary traffic.",
	})

	// PCI-DSS 2.2 - Secure system configurations
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "pci-dss-2.2",
		Name:        "Secure System Configurations",
		Description: "Develop configuration standards for all system components",
		Framework:   "pci_dss_v3.2.1",
		CheckID:     "2.2",
		Provider:    "aws",
		Service:     "ec2",
		Severity:    "medium",
		SQL: `
SELECT
    'pci_dss_v3.2.1' AS framework,
    '2.2' AS check_id,
    'EC2 instances should use IMDSv2' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN metadata_options:HttpTokens = 'required'
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_ec2_instances
WHERE state:Name = 'running'`,
		Tags:        []string{"ec2", "imds", "configuration", "pci-dss"},
		Remediation: "Configure EC2 instances to require IMDSv2.",
	})

	// PCI-DSS 3.4 - Render PAN unreadable
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "pci-dss-3.4",
		Name:        "Render PAN Unreadable",
		Description: "Render PAN unreadable anywhere it is stored",
		Framework:   "pci_dss_v3.2.1",
		CheckID:     "3.4",
		Provider:    "aws",
		Service:     "rds",
		Severity:    "critical",
		SQL: `
SELECT
    'pci_dss_v3.2.1' AS framework,
    '3.4' AS check_id,
    'RDS instances should be encrypted' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN storage_encrypted = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_rds_instances`,
		Tags:        []string{"rds", "encryption", "storage", "pci-dss"},
		Remediation: "Enable encryption for RDS instances storing cardholder data.",
	})

	// PCI-DSS 3.5 - Protect keys used to secure cardholder data
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "pci-dss-3.5",
		Name:        "Protect Encryption Keys",
		Description: "Document and implement procedures to protect keys",
		Framework:   "pci_dss_v3.2.1",
		CheckID:     "3.5",
		Provider:    "aws",
		Service:     "kms",
		Severity:    "high",
		SQL: `
SELECT
    'pci_dss_v3.2.1' AS framework,
    '3.5' AS check_id,
    'KMS keys should have rotation enabled' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN key_rotation_enabled = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_kms_keys
WHERE key_manager = 'CUSTOMER'
  AND key_state = 'Enabled'`,
		Tags:        []string{"kms", "encryption", "key-rotation", "pci-dss"},
		Remediation: "Enable automatic key rotation for customer managed KMS keys.",
	})

	// PCI-DSS 4.1 - Use strong cryptography
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "pci-dss-4.1",
		Name:        "Use Strong Cryptography",
		Description: "Use strong cryptography and security protocols",
		Framework:   "pci_dss_v3.2.1",
		CheckID:     "4.1",
		Provider:    "aws",
		Service:     "elb",
		Severity:    "high",
		SQL: `
SELECT
    'pci_dss_v3.2.1' AS framework,
    '4.1' AS check_id,
    'ELB listeners should use HTTPS/TLS' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN listener_protocol IN ('HTTPS', 'TLS', 'SSL')
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_elbv2_listeners`,
		Tags:        []string{"elb", "encryption", "tls", "pci-dss"},
		Remediation: "Configure load balancers to use HTTPS/TLS listeners.",
	})

	// PCI-DSS 6.2 - Ensure latest security patches
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "pci-dss-6.2",
		Name:        "Install Security Patches",
		Description: "Ensure all system components have latest security patches",
		Framework:   "pci_dss_v3.2.1",
		CheckID:     "6.2",
		Provider:    "aws",
		Service:     "ssm",
		Severity:    "high",
		SQL: `
SELECT
    'pci_dss_v3.2.1' AS framework,
    '6.2' AS check_id,
    'SSM managed instances should be compliant' AS title,
    account_id,
    instance_id AS resource_id,
    CASE WHEN compliance_type = 'Patch' AND status = 'COMPLIANT'
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_ssm_instance_compliance_items
WHERE compliance_type = 'Patch'`,
		Tags:        []string{"ssm", "patching", "compliance", "pci-dss"},
		Remediation: "Apply missing security patches using AWS Systems Manager.",
	})

	// PCI-DSS 7.1 - Limit access to system components
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "pci-dss-7.1",
		Name:        "Limit Access to Cardholder Data",
		Description: "Limit access to system components and cardholder data",
		Framework:   "pci_dss_v3.2.1",
		CheckID:     "7.1",
		Provider:    "aws",
		Service:     "iam",
		Severity:    "high",
		SQL: `
SELECT
    'pci_dss_v3.2.1' AS framework,
    '7.1' AS check_id,
    'IAM users should not have inline policies' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN user_inline_policies IS NULL OR ARRAY_SIZE(user_inline_policies) = 0
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_iam_users`,
		Tags:        []string{"iam", "access-control", "least-privilege", "pci-dss"},
		Remediation: "Remove inline policies from IAM users and use managed policies with groups.",
	})

	// PCI-DSS 8.2.4 - Change user passwords at least every 90 days
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "pci-dss-8.2.4",
		Name:        "Password Expiration",
		Description: "Change user passwords at least once every 90 days",
		Framework:   "pci_dss_v3.2.1",
		CheckID:     "8.2.4",
		Provider:    "aws",
		Service:     "iam",
		Severity:    "medium",
		SQL: `
SELECT
    'pci_dss_v3.2.1' AS framework,
    '8.2.4' AS check_id,
    'IAM users should rotate credentials within 90 days' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN 
        password_last_changed IS NULL 
        OR DATEDIFF(day, password_last_changed, CURRENT_TIMESTAMP()) > 90
    THEN 'fail' ELSE 'pass' END AS status
FROM aws_iam_credential_reports
WHERE password_enabled = TRUE`,
		Tags:        []string{"iam", "passwords", "rotation", "pci-dss"},
		Remediation: "Enforce password rotation policy requiring changes every 90 days.",
	})

	// PCI-DSS 10.1 - Implement audit trails
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "pci-dss-10.1",
		Name:        "Implement Audit Trails",
		Description: "Implement audit trails to link all access to individual user",
		Framework:   "pci_dss_v3.2.1",
		CheckID:     "10.1",
		Provider:    "aws",
		Service:     "cloudtrail",
		Severity:    "high",
		SQL: `
SELECT
    'pci_dss_v3.2.1' AS framework,
    '10.1' AS check_id,
    'CloudTrail should be enabled in all regions' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN 
        is_multi_region_trail = TRUE 
        AND status:IsLogging = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_cloudtrail_trails
WHERE is_organization_trail = FALSE`,
		Tags:        []string{"cloudtrail", "logging", "audit", "pci-dss"},
		Remediation: "Enable CloudTrail in all regions with multi-region trails.",
	})

	// PCI-DSS 10.5.4 - Write logs for external-facing technologies
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "pci-dss-10.5.4",
		Name:        "Centralized Log Management",
		Description: "Write logs for external-facing technologies to centralized location",
		Framework:   "pci_dss_v3.2.1",
		CheckID:     "10.5.4",
		Provider:    "aws",
		Service:     "s3",
		Severity:    "medium",
		SQL: `
SELECT
    'pci_dss_v3.2.1' AS framework,
    '10.5.4' AS check_id,
    'S3 buckets should have access logging enabled' AS title,
    account_id,
    arn AS resource_id,
    CASE WHEN logging_target_bucket IS NOT NULL
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_s3_buckets`,
		Tags:        []string{"s3", "logging", "audit", "pci-dss"},
		Remediation: "Enable server access logging for S3 buckets.",
	})

	// PCI-DSS 11.5 - Deploy change-detection mechanism
	pe.RegisterPolicy(&SQLPolicy{
		ID:          "pci-dss-11.5",
		Name:        "Deploy Change Detection",
		Description: "Deploy a change-detection mechanism to alert on unauthorized modification",
		Framework:   "pci_dss_v3.2.1",
		CheckID:     "11.5",
		Provider:    "aws",
		Service:     "config",
		Severity:    "high",
		SQL: `
SELECT DISTINCT
    'pci_dss_v3.2.1' AS framework,
    '11.5' AS check_id,
    'AWS Config should be enabled' AS title,
    recorder.account_id,
    recorder.account_id AS resource_id,
    CASE WHEN recorder.recording = TRUE
    THEN 'pass' ELSE 'fail' END AS status
FROM aws_config_configuration_recorders recorder`,
		Tags:        []string{"config", "change-detection", "monitoring", "pci-dss"},
		Remediation: "Enable AWS Config to detect configuration changes.",
	})
}
