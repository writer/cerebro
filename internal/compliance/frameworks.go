// Package compliance provides compliance framework definitions and report generation.
//
// Frameworks map security controls (from standards like CIS, PCI-DSS, HIPAA) to
// Cerebro policy IDs. This allows generating compliance reports showing which
// controls pass or fail based on policy evaluation results.
package compliance

// Framework represents a compliance standard with its controls
type Framework struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Description string    `json:"description"`
	Controls    []Control `json:"controls"`
}

// ControlSeverity represents the criticality of a control
type ControlSeverity string

const (
	SeverityCritical ControlSeverity = "critical"
	SeverityHigh     ControlSeverity = "high"
	SeverityMedium   ControlSeverity = "medium"
	SeverityLow      ControlSeverity = "low"
)

// SeverityWeight returns the numeric weight for a severity level
func (s ControlSeverity) Weight() int {
	switch s {
	case SeverityCritical:
		return 10
	case SeverityHigh:
		return 5
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 2 // Default to medium
	}
}

// Control represents a specific requirement within a framework
type Control struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Severity    ControlSeverity `json:"severity,omitempty"` // Control criticality for weighted scoring
	PolicyIDs   []string        `json:"policy_ids"`         // Cerebro policy IDs that implement this control
}

// ControlStatus represents the evaluation status of a control
type ControlStatus struct {
	ControlID   string `json:"control_id"`
	Status      string `json:"status"` // passing, failing, unknown
	PassCount   int    `json:"pass_count"`
	FailCount   int    `json:"fail_count"`
	TotalAssets int    `json:"total_assets"`
}

// ComplianceReport represents a generated compliance report
type ComplianceReport struct {
	FrameworkID   string            `json:"framework_id"`
	FrameworkName string            `json:"framework_name"`
	GeneratedAt   string            `json:"generated_at"`
	Summary       ComplianceSummary `json:"summary"`
	Controls      []ControlStatus   `json:"controls"`
}

// ComplianceSummary provides aggregate compliance metrics
type ComplianceSummary struct {
	TotalControls   int     `json:"total_controls"`
	PassingControls int     `json:"passing_controls"`
	FailingControls int     `json:"failing_controls"`
	ComplianceScore float64 `json:"compliance_score"`         // Simple percentage
	WeightedScore   float64 `json:"weighted_score,omitempty"` // Severity-weighted score
}

// =============================================================================
// CIS AWS Foundations Benchmark v1.5.0
// =============================================================================

var CISAWSv15 = Framework{
	ID:          "cis-aws-1.5",
	Name:        "CIS AWS Foundations Benchmark",
	Version:     "1.5.0",
	Description: "CIS Amazon Web Services Foundations Benchmark v1.5.0",
	Controls: []Control{
		// Section 1: Identity and Access Management
		{
			ID:          "1.4",
			Title:       "Ensure no root user access key exists",
			Description: "The root user is the most privileged user in an AWS account. Access keys provide programmatic access.",
			Severity:    SeverityCritical,
			PolicyIDs:   []string{"aws-iam-root-no-access-keys"},
		},
		{
			ID:          "1.5",
			Title:       "Ensure MFA is enabled for the root user",
			Description: "The root user has unrestricted access. MFA adds an extra layer of protection.",
			Severity:    SeverityCritical,
			PolicyIDs:   []string{"aws-iam-root-mfa-enabled"},
		},
		{
			ID:          "1.8",
			Title:       "Ensure IAM password policy requires minimum length of 14 or greater",
			Description: "Password policies enforce password complexity requirements.",
			Severity:    SeverityMedium,
			PolicyIDs:   []string{"aws-iam-password-policy"},
		},
		{
			ID:          "1.9",
			Title:       "Ensure IAM password policy prevents password reuse",
			Description: "Preventing password reuse increases account resiliency.",
			Severity:    SeverityMedium,
			PolicyIDs:   []string{"aws-iam-password-policy"},
		},
		{
			ID:          "1.10",
			Title:       "Ensure MFA is enabled for all IAM users with console access",
			Description: "MFA adds an extra layer of protection for interactive logins.",
			Severity:    SeverityHigh,
			PolicyIDs:   []string{"aws-iam-user-mfa-enabled"},
		},
		{
			ID:          "1.12",
			Title:       "Ensure credentials unused for 45 days or greater are disabled",
			Description: "Unused credentials should be disabled to reduce attack surface.",
			Severity:    SeverityMedium,
			PolicyIDs:   []string{"aws-iam-user-console-inactive", "aws-iam-user-unused-credentials"},
		},
		{
			ID:          "1.14",
			Title:       "Ensure access keys are rotated every 90 days or less",
			Description: "Rotating access keys reduces the risk from compromised keys.",
			Severity:    SeverityHigh,
			PolicyIDs:   []string{"aws-iam-access-key-rotation"},
		},
		{
			ID:          "1.15",
			Title:       "Ensure IAM users receive permissions only through groups",
			Description: "Assigning permissions through groups simplifies access management.",
			Severity:    SeverityLow,
			PolicyIDs:   []string{"aws-iam-no-policies-attached-user"},
		},
		{
			ID:          "1.16",
			Title:       "Ensure IAM policies that allow full '*:*' administrative privileges are not attached",
			Description: "IAM policies should follow least privilege principles.",
			Severity:    SeverityCritical,
			PolicyIDs:   []string{"aws-iam-policy-no-admin-star"},
		},

		// Section 2: Storage
		{
			ID:          "2.1.1",
			Title:       "Ensure S3 bucket encryption is enabled",
			Description: "S3 bucket default encryption provides encryption at rest.",
			Severity:    SeverityHigh,
			PolicyIDs:   []string{"aws-s3-bucket-encryption-enabled"},
		},
		{
			ID:          "2.1.2",
			Title:       "Ensure S3 bucket policy requires SSL",
			Description: "S3 bucket policies should require TLS for data in transit.",
			Severity:    SeverityHigh,
			PolicyIDs:   []string{"aws-s3-bucket-ssl-only"},
		},
		{
			ID:          "2.1.5",
			Title:       "Ensure S3 buckets are not publicly accessible",
			Description: "S3 buckets should block public access unless explicitly required.",
			PolicyIDs:   []string{"aws-s3-bucket-no-public-access", "aws-s3-bucket-policy-public"},
		},
		{
			ID:          "2.2.1",
			Title:       "Ensure EBS volume encryption is enabled",
			Description: "EBS volumes should be encrypted to protect data at rest.",
			PolicyIDs:   []string{"aws-ebs-encryption-default", "aws-ec2-ebs-volume-encrypted"},
		},
		{
			ID:          "2.3.1",
			Title:       "Ensure RDS instances have encryption enabled",
			Description: "RDS instances should use encryption at rest.",
			PolicyIDs:   []string{"aws-rds-encryption-enabled"},
		},
		{
			ID:          "2.3.3",
			Title:       "Ensure RDS instances are not publicly accessible",
			Description: "RDS instances should not be exposed to the public internet.",
			PolicyIDs:   []string{"aws-rds-no-public-access"},
		},

		// Section 3: Logging
		{
			ID:          "3.1",
			Title:       "Ensure CloudTrail is enabled in all regions",
			Description: "CloudTrail provides event history of AWS API calls.",
			PolicyIDs:   []string{"aws-cloudtrail-enabled"},
		},
		{
			ID:          "3.5",
			Title:       "Ensure AWS Config is enabled in all regions",
			Description: "AWS Config records configuration changes for compliance auditing.",
			PolicyIDs:   []string{"aws-config-enabled-all-regions"},
		},
		{
			ID:          "3.6",
			Title:       "Ensure S3 bucket access logging is enabled",
			Description: "S3 access logging helps with security auditing and incident response.",
			PolicyIDs:   []string{"aws-s3-bucket-logging-enabled"},
		},
		{
			ID:          "3.8",
			Title:       "Ensure rotation for customer-created CMKs is enabled",
			Description: "KMS key rotation limits the impact of compromised keys.",
			PolicyIDs:   []string{"aws-kms-key-rotation-enabled"},
		},
		{
			ID:          "3.9",
			Title:       "Ensure VPC flow logging is enabled in all VPCs",
			Description: "VPC flow logs capture network traffic for security analysis.",
			PolicyIDs:   []string{"aws-vpc-flow-logs-enabled"},
		},

		// Section 4: Monitoring
		{
			ID:          "4.1",
			Title:       "Ensure a log metric filter and alarm exist for unauthorized API calls",
			Description: "Monitoring unauthorized API calls helps detect malicious activity.",
			PolicyIDs:   []string{"aws-cloudwatch-alarm-missing"},
		},
		{
			ID:          "4.15",
			Title:       "Ensure GuardDuty is enabled",
			Description: "GuardDuty provides intelligent threat detection.",
			PolicyIDs:   []string{"aws-guardduty-disabled"},
		},

		// Section 5: Networking
		{
			ID:          "5.2",
			Title:       "Ensure no security groups allow ingress from 0.0.0.0/0 to SSH port 22",
			Description: "SSH should not be open to the entire internet.",
			PolicyIDs:   []string{"aws-security-group-restrict-ssh", "aws-ec2-public-ip-ssh"},
		},
		{
			ID:          "5.3",
			Title:       "Ensure no security groups allow ingress from 0.0.0.0/0 to RDP port 3389",
			Description: "RDP should not be open to the entire internet.",
			PolicyIDs:   []string{"aws-security-group-restrict-rdp", "aws-ec2-public-ip-rdp"},
		},
		{
			ID:          "5.4",
			Title:       "Ensure the default security group restricts all traffic",
			Description: "The default security group should not allow unrestricted traffic.",
			PolicyIDs:   []string{"aws-ec2-sg-no-all-traffic-ingress"},
		},
		{
			ID:          "5.6",
			Title:       "Ensure EC2 instance metadata service version 2 (IMDSv2) is enabled",
			Description: "IMDSv2 provides protection against SSRF attacks.",
			PolicyIDs:   []string{"aws-ec2-imdsv2-required"},
		},
	},
}

// =============================================================================
// PCI DSS v4.0
// =============================================================================

var PCIDSS40 = Framework{
	ID:          "pci-dss-4.0",
	Name:        "PCI DSS",
	Version:     "4.0",
	Description: "Payment Card Industry Data Security Standard v4.0",
	Controls: []Control{
		// Requirement 1: Network Security Controls
		{
			ID:          "1.2.1",
			Title:       "Restrict inbound traffic to cardholder data environment",
			Description: "Inbound traffic to the CDE should be restricted to necessary traffic only.",
			PolicyIDs:   []string{"aws-security-group-restrict-ssh", "aws-security-group-restrict-rdp", "aws-ec2-sg-no-all-traffic-ingress"},
		},
		{
			ID:          "1.3.1",
			Title:       "Inbound traffic to CDE is restricted to necessary traffic",
			Description: "Network security controls must limit inbound traffic.",
			PolicyIDs:   []string{"aws-ec2-public-ip-ssh", "aws-ec2-public-ip-rdp", "aws-rds-no-public-access", "dspm-confidential-data-public"},
		},
		{
			ID:          "1.4.1",
			Title:       "NSCs are implemented between untrusted networks and the CDE",
			Description: "Firewalls or equivalent controls must protect the CDE.",
			PolicyIDs:   []string{"aws-vpc-flow-logs-enabled", "aws-elb-internet-facing-no-waf"},
		},

		// Requirement 2: Secure Configurations
		{
			ID:          "2.2.1",
			Title:       "Configuration standards are developed and implemented",
			Description: "Systems must be configured according to security standards.",
			PolicyIDs:   []string{"aws-ec2-imdsv2-required", "aws-config-enabled-all-regions"},
		},

		// Requirement 3: Protect Stored Account Data
		{
			ID:          "3.5.1",
			Title:       "Account data is rendered unreadable via encryption",
			Description: "Stored cardholder data must be encrypted.",
			PolicyIDs:   []string{"aws-s3-bucket-encryption-enabled", "aws-rds-encryption-enabled", "aws-ebs-encryption-default", "aws-ec2-ebs-volume-encrypted", "dspm-restricted-data-unencrypted"},
		},

		// Requirement 4: Protect Data in Transit
		{
			ID:          "4.2.1",
			Title:       "Strong cryptography protects PAN during transmission",
			Description: "Data in transit must use strong encryption.",
			PolicyIDs:   []string{"aws-s3-bucket-ssl-only", "aws-elb-https-only", "aws-elb-tls-version"},
		},

		// Requirement 6: Secure Systems and Software
		{
			ID:          "6.3.1",
			Title:       "Security vulnerabilities are identified and addressed",
			Description: "Vulnerabilities must be identified through scanning and patching.",
			PolicyIDs:   []string{"aws-ecr-scan-on-push", "aws-lambda-runtime-supported"},
		},

		// Requirement 7: Restrict Access
		{
			ID:          "7.2.1",
			Title:       "Access to system components is based on business need",
			Description: "Access must follow the principle of least privilege.",
			PolicyIDs:   []string{"aws-iam-policy-no-admin-star", "aws-iam-no-policies-attached-user"},
		},
		{
			ID:          "7.2.2",
			Title:       "Access is assigned based on job classification and function",
			Description: "Roles should be assigned based on job responsibilities.",
			PolicyIDs:   []string{"aws-iam-role-trust-any-principal", "aws-iam-role-wildcard-trust"},
		},

		// Requirement 8: Identify Users and Authenticate Access
		{
			ID:          "8.3.1",
			Title:       "Strong authentication for users and administrators",
			Description: "All user and administrator access must use strong authentication.",
			PolicyIDs:   []string{"aws-iam-user-mfa-enabled", "aws-iam-root-mfa-enabled"},
		},
		{
			ID:          "8.3.6",
			Title:       "Authentication factors are changed if compromise suspected",
			Description: "Credentials must be rotated regularly and when compromised.",
			PolicyIDs:   []string{"aws-iam-access-key-rotation", "aws-secretsmanager-rotation-enabled"},
		},
		{
			ID:          "8.3.7",
			Title:       "Inactive accounts are disabled within 90 days",
			Description: "Unused accounts must be disabled promptly.",
			PolicyIDs:   []string{"aws-iam-user-console-inactive", "aws-iam-user-unused-credentials"},
		},

		// Requirement 10: Log and Monitor Access
		{
			ID:          "10.2.1",
			Title:       "Audit logs are enabled and active",
			Description: "All access to system components must be logged.",
			PolicyIDs:   []string{"aws-cloudtrail-enabled", "aws-s3-bucket-logging-enabled", "aws-rds-logging-enabled"},
		},
		{
			ID:          "10.4.1",
			Title:       "Audit logs are reviewed at least daily",
			Description: "Logs must be monitored for suspicious activity.",
			PolicyIDs:   []string{"aws-guardduty-disabled", "aws-cloudwatch-alarm-missing"},
		},

		// Requirement 11: Test Security Regularly
		{
			ID:          "11.3.1",
			Title:       "Vulnerabilities are identified via scanning",
			Description: "Regular vulnerability scans must be performed.",
			PolicyIDs:   []string{"aws-ecr-scan-on-push"},
		},

		// Requirement 12: Security Policies
		{
			ID:          "12.3.1",
			Title:       "Cryptographic key management procedures",
			Description: "Cryptographic keys must be properly managed.",
			PolicyIDs:   []string{"aws-kms-key-rotation-enabled"},
		},
	},
}

// =============================================================================
// HIPAA Security Rule
// =============================================================================

var HIPAA = Framework{
	ID:          "hipaa-security",
	Name:        "HIPAA Security Rule",
	Version:     "2013",
	Description: "Health Insurance Portability and Accountability Act Security Rule",
	Controls: []Control{
		// Administrative Safeguards
		{
			ID:          "164.308(a)(1)",
			Title:       "Security Management Process - Risk Analysis",
			Description: "Conduct accurate and thorough assessment of risks to ePHI.",
			PolicyIDs:   []string{"aws-config-enabled-all-regions", "aws-guardduty-disabled"},
		},
		{
			ID:          "164.308(a)(3)",
			Title:       "Workforce Security - Authorization/Supervision",
			Description: "Implement procedures for authorization and supervision of workforce members.",
			PolicyIDs:   []string{"aws-iam-user-mfa-enabled", "aws-iam-policy-no-admin-star"},
		},
		{
			ID:          "164.308(a)(4)",
			Title:       "Information Access Management",
			Description: "Implement policies and procedures for authorizing access to ePHI.",
			PolicyIDs:   []string{"aws-iam-no-policies-attached-user", "aws-iam-user-console-inactive"},
		},
		{
			ID:          "164.308(a)(5)",
			Title:       "Security Awareness and Training",
			Description: "Implement security awareness program for all workforce members.",
			PolicyIDs:   []string{"aws-iam-password-policy"},
		},

		// Technical Safeguards
		{
			ID:          "164.312(a)(1)",
			Title:       "Access Control - Unique User Identification",
			Description: "Assign unique name and/or number for identifying and tracking user identity.",
			PolicyIDs:   []string{"aws-iam-user-mfa-enabled", "aws-rds-iam-authentication"},
		},
		{
			ID:          "164.312(a)(2)(iv)",
			Title:       "Access Control - Encryption and Decryption",
			Description: "Implement mechanism to encrypt and decrypt ePHI.",
			PolicyIDs:   []string{"aws-s3-bucket-encryption-enabled", "aws-rds-encryption-enabled", "aws-ebs-encryption-default", "dspm-restricted-data-unencrypted"},
		},
		{
			ID:          "164.312(b)",
			Title:       "Audit Controls",
			Description: "Implement mechanisms to record and examine access to ePHI.",
			PolicyIDs:   []string{"aws-cloudtrail-enabled", "aws-s3-bucket-logging-enabled", "aws-vpc-flow-logs-enabled"},
		},
		{
			ID:          "164.312(c)(1)",
			Title:       "Integrity - Mechanism to Authenticate ePHI",
			Description: "Implement mechanisms to corroborate that ePHI has not been altered.",
			PolicyIDs:   []string{"aws-s3-bucket-versioning-enabled", "aws-s3-bucket-mfa-delete"},
		},
		{
			ID:          "164.312(d)",
			Title:       "Person or Entity Authentication",
			Description: "Implement procedures to verify identity of persons seeking access to ePHI.",
			PolicyIDs:   []string{"aws-iam-user-mfa-enabled", "aws-iam-root-mfa-enabled", "aws-iam-access-key-rotation"},
		},
		{
			ID:          "164.312(e)(1)",
			Title:       "Transmission Security - Integrity Controls",
			Description: "Implement security measures to ensure transmitted ePHI is not improperly modified.",
			PolicyIDs:   []string{"aws-s3-bucket-ssl-only", "aws-elb-https-only", "dspm-confidential-data-public"},
		},
		{
			ID:          "164.312(e)(2)(ii)",
			Title:       "Transmission Security - Encryption",
			Description: "Implement mechanism to encrypt ePHI in transit.",
			PolicyIDs:   []string{"aws-elb-tls-version", "aws-cloudfront-http"},
		},
	},
}

// =============================================================================
// SOC 2 Type II
// =============================================================================

var SOC2 = Framework{
	ID:          "soc2-type2",
	Name:        "SOC 2 Type II",
	Version:     "2017",
	Description: "Service Organization Control 2 Type II - Trust Services Criteria",
	Controls: []Control{
		// CC6: Logical and Physical Access Controls
		{
			ID:          "CC6.1",
			Title:       "Logical Access Security Software, Infrastructure, and Architectures",
			Description: "The entity implements logical access security software, infrastructure, and architectures to protect information assets.",
			PolicyIDs:   []string{"aws-iam-user-mfa-enabled", "aws-iam-root-mfa-enabled", "aws-iam-password-policy"},
		},
		{
			ID:          "CC6.2",
			Title:       "User Registration and Authorization",
			Description: "Prior to issuing system credentials, the entity registers and authorizes new users.",
			PolicyIDs:   []string{"aws-iam-no-policies-attached-user", "aws-iam-policy-no-admin-star"},
		},
		{
			ID:          "CC6.3",
			Title:       "Credential Lifecycle Management",
			Description: "The entity identifies and manages the inventory of information assets.",
			PolicyIDs:   []string{"aws-iam-access-key-rotation", "aws-iam-user-unused-credentials", "aws-secretsmanager-rotation-enabled"},
		},
		{
			ID:          "CC6.6",
			Title:       "System Boundary Protection",
			Description: "The entity implements logical access security measures to protect against threats from sources outside system boundaries.",
			PolicyIDs:   []string{"aws-ec2-imdsv2-required", "aws-security-group-restrict-ssh", "aws-security-group-restrict-rdp", "aws-rds-no-public-access"},
		},
		{
			ID:          "CC6.7",
			Title:       "Encryption of Data",
			Description: "The entity restricts the transmission, movement, and removal of information.",
			PolicyIDs:   []string{"aws-s3-bucket-encryption-enabled", "aws-rds-encryption-enabled", "aws-s3-bucket-ssl-only"},
		},

		// CC7: System Operations
		{
			ID:          "CC7.1",
			Title:       "Detection and Monitoring",
			Description: "The entity detects and monitors security events to identify anomalies.",
			PolicyIDs:   []string{"aws-cloudtrail-enabled", "aws-guardduty-disabled", "aws-config-enabled-all-regions"},
		},
		{
			ID:          "CC7.2",
			Title:       "Security Event Analysis",
			Description: "The entity evaluates potential security events and incidents.",
			PolicyIDs:   []string{"aws-cloudwatch-alarm-missing", "aws-vpc-flow-logs-enabled"},
		},
		{
			ID:          "CC7.3",
			Title:       "Response to Identified Security Incidents",
			Description: "The entity responds to identified security incidents.",
			PolicyIDs:   []string{"aws-s3-bucket-logging-enabled"},
		},

		// CC8: Change Management
		{
			ID:          "CC8.1",
			Title:       "Change Management Process",
			Description: "The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes.",
			PolicyIDs:   []string{"aws-ecr-immutable-tags", "aws-s3-bucket-versioning-enabled"},
		},

		// A1: Availability
		{
			ID:          "A1.2",
			Title:       "Recovery Planning and Testing",
			Description: "The entity identifies and tests data backup and recovery procedures.",
			PolicyIDs:   []string{"aws-rds-backup-enabled", "aws-rds-multi-az-enabled", "aws-rds-deletion-protection"},
		},
	},
}

// =============================================================================
// CIS GCP Foundations Benchmark v1.3.0
// =============================================================================

var CISGCPv13 = Framework{
	ID:          "cis-gcp-1.3",
	Name:        "CIS Google Cloud Platform Benchmark",
	Version:     "1.3.0",
	Description: "CIS Google Cloud Platform Foundation Benchmark v1.3.0",
	Controls: []Control{
		{
			ID:          "1.1",
			Title:       "Ensure service account has no admin privileges",
			Description: "Service accounts should not have admin privileges.",
			PolicyIDs:   []string{"gcp-iam-sa-no-admin-privileges", "gcp-sa-admin-privileges"},
		},
		{
			ID:          "1.4",
			Title:       "Ensure user-managed service account keys are rotated",
			Description: "Service account keys should be rotated within 90 days.",
			PolicyIDs:   []string{"gcp-service-account-key-rotation", "gcp-iam-minimize-user-managed-keys"},
		},
		{
			ID:          "4.1",
			Title:       "Ensure default Compute Engine service account is not used",
			Description: "VMs should not use the default compute service account.",
			PolicyIDs:   []string{"gcp-compute-no-default-service-account", "gcp-gke-default-sa"},
		},
		{
			ID:          "5.1",
			Title:       "Ensure Cloud Storage bucket is not publicly accessible",
			Description: "Cloud Storage buckets should not be anonymously or publicly accessible.",
			PolicyIDs:   []string{"gcp-storage-bucket-no-public", "gcp-storage-no-public-allusers"},
		},
		{
			ID:          "6.2.1",
			Title:       "Ensure Cloud SQL database instances require SSL",
			Description: "Cloud SQL instances should require SSL connections.",
			PolicyIDs:   []string{"gcp-sql-ssl-required", "gcp-cloudsql-no-public-ip"},
		},
	},
}

// =============================================================================
// CIS Azure Foundations Benchmark v1.5.0
// =============================================================================

var CISAzurev15 = Framework{
	ID:          "cis-azure-1.5",
	Name:        "CIS Microsoft Azure Foundations Benchmark",
	Version:     "1.5.0",
	Description: "CIS Microsoft Azure Foundations Benchmark v1.5.0",
	Controls: []Control{
		{
			ID:          "1.1.1",
			Title:       "Ensure MFA is enabled for all users",
			Description: "Multi-factor authentication should be enabled for all users.",
			PolicyIDs:   []string{"azure-user-mfa-disabled"},
		},
		{
			ID:          "3.1",
			Title:       "Ensure 'Secure transfer required' is enabled",
			Description: "Storage accounts should require secure transfer (HTTPS).",
			PolicyIDs:   []string{"azure-storage-https-only"},
		},
		{
			ID:          "3.7",
			Title:       "Ensure default network access rule for Storage Accounts is deny",
			Description: "Storage accounts should deny access by default.",
			PolicyIDs:   []string{"azure-storage-network-default-deny", "azure-storage-network-allow"},
		},
		{
			ID:          "4.1.1",
			Title:       "Ensure SQL server auditing is enabled",
			Description: "Auditing should be enabled for Azure SQL servers.",
			PolicyIDs:   []string{"azure-sql-auditing-enabled"},
		},
		{
			ID:          "7.1",
			Title:       "Ensure VMs utilize Managed Disks",
			Description: "Virtual machines should use managed disks.",
			PolicyIDs:   []string{"azure-vm-unmanaged-disk"},
		},
	},
}

// =============================================================================
// Business Compliance Frameworks
// =============================================================================

var SLAComplianceV1 = Framework{
	ID:          "sla-compliance-v1",
	Name:        "Service Level Agreement Compliance",
	Version:     "1.0",
	Description: "Operational SLA control framework for customer response, uptime, and resolution commitments.",
	Controls: []Control{
		{
			ID:          "SLA-1",
			Title:       "Response Time SLA",
			Description: "Critical tickets should meet contractual response windows.",
			Severity:    SeverityHigh,
			PolicyIDs:   []string{"zendesk-sla-breach"},
		},
		{
			ID:          "SLA-2",
			Title:       "Uptime SLA",
			Description: "Enterprise uptime must remain above contracted targets.",
			Severity:    SeverityCritical,
			PolicyIDs:   []string{"uptime-breach-enterprise"},
		},
		{
			ID:          "SLA-3",
			Title:       "Resolution Time SLA",
			Description: "Incident resolution should meet contracted resolution windows.",
			Severity:    SeverityHigh,
			PolicyIDs:   []string{"resolution-time-breach"},
		},
	},
}

var RevOpsHygieneV1 = Framework{
	ID:          "revops-hygiene-v1",
	Name:        "Revenue Operations Hygiene",
	Version:     "1.0",
	Description: "Business pipeline and forecasting control framework for revenue operations.",
	Controls: []Control{
		{
			ID:          "REV-1",
			Title:       "Pipeline Hygiene",
			Description: "Open opportunities should stay active with timely progression signals.",
			Severity:    SeverityHigh,
			PolicyIDs:   []string{"hubspot-stale-deal", "hubspot-no-next-step", "sf-close-date-slip"},
		},
		{
			ID:          "REV-2",
			Title:       "Discount Governance",
			Description: "Discounting should remain within approved guardrails.",
			Severity:    SeverityMedium,
			PolicyIDs:   []string{"hubspot-excessive-discount"},
		},
		{
			ID:          "REV-3",
			Title:       "Forecast Accuracy",
			Description: "Enterprise opportunities should not remain stale in open stages.",
			Severity:    SeverityHigh,
			PolicyIDs:   []string{"sf-stale-enterprise-opp"},
		},
		{
			ID:          "REV-4",
			Title:       "Payment Health",
			Description: "Recurring payment failure streaks should trigger intervention.",
			Severity:    SeverityCritical,
			PolicyIDs:   []string{"stripe-payment-failure-streak"},
		},
	},
}

var FinancialControlsV1 = Framework{
	ID:          "financial-controls-v1",
	Name:        "Financial Controls",
	Version:     "1.0",
	Description: "Financial governance framework for authorization, revenue recognition, and duty segregation.",
	Controls: []Control{
		{
			ID:          "FIN-1",
			Title:       "Refund Authorization",
			Description: "Large refunds should require explicit approval.",
			Severity:    SeverityHigh,
			PolicyIDs:   []string{"stripe-large-refund"},
		},
		{
			ID:          "FIN-2",
			Title:       "Revenue Recognition",
			Description: "Contractual and billing records should remain aligned.",
			Severity:    SeverityHigh,
			PolicyIDs:   []string{"contract-billing-mismatch"},
		},
		{
			ID:          "FIN-3",
			Title:       "Separation of Duties",
			Description: "Approvers and executors should remain distinct for sensitive finance actions.",
			Severity:    SeverityCritical,
			PolicyIDs:   []string{"same-user-approve-execute"},
		},
	},
}

// =============================================================================
// Framework Registry
// =============================================================================

// GetFrameworks returns all available compliance frameworks
func GetFrameworks() []Framework {
	return []Framework{
		CISAWSv15,
		PCIDSS40,
		HIPAA,
		SOC2,
		CISGCPv13,
		CISAzurev15,
		SLAComplianceV1,
		RevOpsHygieneV1,
		FinancialControlsV1,
	}
}

// GetFramework returns a specific framework by ID
func GetFramework(id string) *Framework {
	for _, f := range GetFrameworks() {
		if f.ID == id {
			return &f
		}
	}
	return nil
}

// GetFrameworkIDs returns the list of all framework IDs
func GetFrameworkIDs() []string {
	frameworks := GetFrameworks()
	ids := make([]string, len(frameworks))
	for i, f := range frameworks {
		ids[i] = f.ID
	}
	return ids
}

// GetControlsForPolicy returns all controls that reference a given policy ID
func GetControlsForPolicy(policyID string) []struct {
	Framework Framework
	Control   Control
} {
	var results []struct {
		Framework Framework
		Control   Control
	}

	for _, f := range GetFrameworks() {
		for _, c := range f.Controls {
			for _, pid := range c.PolicyIDs {
				if pid == policyID {
					results = append(results, struct {
						Framework Framework
						Control   Control
					}{f, c})
					break
				}
			}
		}
	}

	return results
}

// CalculateWeightedScore calculates a severity-weighted compliance score
// Returns (weightedScore, totalWeight, passingWeight)
func CalculateWeightedScore(controls []Control, failingControlIDs map[string]bool) (float64, int, int) {
	totalWeight := 0
	passingWeight := 0

	for _, ctrl := range controls {
		weight := ctrl.Severity.Weight()
		totalWeight += weight

		if !failingControlIDs[ctrl.ID] {
			passingWeight += weight
		}
	}

	if totalWeight == 0 {
		return 0, 0, 0
	}

	score := float64(passingWeight) / float64(totalWeight) * 100
	return score, totalWeight, passingWeight
}
