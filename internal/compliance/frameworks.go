package compliance

type Framework struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Description string     `json:"description"`
	Controls    []Control  `json:"controls"`
}

type Control struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	PolicyIDs   []string `json:"policy_ids"`
}

type ControlStatus struct {
	ControlID   string `json:"control_id"`
	Status      string `json:"status"` // passing, failing, unknown
	PassCount   int    `json:"pass_count"`
	FailCount   int    `json:"fail_count"`
	TotalAssets int    `json:"total_assets"`
}

type ComplianceReport struct {
	FrameworkID   string                   `json:"framework_id"`
	FrameworkName string                   `json:"framework_name"`
	GeneratedAt   string                   `json:"generated_at"`
	Summary       ComplianceSummary        `json:"summary"`
	Controls      []ControlStatus          `json:"controls"`
}

type ComplianceSummary struct {
	TotalControls   int     `json:"total_controls"`
	PassingControls int     `json:"passing_controls"`
	FailingControls int     `json:"failing_controls"`
	ComplianceScore float64 `json:"compliance_score"`
}

var CISAWSv14 = Framework{
	ID:          "cis-aws-1.4",
	Name:        "CIS AWS Foundations Benchmark",
	Version:     "1.4.0",
	Description: "CIS Amazon Web Services Foundations Benchmark",
	Controls: []Control{
		{
			ID:          "1.4",
			Title:       "Ensure MFA is enabled for the root account",
			Description: "The root account is the most privileged user in an AWS account.",
			PolicyIDs:   []string{"aws-iam-user-mfa-enabled"},
		},
		{
			ID:          "2.1.5",
			Title:       "Ensure S3 bucket access logging is enabled",
			Description: "S3 Bucket Access Logging generates access records for requests.",
			PolicyIDs:   []string{"aws-s3-bucket-no-public-access"},
		},
		{
			ID:          "2.3.1",
			Title:       "Ensure RDS encryption is enabled",
			Description: "Amazon RDS encrypted instances use AES-256 encryption.",
			PolicyIDs:   []string{"aws-rds-encryption-enabled"},
		},
		{
			ID:          "3.1",
			Title:       "Ensure CloudTrail is enabled in all regions",
			Description: "AWS CloudTrail records AWS API calls for your account.",
			PolicyIDs:   []string{"aws-cloudtrail-enabled"},
		},
		{
			ID:          "5.6",
			Title:       "Ensure EC2 instance metadata service version 2 (IMDSv2) is enabled",
			Description: "IMDSv2 adds defense against SSRF attacks.",
			PolicyIDs:   []string{"aws-ec2-imdsv2-required"},
		},
	},
}

var CISGCPv12 = Framework{
	ID:          "cis-gcp-1.2",
	Name:        "CIS Google Cloud Platform Benchmark",
	Version:     "1.2.0",
	Description: "CIS Google Cloud Platform Foundation Benchmark",
	Controls: []Control{
		{
			ID:          "5.1",
			Title:       "Ensure Cloud Storage bucket is not publicly accessible",
			Description: "Cloud Storage buckets should not be anonymously or publicly accessible.",
			PolicyIDs:   []string{"gcp-storage-bucket-no-public"},
		},
	},
}

var CISAzurev14 = Framework{
	ID:          "cis-azure-1.4",
	Name:        "CIS Microsoft Azure Foundations Benchmark",
	Version:     "1.4.0",
	Description: "CIS Microsoft Azure Foundations Benchmark",
	Controls: []Control{
		{
			ID:          "3.1",
			Title:       "Ensure 'Secure transfer required' is enabled",
			Description: "Storage accounts should require secure transfer (HTTPS).",
			PolicyIDs:   []string{"azure-storage-https-only"},
		},
	},
}

var SOC2 = Framework{
	ID:          "soc2-type2",
	Name:        "SOC 2 Type II",
	Version:     "2017",
	Description: "Service Organization Control 2 Type II",
	Controls: []Control{
		{
			ID:          "CC6.1",
			Title:       "Logical and Physical Access Controls",
			Description: "Logical access to system components is restricted.",
			PolicyIDs:   []string{"aws-iam-user-mfa-enabled", "aws-s3-bucket-no-public-access"},
		},
		{
			ID:          "CC6.6",
			Title:       "System Boundary Protection",
			Description: "System boundaries are protected from external threats.",
			PolicyIDs:   []string{"aws-ec2-imdsv2-required"},
		},
		{
			ID:          "CC7.2",
			Title:       "System Monitoring",
			Description: "Security events are logged and monitored.",
			PolicyIDs:   []string{"aws-cloudtrail-enabled"},
		},
	},
}

func GetFrameworks() []Framework {
	return []Framework{CISAWSv14, CISGCPv12, CISAzurev14, SOC2}
}

func GetFramework(id string) *Framework {
	for _, f := range GetFrameworks() {
		if f.ID == id {
			return &f
		}
	}
	return nil
}
