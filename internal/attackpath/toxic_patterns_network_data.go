package attackpath

func networkAndDataToxicPatterns() []ToxicPattern {
	return []ToxicPattern{
		{
			ID:          "internet-facing-vuln-data-access",
			Title:       "Internet-facing %s with initial access vulnerabilities and data access to sensitive data",
			Description: "This %s is exposed to the public Internet with high exposure level, has a role with access to sensitive data, and has a critical/high severity initial access vulnerability.",
			RequiredFactors: []RiskFactorType{
				RiskFactorNetworkExposed,
				RiskFactorVulnerable,
				RiskFactorDataAccess,
			},
			BaseSeverity: RiskCritical,
			Remediation: `### Limit external exposure
* Restrict access to resources that do not need to be accessible from the internet.
* Ensure that exposed ports allow only encrypted communications.

### Patch vulnerabilities
* Update to the latest patched version of vulnerable software.
* If patching is not immediately possible, implement compensating controls.

### Restrict data access
* Review and minimize data access permissions using least privilege principle.`,
			MitreAttack: []string{"T1190", "T1530"},
			ControlID:   "wc-id-1211",
		},
		{
			ID:          "public-serverless-high-priv-no-auth",
			Title:       "Publicly exposed %s with high privileges can be invoked by unauthenticated users",
			Description: "This %s is exposed to the public internet, has high privileges and authentication disabled, meaning that any unauthenticated user can invoke it.",
			RequiredFactors: []RiskFactorType{
				RiskFactorNetworkExposed,
				RiskFactorHighPrivilege,
				RiskFactorNoAuth,
			},
			BaseSeverity: RiskHigh,
			Remediation: `### Limit external exposure
* Restrict access to resources that do not need to be accessible from the internet.

### Protect highly privileged principals
* Use the "least privilege" principle when assigning permissions.
* Remove unnecessary high-privilege access.

### Enable authentication
* Require authentication for all public-facing services.
* Use IAM or identity-aware proxy for access control.`,
			MitreAttack: []string{"T1190", "T1078"},
			ControlID:   "wc-id-1234",
		},
		{
			ID:          "public-vm-high-priv-data",
			Title:       "Publicly exposed %s with data access to sensitive data",
			Description: "This %s is exposed to the public internet and has a role with access to sensitive data. An attacker who compromises this resource could access sensitive information.",
			RequiredFactors: []RiskFactorType{
				RiskFactorNetworkExposed,
				RiskFactorDataAccess,
			},
			OptionalFactors: []RiskFactorType{
				RiskFactorHighPrivilege,
				RiskFactorVulnerable,
			},
			BaseSeverity: RiskMedium,
			SeverityEscalation: map[int]RiskLevel{
				3: RiskHigh,
				4: RiskCritical,
			},
			Remediation: `### Limit external exposure
* Move resources behind a load balancer or bastion host.
* Use VPC private subnets where possible.

### Restrict data access
* Apply least privilege to data access permissions.
* Use separate service accounts for public-facing workloads.`,
			MitreAttack: []string{"T1190", "T1530"},
		},
		{
			ID:          "public-bucket-sensitive-data",
			Title:       "Publicly readable bucket contains sensitive data",
			Description: "This storage bucket allows public read access and contains sensitive data. Anyone on the internet can access the sensitive information.",
			RequiredFactors: []RiskFactorType{
				RiskFactorPublicAccess,
				RiskFactorSensitiveData,
			},
			BaseSeverity: RiskCritical,
			Remediation: `### Remove public access
* Disable public access on the bucket immediately.
* Enable Block Public Access settings.

### Review bucket contents
* Identify and classify sensitive data.
* Consider encryption and access logging.`,
			MitreAttack: []string{"T1530"},
			AppliesTo:   []string{"bucket", "s3", "storage"},
		},
		{
			ID:          "data-resource-excessive-access",
			Title:       "Data resource with sensitive data has excessive access permissions",
			Description: "This data resource contains sensitive data and has excessive access permissions, allowing more principals than necessary to access sensitive information.",
			RequiredFactors: []RiskFactorType{
				RiskFactorSensitiveData,
				RiskFactorHighPrivilege,
			},
			BaseSeverity: RiskMedium,
			Remediation: `### Restrict access permissions
* Review and remove excessive permissions.
* Implement least privilege access.
* Use resource-based policies to limit access.`,
			MitreAttack: []string{"T1530"},
		},
	}
}
