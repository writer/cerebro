package attackpath

func containerToxicPatterns() []ToxicPattern {
	return []ToxicPattern{
		{
			ID:          "container-cleartext-keys-high-priv",
			Title:       "Container image with cleartext cloud keys granting high privileges",
			Description: "This container image contains cloud keys in cleartext that permit a service account with high privileges. High permissions allow access to data or the ability to delete resources and disrupt workflows.",
			RequiredFactors: []RiskFactorType{
				RiskFactorSecretsExposed,
				RiskFactorHighPrivilege,
			},
			BaseSeverity: RiskMedium,
			SeverityEscalation: map[int]RiskLevel{
				3: RiskHigh,
			},
			Remediation: `### Ensure secure use of secrets
* Manage all cloud keys using approved secret management solutions.
* Use AWS Secrets Manager, Parameter Store, or workload identity federation.
* Remove cleartext keys from container images.

### Restrict privileges
* Review and minimize permissions assigned to the cloud key.
* Use separate keys for different permission levels.`,
			MitreAttack: []string{"T1552.001", "T1078"},
			ControlID:   "wc-id-5678",
			AppliesTo:   []string{"container", "deployment", "task_definition"},
		},
		{
			ID:          "ecs-task-privileged-exposed",
			Title:       "ECS task with privileged container exposed to network",
			Description: "This ECS task runs a privileged container and is exposed to network access, enabling container escape and lateral movement.",
			RequiredFactors: []RiskFactorType{
				RiskFactorPrivilegedContainer,
				RiskFactorNetworkExposed,
			},
			BaseSeverity: RiskHigh,
			SeverityEscalation: map[int]RiskLevel{
				3: RiskCritical,
			},
			Remediation: `### Remove privileged mode
* Remove the privileged flag from container definitions.
* Use specific Linux capabilities instead.

### Restrict network access
* Use security groups to limit inbound access.
* Place tasks in private subnets where possible.`,
			MitreAttack: []string{"T1611", "T1021"},
			AppliesTo:   []string{"task_definition", "ecs", "container"},
		},
	}
}
