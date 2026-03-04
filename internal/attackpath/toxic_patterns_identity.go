package attackpath

func identityToxicPatterns() []ToxicPattern {
	return []ToxicPattern{
		{
			ID:          "privileged-inactive-keys",
			Title:       "Admin user/service account with active access keys unrotated in the past year",
			Description: "This admin account has active access keys that have not been rotated in over a year, increasing the risk of credential compromise.",
			RequiredFactors: []RiskFactorType{
				RiskFactorHighPrivilege,
				RiskFactorUnrotatedKeys,
			},
			OptionalFactors: []RiskFactorType{
				RiskFactorInactive,
			},
			BaseSeverity: RiskMedium,
			Remediation: `### Rotate access keys
* Rotate all access keys that are over 90 days old.
* Implement automated key rotation.

### Review account necessity
* Disable inactive admin accounts.
* Remove unnecessary admin privileges.`,
			MitreAttack: []string{"T1078.004"},
		},
	}
}
