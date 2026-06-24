package runtime

import "time"

const IdentityTamperThenCredentialChangeHintID = "identity-control-tamper-with-credential-change"

const RuntimeActiveThreatWithPublicExposureHintID = "runtime-active-threat-with-public-exposure"

type CorrelationHint struct {
	ID         string
	Name       string
	RuleIDs    []string
	Dimensions []string
	Window     time.Duration
	ScoreBonus int
	Reasons    []string
	Tests      []CorrelationHintTest
}

type CorrelationHintTest struct {
	Name        string
	Description string
	ExpectMatch bool
}

func BuiltinHints() []CorrelationHint {
	return []CorrelationHint{
		IdentityTamperThenCredentialChangeHint(),
		RuntimeActiveThreatWithPublicExposureHint(),
	}
}

func IdentityTamperThenCredentialChangeHint() CorrelationHint {
	return CorrelationHint{
		ID:   IdentityTamperThenCredentialChangeHintID,
		Name: "Identity control tamper with credential change",
		RuleIDs: []string{
			"identity-auth-control-lifecycle-tampering",
			"identity-api-token-or-oauth-app-created",
		},
		Dimensions: []string{"actor", "resource"},
		Window:     24 * time.Hour,
		ScoreBonus: 10,
		Reasons:    []string{"control_tamper", "credential_change"},
		Tests: []CorrelationHintTest{
			{
				Name:        "shared-actor-positive",
				Description: "Matches when the same actor changes an identity control and creates a credential inside the window.",
				ExpectMatch: true,
			},
		},
	}
}

func RuntimeActiveThreatWithPublicExposureHint() CorrelationHint {
	return CorrelationHint{
		ID:   RuntimeActiveThreatWithPublicExposureHintID,
		Name: "Runtime active threat with public exposure",
		RuleIDs: []string{
			"cloud-public-resource-exposure",
			"runtime-active-threat-evidence",
		},
		Dimensions: []string{"resource"},
		Window:     24 * time.Hour,
		ScoreBonus: 14,
		Reasons:    []string{"active_threat", "external_exposure"},
		Tests: []CorrelationHintTest{
			{
				Name:        "shared-resource-positive",
				Description: "Matches when runtime threat evidence and public exposure share the same workload or resource inside the window.",
				ExpectMatch: true,
			},
		},
	}
}
