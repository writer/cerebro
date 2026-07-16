package findingrule

import (
	"reflect"
	"testing"

	"github.com/writer/cerebro/internal/findings"
)

func TestRequiredCasesDerivesDurableSourceStateContract(t *testing.T) {
	contract := Contract{
		Definition:               durableDefinition(),
		SupportsCounterEvents:    true,
		SupportsDeprovisionClose: true,
	}
	want := []Case{
		CasePositiveOpen,
		CaseNegativeNonOpen,
		CaseMissingRequiredAttribute,
		CaseStableFingerprint,
		CaseRemediationClose,
		CaseUnrelatedNonClose,
		CaseDeprovisionClose,
		CaseCrossTenantIsolation,
		CaseRepeatEventIdempotency,
	}
	got, err := RequiredCases(contract)
	if err != nil {
		t.Fatalf("RequiredCases() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RequiredCases() = %v, want %v", got, want)
	}
}

func TestAuthorMissingEmitsDeterministicValidatedSpecifications(t *testing.T) {
	contract := Contract{Definition: durableDefinition(), SupportsCounterEvents: true}
	covered := []Case{CasePositiveOpen, CaseNegativeNonOpen, CaseMissingRequiredAttribute}

	first, err := AuthorMissing(contract, covered)
	if err != nil {
		t.Fatalf("AuthorMissing() error = %v", err)
	}
	second, err := AuthorMissing(contract, covered)
	if err != nil {
		t.Fatalf("second AuthorMissing() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("AuthorMissing() is not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}
	if len(first) != 5 {
		t.Fatalf("AuthorMissing() count = %d, want 5", len(first))
	}
	for _, spec := range first {
		if err := spec.Validate(); err != nil {
			t.Fatalf("generated spec %q Validate() error = %v", spec.ID, err)
		}
		if spec.Subject != contract.Definition.ID {
			t.Fatalf("generated spec subject = %q, want %q", spec.Subject, contract.Definition.ID)
		}
	}
	if first[0].ID != "example-risk-stable-fingerprint" {
		t.Fatalf("first missing spec id = %q, want stable fingerprint case", first[0].ID)
	}
}

func TestAuthorMissingRejectsUnknownCoveredCase(t *testing.T) {
	_, err := AuthorMissing(Contract{Definition: durableDefinition()}, []Case{"coverage_only"})
	if err == nil {
		t.Fatal("AuthorMissing() error = nil, want unsupported case")
	}
}

func TestRequiredCasesRetiredRuleOnlyRequiresNonOpen(t *testing.T) {
	definition := durableDefinition()
	definition.Lifecycle = findings.Lifecycle{Kind: findings.LifecycleRetired, Anchor: findings.AnchorNone}
	got, err := RequiredCases(Contract{Definition: definition})
	if err != nil {
		t.Fatalf("RequiredCases() error = %v", err)
	}
	want := []Case{CaseRetiredNonOpen}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RequiredCases() = %v, want %v", got, want)
	}
}

func TestRequiredCasesRejectsUnsupportedCloseCapabilities(t *testing.T) {
	tests := []Contract{
		{
			Definition: func() findings.RuleDefinition {
				definition := durableDefinition()
				definition.Lifecycle = findings.Lifecycle{Kind: findings.LifecycleAuditEvidence, Anchor: findings.AnchorNone}
				return definition
			}(),
			SupportsCounterEvents: true,
		},
		{
			Definition:               durableDefinition(),
			SupportsDeprovisionClose: true,
		},
	}
	for _, contract := range tests {
		if _, err := RequiredCases(contract); err == nil {
			t.Fatalf("RequiredCases(%#v) error = nil, want invalid capability", contract)
		}
	}
}

func durableDefinition() findings.RuleDefinition {
	return findings.RuleDefinition{
		ID:                 "example_risk",
		Name:               "Example risk",
		SourceID:           "example",
		OutputKind:         "finding.example_risk",
		RequiredAttributes: []string{"resource_id"},
		FingerprintFields:  []string{"resource_id"},
		Lifecycle: findings.Lifecycle{
			Kind:   findings.LifecycleDurableState,
			Anchor: findings.AnchorSourceState,
		},
	}
}
