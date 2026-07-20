package testauthor

import (
	"errors"
	"testing"
)

func TestSpecNormalizeAndDigestAreDeterministic(t *testing.T) {
	spec := validSpec()
	spec.ID = "  FINDING-RULE-UNRELATED-CLOSE "
	spec.Family = " FINDING_RULE "
	spec.Signal.Kind = " CONTRACT_GAP "
	spec.Oracle.Kind = " LIFECYCLE_CONTRACT "
	spec.Fixture.Kind = " SYNTHETIC_EVENT_SEQUENCE "

	first, err := spec.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	second, err := spec.Normalize().Digest()
	if err != nil {
		t.Fatalf("normalized Digest() error = %v", err)
	}
	if first != second {
		t.Fatalf("digest mismatch: %q != %q", first, second)
	}
	if len(first) != 64 {
		t.Fatalf("digest length = %d, want 64", len(first))
	}
}

func TestSpecValidateRejectsIncompleteOrUnownedContracts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*TestSpec)
		field  string
	}{
		{name: "api version", mutate: func(spec *TestSpec) { spec.APIVersion = "v1" }, field: "api_version"},
		{name: "stable id", mutate: func(spec *TestSpec) { spec.ID = "not stable!" }, field: "id"},
		{name: "family", mutate: func(spec *TestSpec) { spec.Family = "free_form_go" }, field: "family"},
		{name: "subject", mutate: func(spec *TestSpec) { spec.Subject = "" }, field: "subject"},
		{name: "behavior", mutate: func(spec *TestSpec) { spec.Behavior = "" }, field: "behavior"},
		{name: "signal kind", mutate: func(spec *TestSpec) { spec.Signal.Kind = "coverage" }, field: "signal.kind"},
		{name: "signal reference", mutate: func(spec *TestSpec) { spec.Signal.Reference = "" }, field: "signal.reference"},
		{name: "oracle kind", mutate: func(spec *TestSpec) { spec.Oracle.Kind = "implementation_snapshot" }, field: "oracle.kind"},
		{name: "oracle assertion", mutate: func(spec *TestSpec) { spec.Oracle.Assertion = "" }, field: "oracle.assertion"},
		{name: "fixture kind", mutate: func(spec *TestSpec) { spec.Fixture.Kind = "runtime_payload" }, field: "fixture.kind"},
		{name: "schema ref", mutate: func(spec *TestSpec) { spec.Fixture.SchemaRef = "" }, field: "fixture.schema_ref"},
		{name: "generator name", mutate: func(spec *TestSpec) { spec.Generator.Name = "" }, field: "generator.name"},
		{name: "generator version", mutate: func(spec *TestSpec) { spec.Generator.Version = "" }, field: "generator.version"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := validSpec()
			test.mutate(&spec)
			err := spec.Validate()
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("Validate() error = %v, want ValidationError", err)
			}
			if !hasIssue(validationErr.Issues, test.field) {
				t.Fatalf("issues = %#v, want field %q", validationErr.Issues, test.field)
			}
		})
	}
}

func TestNewValidationReceiptBindsGateToNormalizedSpec(t *testing.T) {
	spec := validSpec()
	receipt, err := NewValidationReceipt(spec, " reproducibility ", ReceiptPassed, " byte-identical output ")
	if err != nil {
		t.Fatalf("NewValidationReceipt() error = %v", err)
	}
	digest, err := spec.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	if receipt.SpecID != spec.ID || receipt.SpecDigest != digest {
		t.Fatalf("receipt identity = %#v, want id %q digest %q", receipt, spec.ID, digest)
	}
	if receipt.Gate != "reproducibility" || receipt.Detail != "byte-identical output" {
		t.Fatalf("receipt text = %#v, want normalized values", receipt)
	}
	if receipt.Generator != spec.Generator.Name || receipt.GeneratorVersion != spec.Generator.Version {
		t.Fatalf("receipt generator = %#v, want specification generator", receipt)
	}
}

func TestNewValidationReceiptRejectsUnknownStatus(t *testing.T) {
	_, err := NewValidationReceipt(validSpec(), "contract", "unknown", "")
	if err == nil {
		t.Fatal("NewValidationReceipt() error = nil, want unsupported status")
	}
}

func validSpec() TestSpec {
	return TestSpec{
		APIVersion: APIVersion,
		ID:         "finding-rule-unrelated-close",
		Family:     FamilyFindingRule,
		Subject:    "github-secret-scanning-disabled",
		Behavior:   "unrelated events do not close an open finding",
		Signal: Signal{
			Kind:      SignalContractGap,
			Reference: "finding-lifecycle/unrelated-close",
		},
		Oracle: Oracle{
			Kind:      OracleLifecycleContract,
			Assertion: "finding_status == open",
		},
		Fixture: Fixture{
			Kind:      FixtureSyntheticEventSequence,
			SchemaRef: "github/audit/v1",
		},
		Generator: Generator{
			Name:    "finding_rule_fixture",
			Version: "v1",
		},
	}
}

func hasIssue(issues []ValidationIssue, field string) bool {
	for _, issue := range issues {
		if issue.Field == field {
			return true
		}
	}
	return false
}
