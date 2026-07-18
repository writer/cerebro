package findingrule

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/writer/cerebro/internal/findings"
	"github.com/writer/cerebro/internal/testauthor"
)

type Case string

const (
	CasePositiveOpen             Case = "positive_open"
	CaseNegativeNonOpen          Case = "negative_non_open"
	CaseMissingRequiredAttribute Case = "missing_required_attribute"
	CaseStableFingerprint        Case = "stable_fingerprint"
	CaseRemediationClose         Case = "remediation_close"
	CaseUnrelatedNonClose        Case = "unrelated_non_close"
	CaseDeprovisionClose         Case = "deprovision_close"
	CaseCrossTenantIsolation     Case = "cross_tenant_isolation"
	CaseRepeatEventIdempotency   Case = "repeat_event_idempotency"
	CaseRetiredNonOpen           Case = "retired_non_open"
)

type Contract struct {
	Definition               findings.RuleDefinition
	SupportsCounterEvents    bool
	SupportsDeprovisionClose bool
}

func RequiredCases(contract Contract) ([]Case, error) {
	if err := validateContract(contract); err != nil {
		return nil, err
	}
	definition := contract.Definition
	if definition.Lifecycle.Kind == findings.LifecycleRetired {
		return []Case{CaseRetiredNonOpen}, nil
	}

	cases := []Case{
		CasePositiveOpen,
		CaseNegativeNonOpen,
	}
	if len(definition.RequiredAttributes) > 0 || len(definition.RequiredAttributesByKind) > 0 {
		cases = append(cases, CaseMissingRequiredAttribute)
	}
	if len(definition.FingerprintFields) > 0 {
		cases = append(cases, CaseStableFingerprint)
	}
	if contract.SupportsCounterEvents {
		cases = append(cases, CaseRemediationClose)
	}
	if definition.Lifecycle.Kind == findings.LifecycleDurableState {
		cases = append(cases, CaseUnrelatedNonClose)
	}
	if contract.SupportsDeprovisionClose {
		cases = append(cases, CaseDeprovisionClose)
	}
	cases = append(cases, CaseCrossTenantIsolation, CaseRepeatEventIdempotency)
	return cases, nil
}

func AuthorMissing(contract Contract, covered []Case) ([]testauthor.TestSpec, error) {
	required, err := RequiredCases(contract)
	if err != nil {
		return nil, err
	}
	coveredSet := make(map[Case]struct{}, len(covered))
	for _, testCase := range covered {
		if !validCase(testCase) {
			return nil, fmt.Errorf("unsupported finding-rule test case %q", testCase)
		}
		coveredSet[testCase] = struct{}{}
	}

	specs := make([]testauthor.TestSpec, 0, len(required))
	for _, testCase := range required {
		if _, ok := coveredSet[testCase]; ok {
			continue
		}
		spec := specForCase(contract.Definition, testCase)
		if err := spec.Validate(); err != nil {
			return nil, fmt.Errorf("validate generated specification for %s: %w", testCase, err)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func validateContract(contract Contract) error {
	if err := contract.Definition.Validate(); err != nil {
		return fmt.Errorf("validate finding rule definition: %w", err)
	}
	if contract.SupportsCounterEvents && contract.Definition.Lifecycle.Kind != findings.LifecycleDurableState {
		return fmt.Errorf("finding rule %q counter events require durable_state lifecycle", contract.Definition.ID)
	}
	if contract.SupportsDeprovisionClose && !contract.SupportsCounterEvents {
		return fmt.Errorf("finding rule %q deprovision close requires counter-event support", contract.Definition.ID)
	}
	return nil
}

func specForCase(definition findings.RuleDefinition, testCase Case) testauthor.TestSpec {
	oracle, fixture, behavior := caseContract(testCase)
	return testauthor.TestSpec{
		APIVersion: testauthor.APIVersion,
		ID:         stablePart(definition.ID) + "-" + strings.ReplaceAll(string(testCase), "_", "-"),
		Family:     testauthor.FamilyFindingRule,
		Subject:    strings.TrimSpace(definition.ID),
		Behavior:   behavior,
		Signal: testauthor.Signal{
			Kind:      testauthor.SignalContractGap,
			Reference: "finding-rule/" + strings.TrimSpace(definition.ID) + "/" + string(testCase),
		},
		Oracle: testauthor.Oracle{
			Kind:      oracle,
			Assertion: assertionForCase(testCase),
		},
		Fixture: testauthor.Fixture{
			Kind:      fixture,
			SchemaRef: strings.TrimSpace(definition.SourceID) + "/synthetic/v1",
		},
		Generator: testauthor.Generator{
			Name:    "finding_rule_fixture",
			Version: "v1",
		},
	}
}

func caseContract(testCase Case) (testauthor.OracleKind, testauthor.FixtureKind, string) {
	switch testCase {
	case CasePositiveOpen:
		return testauthor.OracleSchemaContract, testauthor.FixtureSyntheticEvent, "matching evidence opens the finding"
	case CaseNegativeNonOpen:
		return testauthor.OracleSchemaContract, testauthor.FixtureSyntheticEvent, "unmatched evidence does not open the finding"
	case CaseMissingRequiredAttribute:
		return testauthor.OracleSchemaContract, testauthor.FixtureSyntheticEvent, "evidence missing a required attribute does not open the finding"
	case CaseStableFingerprint:
		return testauthor.OracleIdempotencyContract, testauthor.FixtureSyntheticEventSequence, "equivalent evidence preserves the finding fingerprint"
	case CaseRemediationClose:
		return testauthor.OracleLifecycleContract, testauthor.FixtureSyntheticEventSequence, "matching remediation evidence closes the finding"
	case CaseUnrelatedNonClose:
		return testauthor.OracleLifecycleContract, testauthor.FixtureSyntheticEventSequence, "unrelated evidence does not close the finding"
	case CaseDeprovisionClose:
		return testauthor.OracleLifecycleContract, testauthor.FixtureSyntheticEventSequence, "deprovision evidence closes the resource finding"
	case CaseCrossTenantIsolation:
		return testauthor.OracleAuthorizationContract, testauthor.FixtureSyntheticEventSequence, "evidence from another tenant cannot change the finding"
	case CaseRepeatEventIdempotency:
		return testauthor.OracleIdempotencyContract, testauthor.FixtureSyntheticEventSequence, "repeated evidence does not duplicate the finding"
	case CaseRetiredNonOpen:
		return testauthor.OracleLifecycleContract, testauthor.FixtureSyntheticEvent, "retired rules do not open findings"
	default:
		return "", "", ""
	}
}

func assertionForCase(testCase Case) string {
	switch testCase {
	case CasePositiveOpen:
		return "finding_count == 1"
	case CaseNegativeNonOpen, CaseMissingRequiredAttribute, CaseRetiredNonOpen:
		return "finding_count == 0"
	case CaseStableFingerprint:
		return "first_fingerprint == repeated_fingerprint"
	case CaseRemediationClose, CaseDeprovisionClose:
		return "finding_status == closed"
	case CaseUnrelatedNonClose, CaseCrossTenantIsolation:
		return "finding_status == open"
	case CaseRepeatEventIdempotency:
		return "finding_count == 1"
	default:
		return ""
	}
}

func stablePart(value string) string {
	var result strings.Builder
	separator := false
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if separator && result.Len() > 0 {
				result.WriteByte('-')
			}
			result.WriteRune(r)
			separator = false
			continue
		}
		separator = true
	}
	return strings.Trim(result.String(), "-")
}

func validCase(testCase Case) bool {
	switch testCase {
	case CasePositiveOpen,
		CaseNegativeNonOpen,
		CaseMissingRequiredAttribute,
		CaseStableFingerprint,
		CaseRemediationClose,
		CaseUnrelatedNonClose,
		CaseDeprovisionClose,
		CaseCrossTenantIsolation,
		CaseRepeatEventIdempotency,
		CaseRetiredNonOpen:
		return true
	default:
		return false
	}
}
