package complianceassessment

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/writer/cerebro/internal/compliance"
)

type conformanceFixture struct {
	Version      string          `json:"version"`
	BaseInput    json.RawMessage `json:"base_input"`
	BaseExpected json.RawMessage `json:"base_expected"`
	Cases        []fixtureCase   `json:"cases"`
}

type fixtureCase struct {
	Name           string          `json:"name"`
	Input          json.RawMessage `json:"input"`
	Expected       json.RawMessage `json:"expected"`
	ExpectedDigest string          `json:"expected_digest"`
}

type fixtureExpected struct {
	ScopeState                  ScopeState                  `json:"scope_state"`
	AutomatedOutcome            AutomatedOutcome            `json:"automated_outcome"`
	DesignState                 DesignState                 `json:"design_state"`
	OperatingEffectivenessState OperatingEffectivenessState `json:"operating_effectiveness_state"`
	EvidenceState               EvidenceState               `json:"evidence_state"`
	DispositionState            DispositionState            `json:"disposition_state"`
	Assurance                   Assurance                   `json:"assurance"`
	AuditorState                AuditorState                `json:"auditor_state"`
	ReasonCodes                 []ReasonCode                `json:"reason_codes"`
	NextActions                 []NextAction                `json:"next_actions"`
	LegacyStatus                string                      `json:"legacy_status"`
}

func TestObjectiveConformanceFixtures(t *testing.T) {
	fixture := loadConformanceFixture(t)
	if fixture.Version != "compliance-assessment-conformance/v1" {
		t.Fatalf("fixture version = %q", fixture.Version)
	}
	if len(fixture.Cases) < 16 {
		t.Fatalf("fixture cases = %d, want at least 16", len(fixture.Cases))
	}
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			input := mergedFixtureValue[EvaluateInput](t, fixture.BaseInput, testCase.Input)
			expectedAxes := mergedFixtureValue[fixtureExpected](t, fixture.BaseExpected, testCase.Expected)
			result, err := EvaluateObjective(input)
			if err != nil {
				t.Fatalf("EvaluateObjective() error = %v", err)
			}
			expected := expectedFixtureResult(input, expectedAxes)
			gotBytes, err := CanonicalResultBytes(result)
			if err != nil {
				t.Fatalf("CanonicalResultBytes(result) error = %v", err)
			}
			wantBytes, err := CanonicalResultBytes(expected)
			if err != nil {
				t.Fatalf("CanonicalResultBytes(expected) error = %v", err)
			}
			if !bytes.Equal(gotBytes, wantBytes) {
				t.Fatalf("canonical result mismatch\n got: %s\nwant: %s", gotBytes, wantBytes)
			}
			if got := LegacyStatus(result); got != expectedAxes.LegacyStatus {
				t.Fatalf("LegacyStatus() = %q, want %q", got, expectedAxes.LegacyStatus)
			}
			digest, err := CanonicalResultDigest(result)
			if err != nil {
				t.Fatalf("CanonicalResultDigest() error = %v", err)
			}
			if testCase.ExpectedDigest == "" {
				t.Errorf("expected_digest is empty; generated %s", digest)
			} else if digest != testCase.ExpectedDigest {
				t.Fatalf("digest = %q, want %q", digest, testCase.ExpectedDigest)
			}
		})
	}
}

func TestObjectiveConformanceIsInvariantToInputOrder(t *testing.T) {
	fixture := loadConformanceFixture(t)
	for _, testCase := range fixture.Cases {
		input := mergedFixtureValue[EvaluateInput](t, fixture.BaseInput, testCase.Input)
		baseline, err := EvaluateObjective(input)
		if err != nil {
			t.Fatalf("%s baseline error = %v", testCase.Name, err)
		}
		baselineBytes, err := CanonicalResultBytes(baseline)
		if err != nil {
			t.Fatalf("%s baseline bytes error = %v", testCase.Name, err)
		}
		for iteration := 0; iteration < 32; iteration++ {
			shuffled := cloneEvaluateInput(input)
			rotateStrings(shuffled.FindingIDs, iteration)
			rotateStrings(shuffled.SourceRuntimeIDs, iteration+1)
			rotateAssessments(shuffled.RequirementAssessments, iteration+2)
			for index := range shuffled.RequirementAssessments {
				rotateStrings(shuffled.RequirementAssessments[index].EvidenceIDs, iteration+index)
			}
			result, err := EvaluateObjective(shuffled)
			if err != nil {
				t.Fatalf("%s iteration %d error = %v", testCase.Name, iteration, err)
			}
			data, err := CanonicalResultBytes(result)
			if err != nil {
				t.Fatalf("%s iteration %d bytes error = %v", testCase.Name, iteration, err)
			}
			if !bytes.Equal(data, baselineBytes) {
				t.Fatalf("%s iteration %d changed canonical bytes", testCase.Name, iteration)
			}
		}
	}
}

func loadConformanceFixture(t *testing.T) conformanceFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/objective_conformance.json") // #nosec G304 -- fixed repository fixture path.
	if err != nil {
		t.Fatalf("read conformance fixture: %v", err)
	}
	var fixture conformanceFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode conformance fixture: %v", err)
	}
	return fixture
}

func mergedFixtureValue[T any](t *testing.T, base json.RawMessage, override json.RawMessage) T {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(base, &fields); err != nil {
		t.Fatalf("decode fixture base: %v", err)
	}
	var overrides map[string]json.RawMessage
	if len(override) != 0 {
		if err := json.Unmarshal(override, &overrides); err != nil {
			t.Fatalf("decode fixture override: %v", err)
		}
	}
	for key, value := range overrides {
		fields[key] = value
	}
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal merged fixture: %v", err)
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode merged fixture: %v", err)
	}
	return result
}

func expectedFixtureResult(input EvaluateInput, expected fixtureExpected) ObjectiveResult {
	evidenceIDs := []string{}
	for _, assessment := range input.RequirementAssessments {
		evidenceIDs = append(evidenceIDs, assessment.EvidenceIDs...)
	}
	return NormalizeResult(ObjectiveResult{
		ID:                          input.ResultID,
		ControlRef:                  input.Control,
		ObjectiveID:                 input.ObjectiveID,
		ScopeState:                  expected.ScopeState,
		AutomatedOutcome:            expected.AutomatedOutcome,
		DesignState:                 expected.DesignState,
		OperatingEffectivenessState: expected.OperatingEffectivenessState,
		EvidenceState:               expected.EvidenceState,
		DispositionState:            expected.DispositionState,
		Assurance:                   expected.Assurance,
		AuditorState:                expected.AuditorState,
		ReasonCodes:                 expected.ReasonCodes,
		NextActions:                 expected.NextActions,
		EvidenceIDs:                 evidenceIDs,
		FindingIDs:                  input.FindingIDs,
		SourceRuntimeIDs:            input.SourceRuntimeIDs,
		EvaluatorRevision:           input.EvaluatorRevision,
		EvaluatedAt:                 input.Now,
	})
}

func cloneEvaluateInput(input EvaluateInput) EvaluateInput {
	clone := input
	clone.FindingIDs = append([]string(nil), input.FindingIDs...)
	clone.SourceRuntimeIDs = append([]string(nil), input.SourceRuntimeIDs...)
	clone.RequirementAssessments = append([]compliance.ControlEvidenceRequirementAssessment(nil), input.RequirementAssessments...)
	for index := range clone.RequirementAssessments {
		clone.RequirementAssessments[index].EvidenceIDs = append([]string(nil), input.RequirementAssessments[index].EvidenceIDs...)
	}
	return clone
}

func rotateStrings(values []string, count int) {
	if len(values) < 2 {
		return
	}
	count %= len(values)
	rotated := append(append([]string(nil), values[count:]...), values[:count]...)
	copy(values, rotated)
}

func rotateAssessments(values []compliance.ControlEvidenceRequirementAssessment, count int) {
	if len(values) < 2 {
		return
	}
	count %= len(values)
	rotated := append(append([]compliance.ControlEvidenceRequirementAssessment(nil), values[count:]...), values[:count]...)
	copy(values, rotated)
}

func TestFixtureNamesAreUnique(t *testing.T) {
	fixture := loadConformanceFixture(t)
	seen := map[string]struct{}{}
	for _, testCase := range fixture.Cases {
		if _, exists := seen[testCase.Name]; exists {
			t.Fatalf("duplicate fixture name %q", testCase.Name)
		}
		seen[testCase.Name] = struct{}{}
	}
}
