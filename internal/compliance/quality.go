package compliance

import (
	"fmt"
	"sort"
	"strings"
)

type ControlReadinessStatus string

const (
	ControlReadinessAuditorReady    ControlReadinessStatus = "auditor_ready"
	ControlReadinessNeedsEnrichment ControlReadinessStatus = "needs_enrichment"
	ControlReadinessPlaceholder     ControlReadinessStatus = "placeholder"
)

type ControlReadiness struct {
	Status        ControlReadinessStatus `json:"status" yaml:"status"`
	Score         int                    `json:"score" yaml:"score"`
	MissingFields []string               `json:"missing_fields,omitempty" yaml:"missing_fields,omitempty"`
}

type controlReadinessCheck struct {
	Field string
	OK    bool
}

func EvaluateControlReadiness(control ResolvedControl) ControlReadiness {
	expectations := control.Evidence
	if len(expectations) == 0 && len(control.Control.EvidenceExpectations) != 0 {
		expectations = control.Control.EvidenceExpectations
	}
	checks := []controlReadinessCheck{
		{Field: "title", OK: strings.TrimSpace(control.Control.Title) != ""},
		{Field: "objective", OK: strings.TrimSpace(control.Control.Objective) != ""},
		{Field: "intent", OK: strings.TrimSpace(control.Control.Intent) != ""},
		{Field: "applicability", OK: hasNonEmptyString(control.Control.Applicability)},
		{Field: "assessment_methods", OK: hasNonEmptyString(control.Control.AssessmentMethods)},
		{Field: "implementation_guidance", OK: hasNonEmptyString(control.Control.ImplementationGuidance)},
		{Field: "audit_procedure", OK: hasNonEmptyString(control.Control.AuditProcedure)},
		{Field: "failure_modes", OK: hasNonEmptyString(control.Control.FailureModes)},
		{Field: "remediation_guidance", OK: hasNonEmptyString(control.Control.RemediationGuidance)},
		{Field: "exception_guidance", OK: strings.TrimSpace(control.Control.ExceptionGuidance) != ""},
		{Field: "freshness_sla", OK: strings.TrimSpace(control.Control.FreshnessSLA) != ""},
		{Field: "owner_domain", OK: strings.TrimSpace(control.Control.OwnerDomain) != ""},
		{Field: "automatable", OK: control.Control.Automatable != nil},
		{Field: "manual_evidence_allowed", OK: control.Control.ManualEvidenceAllowed != nil},
		{Field: "evidence_expectations", OK: len(expectations) != 0},
		{Field: "evidence_expectations.title", OK: evidenceExpectationsHaveTitle(expectations)},
		{Field: "evidence_expectations.description", OK: evidenceExpectationsHaveDescription(expectations)},
		{Field: "evidence_expectations.required", OK: evidenceExpectationsHaveRequired(expectations)},
		{Field: "evidence_expectations.assessment_methods", OK: evidenceExpectationsHaveAssessmentMethods(expectations)},
		{Field: "evidence_expectations.freshness_sla", OK: evidenceExpectationsHaveFreshness(expectations, control.Control.FreshnessSLA)},
		{Field: "evidence_expectations.accepted_from", OK: evidenceExpectationsHaveAcceptedFrom(expectations)},
	}
	missing := []string{}
	for _, check := range checks {
		if !check.OK {
			missing = append(missing, check.Field)
		}
	}
	sort.Strings(missing)
	score := 100
	if len(checks) != 0 {
		score = ((len(checks) - len(missing)) * 100) / len(checks)
	}
	return ControlReadiness{
		Status:        controlReadinessStatus(score, missing),
		Score:         score,
		MissingFields: missing,
	}
}

func controlReadinessStatus(score int, missing []string) ControlReadinessStatus {
	if len(missing) == 0 {
		return ControlReadinessAuditorReady
	}
	if score < 50 {
		return ControlReadinessPlaceholder
	}
	return ControlReadinessNeedsEnrichment
}

func validateControlReadinessStatuses(path string, values []string) []ValidationIssue {
	var issues []ValidationIssue
	for idx, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		switch ControlReadinessStatus(normalized) {
		case ControlReadinessAuditorReady, ControlReadinessNeedsEnrichment, ControlReadinessPlaceholder:
		default:
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("%s[%d] must be one of auditor_ready, needs_enrichment, placeholder", path, idx)})
		}
	}
	return issues
}

func controlReadinessMatches(status ControlReadinessStatus, values []string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), string(status)) {
			return true
		}
	}
	return false
}

func hasNonEmptyString(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func evidenceExpectationsHaveTitle(expectations []EvidenceExpectation) bool {
	if len(expectations) == 0 {
		return false
	}
	for _, expectation := range expectations {
		if strings.TrimSpace(expectation.Title) == "" {
			return false
		}
	}
	return true
}

func evidenceExpectationsHaveDescription(expectations []EvidenceExpectation) bool {
	if len(expectations) == 0 {
		return false
	}
	for _, expectation := range expectations {
		if strings.TrimSpace(expectation.Description) == "" {
			return false
		}
	}
	return true
}

func evidenceExpectationsHaveRequired(expectations []EvidenceExpectation) bool {
	if len(expectations) == 0 {
		return false
	}
	for _, expectation := range expectations {
		if expectation.Required == nil {
			return false
		}
	}
	return true
}

func evidenceExpectationsHaveAssessmentMethods(expectations []EvidenceExpectation) bool {
	if len(expectations) == 0 {
		return false
	}
	for _, expectation := range expectations {
		if !hasNonEmptyString(expectation.AssessmentMethods) {
			return false
		}
	}
	return true
}

func evidenceExpectationsHaveFreshness(expectations []EvidenceExpectation, fallback string) bool {
	if len(expectations) == 0 {
		return false
	}
	for _, expectation := range expectations {
		expectation = expectationWithControlFreshness(expectation, fallback)
		if strings.TrimSpace(expectation.FreshnessSLA) == "" {
			return false
		}
	}
	return true
}

func evidenceExpectationsHaveAcceptedFrom(expectations []EvidenceExpectation) bool {
	if len(expectations) == 0 {
		return false
	}
	for _, expectation := range expectations {
		if !hasNonEmptyString(expectation.AcceptedFrom) {
			return false
		}
	}
	return true
}
