package compliance

import (
	"fmt"
	"sort"
	"strings"
)

const CoverageGapExplanationVersion = "2026-06-29"

type CoverageExplanationState string

const (
	CoverageExplanationSourceBacked CoverageExplanationState = "source_backed"
	CoverageExplanationPartial      CoverageExplanationState = "partial"
	CoverageExplanationMissing      CoverageExplanationState = "missing"
)

type CoverageGapExplanationInput struct {
	CoverageFindingContext
	CoverageRequirementContext
	CoverageClaimContext
	CoverageEvidenceContext
}

type CoverageFindingContext struct {
	FindingID             string
	FindingName           string
	FindingSourceID       string
	FindingEvaluationMode string
	FindingPackID         string
	Control               ControlRef
	ControlFamily         string
}

type CoverageRequirementContext struct {
	RequirementProfile      string
	RequirementSourceID     string
	RequirementEntityType   string
	RequiredFields          []string
	FreshnessWindow         string
	PolicyDocumentRequired  bool
	ManualReviewRequired    bool
	ExceptionReviewRequired bool
	SourceFreshnessStatus   string
}

type CoverageClaimContext struct {
	ClaimRuleID              string
	ClaimStrength            string
	CoverageClaim            string
	OverclaimGuard           string
	AdjacentControlRationale string
	ComplianceEvidenceStatus string
	SourceCapabilityStatus   string
	ClaimStatus              string
}

type CoverageEvidenceContext struct {
	SourceFacts        []CoverageSourceFactInput
	PolicyDocumentRefs []string
	ExceptionRefs      []string
	RemediationRefs    []string
}

type CoverageSourceFactInput struct {
	SourceID       string
	DimensionID    string
	DimensionType  string
	SupportLevel   string
	HighValue      bool
	EvidenceTypes  []string
	ControlRefs    []ControlRef
	ProvenanceURNs []string
	Freshness      []string
}

type CoverageGapExplanation struct {
	Version string `json:"version"`
	CoverageGapIdentity
	CoverageGapStatus
	CoverageGapEvidence
	CoverageGapReview
	CoverageGapRefs
}

type CoverageGapIdentity struct {
	FindingID             string `json:"finding_id,omitempty"`
	FindingName           string `json:"finding_name,omitempty"`
	FindingSourceID       string `json:"finding_source_id,omitempty"`
	FindingEvaluationMode string `json:"finding_evaluation_mode,omitempty"`
	FindingPackID         string `json:"finding_pack_id,omitempty"`
	ControlRef            string `json:"control_ref,omitempty"`
	ControlFamily         string `json:"control_family,omitempty"`
	RequirementProfile    string `json:"requirement_profile,omitempty"`
	RequirementSourceID   string `json:"requirement_source_id,omitempty"`
	RequirementEntityType string `json:"requirement_entity_type,omitempty"`
}

type CoverageGapStatus struct {
	CoverageState            CoverageExplanationState `json:"coverage_state"`
	Explanation              string                   `json:"explanation"`
	Confidence               string                   `json:"confidence"`
	ComplianceEvidenceStatus string                   `json:"compliance_evidence_status,omitempty"`
	SourceCapabilityStatus   string                   `json:"source_capability_status,omitempty"`
	ClaimStatus              string                   `json:"claim_status,omitempty"`
}

type CoverageGapEvidence struct {
	GraphEvidence     []CoverageGraphFact        `json:"graph_evidence,omitempty"`
	GraphPath         []CoverageGraphFact        `json:"graph_path,omitempty"`
	BoundedEvidence   []CoverageEvidenceFact     `json:"bounded_evidence,omitempty"`
	SourceCitations   []CoverageCitation         `json:"source_citations,omitempty"`
	PolicyCitations   []CoverageCitation         `json:"policy_citations,omitempty"`
	MissingDimensions []CoverageMissingDimension `json:"missing_dimensions,omitempty"`
	Freshness         CoverageFreshness          `json:"freshness"`
	Provenance        []CoverageProvenance       `json:"provenance,omitempty"`
	UnsupportedClaims []string                   `json:"unsupported_claims,omitempty"`
}

type CoverageGapReview struct {
	Owner                    string             `json:"owner,omitempty"`
	ManualReviewState        string             `json:"manual_review_state,omitempty"`
	EvidencePacketReadiness  string             `json:"evidence_packet_readiness"`
	NextAction               string             `json:"next_action"`
	OverclaimGuard           string             `json:"overclaim_guard,omitempty"`
	AdjacentControlRationale string             `json:"adjacent_control_rationale,omitempty"`
	LLMContext               CoverageLLMContext `json:"llm_context"`
}

type CoverageGapRefs struct {
	PolicyDocumentRefs []string `json:"policy_document_refs,omitempty"`
	ExceptionRefs      []string `json:"exception_refs,omitempty"`
	RemediationRefs    []string `json:"remediation_refs,omitempty"`
}

type CoverageGraphFact struct {
	From     string `json:"from"`
	Relation string `json:"relation"`
	To       string `json:"to"`
	Basis    string `json:"basis,omitempty"`
}

type CoverageEvidenceFact struct {
	SourceID      string   `json:"source_id,omitempty"`
	DimensionID   string   `json:"dimension_id,omitempty"`
	DimensionType string   `json:"dimension_type,omitempty"`
	SupportLevel  string   `json:"support_level,omitempty"`
	HighValue     bool     `json:"high_value,omitempty"`
	EvidenceTypes []string `json:"evidence_types,omitempty"`
	ControlRefs   []string `json:"control_refs,omitempty"`
}

type CoverageMissingDimension struct {
	SourceID     string   `json:"source_id"`
	EntityType   string   `json:"entity_type,omitempty"`
	Fields       []string `json:"fields,omitempty"`
	Requirement  string   `json:"requirement"`
	RecoveryHint string   `json:"recovery_hint"`
}

type CoverageFreshness struct {
	Requirement string   `json:"requirement,omitempty"`
	Status      string   `json:"status"`
	Signals     []string `json:"signals,omitempty"`
}

type CoverageProvenance struct {
	Surface string   `json:"surface"`
	Scope   string   `json:"scope,omitempty"`
	URNs    []string `json:"urns,omitempty"`
	Status  string   `json:"status"`
}

type CoverageCitation struct {
	Surface   string   `json:"surface"`
	Reference string   `json:"reference"`
	URNs      []string `json:"urns,omitempty"`
	Status    string   `json:"status"`
}

type CoverageLLMContext struct {
	Question          string   `json:"question"`
	AnswerBasis       []string `json:"answer_basis,omitempty"`
	MissingDimensions []string `json:"missing_dimensions,omitempty"`
	NextAction        string   `json:"next_action"`
	OverclaimGuard    string   `json:"overclaim_guard,omitempty"`
}

func BuildCoverageGapExplanation(input CoverageGapExplanationInput) CoverageGapExplanation {
	input = normalizeCoverageExplanationInput(input)
	state := coverageExplanationState(input)
	missing := coverageMissingDimensions(input)
	freshness := coverageFreshness(input, state)
	nextAction := coverageNextAction(input, state, missing)
	readiness := coveragePacketReadiness(state, missing)
	owner := coverageOwner(input)
	graphPath := coverageGraphPath(input)
	evidence := coverageEvidenceFacts(input.SourceFacts)
	sourceCitations := coverageSourceCitations(input)
	policyCitations := coveragePolicyCitations(input)
	unsupportedClaims := coverageUnsupportedClaims(input, state, missing, freshness, policyCitations)
	confidence := coverageConfidence(state, missing, freshness, unsupportedClaims)
	explanation := coverageExplanationText(input, state, missing, evidence)
	overclaimGuard := firstCoverageValue(input.OverclaimGuard, defaultCoverageOverclaimGuard(state))
	return CoverageGapExplanation{
		Version: CoverageGapExplanationVersion,
		CoverageGapIdentity: CoverageGapIdentity{
			FindingID:             input.FindingID,
			FindingName:           input.FindingName,
			FindingSourceID:       input.FindingSourceID,
			FindingEvaluationMode: input.FindingEvaluationMode,
			FindingPackID:         input.FindingPackID,
			ControlRef:            controlRefLabel(input.Control),
			ControlFamily:         input.ControlFamily,
			RequirementProfile:    input.RequirementProfile,
			RequirementSourceID:   input.RequirementSourceID,
			RequirementEntityType: input.RequirementEntityType,
		},
		CoverageGapStatus: CoverageGapStatus{
			CoverageState:            state,
			Explanation:              explanation,
			Confidence:               confidence,
			ComplianceEvidenceStatus: input.ComplianceEvidenceStatus,
			SourceCapabilityStatus:   input.SourceCapabilityStatus,
			ClaimStatus:              input.ClaimStatus,
		},
		CoverageGapEvidence: CoverageGapEvidence{
			GraphEvidence:     graphPath,
			GraphPath:         graphPath,
			BoundedEvidence:   evidence,
			SourceCitations:   sourceCitations,
			PolicyCitations:   policyCitations,
			MissingDimensions: missing,
			Freshness:         freshness,
			Provenance:        coverageProvenance(input),
			UnsupportedClaims: unsupportedClaims,
		},
		CoverageGapReview: CoverageGapReview{
			Owner:                    owner,
			ManualReviewState:        coverageManualReviewState(input, state, missing),
			EvidencePacketReadiness:  readiness,
			NextAction:               nextAction,
			OverclaimGuard:           overclaimGuard,
			AdjacentControlRationale: input.AdjacentControlRationale,
			LLMContext: CoverageLLMContext{
				Question:          coverageLLMQuestion(input, state),
				AnswerBasis:       coverageAnswerBasis(input, graphPath, evidence),
				MissingDimensions: missingDimensionLabels(missing),
				NextAction:        nextAction,
				OverclaimGuard:    overclaimGuard,
			},
		},
		CoverageGapRefs: CoverageGapRefs{
			PolicyDocumentRefs: sortedUniqueCoverageStrings(input.PolicyDocumentRefs),
			ExceptionRefs:      sortedUniqueCoverageStrings(input.ExceptionRefs),
			RemediationRefs:    sortedUniqueCoverageStrings(input.RemediationRefs),
		},
	}
}

func normalizeCoverageExplanationInput(input CoverageGapExplanationInput) CoverageGapExplanationInput {
	input.FindingID = strings.TrimSpace(input.FindingID)
	input.FindingName = strings.TrimSpace(input.FindingName)
	input.FindingSourceID = strings.TrimSpace(input.FindingSourceID)
	input.FindingEvaluationMode = strings.TrimSpace(input.FindingEvaluationMode)
	input.FindingPackID = strings.TrimSpace(input.FindingPackID)
	input.Control.FrameworkID = strings.TrimSpace(input.Control.FrameworkID)
	input.Control.FrameworkName = strings.TrimSpace(input.Control.FrameworkName)
	input.Control.Framework = strings.TrimSpace(input.Control.Framework)
	input.Control.ControlID = strings.TrimSpace(input.Control.ControlID)
	input.ControlFamily = strings.TrimSpace(input.ControlFamily)
	input.RequirementProfile = strings.TrimSpace(input.RequirementProfile)
	input.RequirementSourceID = strings.TrimSpace(input.RequirementSourceID)
	input.RequirementEntityType = strings.TrimSpace(input.RequirementEntityType)
	input.RequiredFields = sortedUniqueCoverageStrings(input.RequiredFields)
	input.FreshnessWindow = strings.TrimSpace(input.FreshnessWindow)
	input.ClaimRuleID = strings.TrimSpace(input.ClaimRuleID)
	input.ClaimStrength = strings.TrimSpace(input.ClaimStrength)
	input.CoverageClaim = strings.TrimSpace(input.CoverageClaim)
	input.OverclaimGuard = strings.TrimSpace(input.OverclaimGuard)
	input.AdjacentControlRationale = strings.TrimSpace(input.AdjacentControlRationale)
	input.ComplianceEvidenceStatus = strings.TrimSpace(input.ComplianceEvidenceStatus)
	input.SourceCapabilityStatus = strings.TrimSpace(input.SourceCapabilityStatus)
	input.ClaimStatus = strings.TrimSpace(input.ClaimStatus)
	input.SourceFreshnessStatus = strings.TrimSpace(input.SourceFreshnessStatus)
	return input
}

func coverageExplanationState(input CoverageGapExplanationInput) CoverageExplanationState {
	switch strings.TrimSpace(input.ClaimStatus) {
	case "source_evidence_claim":
		return CoverageExplanationSourceBacked
	case "partial_source_evidence_claim", "requirement_source_available":
		return CoverageExplanationPartial
	case "control_ref_review_claim", "requirement_missing":
		return CoverageExplanationMissing
	}
	switch strings.TrimSpace(input.ComplianceEvidenceStatus) {
	case "source_backed":
		return CoverageExplanationSourceBacked
	case "partial_source_backed", "source_only":
		return CoverageExplanationPartial
	default:
		return CoverageExplanationMissing
	}
}

func coverageMissingDimensions(input CoverageGapExplanationInput) []CoverageMissingDimension {
	if input.RequirementSourceID == "" {
		return nil
	}
	for _, fact := range input.SourceFacts {
		if strings.EqualFold(strings.TrimSpace(fact.SourceID), input.RequirementSourceID) {
			return nil
		}
	}
	requirement := input.RequirementSourceID
	if input.RequirementEntityType != "" {
		requirement += "/" + input.RequirementEntityType
	}
	return []CoverageMissingDimension{{
		SourceID:     input.RequirementSourceID,
		EntityType:   input.RequirementEntityType,
		Fields:       append([]string(nil), input.RequiredFields...),
		Requirement:  requirement,
		RecoveryHint: "Connect this source dimension or assign a manual evidence owner before claiming coverage.",
	}}
}

func coverageFreshness(input CoverageGapExplanationInput, state CoverageExplanationState) CoverageFreshness {
	status := "freshness_requirement_missing"
	if input.SourceFreshnessStatus != "" {
		status = input.SourceFreshnessStatus
	}
	if input.FreshnessWindow != "" {
		status = "freshness_review_required"
	}
	if state == CoverageExplanationSourceBacked && input.FreshnessWindow != "" {
		status = "freshness_requirement_defined"
	}
	if strings.Contains(strings.ToLower(input.SourceFreshnessStatus), "stale") {
		status = "stale_source"
	}
	signals := []string{}
	for _, fact := range input.SourceFacts {
		signals = append(signals, fact.Freshness...)
	}
	return CoverageFreshness{
		Requirement: input.FreshnessWindow,
		Status:      status,
		Signals:     sortedUniqueCoverageStrings(signals),
	}
}

func coverageNextAction(input CoverageGapExplanationInput, state CoverageExplanationState, missing []CoverageMissingDimension) string {
	if len(missing) != 0 {
		return "Connect the required source dimension or document a manual evidence owner."
	}
	if input.PolicyDocumentRequired && len(input.PolicyDocumentRefs) == 0 {
		return "Link the policy document citation before packaging evidence."
	}
	if input.ExceptionReviewRequired || len(input.ExceptionRefs) != 0 {
		return "Review the exception or remediation record before claiming coverage."
	}
	if input.ManualReviewRequired {
		return "Assign manual review and attach the reviewer decision to the evidence packet."
	}
	switch state {
	case CoverageExplanationSourceBacked:
		return "Package runtime evidence and keep freshness within the stated window."
	case CoverageExplanationPartial:
		return "Review the bounded source facts and close any unbacked graph relationship or control requirement."
	default:
		return "Map source facts, evidence packets, policy documents, exceptions, or remediation before claiming coverage."
	}
}

func coveragePacketReadiness(state CoverageExplanationState, missing []CoverageMissingDimension) string {
	if len(missing) != 0 {
		return "missing_required_source_dimensions"
	}
	switch state {
	case CoverageExplanationSourceBacked:
		return "ready_for_packet"
	case CoverageExplanationPartial:
		return "needs_source_review"
	default:
		return "manual_packet_required"
	}
}

func coverageOwner(input CoverageGapExplanationInput) string {
	switch strings.TrimSpace(input.RequirementProfile) {
	case "identity-access":
		return "identity_owner"
	case "privacy-rights":
		return "privacy_owner"
	case "ai-governance":
		return "ai_governance_owner"
	case "payment-card-security":
		return "payment_owner"
	case "vulnerability-remediation":
		return "vulnerability_owner"
	case "network-exposure":
		return "network_owner"
	case "data-protection":
		return "data_owner"
	case "email-authentication":
		return "email_security_owner"
	case "logging-monitoring":
		return "security_operations_owner"
	case "availability-resilience":
		return "resilience_owner"
	case "change-configuration":
		return "change_owner"
	case "governance-risk":
		return "risk_owner"
	default:
		return "control_owner"
	}
}

func coverageManualReviewState(input CoverageGapExplanationInput, state CoverageExplanationState, missing []CoverageMissingDimension) string {
	if input.ExceptionReviewRequired || len(input.ExceptionRefs) != 0 {
		return "exception_review_required"
	}
	if len(missing) != 0 {
		return "owner_review_required"
	}
	if input.ManualReviewRequired {
		return "manual_review_required"
	}
	if state == CoverageExplanationSourceBacked {
		return "packet_review"
	}
	return "manual_review_required"
}

func coverageGraphPath(input CoverageGapExplanationInput) []CoverageGraphFact {
	findingNode := nodeID("finding", input.FindingID)
	controlNode := nodeID("control", controlRefLabel(input.Control))
	steps := []CoverageGraphFact{}
	if findingNode != "" && controlNode != "" {
		steps = append(steps, CoverageGraphFact{From: findingNode, Relation: "maps_to_control", To: controlNode, Basis: "finding control reference"})
	}
	for _, fact := range input.SourceFacts {
		sourceNode := nodeID("source_fact", sourceFactLabel(fact))
		if findingNode != "" && sourceNode != "" {
			steps = append(steps, CoverageGraphFact{From: findingNode, Relation: "supported_by_source_fact", To: sourceNode, Basis: strings.TrimSpace(fact.SupportLevel)})
		}
		if sourceNode != "" && controlNode != "" {
			steps = append(steps, CoverageGraphFact{From: sourceNode, Relation: "backs_control", To: controlNode, Basis: strings.Join(controlRefLabels(fact.ControlRefs), "; ")})
		}
	}
	if controlNode != "" && input.ClaimRuleID != "" {
		steps = append(steps, CoverageGraphFact{From: controlNode, Relation: "requires_framework_evidence", To: nodeID("requirement", input.ClaimRuleID), Basis: input.CoverageClaim})
	}
	if input.RequirementSourceID != "" && input.ClaimRuleID != "" {
		steps = append(steps, CoverageGraphFact{From: nodeID("requirement", input.ClaimRuleID), Relation: "requires_source_dimension", To: nodeID("source_requirement", input.RequirementSourceID+"/"+input.RequirementEntityType), Basis: strings.Join(input.RequiredFields, "; ")})
	}
	return steps
}

func coverageEvidenceFacts(sourceFacts []CoverageSourceFactInput) []CoverageEvidenceFact {
	out := make([]CoverageEvidenceFact, 0, len(sourceFacts))
	for _, fact := range sourceFacts {
		out = append(out, CoverageEvidenceFact{
			SourceID:      strings.TrimSpace(fact.SourceID),
			DimensionID:   strings.TrimSpace(fact.DimensionID),
			DimensionType: strings.TrimSpace(fact.DimensionType),
			SupportLevel:  strings.TrimSpace(fact.SupportLevel),
			HighValue:     fact.HighValue,
			EvidenceTypes: sortedUniqueCoverageStrings(fact.EvidenceTypes),
			ControlRefs:   controlRefLabels(fact.ControlRefs),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return sourceFactSortKey(out[i]) < sourceFactSortKey(out[j])
	})
	return out
}

func coverageProvenance(input CoverageGapExplanationInput) []CoverageProvenance {
	var urns []string
	for _, fact := range input.SourceFacts {
		urns = append(urns, fact.ProvenanceURNs...)
	}
	status := "bounded"
	if len(urns) == 0 {
		status = "derived_from_catalog_and_requirements"
	}
	return []CoverageProvenance{{
		Surface: "compliance-coverage-ops",
		Scope:   firstCoverageValue(input.FindingID, controlRefLabel(input.Control)),
		URNs:    sortedUniqueCoverageStrings(urns),
		Status:  status,
	}}
}

func coverageSourceCitations(input CoverageGapExplanationInput) []CoverageCitation {
	out := make([]CoverageCitation, 0, len(input.SourceFacts))
	for _, fact := range input.SourceFacts {
		reference := sourceFactLabel(fact)
		if reference == "" {
			continue
		}
		out = append(out, CoverageCitation{
			Surface:   "source_fact",
			Reference: reference,
			URNs:      sortedUniqueCoverageStrings(fact.ProvenanceURNs),
			Status:    firstCoverageValue(fact.SupportLevel, "referenced"),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Reference < out[j].Reference
	})
	return out
}

func coveragePolicyCitations(input CoverageGapExplanationInput) []CoverageCitation {
	refs := sortedUniqueCoverageStrings(input.PolicyDocumentRefs)
	out := make([]CoverageCitation, 0, len(refs))
	for _, ref := range refs {
		out = append(out, CoverageCitation{
			Surface:   "policy_document",
			Reference: ref,
			Status:    "referenced",
		})
	}
	return out
}

func coverageUnsupportedClaims(input CoverageGapExplanationInput, state CoverageExplanationState, missing []CoverageMissingDimension, freshness CoverageFreshness, policyCitations []CoverageCitation) []string {
	values := []string{}
	if state != CoverageExplanationSourceBacked {
		values = append(values, "source_backed_coverage_not_established")
	}
	for _, dimension := range missing {
		values = append(values, "missing_required_source_dimension:"+dimension.Requirement)
	}
	if input.PolicyDocumentRequired && len(policyCitations) == 0 {
		values = append(values, "policy_document_not_linked")
	}
	if input.ExceptionReviewRequired || len(input.ExceptionRefs) != 0 {
		values = append(values, "exception_or_remediation_review_required")
	}
	if input.ManualReviewRequired {
		values = append(values, "manual_review_decision_not_attached")
	}
	if strings.Contains(strings.ToLower(freshness.Status), "stale") {
		values = append(values, "stale_source_freshness")
	}
	return sortedUniqueCoverageStrings(values)
}

func coverageConfidence(state CoverageExplanationState, missing []CoverageMissingDimension, freshness CoverageFreshness, unsupportedClaims []string) string {
	if state == CoverageExplanationSourceBacked && len(missing) == 0 && len(unsupportedClaims) == 0 && !strings.Contains(strings.ToLower(freshness.Status), "stale") {
		return "high"
	}
	if state == CoverageExplanationMissing || len(missing) != 0 || strings.Contains(strings.ToLower(freshness.Status), "stale") {
		return "low"
	}
	return "medium"
}

func coverageExplanationText(input CoverageGapExplanationInput, state CoverageExplanationState, missing []CoverageMissingDimension, evidence []CoverageEvidenceFact) string {
	control := controlRefLabel(input.Control)
	switch state {
	case CoverageExplanationSourceBacked:
		return fmt.Sprintf("%s is source-backed because the finding has bounded source facts that match the control and the requirement source.", firstCoverageValue(control, "Control"))
	case CoverageExplanationPartial:
		if len(missing) != 0 {
			return fmt.Sprintf("%s is partial because source facts exist, but required source dimension %s is missing.", firstCoverageValue(control, "Control"), missing[0].Requirement)
		}
		return fmt.Sprintf("%s is partial because source facts exist but still need control or packet review before coverage is claimed.", firstCoverageValue(control, "Control"))
	default:
		if len(evidence) == 0 {
			return fmt.Sprintf("%s is missing source-backed coverage because no bounded source facts are linked to the finding-control requirement.", firstCoverageValue(control, "Control"))
		}
		return fmt.Sprintf("%s is missing source-backed coverage because the linked facts do not satisfy the required control evidence path.", firstCoverageValue(control, "Control"))
	}
}

func coverageLLMQuestion(input CoverageGapExplanationInput, state CoverageExplanationState) string {
	control := firstCoverageValue(controlRefLabel(input.Control), "this control")
	return fmt.Sprintf("Why is %s coverage %s for finding %s?", control, state, firstCoverageValue(input.FindingID, input.FindingName, "this finding"))
}

func coverageAnswerBasis(input CoverageGapExplanationInput, graphPath []CoverageGraphFact, evidence []CoverageEvidenceFact) []string {
	values := []string{}
	if input.ClaimRuleID != "" {
		values = append(values, "claim_rule="+input.ClaimRuleID)
	}
	if input.ClaimStrength != "" {
		values = append(values, "claim_strength_defined")
	}
	if input.CoverageClaim != "" {
		values = append(values, "coverage_claim_defined")
	}
	if len(graphPath) != 0 {
		values = append(values, fmt.Sprintf("graph_path_steps=%d", len(graphPath)))
	}
	if len(evidence) != 0 {
		values = append(values, fmt.Sprintf("bounded_evidence=%d", len(evidence)))
	}
	return values
}

func defaultCoverageOverclaimGuard(state CoverageExplanationState) string {
	if state == CoverageExplanationSourceBacked {
		return "Use only the bounded source facts and freshness window in this explanation; do not claim broader framework coverage."
	}
	return "Do not claim operating effectiveness or framework coverage until the missing dimensions and evidence packet requirements are resolved."
}

func missingDimensionLabels(values []CoverageMissingDimension) []string {
	labels := make([]string, 0, len(values))
	for _, value := range values {
		labels = append(labels, value.Requirement)
	}
	return sortedUniqueCoverageStrings(labels)
}

func controlRefLabels(refs []ControlRef) []string {
	labels := make([]string, 0, len(refs))
	for _, ref := range refs {
		if label := controlRefLabel(ref); label != "" {
			labels = append(labels, label)
		}
	}
	return sortedUniqueCoverageStrings(labels)
}

func controlRefLabel(ref ControlRef) string {
	return strings.TrimSpace(firstCoverageValue(ref.FrameworkName, ref.Framework, ref.FrameworkID) + " " + strings.TrimSpace(ref.ControlID))
}

func sourceFactLabel(fact CoverageSourceFactInput) string {
	sourceID := strings.TrimSpace(fact.SourceID)
	dimensionID := strings.TrimSpace(fact.DimensionID)
	switch {
	case sourceID != "" && dimensionID != "":
		return sourceID + "/" + dimensionID
	case sourceID != "":
		return sourceID
	default:
		return dimensionID
	}
}

func sourceFactSortKey(fact CoverageEvidenceFact) string {
	return strings.Join([]string{fact.SourceID, fact.DimensionID, fact.DimensionType}, "\x00")
}

func nodeID(kind string, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.TrimSpace(kind) + ":" + value
}

func sortedUniqueCoverageStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func firstCoverageValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
