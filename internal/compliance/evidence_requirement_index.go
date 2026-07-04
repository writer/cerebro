package compliance

import (
	"sort"
	"strings"
	"time"
)

type ControlEvidenceRequirementIndex struct {
	version        string
	requirements   []ResolvedControlEvidenceRequirement
	byControl      map[string][]int
	bySourceEntity map[string][]int
	byProfile      map[string][]int
}

type ControlEvidenceRequirementAssessmentStatus string

const (
	ControlEvidenceRequirementSatisfied    ControlEvidenceRequirementAssessmentStatus = "satisfied"
	ControlEvidenceRequirementManualReview ControlEvidenceRequirementAssessmentStatus = "manual_review"
	ControlEvidenceRequirementMissing      ControlEvidenceRequirementAssessmentStatus = "missing"
	ControlEvidenceRequirementMissingField ControlEvidenceRequirementAssessmentStatus = "missing_fields"
	ControlEvidenceRequirementStale        ControlEvidenceRequirementAssessmentStatus = "stale"
)

type ControlEvidenceRequirementAssessmentInput struct {
	Index    *ControlEvidenceRequirementIndex
	Control  ControlRef
	Evidence []ControlEvidenceRequirementSignal
	Now      time.Time
}

type ControlEvidenceRequirementSignal struct {
	ID           string            `json:"id,omitempty"`
	SourceID     string            `json:"source_id,omitempty"`
	EntityType   string            `json:"entity_type,omitempty"`
	EvidenceType string            `json:"evidence_type,omitempty"`
	Status       string            `json:"status,omitempty"`
	Fields       []string          `json:"fields,omitempty"`
	FieldValues  map[string]string `json:"field_values,omitempty"`
	ControlRefs  []ControlRef      `json:"control_refs,omitempty"`
	ObservedAt   time.Time         `json:"observed_at,omitempty"`
	ExpiresAt    time.Time         `json:"expires_at,omitempty"`
	Manual       bool              `json:"manual,omitempty"`
}

type ControlEvidenceRequirementAssessment struct {
	RequirementKey       string                                     `json:"requirement_key"`
	ControlRef           ControlRef                                 `json:"control_ref"`
	ProfileID            string                                     `json:"profile_id"`
	ProfileName          string                                     `json:"profile_name,omitempty"`
	SourceID             string                                     `json:"source_id"`
	EntityType           string                                     `json:"entity_type"`
	RequiredFields       []string                                   `json:"required_fields,omitempty"`
	FreshnessWindow      string                                     `json:"freshness_window,omitempty"`
	AssessmentMethods    []string                                   `json:"assessment_methods,omitempty"`
	ClaimStrength        string                                     `json:"claim_strength,omitempty"`
	SufficiencyRule      string                                     `json:"sufficiency_rule,omitempty"`
	CoverageClaim        string                                     `json:"coverage_claim,omitempty"`
	OverclaimGuard       string                                     `json:"overclaim_guard,omitempty"`
	Status               ControlEvidenceRequirementAssessmentStatus `json:"status"`
	Reason               string                                     `json:"reason,omitempty"`
	NextAction           string                                     `json:"next_action,omitempty"`
	EvidenceIDs          []string                                   `json:"evidence_ids,omitempty"`
	StaleEvidenceIDs     []string                                   `json:"stale_evidence_ids,omitempty"`
	MissingFields        []string                                   `json:"missing_fields,omitempty"`
	ManualReviewRequired bool                                       `json:"manual_review_required,omitempty"`
}

func BuildControlEvidenceRequirementIndex(resolution ControlEvidenceRequirementResolution) *ControlEvidenceRequirementIndex {
	index := &ControlEvidenceRequirementIndex{
		version:        strings.TrimSpace(resolution.Version),
		requirements:   make([]ResolvedControlEvidenceRequirement, 0, len(resolution.Requirements)),
		byControl:      map[string][]int{},
		bySourceEntity: map[string][]int{},
		byProfile:      map[string][]int{},
	}
	for _, requirement := range resolution.Requirements {
		requirement = cloneResolvedControlEvidenceRequirement(requirement)
		idx := len(index.requirements)
		index.requirements = append(index.requirements, requirement)
		index.byControl[controlEvidenceRequirementControlKey(requirement)] = append(index.byControl[controlEvidenceRequirementControlKey(requirement)], idx)
		index.bySourceEntity[controlEvidenceRequirementSourceKey(requirement.SourceRequirement.SourceID, requirement.SourceRequirement.EntityType)] = append(index.bySourceEntity[controlEvidenceRequirementSourceKey(requirement.SourceRequirement.SourceID, requirement.SourceRequirement.EntityType)], idx)
		if profileID := strings.TrimSpace(requirement.ProfileID); profileID != "" {
			index.byProfile[profileID] = append(index.byProfile[profileID], idx)
		}
	}
	for key := range index.byControl {
		sortRequirementIndexes(index.requirements, index.byControl[key])
	}
	for key := range index.bySourceEntity {
		sortRequirementIndexes(index.requirements, index.bySourceEntity[key])
	}
	for key := range index.byProfile {
		sortRequirementIndexes(index.requirements, index.byProfile[key])
	}
	return index
}

func (index *ControlEvidenceRequirementIndex) Version() string {
	if index == nil {
		return ""
	}
	return index.version
}

func (index *ControlEvidenceRequirementIndex) Requirements() []ResolvedControlEvidenceRequirement {
	if index == nil {
		return nil
	}
	return cloneResolvedControlEvidenceRequirements(index.requirements)
}

func (index *ControlEvidenceRequirementIndex) RequirementsForControl(ref ControlRef) []ResolvedControlEvidenceRequirement {
	if index == nil {
		return nil
	}
	return index.requirementsForIndexes(index.byControl[ControlKey(ref)])
}

func (index *ControlEvidenceRequirementIndex) RequirementsForSource(sourceID string, entityType string) []ResolvedControlEvidenceRequirement {
	if index == nil {
		return nil
	}
	return index.requirementsForIndexes(index.bySourceEntity[controlEvidenceRequirementSourceKey(sourceID, entityType)])
}

func (index *ControlEvidenceRequirementIndex) RequirementsForProfile(profileID string) []ResolvedControlEvidenceRequirement {
	if index == nil {
		return nil
	}
	return index.requirementsForIndexes(index.byProfile[strings.TrimSpace(profileID)])
}

func (index *ControlEvidenceRequirementIndex) RequirementKeysForControl(ref ControlRef) []string {
	requirements := index.RequirementsForControl(ref)
	keys := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		keys = appendUniqueString(keys, ControlEvidenceRequirementKey(requirement))
	}
	sort.Strings(keys)
	return keys
}

func AssessControlEvidenceRequirements(input ControlEvidenceRequirementAssessmentInput) []ControlEvidenceRequirementAssessment {
	if input.Index == nil {
		return nil
	}
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	requirements := input.Index.RequirementsForControl(input.Control)
	assessments := make([]ControlEvidenceRequirementAssessment, 0, len(requirements))
	for _, requirement := range requirements {
		assessments = append(assessments, assessControlEvidenceRequirement(requirement, input.Evidence, now))
	}
	sort.Slice(assessments, func(i, j int) bool {
		return assessments[i].RequirementKey < assessments[j].RequirementKey
	})
	return assessments
}

func ControlEvidenceRequirementKey(requirement ResolvedControlEvidenceRequirement) string {
	parts := []string{
		controlEvidenceRequirementControlLabel(requirement),
		strings.TrimSpace(requirement.ProfileID),
		strings.TrimSpace(requirement.SourceRequirement.SourceID),
		strings.TrimSpace(requirement.SourceRequirement.EntityType),
	}
	return strings.Join(parts, "/")
}

func (index *ControlEvidenceRequirementIndex) requirementsForIndexes(indexes []int) []ResolvedControlEvidenceRequirement {
	if len(indexes) == 0 {
		return nil
	}
	requirements := make([]ResolvedControlEvidenceRequirement, 0, len(indexes))
	for _, idx := range indexes {
		if idx < 0 || idx >= len(index.requirements) {
			continue
		}
		requirements = append(requirements, cloneResolvedControlEvidenceRequirement(index.requirements[idx]))
	}
	return requirements
}

func assessControlEvidenceRequirement(requirement ResolvedControlEvidenceRequirement, evidence []ControlEvidenceRequirementSignal, now time.Time) ControlEvidenceRequirementAssessment {
	sourceRequirement := requirement.SourceRequirement
	assessment := ControlEvidenceRequirementAssessment{
		RequirementKey:    ControlEvidenceRequirementKey(requirement),
		ControlRef:        ControlRef{FrameworkID: requirement.FrameworkID, FrameworkName: requirement.FrameworkName, ControlID: requirement.ControlID},
		ProfileID:         strings.TrimSpace(requirement.ProfileID),
		ProfileName:       strings.TrimSpace(requirement.ProfileName),
		SourceID:          strings.TrimSpace(sourceRequirement.SourceID),
		EntityType:        strings.TrimSpace(sourceRequirement.EntityType),
		RequiredFields:    sortedUniqueStrings(sourceRequirement.RequiredFields),
		FreshnessWindow:   strings.TrimSpace(sourceRequirement.FreshnessWindow),
		AssessmentMethods: sortedUniqueStrings(sourceRequirement.AssessmentMethods),
		ClaimStrength:     strings.TrimSpace(sourceRequirement.ClaimStrength),
		SufficiencyRule:   strings.TrimSpace(sourceRequirement.SufficiencyRule),
		CoverageClaim:     strings.TrimSpace(sourceRequirement.CoverageClaim),
		OverclaimGuard:    strings.TrimSpace(sourceRequirement.OverclaimGuard),
		Status:            ControlEvidenceRequirementMissing,
		Reason:            "Required evidence has not been supplied.",
		NextAction:        "Connect the required evidence source or record an approved manual evidence owner.",
	}
	matches := controlEvidenceRequirementMatches(requirement, evidence)
	if len(matches) == 0 {
		return assessment
	}
	assessment.EvidenceIDs = sortedUniqueStrings(controlEvidenceRequirementSignalIDs(matches, assessment.RequirementKey))
	missingFields := []string{}
	staleEvidenceIDs := []string{}
	hasFreshCompleteEvidence := false
	hasCompleteEvidence := false
	for _, signal := range matches {
		signalMissingFields := controlEvidenceRequirementMissingFields(sourceRequirement.RequiredFields, signal)
		if len(signalMissingFields) != 0 {
			missingFields = appendUniqueStrings(missingFields, signalMissingFields...)
			continue
		}
		hasCompleteEvidence = true
		if controlEvidenceRequirementSignalStale(sourceRequirement.FreshnessWindow, signal, now) {
			staleEvidenceIDs = appendUniqueString(staleEvidenceIDs, controlEvidenceRequirementSignalID(signal, assessment.RequirementKey))
			continue
		}
		hasFreshCompleteEvidence = true
	}
	assessment.StaleEvidenceIDs = sortedUniqueStrings(staleEvidenceIDs)
	assessment.MissingFields = sortedUniqueStrings(missingFields)
	assessment.ManualReviewRequired = controlEvidenceRequirementManualReviewRequired(sourceRequirement, matches)
	switch {
	case hasFreshCompleteEvidence && assessment.ManualReviewRequired:
		assessment.Status = ControlEvidenceRequirementManualReview
		assessment.Reason = "Evidence is present and current, but the assessment method requires human review."
		assessment.NextAction = "Review the evidence packet and record the reviewer decision."
	case hasFreshCompleteEvidence:
		assessment.Status = ControlEvidenceRequirementSatisfied
		assessment.Reason = "Required evidence is present and current."
		assessment.NextAction = "Package the evidence and keep the source within the freshness window."
	case hasCompleteEvidence:
		assessment.Status = ControlEvidenceRequirementStale
		assessment.Reason = "Evidence is present but outside the required freshness window."
		assessment.NextAction = "Refresh the evidence source and rerun assessment."
	default:
		assessment.Status = ControlEvidenceRequirementMissingField
		assessment.Reason = "Evidence is present but missing required fields."
		assessment.NextAction = "Add the missing fields to the source projection or evidence packet."
	}
	return assessment
}

func controlEvidenceRequirementMatches(requirement ResolvedControlEvidenceRequirement, evidence []ControlEvidenceRequirementSignal) []ControlEvidenceRequirementSignal {
	matches := []ControlEvidenceRequirementSignal{}
	wantControlKey := controlEvidenceRequirementControlKey(requirement)
	wantSourceID := strings.TrimSpace(requirement.SourceRequirement.SourceID)
	wantEntityType := strings.TrimSpace(requirement.SourceRequirement.EntityType)
	for _, signal := range evidence {
		if !evidenceUsable(signal.Status) {
			continue
		}
		if wantSourceID != "" && !strings.EqualFold(strings.TrimSpace(signal.SourceID), wantSourceID) {
			continue
		}
		if wantEntityType != "" && !strings.EqualFold(strings.TrimSpace(signal.EntityType), wantEntityType) {
			continue
		}
		if len(signal.ControlRefs) != 0 && !controlEvidenceRequirementSignalReferencesControl(signal.ControlRefs, wantControlKey) {
			continue
		}
		matches = append(matches, signal)
	}
	return matches
}

func controlEvidenceRequirementSignalReferencesControl(refs []ControlRef, wantControlKey string) bool {
	for _, ref := range refs {
		if ControlKey(ref) == wantControlKey {
			return true
		}
	}
	return false
}

func controlEvidenceRequirementMissingFields(required []string, signal ControlEvidenceRequirementSignal) []string {
	if len(required) == 0 {
		return nil
	}
	present := map[string]struct{}{}
	for _, field := range signal.Fields {
		if field = strings.ToLower(strings.TrimSpace(field)); field != "" {
			present[field] = struct{}{}
		}
	}
	for field, value := range signal.FieldValues {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if field = strings.ToLower(strings.TrimSpace(field)); field != "" {
			present[field] = struct{}{}
		}
	}
	missing := []string{}
	for _, field := range required {
		trimmed := strings.TrimSpace(field)
		if trimmed == "" {
			continue
		}
		if _, ok := present[strings.ToLower(trimmed)]; !ok {
			missing = appendUniqueString(missing, trimmed)
		}
	}
	sort.Strings(missing)
	return missing
}

func controlEvidenceRequirementSignalStale(freshnessWindow string, signal ControlEvidenceRequirementSignal, now time.Time) bool {
	if !signal.ExpiresAt.IsZero() && !signal.ExpiresAt.After(now) {
		return true
	}
	window, ok := parseFreshnessWindow(freshnessWindow)
	return ok && !signal.ObservedAt.IsZero() && signal.ObservedAt.Add(window).Before(now)
}

func controlEvidenceRequirementManualReviewRequired(requirement ControlEvidenceSourceRequirement, signals []ControlEvidenceRequirementSignal) bool {
	if hasAssessmentMethod(requirement.AssessmentMethods, "interview") {
		return true
	}
	for _, signal := range signals {
		if signal.Manual {
			return true
		}
	}
	return false
}

func controlEvidenceRequirementSignalIDs(signals []ControlEvidenceRequirementSignal, fallback string) []string {
	ids := []string{}
	for _, signal := range signals {
		ids = appendUniqueString(ids, controlEvidenceRequirementSignalID(signal, fallback))
	}
	sort.Strings(ids)
	return ids
}

func controlEvidenceRequirementSignalID(signal ControlEvidenceRequirementSignal, fallback string) string {
	if id := strings.TrimSpace(signal.ID); id != "" {
		return id
	}
	return strings.TrimSpace(fallback)
}

func controlEvidenceRequirementControlKey(requirement ResolvedControlEvidenceRequirement) string {
	return ControlKey(ControlRef{FrameworkID: requirement.FrameworkID, FrameworkName: requirement.FrameworkName, ControlID: requirement.ControlID})
}

func controlEvidenceRequirementControlLabel(requirement ResolvedControlEvidenceRequirement) string {
	framework := firstNonEmpty(requirement.FrameworkName, requirement.FrameworkID)
	controlID := strings.TrimSpace(requirement.ControlID)
	switch {
	case framework != "" && controlID != "":
		return framework + ":" + controlID
	case framework != "":
		return framework
	default:
		return controlID
	}
}

func controlEvidenceRequirementSourceKey(sourceID string, entityType string) string {
	return strings.ToLower(strings.TrimSpace(sourceID)) + "/" + strings.ToLower(strings.TrimSpace(entityType))
}

func sortRequirementIndexes(requirements []ResolvedControlEvidenceRequirement, indexes []int) {
	sort.Slice(indexes, func(i, j int) bool {
		return ControlEvidenceRequirementKey(requirements[indexes[i]]) < ControlEvidenceRequirementKey(requirements[indexes[j]])
	})
}

func cloneResolvedControlEvidenceRequirements(requirements []ResolvedControlEvidenceRequirement) []ResolvedControlEvidenceRequirement {
	if len(requirements) == 0 {
		return nil
	}
	cloned := make([]ResolvedControlEvidenceRequirement, 0, len(requirements))
	for _, requirement := range requirements {
		cloned = append(cloned, cloneResolvedControlEvidenceRequirement(requirement))
	}
	return cloned
}

func cloneResolvedControlEvidenceRequirement(requirement ResolvedControlEvidenceRequirement) ResolvedControlEvidenceRequirement {
	requirement.SourceRequirement.RequiredFields = sortedUniqueStrings(requirement.SourceRequirement.RequiredFields)
	requirement.SourceRequirement.AssessmentMethods = sortedUniqueStrings(requirement.SourceRequirement.AssessmentMethods)
	requirement.ManualEvidenceAllowed = cloneBool(requirement.ManualEvidenceAllowed)
	return requirement
}
