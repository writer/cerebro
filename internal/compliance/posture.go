package compliance

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ControlPostureStatus string

const (
	ControlPosturePassing         ControlPostureStatus = "passing"
	ControlPostureFailing         ControlPostureStatus = "failing"
	ControlPostureMissingEvidence ControlPostureStatus = "missing_evidence"
	ControlPostureStaleEvidence   ControlPostureStatus = "stale_evidence"
	ControlPostureManualReview    ControlPostureStatus = "manual_review"
	ControlPostureException       ControlPostureStatus = "exception"
	ControlPostureNotApplicable   ControlPostureStatus = "not_applicable"
)

type ControlPostureInput struct {
	Selection    SelectionResolution      `json:"selection"`
	RuleCoverage RuleCoverage             `json:"rule_coverage"`
	Findings     []ControlFindingSignal   `json:"findings,omitempty"`
	Evidence     []ControlEvidenceSignal  `json:"evidence,omitempty"`
	Overrides    []ControlPostureOverride `json:"overrides,omitempty"`
	Now          time.Time                `json:"-"`
}

type ControlFindingSignal struct {
	ID              string       `json:"id,omitempty"`
	RuleID          string       `json:"rule_id,omitempty"`
	Title           string       `json:"title,omitempty"`
	Status          string       `json:"status,omitempty"`
	Severity        string       `json:"severity,omitempty"`
	ControlRefs     []ControlRef `json:"control_refs,omitempty"`
	FirstObservedAt time.Time    `json:"first_observed_at,omitempty"`
	LastObservedAt  time.Time    `json:"last_observed_at,omitempty"`
}

type ControlEvidenceSignal struct {
	ID           string       `json:"id,omitempty"`
	RuleID       string       `json:"rule_id,omitempty"`
	EvidenceType string       `json:"evidence_type,omitempty"`
	Status       string       `json:"status,omitempty"`
	Source       string       `json:"source,omitempty"`
	ControlRefs  []ControlRef `json:"control_refs,omitempty"`
	ObservedAt   time.Time    `json:"observed_at,omitempty"`
	ExpiresAt    time.Time    `json:"expires_at,omitempty"`
	Manual       bool         `json:"manual,omitempty"`
}

type ControlPostureOverride struct {
	ID          string               `json:"id,omitempty"`
	RuleID      string               `json:"rule_id,omitempty"`
	Status      ControlPostureStatus `json:"status"`
	Reason      string               `json:"reason,omitempty"`
	ControlRefs []ControlRef         `json:"control_refs,omitempty"`
	ObservedAt  time.Time            `json:"observed_at,omitempty"`
	ExpiresAt   time.Time            `json:"expires_at,omitempty"`
}

type ControlPosture struct {
	SelectionID string                       `json:"selection_id,omitempty"`
	Control     ControlPostureControl        `json:"control"`
	Status      ControlPostureStatus         `json:"status"`
	Reasons     []string                     `json:"reasons,omitempty"`
	Tags        []string                     `json:"tags,omitempty"`
	MappedRules []string                     `json:"mapped_rules,omitempty"`
	Findings    ControlPostureFindingSummary `json:"findings,omitempty"`
	Evidence    ControlPostureEvidence       `json:"evidence,omitempty"`
	Overrides   ControlPostureOverrides      `json:"overrides,omitempty"`
}

type ControlPostureControl struct {
	FrameworkID      string `json:"framework_id,omitempty"`
	FrameworkName    string `json:"framework_name"`
	FrameworkVersion string `json:"framework_version,omitempty"`
	FamilyID         string `json:"family_id"`
	FamilyName       string `json:"family_name"`
	ControlID        string `json:"control_id"`
	Title            string `json:"title,omitempty"`
	OwnerDomain      string `json:"owner_domain,omitempty"`
}

type ControlPostureFindingSummary struct {
	OpenFindingIDs []string `json:"open_finding_ids,omitempty"`
}

type ControlPostureEvidence struct {
	EvidenceIDs            []string  `json:"evidence_ids,omitempty"`
	MissingEvidenceIDs     []string  `json:"missing_evidence_ids,omitempty"`
	StaleEvidenceIDs       []string  `json:"stale_evidence_ids,omitempty"`
	ManualEvidenceIDs      []string  `json:"manual_evidence_ids,omitempty"`
	EvidenceExpectationIDs []string  `json:"evidence_expectation_ids,omitempty"`
	RequiredEvidenceIDs    []string  `json:"required_evidence_ids,omitempty"`
	FreshnessSLA           string    `json:"freshness_sla,omitempty"`
	LatestEvidenceAt       time.Time `json:"latest_evidence_at,omitempty"`
	EvidenceDueAt          time.Time `json:"evidence_due_at,omitempty"`
}

type ControlPostureOverrides struct {
	ExceptionIDs     []string `json:"exception_ids,omitempty"`
	NotApplicableIDs []string `json:"not_applicable_ids,omitempty"`
}

type ControlPostureSummary struct {
	SelectionID string                       `json:"selection_id,omitempty"`
	Total       int                          `json:"total"`
	ByStatus    map[ControlPostureStatus]int `json:"by_status"`
}

func EvaluateControlPosture(input ControlPostureInput) []ControlPosture {
	now := input.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	buckets := buildControlPostureBuckets(input, now)
	postures := make([]ControlPosture, 0, len(input.Selection.Controls))
	for _, control := range input.Selection.Controls {
		key := ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID})
		bucket := buckets[key]
		if bucket == nil {
			bucket = &controlPostureBucket{control: control}
		}
		postures = append(postures, evaluateControlPosture(input.Selection.SelectionID, bucket, now))
	}
	sort.Slice(postures, func(i, j int) bool {
		return ControlKey(ControlRef{FrameworkName: postures[i].Control.FrameworkName, ControlID: postures[i].Control.ControlID}) <
			ControlKey(ControlRef{FrameworkName: postures[j].Control.FrameworkName, ControlID: postures[j].Control.ControlID})
	})
	return postures
}

func SummarizeControlPosture(selectionID string, postures []ControlPosture) ControlPostureSummary {
	summary := ControlPostureSummary{
		SelectionID: strings.TrimSpace(selectionID),
		Total:       len(postures),
		ByStatus:    map[ControlPostureStatus]int{},
	}
	for _, posture := range postures {
		summary.ByStatus[posture.Status]++
	}
	return summary
}

type controlPostureBucket struct {
	control      ResolvedControl
	mappedRules  []string
	openFindings []ControlFindingSignal
	evidence     []ControlEvidenceSignal
	overrides    []ControlPostureOverride
}

func buildControlPostureBuckets(input ControlPostureInput, now time.Time) map[string]*controlPostureBucket {
	context := buildControlPostureContext(input.Selection, input.RuleCoverage)
	buckets := map[string]*controlPostureBucket{}
	for _, control := range input.Selection.Controls {
		key := ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID})
		buckets[key] = &controlPostureBucket{
			control:     control,
			mappedRules: append([]string(nil), input.RuleCoverage.RulesByControl[key]...),
		}
	}
	for _, finding := range input.Findings {
		if !findingIsOpen(finding.Status) {
			continue
		}
		for _, key := range matchingPostureControlKeys(context, finding.RuleID, finding.ControlRefs) {
			if bucket := buckets[key]; bucket != nil {
				bucket.openFindings = append(bucket.openFindings, finding)
			}
		}
	}
	for _, evidence := range input.Evidence {
		if !evidenceUsable(evidence.Status) {
			continue
		}
		for _, key := range matchingPostureControlKeys(context, evidence.RuleID, evidence.ControlRefs) {
			if bucket := buckets[key]; bucket != nil {
				bucket.evidence = append(bucket.evidence, evidence)
			}
		}
	}
	for _, override := range input.Overrides {
		if !postureOverrideActive(override, now) {
			continue
		}
		for _, key := range matchingPostureControlKeys(context, override.RuleID, override.ControlRefs) {
			if bucket := buckets[key]; bucket != nil {
				bucket.overrides = append(bucket.overrides, override)
			}
		}
	}
	return buckets
}

type controlPostureContext struct {
	selectedKeys map[string]struct{}
	aliases      map[string][]string
	keysByRuleID map[string][]string
}

func buildControlPostureContext(resolution SelectionResolution, coverage RuleCoverage) controlPostureContext {
	context := controlPostureContext{
		selectedKeys: map[string]struct{}{},
		aliases:      map[string][]string{},
		keysByRuleID: map[string][]string{},
	}
	for _, control := range resolution.Controls {
		ref := ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID}
		selectedKey := ControlKey(ref)
		context.selectedKeys[selectedKey] = struct{}{}
		context.aliases[selectedKey] = appendUniqueString(context.aliases[selectedKey], selectedKey)
		if control.FrameworkID != "" {
			frameworkIDKey := ControlKey(ControlRef{FrameworkID: control.FrameworkID, ControlID: control.Control.ID})
			context.aliases[frameworkIDKey] = appendUniqueString(context.aliases[frameworkIDKey], selectedKey)
		}
		for _, mappedRef := range control.Control.MapsTo {
			mappedKey := ControlKey(mappedRef)
			context.aliases[mappedKey] = appendUniqueString(context.aliases[mappedKey], selectedKey)
		}
	}
	for key, rules := range coverage.RulesByControl {
		if _, ok := context.selectedKeys[key]; !ok {
			continue
		}
		for _, ruleID := range rules {
			ruleID = strings.TrimSpace(ruleID)
			if ruleID == "" {
				continue
			}
			context.keysByRuleID[ruleID] = appendUniqueString(context.keysByRuleID[ruleID], key)
		}
	}
	for ruleID, refs := range coverage.ControlsByRule {
		ruleID = strings.TrimSpace(ruleID)
		if ruleID == "" {
			continue
		}
		for _, ref := range refs {
			for _, key := range context.aliases[ControlKey(ref)] {
				if _, ok := context.selectedKeys[key]; !ok {
					continue
				}
				context.keysByRuleID[ruleID] = appendUniqueString(context.keysByRuleID[ruleID], key)
			}
		}
	}
	for ruleID := range context.keysByRuleID {
		sort.Strings(context.keysByRuleID[ruleID])
	}
	return context
}

func matchingPostureControlKeys(context controlPostureContext, ruleID string, refs []ControlRef) []string {
	keys := []string{}
	ruleID = strings.TrimSpace(ruleID)
	if ruleID != "" {
		keys = appendUniqueStrings(keys, context.keysByRuleID[ruleID]...)
	}
	for _, ref := range refs {
		keys = appendUniqueStrings(keys, context.aliases[ControlKey(ref)]...)
	}
	sort.Strings(keys)
	return keys
}

func evaluateControlPosture(selectionID string, bucket *controlPostureBucket, now time.Time) ControlPosture {
	control := bucket.control
	posture := ControlPosture{
		SelectionID: strings.TrimSpace(selectionID),
		Control: ControlPostureControl{
			FrameworkID:      control.FrameworkID,
			FrameworkName:    control.FrameworkName,
			FrameworkVersion: control.FrameworkVersion,
			FamilyID:         control.FamilyID,
			FamilyName:       control.FamilyName,
			ControlID:        control.Control.ID,
			Title:            control.Control.Title,
			OwnerDomain:      control.Control.OwnerDomain,
		},
		Status:      ControlPosturePassing,
		Tags:        append([]string(nil), control.EffectiveTags...),
		MappedRules: sortedUniqueStrings(bucket.mappedRules),
		Findings: ControlPostureFindingSummary{
			OpenFindingIDs: sortedUniqueStrings(controlFindingIDs(bucket.openFindings)),
		},
		Evidence: ControlPostureEvidence{
			EvidenceIDs:       sortedUniqueStrings(controlEvidenceIDs(bucket.evidence)),
			ManualEvidenceIDs: sortedUniqueStrings(manualEvidenceIDs(bucket.evidence)),
			FreshnessSLA:      effectiveControlFreshnessSLA(control),
		},
		Overrides: ControlPostureOverrides{
			ExceptionIDs:     sortedUniqueStrings(postureOverrideIDs(bucket.overrides, ControlPostureException)),
			NotApplicableIDs: sortedUniqueStrings(postureOverrideIDs(bucket.overrides, ControlPostureNotApplicable)),
		},
	}
	posture.Evidence.EvidenceExpectationIDs, posture.Evidence.RequiredEvidenceIDs = evidenceExpectationIDs(control.Evidence)
	posture.Evidence.LatestEvidenceAt = latestEvidenceTime(bucket.evidence)
	posture.Evidence.EvidenceDueAt = evidenceDueAt(posture.Evidence.LatestEvidenceAt, posture.Evidence.FreshnessSLA)

	if hasPostureOverride(bucket.overrides, ControlPostureNotApplicable) {
		posture.Status = ControlPostureNotApplicable
		posture.Reasons = append(posture.Reasons, overrideReason(bucket.overrides, ControlPostureNotApplicable, "Control is marked not applicable for this assessment scope."))
		return finalizeControlPosture(posture)
	}
	if hasPostureOverride(bucket.overrides, ControlPostureException) {
		posture.Status = ControlPostureException
		posture.Reasons = append(posture.Reasons, overrideReason(bucket.overrides, ControlPostureException, "Control has an active exception for this assessment scope."))
		return finalizeControlPosture(posture)
	}
	if len(bucket.openFindings) > 0 {
		posture.Status = ControlPostureFailing
		posture.Reasons = append(posture.Reasons, fmt.Sprintf("%d open finding(s) indicate the control is not operating as expected.", len(bucket.openFindings)))
		return finalizeControlPosture(posture)
	}

	missingEvidenceIDs, staleEvidenceIDs := assessEvidenceExpectations(control, bucket.evidence, now)
	posture.Evidence.MissingEvidenceIDs = sortedUniqueStrings(missingEvidenceIDs)
	posture.Evidence.StaleEvidenceIDs = sortedUniqueStrings(staleEvidenceIDs)
	if len(posture.Evidence.MissingEvidenceIDs) > 0 {
		posture.Status = ControlPostureMissingEvidence
		posture.Reasons = append(posture.Reasons, missingEvidenceReason(posture.Evidence.MissingEvidenceIDs, posture.MappedRules))
		return finalizeControlPosture(posture)
	}
	if len(posture.Evidence.StaleEvidenceIDs) > 0 {
		posture.Status = ControlPostureStaleEvidence
		posture.Reasons = append(posture.Reasons, fmt.Sprintf("%d evidence item(s) are older than the required freshness window.", len(posture.Evidence.StaleEvidenceIDs)))
		return finalizeControlPosture(posture)
	}
	if postureRequiresManualReview(control, bucket.evidence, bucket.overrides) {
		posture.Status = ControlPostureManualReview
		posture.Reasons = append(posture.Reasons, "Evidence is present but requires human assessment before audit reliance.")
		return finalizeControlPosture(posture)
	}
	posture.Reasons = append(posture.Reasons, "Required evidence is present and no open findings are mapped to the selected control.")
	return finalizeControlPosture(posture)
}

func assessEvidenceExpectations(control ResolvedControl, evidence []ControlEvidenceSignal, now time.Time) ([]string, []string) {
	if len(control.Evidence) == 0 {
		if len(evidence) == 0 {
			return []string{"control-evidence"}, nil
		}
		return nil, staleEvidenceIDsForExpectation(EvidenceExpectation{ID: "control-evidence", FreshnessSLA: control.Control.FreshnessSLA}, evidence, now)
	}
	missing := []string{}
	stale := []string{}
	for _, expectation := range control.Evidence {
		if !evidenceExpectationRequired(expectation) {
			continue
		}
		matches := evidenceForExpectation(expectation, evidence)
		if len(matches) == 0 {
			missing = appendUniqueString(missing, strings.TrimSpace(expectation.ID))
			continue
		}
		stale = appendUniqueStrings(stale, staleEvidenceIDsForExpectation(expectationWithControlFreshness(expectation, control.Control.FreshnessSLA), matches, now)...)
	}
	return missing, stale
}

func evidenceForExpectation(expectation EvidenceExpectation, evidence []ControlEvidenceSignal) []ControlEvidenceSignal {
	expectedType := strings.TrimSpace(expectation.Type)
	if expectedType == "" {
		return append([]ControlEvidenceSignal(nil), evidence...)
	}
	matches := []ControlEvidenceSignal{}
	for _, item := range evidence {
		if strings.EqualFold(strings.TrimSpace(item.EvidenceType), expectedType) {
			matches = append(matches, item)
		}
	}
	return matches
}

func staleEvidenceIDsForExpectation(expectation EvidenceExpectation, evidence []ControlEvidenceSignal, now time.Time) []string {
	stale := []string{}
	window, hasWindow := parseFreshnessWindow(expectation.FreshnessSLA)
	for _, item := range evidence {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			id = strings.TrimSpace(expectation.ID)
		}
		if !item.ExpiresAt.IsZero() && !item.ExpiresAt.After(now) {
			stale = appendUniqueString(stale, id)
			continue
		}
		if hasWindow && !item.ObservedAt.IsZero() && item.ObservedAt.Add(window).Before(now) {
			stale = appendUniqueString(stale, id)
		}
	}
	return stale
}

func expectationWithControlFreshness(expectation EvidenceExpectation, fallback string) EvidenceExpectation {
	if strings.TrimSpace(expectation.FreshnessSLA) == "" {
		expectation.FreshnessSLA = strings.TrimSpace(fallback)
	}
	return expectation
}

func evidenceExpectationRequired(expectation EvidenceExpectation) bool {
	return expectation.Required == nil || *expectation.Required
}

func evidenceExpectationIDs(expectations []EvidenceExpectation) ([]string, []string) {
	all := []string{}
	required := []string{}
	for _, expectation := range expectations {
		id := strings.TrimSpace(expectation.ID)
		if id == "" {
			continue
		}
		all = appendUniqueString(all, id)
		if evidenceExpectationRequired(expectation) {
			required = appendUniqueString(required, id)
		}
	}
	sort.Strings(all)
	sort.Strings(required)
	return all, required
}

func effectiveControlFreshnessSLA(control ResolvedControl) string {
	if value := strings.TrimSpace(control.Control.FreshnessSLA); value != "" {
		return value
	}
	for _, expectation := range control.Evidence {
		if !evidenceExpectationRequired(expectation) {
			continue
		}
		if value := strings.TrimSpace(expectation.FreshnessSLA); value != "" {
			return value
		}
	}
	for _, expectation := range control.Evidence {
		if value := strings.TrimSpace(expectation.FreshnessSLA); value != "" {
			return value
		}
	}
	return ""
}

func postureRequiresManualReview(control ResolvedControl, evidence []ControlEvidenceSignal, overrides []ControlPostureOverride) bool {
	for _, override := range overrides {
		if override.Status == ControlPostureManualReview {
			return true
		}
	}
	for _, item := range evidence {
		if item.Manual {
			return true
		}
	}
	if hasAssessmentMethod(control.Control.AssessmentMethods, "interview") {
		return true
	}
	for _, expectation := range control.Evidence {
		if hasAssessmentMethod(expectation.AssessmentMethods, "interview") {
			return true
		}
	}
	return false
}

func hasAssessmentMethod(values []string, method string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), method) {
			return true
		}
	}
	return false
}

func findingIsOpen(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "open", "finding_status_open":
		return true
	case "resolved", "closed", "suppressed", "finding_status_resolved", "finding_status_suppressed":
		return false
	default:
		return true
	}
}

func evidenceUsable(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "invalid", "rejected", "failed", "error":
		return false
	default:
		return true
	}
}

func postureOverrideActive(override ControlPostureOverride, now time.Time) bool {
	switch override.Status {
	case ControlPostureException, ControlPostureNotApplicable, ControlPostureManualReview:
	default:
		return false
	}
	return override.ExpiresAt.IsZero() || override.ExpiresAt.After(now)
}

func overrideReason(overrides []ControlPostureOverride, status ControlPostureStatus, fallback string) string {
	for _, override := range overrides {
		if override.Status != status {
			continue
		}
		if reason := strings.TrimSpace(override.Reason); reason != "" {
			return reason
		}
	}
	return fallback
}

func missingEvidenceReason(missingEvidenceIDs []string, mappedRules []string) string {
	if len(mappedRules) == 0 {
		return "No mapped rules or evidence are available for this selected control."
	}
	if len(missingEvidenceIDs) == 1 && missingEvidenceIDs[0] == "control-evidence" {
		return "No evidence has been supplied for this selected control."
	}
	return fmt.Sprintf("%d required evidence expectation(s) are missing.", len(missingEvidenceIDs))
}

func latestEvidenceTime(evidence []ControlEvidenceSignal) time.Time {
	var latest time.Time
	for _, item := range evidence {
		if item.ObservedAt.After(latest) {
			latest = item.ObservedAt
		}
	}
	return latest
}

func evidenceDueAt(latest time.Time, freshnessSLA string) time.Time {
	if latest.IsZero() {
		return time.Time{}
	}
	window, ok := parseFreshnessWindow(freshnessSLA)
	if !ok {
		return time.Time{}
	}
	return latest.Add(window)
}

func parseFreshnessWindow(value string) (time.Duration, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return 0, false
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return duration, true
	}
	multiplier := 24 * time.Hour
	switch {
	case strings.HasSuffix(value, "d"):
		value = strings.TrimSpace(strings.TrimSuffix(value, "d"))
	case strings.HasSuffix(value, "w"):
		value = strings.TrimSpace(strings.TrimSuffix(value, "w"))
		multiplier = 7 * 24 * time.Hour
	default:
		return 0, false
	}
	count, err := strconv.Atoi(value)
	if err != nil || count <= 0 {
		return 0, false
	}
	return time.Duration(count) * multiplier, true
}

func controlFindingIDs(findings []ControlFindingSignal) []string {
	ids := []string{}
	for _, finding := range findings {
		if id := strings.TrimSpace(finding.ID); id != "" {
			ids = appendUniqueString(ids, id)
		}
	}
	return ids
}

func controlEvidenceIDs(evidence []ControlEvidenceSignal) []string {
	ids := []string{}
	for _, item := range evidence {
		if id := strings.TrimSpace(item.ID); id != "" {
			ids = appendUniqueString(ids, id)
		}
	}
	return ids
}

func manualEvidenceIDs(evidence []ControlEvidenceSignal) []string {
	ids := []string{}
	for _, item := range evidence {
		if !item.Manual {
			continue
		}
		if id := strings.TrimSpace(item.ID); id != "" {
			ids = appendUniqueString(ids, id)
		}
	}
	return ids
}

func postureOverrideIDs(overrides []ControlPostureOverride, status ControlPostureStatus) []string {
	ids := []string{}
	for _, override := range overrides {
		if override.Status != status {
			continue
		}
		if id := strings.TrimSpace(override.ID); id != "" {
			ids = appendUniqueString(ids, id)
		}
	}
	return ids
}

func hasPostureOverride(overrides []ControlPostureOverride, status ControlPostureStatus) bool {
	for _, override := range overrides {
		if override.Status == status {
			return true
		}
	}
	return false
}

func finalizeControlPosture(posture ControlPosture) ControlPosture {
	posture.Tags = sortedUniqueStrings(posture.Tags)
	posture.MappedRules = sortedUniqueStrings(posture.MappedRules)
	posture.Findings.OpenFindingIDs = sortedUniqueStrings(posture.Findings.OpenFindingIDs)
	posture.Evidence.EvidenceIDs = sortedUniqueStrings(posture.Evidence.EvidenceIDs)
	posture.Evidence.MissingEvidenceIDs = sortedUniqueStrings(posture.Evidence.MissingEvidenceIDs)
	posture.Evidence.StaleEvidenceIDs = sortedUniqueStrings(posture.Evidence.StaleEvidenceIDs)
	posture.Evidence.ManualEvidenceIDs = sortedUniqueStrings(posture.Evidence.ManualEvidenceIDs)
	posture.Evidence.EvidenceExpectationIDs = sortedUniqueStrings(posture.Evidence.EvidenceExpectationIDs)
	posture.Evidence.RequiredEvidenceIDs = sortedUniqueStrings(posture.Evidence.RequiredEvidenceIDs)
	posture.Overrides.ExceptionIDs = sortedUniqueStrings(posture.Overrides.ExceptionIDs)
	posture.Overrides.NotApplicableIDs = sortedUniqueStrings(posture.Overrides.NotApplicableIDs)
	posture.Reasons = sortedUniqueStrings(posture.Reasons)
	return posture
}

func appendUniqueStrings(values []string, additions ...string) []string {
	for _, value := range additions {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		values = appendUniqueString(values, value)
	}
	return values
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	unique := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		unique = appendUniqueString(unique, value)
	}
	sort.Strings(unique)
	return unique
}
