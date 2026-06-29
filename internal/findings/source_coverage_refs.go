package findings

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const maxPublicDetectionSourceCoverageRefs = 12

// SourceCoverageRef links a public detection back to source coverage dimensions
// that can supply evidence for the detection's mapped controls.
type SourceCoverageRef struct {
	SourceID           string                    `json:"source_id"`
	DimensionID        string                    `json:"dimension_id"`
	DimensionType      string                    `json:"dimension_type"`
	SupportLevel       string                    `json:"support_level,omitempty"`
	HighValue          bool                      `json:"high_value,omitempty"`
	Families           []string                  `json:"families,omitempty"`
	EvidenceTypes      []string                  `json:"evidence_types,omitempty"`
	ControlDomains     []string                  `json:"control_domains,omitempty"`
	MatchedControlRefs []ports.FindingControlRef `json:"matched_control_refs,omitempty"`
}

// EnrichPublicDetectionCatalogWithSourceCoverage returns a copy of catalog with
// deterministic links from detections to source coverage dimensions.
func EnrichPublicDetectionCatalogWithSourceCoverage(catalog PublicDetectionCatalog, contracts []sourcecdk.CoverageContract) PublicDetectionCatalog {
	enriched := PublicDetectionCatalog{
		Version:    strings.TrimSpace(catalog.Version),
		Detections: make([]PublicDetection, 0, len(catalog.Detections)),
	}
	for _, detection := range catalog.Detections {
		next := clonePublicDetection(detection)
		next.SourceCoverageRefs = sourceCoverageRefsForDetection(next, contracts)
		enriched.Detections = append(enriched.Detections, next)
	}
	return enriched
}

func sourceCoverageRefsForDetection(detection PublicDetection, contracts []sourcecdk.CoverageContract) []SourceCoverageRef {
	if len(detection.ControlRefs) == 0 || len(contracts) == 0 {
		return nil
	}
	searchText := detectionCoverageSearchText(detection)
	candidates := make([]sourceCoverageCandidate, 0)
	for _, contract := range contracts {
		sourceID := strings.TrimSpace(contract.SourceID)
		if sourceID == "" {
			continue
		}
		sourceMatched := sourceMatchesDetection(detection, sourceID, searchText)
		sourceConflicted := coverageSourceConflictsWithPolicyDetection(detection.SourceID, sourceID, searchText)
		for _, dimension := range contract.Dimensions {
			dimensionMatched := dimensionMatchesDetection(dimension, searchText)
			evidenceMatched := evidenceMatchesDetection(detection.EvidenceType, dimension.EvidenceTypes)
			coverageRefs := dimension.ControlRefs
			// Domain-derived control coverage is credited only within the
			// detection's own (or explicitly named) source and only when the
			// coverage dimension or evidence type also matches. This lets broad
			// control_domains fill missing refs without letting every dimension
			// from the same source inherit every matching framework control.
			if sourceMatched && (dimensionMatched || evidenceMatched) {
				coverageRefs = effectiveCoverageControlRefs(dimension)
			}
			matches, exactControlMatch := matchingCoverageControlRefs(detection.ControlRefs, coverageRefs)
			if len(matches) == 0 || sourceConflicted || !coverageControlMatchAllowed(detection.SourceID, sourceMatched, dimensionMatched, evidenceMatched, exactControlMatch) {
				continue
			}
			matchedControls := appendUniqueMatchedCoverageRefs(nil, matches)
			ref := SourceCoverageRef{
				SourceID:           sourceID,
				DimensionID:        strings.TrimSpace(dimension.ID),
				DimensionType:      strings.TrimSpace(dimension.Type),
				SupportLevel:       strings.TrimSpace(dimension.Support),
				HighValue:          dimension.HighValue,
				Families:           uniqueSortedStrings(dimension.Families),
				EvidenceTypes:      uniqueSortedStrings(dimension.EvidenceTypes),
				ControlDomains:     uniqueSortedStrings(dimension.ControlDomains),
				MatchedControlRefs: matchedControls,
			}
			candidates = append(candidates, sourceCoverageCandidate{
				ref:                ref,
				score:              sourceCoverageCandidateScore(sourceMatched, dimensionMatched, evidenceMatched, exactControlMatch, dimension, len(matchedControls)),
				exactControlMatch:  exactControlMatch,
				dimensionMatched:   dimensionMatched,
				evidenceMatched:    evidenceMatched,
				matchedControlRefs: len(matchedControls),
			})
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i int, j int) bool {
		left := candidates[i]
		right := candidates[j]
		if left.score != right.score {
			return left.score > right.score
		}
		if left.dimensionMatched != right.dimensionMatched {
			return left.dimensionMatched
		}
		if left.evidenceMatched != right.evidenceMatched {
			return left.evidenceMatched
		}
		if left.exactControlMatch != right.exactControlMatch {
			return left.exactControlMatch
		}
		if left.matchedControlRefs != right.matchedControlRefs {
			return left.matchedControlRefs > right.matchedControlRefs
		}
		if left.ref.SourceID != right.ref.SourceID {
			return left.ref.SourceID < right.ref.SourceID
		}
		return left.ref.DimensionID < right.ref.DimensionID
	})
	limit := len(candidates)
	if limit > maxPublicDetectionSourceCoverageRefs {
		limit = maxPublicDetectionSourceCoverageRefs
	}
	refs := make([]SourceCoverageRef, 0, limit)
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		key := candidate.ref.SourceID + "\x00" + candidate.ref.DimensionID
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, candidate.ref)
		if len(refs) == limit {
			break
		}
	}
	return refs
}

type sourceCoverageCandidate struct {
	ref                SourceCoverageRef
	score              int
	exactControlMatch  bool
	dimensionMatched   bool
	evidenceMatched    bool
	matchedControlRefs int
}

func sourceCoverageCandidateScore(sourceMatched bool, dimensionMatched bool, evidenceMatched bool, exactControlMatch bool, dimension sourcecdk.CoverageDimension, matchedControls int) int {
	score := 0
	if sourceMatched {
		score += 10
	}
	if dimensionMatched {
		score += 8
	}
	if evidenceMatched {
		score += 4
	}
	if exactControlMatch {
		score += 3
	}
	if dimension.HighValue {
		score += 2
	}
	switch strings.TrimSpace(dimension.Support) {
	case sourcecdk.CoverageSupportSupported:
		score += 2
	case sourcecdk.CoverageSupportPartial:
		score++
	}
	if matchedControls > 3 {
		matchedControls = 3
	}
	return score + matchedControls
}

func coverageControlMatchAllowed(detectionSourceID string, sourceMatched bool, dimensionMatched bool, evidenceMatched bool, exactControlMatch bool) bool {
	if !sourceMatched && !dimensionMatched {
		return false
	}
	if strings.TrimSpace(detectionSourceID) == policyRuleSourceID && !dimensionMatched {
		return false
	}
	if !exactControlMatch && !dimensionMatched && !evidenceMatched {
		return false
	}
	return true
}

func coverageSourceConflictsWithPolicyDetection(detectionSourceID string, coverageSourceID string, searchText string) bool {
	if strings.TrimSpace(detectionSourceID) != policyRuleSourceID {
		return false
	}
	return cloudProviderCoverageSourceConflicts(coverageSourceID, searchText)
}

var cloudProviderCoverageAliases = map[string][]string{
	"aws":   {"aws", "amazon_web_services"},
	"azure": {"azure", "microsoft_azure"},
	"gcp":   {"gcp", "google_cloud", "google_cloud_platform"},
}

func cloudProviderCoverageSourceConflicts(coverageSourceID string, searchText string) bool {
	sourceID := normalizeCoverageText(coverageSourceID)
	aliases, ok := cloudProviderCoverageAliases[sourceID]
	if !ok {
		return false
	}
	if coverageTextContainsAny(searchText, aliases) {
		return false
	}
	for provider, providerAliases := range cloudProviderCoverageAliases {
		if provider == sourceID {
			continue
		}
		if coverageTextContainsAny(searchText, providerAliases) {
			return true
		}
	}
	return false
}

func coverageTextContainsAny(searchText string, values []string) bool {
	for _, value := range values {
		if coverageTextContains(searchText, value) {
			return true
		}
	}
	return false
}

func appendUniqueMatchedCoverageRefs(base []ports.FindingControlRef, next []ports.FindingControlRef) []ports.FindingControlRef {
	if len(next) == 0 {
		return base
	}
	seen := map[string]struct{}{}
	for _, ref := range base {
		seen[controlRefKey(ref)] = struct{}{}
	}
	for _, ref := range next {
		key := controlRefKey(ref)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		base = append(base, ref)
	}
	sort.Slice(base, func(i int, j int) bool {
		if base[i].FrameworkName != base[j].FrameworkName {
			return base[i].FrameworkName < base[j].FrameworkName
		}
		return base[i].ControlID < base[j].ControlID
	})
	return base
}

func sourceMatchesDetection(detection PublicDetection, sourceID string, searchText string) bool {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return false
	}
	if detectionSourceID := strings.TrimSpace(detection.SourceID); detectionSourceID != "" && detectionSourceID != policyRuleSourceID {
		return strings.EqualFold(detectionSourceID, sourceID)
	}
	for _, alias := range sourceCoverageAliases(sourceID) {
		if coverageTextContains(searchText, alias) {
			return true
		}
	}
	return false
}

func dimensionMatchesDetection(dimension sourcecdk.CoverageDimension, searchText string) bool {
	if coverageTextContains(searchText, dimension.ID) {
		return true
	}
	for _, family := range dimension.Families {
		if coverageTextContains(searchText, family) {
			return true
		}
	}
	return false
}

func evidenceMatchesDetection(evidenceType string, dimensionEvidenceTypes []string) bool {
	evidenceType = normalizeCoverageText(evidenceType)
	if evidenceType == "" {
		return false
	}
	for _, candidate := range dimensionEvidenceTypes {
		if normalizeCoverageText(candidate) == evidenceType {
			return true
		}
	}
	return false
}

// effectiveCoverageControlRefs returns the dimension's declared control refs
// combined with the control refs derived from its declared control_domains. The
// derived refs let coverage dimensions that declare only control_domains (the
// large majority of source contracts) participate in the all-finding compliance
// mapping without hand-authoring control_refs on every dimension. Duplicates are
// harmless because the caller deduplicates matched refs.
func effectiveCoverageControlRefs(dimension sourcecdk.CoverageDimension) []sourcecdk.CoverageControlRef {
	derived := controlRefsForControlDomains(dimension.ControlDomains)
	if len(derived) == 0 {
		return dimension.ControlRefs
	}
	if len(dimension.ControlRefs) == 0 {
		return derived
	}
	combined := make([]sourcecdk.CoverageControlRef, 0, len(dimension.ControlRefs)+len(derived))
	combined = append(combined, dimension.ControlRefs...)
	combined = append(combined, derived...)
	return combined
}

func matchingCoverageControlRefs(detectionRefs []ports.FindingControlRef, coverageRefs []sourcecdk.CoverageControlRef) ([]ports.FindingControlRef, bool) {
	matched := make([]ports.FindingControlRef, 0)
	seen := map[string]struct{}{}
	exact := false
	for _, coverageRef := range coverageRefs {
		for _, detectionRef := range detectionRefs {
			controlMatch, exactControlMatch := coverageControlRefMatches(detectionRef, coverageRef)
			if !controlMatch {
				continue
			}
			if exactControlMatch {
				exact = true
			}
			ref := ports.FindingControlRef{
				FrameworkName: coverageFrameworkLabel(coverageRef),
				ControlID:     strings.TrimSpace(coverageRef.ControlID),
			}
			key := controlRefKey(ref)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			matched = append(matched, ref)
		}
	}
	sort.Slice(matched, func(i int, j int) bool {
		if matched[i].FrameworkName != matched[j].FrameworkName {
			return matched[i].FrameworkName < matched[j].FrameworkName
		}
		return matched[i].ControlID < matched[j].ControlID
	})
	return matched, exact
}

func coverageControlRefMatches(detectionRef ports.FindingControlRef, coverageRef sourcecdk.CoverageControlRef) (bool, bool) {
	if !coverageFrameworkMatches(detectionRef, coverageRef) {
		return false, false
	}
	return coverageControlIDMatches(detectionRef.ControlID, coverageRef.ControlID)
}

func coverageFrameworkMatches(detectionRef ports.FindingControlRef, coverageRef sourcecdk.CoverageControlRef) bool {
	detectionName := normalizeFramework(detectionRef.FrameworkName)
	coverageName := normalizeFramework(coverageRef.FrameworkName)
	if detectionName != "" && coverageName != "" && detectionName == coverageName {
		return true
	}
	coverageID := normalizeFramework(coverageRef.FrameworkID)
	return detectionName != "" && coverageID != "" && detectionName == coverageID
}

func coverageFrameworkLabel(ref sourcecdk.CoverageControlRef) string {
	if value := strings.TrimSpace(ref.FrameworkName); value != "" {
		return value
	}
	return strings.TrimSpace(ref.FrameworkID)
}

func coverageControlIDMatches(left string, right string) (bool, bool) {
	left = normalizeControlID(left)
	right = normalizeControlID(right)
	if left == "" || right == "" {
		return false, false
	}
	if left == right {
		return true, true
	}
	if coverageControlIDIsParent(left, right) || coverageControlIDIsParent(right, left) {
		return true, false
	}
	return false, false
}

func coverageControlIDIsParent(parent string, child string) bool {
	return strings.HasPrefix(child, parent+".") || strings.HasPrefix(child, parent+"-")
}

func detectionCoverageSearchText(detection PublicDetection) string {
	values := []string{
		detection.ID,
		detection.Name,
		detection.Description,
		detection.SourceID,
		detection.EvidenceType,
		strings.Join(detection.Tags, " "),
		strings.Join(detection.EventKinds, " "),
	}
	text := normalizeCoverageText(strings.Join(values, " "))
	if text == "" {
		return ""
	}
	return "_" + text + "_"
}

func coverageTextContains(searchText string, value string) bool {
	token := normalizeCoverageText(value)
	return token != "" && strings.Contains(searchText, "_"+token+"_")
}

func normalizeCoverageText(value string) string {
	var b strings.Builder
	lastUnderscore := true
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

func normalizeFramework(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func normalizeControlID(value string) string {
	normalized := strings.ToUpper(strings.Join(strings.Fields(strings.TrimSpace(value)), ""))
	if normalized == "" {
		return ""
	}
	return normalizeGDPRArticleControlID(normalized)
}

func normalizeGDPRArticleControlID(value string) string {
	for _, prefix := range []string{"ART.", "ART-"} {
		if suffix := strings.TrimPrefix(value, prefix); suffix != value && suffix != "" {
			return "ARTICLE" + suffix
		}
	}
	if len(value) > len("ART") && strings.HasPrefix(value, "ART") {
		suffix := value[len("ART"):]
		first, _ := utf8.DecodeRuneInString(suffix)
		if unicode.IsDigit(first) {
			return "ARTICLE" + suffix
		}
	}
	return value
}

func sourceCoverageAliases(sourceID string) []string {
	sourceID = strings.TrimSpace(sourceID)
	if sourceID == "" {
		return nil
	}
	return uniqueSortedStrings([]string{
		sourceID,
		strings.ReplaceAll(sourceID, "_", "-"),
		strings.ReplaceAll(sourceID, "_", ""),
	})
}

func controlRefKey(ref ports.FindingControlRef) string {
	return normalizeFramework(ref.FrameworkName) + "\x00" + normalizeControlID(ref.ControlID)
}

func clonePublicDetection(detection PublicDetection) PublicDetection {
	return PublicDetection{
		ID:             strings.TrimSpace(detection.ID),
		PackID:         strings.TrimSpace(detection.PackID),
		PackName:       strings.TrimSpace(detection.PackName),
		Name:           strings.TrimSpace(detection.Name),
		Description:    strings.TrimSpace(detection.Description),
		SourceID:       strings.TrimSpace(detection.SourceID),
		EvaluationMode: strings.TrimSpace(detection.EvaluationMode),
		EventKinds:     cloneStringSlice(detection.EventKinds),
		OutputKind:     strings.TrimSpace(detection.OutputKind),
		Severity:       strings.TrimSpace(detection.Severity),
		Status:         strings.TrimSpace(detection.Status),
		Maturity:       strings.TrimSpace(detection.Maturity),
		Tags:           cloneStringSlice(detection.Tags),
		References:     cloneStringSlice(detection.References),
		FalsePositives: cloneStringSlice(detection.FalsePositives),
		Runbook:        strings.TrimSpace(detection.Runbook),
		PublicDetectionAuditDepth: PublicDetectionAuditDepth{
			EvidenceType:      strings.TrimSpace(detection.EvidenceType),
			AssessmentMethods: cloneStringSlice(detection.AssessmentMethods),
			AuditorGuidance:   strings.TrimSpace(detection.AuditorGuidance),
			RiskStatement:     strings.TrimSpace(detection.RiskStatement),
			RemediationIntent: strings.TrimSpace(detection.RemediationIntent),
		},
		RequiredAttributes:       cloneStringSlice(detection.RequiredAttributes),
		RequiredAttributesByKind: cloneStringSliceMap(detection.RequiredAttributesByKind),
		FingerprintFields:        cloneStringSlice(detection.FingerprintFields),
		ControlRefs:              cloneFindingControlRefs(detection.ControlRefs),
		SourceCoverageRefs:       cloneSourceCoverageRefs(detection.SourceCoverageRefs),
	}
}

func cloneSourceCoverageRefs(refs []SourceCoverageRef) []SourceCoverageRef {
	if len(refs) == 0 {
		return nil
	}
	cloned := make([]SourceCoverageRef, 0, len(refs))
	for _, ref := range refs {
		cloned = append(cloned, SourceCoverageRef{
			SourceID:           strings.TrimSpace(ref.SourceID),
			DimensionID:        strings.TrimSpace(ref.DimensionID),
			DimensionType:      strings.TrimSpace(ref.DimensionType),
			SupportLevel:       strings.TrimSpace(ref.SupportLevel),
			HighValue:          ref.HighValue,
			Families:           cloneStringSlice(ref.Families),
			EvidenceTypes:      cloneStringSlice(ref.EvidenceTypes),
			ControlDomains:     cloneStringSlice(ref.ControlDomains),
			MatchedControlRefs: cloneFindingControlRefs(ref.MatchedControlRefs),
		})
	}
	return cloned
}
