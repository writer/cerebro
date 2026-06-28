package compliance

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

const DefaultControlEvidenceRequirementsPath = "internal/compliance/control_evidence_requirements.yaml"

type ControlEvidenceRequirementCatalog struct {
	Version    string                              `json:"version" yaml:"version"`
	Defaults   ControlEvidenceRequirementDefaults  `json:"defaults" yaml:"defaults"`
	ClaimRules []ControlEvidenceClaimRule          `json:"claim_rules,omitempty" yaml:"claim_rules,omitempty"`
	Profiles   []ControlEvidenceRequirementProfile `json:"profiles" yaml:"profiles"`
}

type ControlEvidenceRequirementDefaults struct {
	SourceID                 string   `json:"source_id,omitempty" yaml:"source_id,omitempty"`
	EntityType               string   `json:"entity_type,omitempty" yaml:"entity_type,omitempty"`
	RequiredFields           []string `json:"required_fields,omitempty" yaml:"required_fields,omitempty"`
	FreshnessWindow          string   `json:"freshness_window,omitempty" yaml:"freshness_window,omitempty"`
	AssessmentMethods        []string `json:"assessment_methods,omitempty" yaml:"assessment_methods,omitempty"`
	AuditorGradeEvidence     string   `json:"auditor_grade_evidence,omitempty" yaml:"auditor_grade_evidence,omitempty"`
	ClaimStrength            string   `json:"claim_strength,omitempty" yaml:"claim_strength,omitempty"`
	SufficiencyRule          string   `json:"sufficiency_rule,omitempty" yaml:"sufficiency_rule,omitempty"`
	CoverageClaim            string   `json:"coverage_claim,omitempty" yaml:"coverage_claim,omitempty"`
	OverclaimGuard           string   `json:"overclaim_guard,omitempty" yaml:"overclaim_guard,omitempty"`
	AdjacentControlRationale string   `json:"adjacent_control_rationale,omitempty" yaml:"adjacent_control_rationale,omitempty"`
	ManualEvidenceAllowed    *bool    `json:"manual_evidence_allowed,omitempty" yaml:"manual_evidence_allowed,omitempty"`
}

type ControlEvidenceRequirementProfile struct {
	ID                 string                             `json:"profile_id" yaml:"profile_id"`
	Name               string                             `json:"name" yaml:"name"`
	Fallback           bool                               `json:"fallback,omitempty" yaml:"fallback,omitempty"`
	AppliesTo          ControlEvidenceRequirementSelector `json:"applies_to,omitempty" yaml:"applies_to,omitempty"`
	SourceRequirements []ControlEvidenceSourceRequirement `json:"source_requirements" yaml:"source_requirements"`
}

type ControlEvidenceRequirementSelector struct {
	Frameworks        []string `json:"frameworks,omitempty" yaml:"frameworks,omitempty"`
	FamilyKeywords    []string `json:"family_keywords,omitempty" yaml:"family_keywords,omitempty"`
	ControlIDPrefixes []string `json:"control_id_prefixes,omitempty" yaml:"control_id_prefixes,omitempty"`
}

type ControlEvidenceSourceRequirement struct {
	SourceID                 string   `json:"source_id" yaml:"source_id"`
	EntityType               string   `json:"entity_type" yaml:"entity_type"`
	RequiredFields           []string `json:"required_fields" yaml:"required_fields"`
	FreshnessWindow          string   `json:"freshness_window" yaml:"freshness_window"`
	AssessmentMethods        []string `json:"assessment_methods" yaml:"assessment_methods"`
	AuditorGradeEvidence     string   `json:"auditor_grade_evidence" yaml:"auditor_grade_evidence"`
	ClaimStrength            string   `json:"claim_strength" yaml:"claim_strength"`
	SufficiencyRule          string   `json:"sufficiency_rule" yaml:"sufficiency_rule"`
	CoverageClaim            string   `json:"coverage_claim" yaml:"coverage_claim"`
	OverclaimGuard           string   `json:"overclaim_guard" yaml:"overclaim_guard"`
	AdjacentControlRationale string   `json:"adjacent_control_rationale" yaml:"adjacent_control_rationale"`
}

type ControlEvidenceClaimRule struct {
	ID                       string                             `json:"rule_id" yaml:"rule_id"`
	AppliesTo                ControlEvidenceRequirementSelector `json:"applies_to" yaml:"applies_to"`
	ClaimStrength            string                             `json:"claim_strength" yaml:"claim_strength"`
	SufficiencyRule          string                             `json:"sufficiency_rule" yaml:"sufficiency_rule"`
	CoverageClaim            string                             `json:"coverage_claim" yaml:"coverage_claim"`
	OverclaimGuard           string                             `json:"overclaim_guard" yaml:"overclaim_guard"`
	AdjacentControlRationale string                             `json:"adjacent_control_rationale" yaml:"adjacent_control_rationale"`
}

type ControlEvidenceRequirementResolution struct {
	Version      string                               `json:"version" yaml:"version"`
	Requirements []ResolvedControlEvidenceRequirement `json:"requirements" yaml:"requirements"`
}

type ResolvedControlEvidenceRequirement struct {
	FrameworkID           string                           `json:"framework_id,omitempty" yaml:"framework_id,omitempty"`
	FrameworkName         string                           `json:"framework_name" yaml:"framework_name"`
	FrameworkVersion      string                           `json:"framework_version,omitempty" yaml:"framework_version,omitempty"`
	FrameworkLifecycle    string                           `json:"framework_lifecycle,omitempty" yaml:"framework_lifecycle,omitempty"`
	FamilyID              string                           `json:"family_id" yaml:"family_id"`
	FamilyName            string                           `json:"family_name" yaml:"family_name"`
	ControlID             string                           `json:"control_id" yaml:"control_id"`
	ControlTitle          string                           `json:"control_title,omitempty" yaml:"control_title,omitempty"`
	ProfileID             string                           `json:"profile_id" yaml:"profile_id"`
	ProfileName           string                           `json:"profile_name" yaml:"profile_name"`
	ClaimRuleID           string                           `json:"claim_rule_id,omitempty" yaml:"claim_rule_id,omitempty"`
	SourceRequirement     ControlEvidenceSourceRequirement `json:"source_requirement" yaml:"source_requirement"`
	ManualEvidenceAllowed *bool                            `json:"manual_evidence_allowed,omitempty" yaml:"manual_evidence_allowed,omitempty"`
}

func LoadControlEvidenceRequirementCatalogFile(path string) (ControlEvidenceRequirementCatalog, error) {
	content, err := readLocalYAMLFile(path) // #nosec G304 -- requirement path is an operator-provided local YAML file; readLocalYAMLFile rejects symlinks.
	if err != nil {
		return ControlEvidenceRequirementCatalog{}, err
	}
	return LoadControlEvidenceRequirementCatalog(content)
}

func LoadControlEvidenceRequirementCatalog(content []byte) (ControlEvidenceRequirementCatalog, error) {
	var catalog ControlEvidenceRequirementCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return ControlEvidenceRequirementCatalog{}, err
	}
	return catalog, nil
}

func ValidateControlEvidenceRequirementCatalog(catalog ControlEvidenceRequirementCatalog) []ValidationIssue {
	var issues []ValidationIssue
	if strings.TrimSpace(catalog.Version) == "" {
		issues = append(issues, ValidationIssue{Message: "version is required"})
	}
	if len(catalog.Profiles) == 0 {
		issues = append(issues, ValidationIssue{Message: "profiles is required"})
	}
	profileIDs := map[string]struct{}{}
	hasFallback := false
	claimRuleIDs := map[string]struct{}{}
	for claimRuleIdx, rule := range catalog.ClaimRules {
		path := fmt.Sprintf("claim_rules[%d]", claimRuleIdx)
		ruleID := strings.TrimSpace(rule.ID)
		if ruleID == "" {
			issues = append(issues, ValidationIssue{Message: path + ".rule_id is required"})
		} else if _, ok := claimRuleIDs[ruleID]; ok {
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("claim rule %q is duplicated", ruleID)})
		}
		claimRuleIDs[ruleID] = struct{}{}
		if controlEvidenceRequirementSelectorEmpty(rule.AppliesTo) {
			issues = append(issues, ValidationIssue{Message: path + ".applies_to is required"})
		}
		issues = append(issues, validateControlEvidenceClaimFields(path, controlEvidenceClaimFields{
			ClaimStrength:            rule.ClaimStrength,
			SufficiencyRule:          rule.SufficiencyRule,
			CoverageClaim:            rule.CoverageClaim,
			OverclaimGuard:           rule.OverclaimGuard,
			AdjacentControlRationale: rule.AdjacentControlRationale,
		})...)
	}
	for profileIdx, profile := range catalog.Profiles {
		path := fmt.Sprintf("profiles[%d]", profileIdx)
		profileID := strings.TrimSpace(profile.ID)
		if profileID == "" {
			issues = append(issues, ValidationIssue{Message: path + ".profile_id is required"})
		} else if _, ok := profileIDs[profileID]; ok {
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("profile %q is duplicated", profileID)})
		}
		profileIDs[profileID] = struct{}{}
		if strings.TrimSpace(profile.Name) == "" {
			issues = append(issues, ValidationIssue{Message: path + ".name is required"})
		}
		if profile.Fallback {
			hasFallback = true
		} else if controlEvidenceRequirementSelectorEmpty(profile.AppliesTo) {
			issues = append(issues, ValidationIssue{Message: path + ".applies_to is required unless fallback is true"})
		}
		if len(profile.SourceRequirements) == 0 {
			issues = append(issues, ValidationIssue{Message: path + ".source_requirements is required"})
		}
		for requirementIdx, requirement := range profile.SourceRequirements {
			requirementPath := fmt.Sprintf("%s.source_requirements[%d]", path, requirementIdx)
			merged := MergeControlEvidenceRequirementDefaults(catalog.Defaults, requirement)
			issues = append(issues, validateResolvedControlEvidenceRequirement(requirementPath, merged)...)
		}
	}
	if !hasFallback {
		issues = append(issues, ValidationIssue{Message: "at least one fallback profile is required"})
	}
	return issues
}

func ResolveControlEvidenceRequirements(index *CatalogIndex, catalog ControlEvidenceRequirementCatalog) (ControlEvidenceRequirementResolution, []ValidationIssue) {
	issues := ValidateControlEvidenceRequirementCatalog(catalog)
	result := ControlEvidenceRequirementResolution{Version: strings.TrimSpace(catalog.Version)}
	if index == nil {
		issues = append(issues, ValidationIssue{Message: "control catalog index is required"})
		return result, issues
	}
	for _, control := range index.Controls() {
		profiles := controlEvidenceRequirementProfilesForControl(catalog.Profiles, control)
		if len(profiles) == 0 {
			issues = append(issues, ValidationIssue{
				Path:    ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID}),
				Message: "no control evidence requirement profile matched",
			})
			continue
		}
		claimRule := controlEvidenceClaimRuleForControl(catalog.ClaimRules, control)
		for _, profile := range profiles {
			for _, requirement := range profile.SourceRequirements {
				sourceRequirement := MergeControlEvidenceRequirementDefaults(catalog.Defaults, requirement)
				sourceRequirement = MergeControlEvidenceClaimRule(sourceRequirement, claimRule)
				result.Requirements = append(result.Requirements, ResolvedControlEvidenceRequirement{
					FrameworkID:           control.FrameworkID,
					FrameworkName:         control.FrameworkName,
					FrameworkVersion:      control.FrameworkVersion,
					FrameworkLifecycle:    control.FrameworkLifecycle,
					FamilyID:              control.FamilyID,
					FamilyName:            control.FamilyName,
					ControlID:             control.Control.ID,
					ControlTitle:          strings.TrimSpace(control.Control.Title),
					ProfileID:             strings.TrimSpace(profile.ID),
					ProfileName:           strings.TrimSpace(profile.Name),
					ClaimRuleID:           strings.TrimSpace(claimRule.ID),
					SourceRequirement:     sourceRequirement,
					ManualEvidenceAllowed: cloneBool(catalog.Defaults.ManualEvidenceAllowed),
				})
			}
		}
	}
	sort.Slice(result.Requirements, func(i, j int) bool {
		return controlEvidenceRequirementSortKey(result.Requirements[i]) < controlEvidenceRequirementSortKey(result.Requirements[j])
	})
	return result, issues
}

func MergeControlEvidenceRequirementDefaults(defaults ControlEvidenceRequirementDefaults, requirement ControlEvidenceSourceRequirement) ControlEvidenceSourceRequirement {
	merged := ControlEvidenceSourceRequirement{
		SourceID:                 strings.TrimSpace(defaults.SourceID),
		EntityType:               strings.TrimSpace(defaults.EntityType),
		RequiredFields:           uniqueStrings(defaults.RequiredFields),
		FreshnessWindow:          strings.TrimSpace(defaults.FreshnessWindow),
		AssessmentMethods:        uniqueStrings(defaults.AssessmentMethods),
		AuditorGradeEvidence:     strings.TrimSpace(defaults.AuditorGradeEvidence),
		ClaimStrength:            strings.TrimSpace(defaults.ClaimStrength),
		SufficiencyRule:          strings.TrimSpace(defaults.SufficiencyRule),
		CoverageClaim:            strings.TrimSpace(defaults.CoverageClaim),
		OverclaimGuard:           strings.TrimSpace(defaults.OverclaimGuard),
		AdjacentControlRationale: strings.TrimSpace(defaults.AdjacentControlRationale),
	}
	if value := strings.TrimSpace(requirement.SourceID); value != "" {
		merged.SourceID = value
	}
	if value := strings.TrimSpace(requirement.EntityType); value != "" {
		merged.EntityType = value
	}
	if values := uniqueStrings(requirement.RequiredFields); len(values) != 0 {
		merged.RequiredFields = values
	}
	if value := strings.TrimSpace(requirement.FreshnessWindow); value != "" {
		merged.FreshnessWindow = value
	}
	if values := uniqueStrings(requirement.AssessmentMethods); len(values) != 0 {
		merged.AssessmentMethods = values
	}
	if value := strings.TrimSpace(requirement.AuditorGradeEvidence); value != "" {
		merged.AuditorGradeEvidence = value
	}
	if value := strings.TrimSpace(requirement.ClaimStrength); value != "" {
		merged.ClaimStrength = value
	}
	if value := strings.TrimSpace(requirement.SufficiencyRule); value != "" {
		merged.SufficiencyRule = value
	}
	if value := strings.TrimSpace(requirement.CoverageClaim); value != "" {
		merged.CoverageClaim = value
	}
	if value := strings.TrimSpace(requirement.OverclaimGuard); value != "" {
		merged.OverclaimGuard = value
	}
	if value := strings.TrimSpace(requirement.AdjacentControlRationale); value != "" {
		merged.AdjacentControlRationale = value
	}
	return merged
}

func MergeControlEvidenceClaimRule(requirement ControlEvidenceSourceRequirement, rule ControlEvidenceClaimRule) ControlEvidenceSourceRequirement {
	if value := strings.TrimSpace(rule.ClaimStrength); value != "" {
		requirement.ClaimStrength = value
	}
	if value := strings.TrimSpace(rule.SufficiencyRule); value != "" {
		requirement.SufficiencyRule = value
	}
	if value := strings.TrimSpace(rule.CoverageClaim); value != "" {
		requirement.CoverageClaim = value
	}
	if value := strings.TrimSpace(rule.OverclaimGuard); value != "" {
		requirement.OverclaimGuard = value
	}
	if value := strings.TrimSpace(rule.AdjacentControlRationale); value != "" {
		requirement.AdjacentControlRationale = value
	}
	return requirement
}

func validateResolvedControlEvidenceRequirement(path string, requirement ControlEvidenceSourceRequirement) []ValidationIssue {
	var issues []ValidationIssue
	if strings.TrimSpace(requirement.SourceID) == "" {
		issues = append(issues, ValidationIssue{Message: path + ".source_id is required"})
	}
	if strings.TrimSpace(requirement.EntityType) == "" {
		issues = append(issues, ValidationIssue{Message: path + ".entity_type is required"})
	}
	if !hasNonEmptyString(requirement.RequiredFields) {
		issues = append(issues, ValidationIssue{Message: path + ".required_fields is required"})
	}
	if strings.TrimSpace(requirement.FreshnessWindow) == "" {
		issues = append(issues, ValidationIssue{Message: path + ".freshness_window is required"})
	}
	if !hasNonEmptyString(requirement.AssessmentMethods) {
		issues = append(issues, ValidationIssue{Message: path + ".assessment_methods is required"})
	}
	issues = append(issues, validateAssessmentMethods(path+".assessment_methods", requirement.AssessmentMethods)...)
	if strings.TrimSpace(requirement.AuditorGradeEvidence) == "" {
		issues = append(issues, ValidationIssue{Message: path + ".auditor_grade_evidence is required"})
	}
	issues = append(issues, validateControlEvidenceClaimFields(path, controlEvidenceClaimFields{
		ClaimStrength:            requirement.ClaimStrength,
		SufficiencyRule:          requirement.SufficiencyRule,
		CoverageClaim:            requirement.CoverageClaim,
		OverclaimGuard:           requirement.OverclaimGuard,
		AdjacentControlRationale: requirement.AdjacentControlRationale,
	})...)
	return issues
}

type controlEvidenceClaimFields struct {
	ClaimStrength            string
	SufficiencyRule          string
	CoverageClaim            string
	OverclaimGuard           string
	AdjacentControlRationale string
}

func validateControlEvidenceClaimFields(path string, claim controlEvidenceClaimFields) []ValidationIssue {
	var issues []ValidationIssue
	if strings.TrimSpace(claim.ClaimStrength) == "" {
		issues = append(issues, ValidationIssue{Message: path + ".claim_strength is required"})
	}
	if strings.TrimSpace(claim.SufficiencyRule) == "" {
		issues = append(issues, ValidationIssue{Message: path + ".sufficiency_rule is required"})
	}
	if strings.TrimSpace(claim.CoverageClaim) == "" {
		issues = append(issues, ValidationIssue{Message: path + ".coverage_claim is required"})
	}
	if strings.TrimSpace(claim.OverclaimGuard) == "" {
		issues = append(issues, ValidationIssue{Message: path + ".overclaim_guard is required"})
	}
	if strings.TrimSpace(claim.AdjacentControlRationale) == "" {
		issues = append(issues, ValidationIssue{Message: path + ".adjacent_control_rationale is required"})
	}
	return issues
}

func controlEvidenceRequirementProfilesForControl(profiles []ControlEvidenceRequirementProfile, control ResolvedControl) []ControlEvidenceRequirementProfile {
	var matched []ControlEvidenceRequirementProfile
	var fallback []ControlEvidenceRequirementProfile
	for _, profile := range profiles {
		if profile.Fallback {
			fallback = append(fallback, profile)
			continue
		}
		if controlEvidenceRequirementProfileApplies(profile, control) {
			matched = append(matched, profile)
		}
	}
	if len(matched) != 0 {
		return matched
	}
	return fallback
}

func controlEvidenceClaimRuleForControl(rules []ControlEvidenceClaimRule, control ResolvedControl) ControlEvidenceClaimRule {
	for _, rule := range rules {
		if controlEvidenceRequirementProfileApplies(ControlEvidenceRequirementProfile{
			AppliesTo: rule.AppliesTo,
		}, control) {
			return rule
		}
	}
	return ControlEvidenceClaimRule{}
}

func controlEvidenceRequirementProfileApplies(profile ControlEvidenceRequirementProfile, control ResolvedControl) bool {
	selector := profile.AppliesTo
	if controlEvidenceRequirementSelectorEmpty(selector) {
		return false
	}

	familyKeywords := trimNonEmptyStrings(selector.FamilyKeywords)
	controlIDPrefixes := trimNonEmptyStrings(selector.ControlIDPrefixes)
	if values := trimNonEmptyStrings(selector.Frameworks); len(values) != 0 {
		if !containsStringFold(values, control.FrameworkName) {
			return false
		}
		if len(familyKeywords) == 0 && len(controlIDPrefixes) == 0 {
			return true
		}
	}

	searchText := strings.Join([]string{
		control.FamilyName,
		control.Control.Title,
	}, " ")
	if len(familyKeywords) != 0 && containsAnyKeywordFold(searchText, familyKeywords) {
		return true
	}
	if len(controlIDPrefixes) != 0 && hasAnyPrefixFold(control.Control.ID, controlIDPrefixes) {
		return true
	}
	return false
}

func controlEvidenceRequirementSelectorEmpty(selector ControlEvidenceRequirementSelector) bool {
	return len(trimNonEmptyStrings(selector.Frameworks)) == 0 &&
		len(trimNonEmptyStrings(selector.FamilyKeywords)) == 0 &&
		len(trimNonEmptyStrings(selector.ControlIDPrefixes)) == 0
}

func controlEvidenceRequirementSortKey(requirement ResolvedControlEvidenceRequirement) string {
	return strings.Join([]string{
		requirement.FrameworkName,
		requirement.ControlID,
		requirement.ProfileID,
		requirement.SourceRequirement.SourceID,
		requirement.SourceRequirement.EntityType,
	}, "\x00")
}

func containsStringFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

func containsAnyKeywordFold(value string, needles []string) bool {
	rawValue := strings.ToLower(strings.TrimSpace(value))
	normalizedValue := normalizeKeywordText(value)
	for _, needle := range needles {
		rawNeedle := strings.ToLower(strings.TrimSpace(needle))
		normalizedNeedle := normalizeKeywordText(needle)
		if normalizedNeedle != "" && strings.Contains(" "+normalizedValue+" ", " "+normalizedNeedle+" ") {
			return true
		}
		if rawNeedle != "" && containsKeywordPunctuation(rawNeedle) && strings.Contains(rawValue, rawNeedle) {
			return true
		}
	}
	return false
}

func containsKeywordPunctuation(value string) bool {
	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func normalizeKeywordText(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			continue
		}
		b.WriteRune(' ')
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func hasAnyPrefixFold(value string, prefixes []string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range prefixes {
		if prefix = strings.ToLower(strings.TrimSpace(prefix)); prefix != "" && strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func trimNonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
