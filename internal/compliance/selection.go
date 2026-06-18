package compliance

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type ControlSelection struct {
	ID                    string               `json:"id" yaml:"id"`
	Name                  string               `json:"name" yaml:"name"`
	Description           string               `json:"description,omitempty" yaml:"description,omitempty"`
	IncludeProfiles       []string             `json:"include_profiles,omitempty" yaml:"include_profiles,omitempty"`
	Frameworks            []FrameworkSelection `json:"frameworks,omitempty" yaml:"frameworks,omitempty"`
	IncludeControls       []ControlRef         `json:"include_controls,omitempty" yaml:"include_controls,omitempty"`
	ExcludeControls       []ControlRef         `json:"exclude_controls,omitempty" yaml:"exclude_controls,omitempty"`
	IncludeTags           []string             `json:"include_tags,omitempty" yaml:"include_tags,omitempty"`
	ExcludeTags           []string             `json:"exclude_tags,omitempty" yaml:"exclude_tags,omitempty"`
	IncludeOwnerDomains   []string             `json:"include_owner_domains,omitempty" yaml:"include_owner_domains,omitempty"`
	IncludeEvidenceTypes  []string             `json:"include_evidence_types,omitempty" yaml:"include_evidence_types,omitempty"`
	IncludeApplicability  []string             `json:"include_applicability,omitempty" yaml:"include_applicability,omitempty"`
	IncludeAssessments    []string             `json:"include_assessment_methods,omitempty" yaml:"include_assessment_methods,omitempty"`
	IncludeReadiness      []string             `json:"include_readiness,omitempty" yaml:"include_readiness,omitempty"`
	Automatable           *bool                `json:"automatable,omitempty" yaml:"automatable,omitempty"`
	ManualEvidenceAllowed *bool                `json:"manual_evidence_allowed,omitempty" yaml:"manual_evidence_allowed,omitempty"`
}

type FrameworkSelection struct {
	ID         string   `json:"id,omitempty" yaml:"id,omitempty"`
	Name       string   `json:"name,omitempty" yaml:"name,omitempty"`
	IncludeAll bool     `json:"include_all,omitempty" yaml:"include_all,omitempty"`
	Families   []string `json:"families,omitempty" yaml:"families,omitempty"`
	Controls   []string `json:"controls,omitempty" yaml:"controls,omitempty"`
}

type SelectionResolution struct {
	SelectionID string            `json:"selection_id,omitempty"`
	Controls    []ResolvedControl `json:"controls"`
	ControlKeys []string          `json:"control_keys"`
}

type RuleControlMapping struct {
	RuleID      string       `json:"rule_id"`
	ControlRefs []ControlRef `json:"control_refs"`
}

type RuleCoverage struct {
	SelectedControls int                     `json:"selected_controls"`
	MappedRules      []string                `json:"mapped_rules"`
	UnmappedControls []ControlRef            `json:"unmapped_controls"`
	RulesByControl   map[string][]string     `json:"rules_by_control"`
	ControlsByRule   map[string][]ControlRef `json:"controls_by_rule"`
}

func LoadControlSelectionFile(path string) (ControlSelection, error) {
	content, err := readLocalYAMLFile(path) // #nosec G304 -- control selection path is an operator-provided local YAML file; readLocalYAMLFile rejects symlinks.
	if err != nil {
		return ControlSelection{}, err
	}
	return LoadControlSelection(content)
}

func LoadControlSelection(content []byte) (ControlSelection, error) {
	var selection ControlSelection
	if err := yaml.Unmarshal(content, &selection); err != nil {
		return ControlSelection{}, err
	}
	return selection, nil
}

func ResolveControlSelection(index *CatalogIndex, selection ControlSelection) (SelectionResolution, []ValidationIssue) {
	var issues []ValidationIssue
	if index == nil {
		return SelectionResolution{SelectionID: strings.TrimSpace(selection.ID)}, []ValidationIssue{{Message: "control catalog index is required"}}
	}
	issues = append(issues, validateControlReadinessStatuses("include_readiness", selection.IncludeReadiness)...)
	if len(selection.IncludeProfiles) != 0 {
		issues = append(issues, ValidationIssue{Path: "include_profiles", Message: "include_profiles can only be resolved by ResolveControlProfiles"})
	}
	selected := map[string]ResolvedControl{}
	if selectionEmpty(selection) {
		for _, control := range index.Controls() {
			selected[ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID})] = control
		}
	} else {
		for idx, frameworkSelection := range selection.Frameworks {
			controls, frameworkIssues := resolveFrameworkSelection(index, idx, frameworkSelection)
			issues = append(issues, frameworkIssues...)
			for _, control := range controls {
				selected[ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID})] = control
			}
		}
		for idx, ref := range selection.IncludeControls {
			control, ok := index.Control(ref)
			if !ok {
				ref = NormalizeControlRef(ref)
				issues = append(issues, ValidationIssue{Message: fmt.Sprintf("include_controls[%d] %s %s is not declared", idx, firstNonEmpty(ref.FrameworkName, ref.FrameworkID), ref.ControlID)})
				continue
			}
			selected[ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID})] = control
		}
		if selectionHasControlFilters(selection) {
			for _, control := range index.Controls() {
				if controlMatchesSelectionFilters(control, selection) {
					selected[ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID})] = control
				}
			}
		}
	}
	issues = append(issues, applyControlSelectionExclusions(index, selected, selection)...)
	return controlSelectionResolution(strings.TrimSpace(selection.ID), selected), issues
}

func applyControlSelectionExclusions(index *CatalogIndex, selected map[string]ResolvedControl, selection ControlSelection) []ValidationIssue {
	var issues []ValidationIssue
	if index == nil {
		if len(selection.ExcludeControls) != 0 {
			return []ValidationIssue{{Path: "exclude_controls", Message: "control catalog index is required"}}
		}
		return nil
	}
	for idx, ref := range selection.ExcludeControls {
		control, ok := index.Control(ref)
		if !ok {
			ref = NormalizeControlRef(ref)
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("exclude_controls[%d] %s %s is not declared", idx, firstNonEmpty(ref.FrameworkName, ref.FrameworkID), ref.ControlID)})
			continue
		}
		delete(selected, ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID}))
	}
	for key, control := range selected {
		if hasAnyFold(control.EffectiveTags, selection.ExcludeTags) {
			delete(selected, key)
		}
	}
	return issues
}

func controlSelectionResolution(selectionID string, selected map[string]ResolvedControl) SelectionResolution {
	result := SelectionResolution{SelectionID: strings.TrimSpace(selectionID)}
	for key, control := range selected {
		result.ControlKeys = append(result.ControlKeys, key)
		result.Controls = append(result.Controls, control)
	}
	sort.Strings(result.ControlKeys)
	sortResolvedControls(result.Controls)
	return result
}

func ResolveRuleCoverage(resolution SelectionResolution, rules []RuleControlMapping) RuleCoverage {
	selected := map[string]ControlRef{}
	aliases := map[string][]string{}
	for _, control := range resolution.Controls {
		ref := ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID}
		selectedKey := ControlKey(ref)
		selected[selectedKey] = ref
		aliases[selectedKey] = appendUniqueString(aliases[selectedKey], selectedKey)
		for _, mappedRef := range control.Control.MapsTo {
			mappedRef = NormalizeControlRef(mappedRef)
			if mappedRef.ControlID == "" || (mappedRef.FrameworkID == "" && mappedRef.FrameworkName == "") {
				continue
			}
			mappedKey := ControlKey(mappedRef)
			aliases[mappedKey] = appendUniqueString(aliases[mappedKey], selectedKey)
		}
	}
	coverage := RuleCoverage{
		SelectedControls: len(selected),
		RulesByControl:   map[string][]string{},
		ControlsByRule:   map[string][]ControlRef{},
	}
	mappedRules := map[string]struct{}{}
	for _, rule := range rules {
		ruleID := strings.TrimSpace(rule.RuleID)
		if ruleID == "" {
			continue
		}
		for _, ref := range rule.ControlRefs {
			candidateKey := ControlKey(ref)
			selectedKeys := aliases[candidateKey]
			if len(selectedKeys) == 0 {
				continue
			}
			for _, selectedKey := range selectedKeys {
				selectedRef, ok := selected[selectedKey]
				if !ok {
					continue
				}
				mappedRules[ruleID] = struct{}{}
				coverage.RulesByControl[selectedKey] = appendUniqueString(coverage.RulesByControl[selectedKey], ruleID)
				coverage.ControlsByRule[ruleID] = appendUniqueControlRef(coverage.ControlsByRule[ruleID], selectedRef)
			}
		}
	}
	for ruleID := range mappedRules {
		coverage.MappedRules = append(coverage.MappedRules, ruleID)
	}
	sort.Strings(coverage.MappedRules)
	for key, ref := range selected {
		if len(coverage.RulesByControl[key]) == 0 {
			coverage.UnmappedControls = append(coverage.UnmappedControls, ref)
		}
	}
	sort.Slice(coverage.UnmappedControls, func(i, j int) bool {
		return ControlKey(coverage.UnmappedControls[i]) < ControlKey(coverage.UnmappedControls[j])
	})
	for key := range coverage.RulesByControl {
		sort.Strings(coverage.RulesByControl[key])
	}
	for ruleID := range coverage.ControlsByRule {
		sort.Slice(coverage.ControlsByRule[ruleID], func(i, j int) bool {
			return ControlKey(coverage.ControlsByRule[ruleID][i]) < ControlKey(coverage.ControlsByRule[ruleID][j])
		})
	}
	return coverage
}

func resolveFrameworkSelection(index *CatalogIndex, idx int, selection FrameworkSelection) ([]ResolvedControl, []ValidationIssue) {
	ref := ControlRef{FrameworkID: strings.TrimSpace(selection.ID), FrameworkName: strings.TrimSpace(selection.Name)}
	var issues []ValidationIssue
	if ref.FrameworkID == "" && ref.FrameworkName == "" {
		return nil, []ValidationIssue{{Message: fmt.Sprintf("frameworks[%d].name or frameworks[%d].id is required", idx, idx)}}
	}
	if selection.IncludeAll || (len(selection.Families) == 0 && len(selection.Controls) == 0) {
		controls, ok := index.FrameworkControls(ref)
		if !ok {
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("frameworks[%d] %s is not declared", idx, firstNonEmpty(ref.FrameworkName, ref.FrameworkID))})
		}
		return controls, issues
	}
	selected := map[string]ResolvedControl{}
	for familyIdx, familyID := range selection.Families {
		familyID = strings.TrimSpace(familyID)
		if familyID == "" {
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("frameworks[%d].families[%d] is required", idx, familyIdx)})
			continue
		}
		controls, ok := index.FamilyControls(firstNonEmpty(ref.FrameworkName, ref.FrameworkID), familyID)
		if !ok {
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("frameworks[%d].families[%d] %s is not declared", idx, familyIdx, familyID)})
			continue
		}
		for _, control := range controls {
			selected[ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID})] = control
		}
	}
	for controlIdx, controlID := range selection.Controls {
		controlID = strings.TrimSpace(controlID)
		if controlID == "" {
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("frameworks[%d].controls[%d] is required", idx, controlIdx)})
			continue
		}
		control, ok := index.Control(ControlRef{FrameworkID: ref.FrameworkID, FrameworkName: ref.FrameworkName, ControlID: controlID})
		if !ok {
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("frameworks[%d].controls[%d] %s is not declared", idx, controlIdx, controlID)})
			continue
		}
		selected[ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID})] = control
	}
	controls := make([]ResolvedControl, 0, len(selected))
	for _, control := range selected {
		controls = append(controls, control)
	}
	sortResolvedControls(controls)
	return controls, issues
}

func selectionEmpty(selection ControlSelection) bool {
	return len(selection.IncludeProfiles) == 0 &&
		len(selection.Frameworks) == 0 &&
		len(selection.IncludeControls) == 0 &&
		len(selection.IncludeTags) == 0 &&
		len(selection.IncludeOwnerDomains) == 0 &&
		len(selection.IncludeEvidenceTypes) == 0 &&
		len(selection.IncludeApplicability) == 0 &&
		len(selection.IncludeAssessments) == 0 &&
		len(selection.IncludeReadiness) == 0 &&
		selection.Automatable == nil &&
		selection.ManualEvidenceAllowed == nil
}

func selectionHasControlFilters(selection ControlSelection) bool {
	return len(selection.IncludeTags) != 0 ||
		len(selection.IncludeOwnerDomains) != 0 ||
		len(selection.IncludeEvidenceTypes) != 0 ||
		len(selection.IncludeApplicability) != 0 ||
		len(selection.IncludeAssessments) != 0 ||
		len(selection.IncludeReadiness) != 0 ||
		selection.Automatable != nil ||
		selection.ManualEvidenceAllowed != nil
}

func controlMatchesSelectionFilters(control ResolvedControl, selection ControlSelection) bool {
	if len(selection.IncludeTags) != 0 && !hasAnyFold(control.EffectiveTags, selection.IncludeTags) {
		return false
	}
	if len(selection.IncludeOwnerDomains) != 0 && !stringSetContainsFold(selection.IncludeOwnerDomains, control.Control.OwnerDomain) {
		return false
	}
	if len(selection.IncludeEvidenceTypes) != 0 && !controlHasEvidenceType(control, selection.IncludeEvidenceTypes) {
		return false
	}
	if len(selection.IncludeApplicability) != 0 && !hasAnyFold(control.Control.Applicability, selection.IncludeApplicability) {
		return false
	}
	if len(selection.IncludeAssessments) != 0 && !controlHasAssessmentMethod(control, selection.IncludeAssessments) {
		return false
	}
	if len(selection.IncludeReadiness) != 0 && !controlReadinessMatches(EvaluateControlReadiness(control).Status, selection.IncludeReadiness) {
		return false
	}
	if selection.Automatable != nil && !controlBoolMatches(control.Control.Automatable, *selection.Automatable) {
		return false
	}
	if selection.ManualEvidenceAllowed != nil && !controlBoolMatches(control.Control.ManualEvidenceAllowed, *selection.ManualEvidenceAllowed) {
		return false
	}
	return true
}

func controlHasEvidenceType(control ResolvedControl, evidenceTypes []string) bool {
	for _, expectation := range control.Evidence {
		if stringSetContainsFold(evidenceTypes, expectation.Type) {
			return true
		}
	}
	return false
}

func controlHasAssessmentMethod(control ResolvedControl, methods []string) bool {
	if hasAnyFold(control.Control.AssessmentMethods, methods) {
		return true
	}
	for _, expectation := range control.Evidence {
		if hasAnyFold(expectation.AssessmentMethods, methods) {
			return true
		}
	}
	return false
}

func controlBoolMatches(value *bool, want bool) bool {
	return value != nil && *value == want
}

func hasAnyFold(values []string, needles []string) bool {
	for _, value := range values {
		if stringSetContainsFold(needles, value) {
			return true
		}
	}
	return false
}

func stringSetContainsFold(values []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), needle) {
			return true
		}
	}
	return false
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueControlRef(values []ControlRef, value ControlRef) []ControlRef {
	value = NormalizeControlRef(value)
	for _, existing := range values {
		if ControlKey(existing) == ControlKey(value) {
			return values
		}
	}
	return append(values, value)
}
