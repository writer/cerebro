package compliance

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultControlProfilesPath = "internal/compliance/control_profiles.yaml"
const DefaultControlCoverageIndexPath = "internal/compliance/control_coverage_index.yaml"

type ControlProfileSet struct {
	Version  string             `json:"version" yaml:"version"`
	Profiles []ControlSelection `json:"profiles" yaml:"profiles"`
}

type ControlProfileResolution struct {
	Version  string                   `json:"version" yaml:"version"`
	Profiles []ResolvedControlProfile `json:"profiles" yaml:"profiles"`
}

type ResolvedControlProfile struct {
	Profile    ControlSelection    `json:"profile" yaml:"profile"`
	Resolution SelectionResolution `json:"resolution" yaml:"resolution"`
}

type ControlCoverageIndex struct {
	Version  string                   `json:"version" yaml:"version"`
	Profiles []ControlCoverageProfile `json:"profiles" yaml:"profiles"`
}

type ControlCoverageProfile struct {
	ID               string                   `json:"id" yaml:"id"`
	Name             string                   `json:"name,omitempty" yaml:"name,omitempty"`
	Description      string                   `json:"description,omitempty" yaml:"description,omitempty"`
	Summary          ControlCoverageSummary   `json:"summary" yaml:"summary"`
	Controls         []ControlCoverageControl `json:"controls,omitempty" yaml:"controls,omitempty"`
	Rules            []ControlCoverageRule    `json:"rules,omitempty" yaml:"rules,omitempty"`
	UnmappedControls []ControlRef             `json:"unmapped_controls,omitempty" yaml:"unmapped_controls,omitempty"`
}

type ControlCoverageSummary struct {
	SelectedControls int `json:"selected_controls" yaml:"selected_controls"`
	MappedControls   int `json:"mapped_controls" yaml:"mapped_controls"`
	UnmappedControls int `json:"unmapped_controls" yaml:"unmapped_controls"`
	MappedRules      int `json:"mapped_rules" yaml:"mapped_rules"`
}

type ControlCoverageControl struct {
	FrameworkID            string                       `json:"framework_id,omitempty" yaml:"framework_id,omitempty"`
	FrameworkName          string                       `json:"framework_name" yaml:"framework_name"`
	FrameworkVersion       string                       `json:"framework_version,omitempty" yaml:"framework_version,omitempty"`
	FamilyID               string                       `json:"family_id" yaml:"family_id"`
	FamilyName             string                       `json:"family_name" yaml:"family_name"`
	ControlID              string                       `json:"control_id" yaml:"control_id"`
	Title                  string                       `json:"title,omitempty" yaml:"title,omitempty"`
	OwnerDomain            string                       `json:"owner_domain,omitempty" yaml:"owner_domain,omitempty"`
	Tags                   []string                     `json:"tags,omitempty" yaml:"tags,omitempty"`
	EvidenceExpectationIDs []string                     `json:"evidence_expectation_ids,omitempty" yaml:"evidence_expectation_ids,omitempty"`
	AuditPlan              *ControlCoverageAuditPlan    `json:"audit_plan,omitempty" yaml:"audit_plan,omitempty"`
	EvidencePlan           *ControlCoverageEvidencePlan `json:"evidence_plan,omitempty" yaml:"evidence_plan,omitempty"`
	MappedControlRefs      []ControlRef                 `json:"mapped_control_refs,omitempty" yaml:"mapped_control_refs,omitempty"`
	CoverageStatus         string                       `json:"coverage_status" yaml:"coverage_status"`
	RuleCount              int                          `json:"rule_count" yaml:"rule_count"`
	MappedRules            []string                     `json:"mapped_rules,omitempty" yaml:"mapped_rules,omitempty"`
}

type ControlCoverageAuditPlan struct {
	Objective              string   `json:"objective,omitempty" yaml:"objective,omitempty"`
	Intent                 string   `json:"intent,omitempty" yaml:"intent,omitempty"`
	FreshnessSLA           string   `json:"freshness_sla,omitempty" yaml:"freshness_sla,omitempty"`
	Applicability          []string `json:"applicability,omitempty" yaml:"applicability,omitempty"`
	AssessmentMethods      []string `json:"assessment_methods,omitempty" yaml:"assessment_methods,omitempty"`
	ImplementationGuidance []string `json:"implementation_guidance,omitempty" yaml:"implementation_guidance,omitempty"`
	AuditProcedure         []string `json:"audit_procedure,omitempty" yaml:"audit_procedure,omitempty"`
	FailureModes           []string `json:"failure_modes,omitempty" yaml:"failure_modes,omitempty"`
	RemediationGuidance    []string `json:"remediation_guidance,omitempty" yaml:"remediation_guidance,omitempty"`
	ExceptionGuidance      string   `json:"exception_guidance,omitempty" yaml:"exception_guidance,omitempty"`
	Automatable            *bool    `json:"automatable,omitempty" yaml:"automatable,omitempty"`
	ManualEvidenceAllowed  *bool    `json:"manual_evidence_allowed,omitempty" yaml:"manual_evidence_allowed,omitempty"`
}

type ControlCoverageEvidencePlan struct {
	Expectations []ControlCoverageEvidenceExpectation `json:"expectations,omitempty" yaml:"expectations,omitempty"`
}

type ControlCoverageRule struct {
	RuleID   string       `json:"rule_id" yaml:"rule_id"`
	Controls []ControlRef `json:"controls" yaml:"controls"`
}

type ControlCoverageEvidenceExpectation struct {
	ID                string   `json:"id" yaml:"id"`
	Title             string   `json:"title,omitempty" yaml:"title,omitempty"`
	Type              string   `json:"type" yaml:"type"`
	Required          bool     `json:"required" yaml:"required"`
	Description       string   `json:"description,omitempty" yaml:"description,omitempty"`
	AssessmentMethods []string `json:"assessment_methods,omitempty" yaml:"assessment_methods,omitempty"`
	FreshnessSLA      string   `json:"freshness_sla,omitempty" yaml:"freshness_sla,omitempty"`
	AcceptedFrom      []string `json:"accepted_from,omitempty" yaml:"accepted_from,omitempty"`
}

func LoadControlProfileSetFile(path string) (ControlProfileSet, error) {
	content, err := readLocalYAMLFile(path) // #nosec G304 -- control profile path is an operator-provided local YAML file; readLocalYAMLFile rejects symlinks.
	if err != nil {
		return ControlProfileSet{}, err
	}
	return LoadControlProfileSet(content)
}

func LoadControlProfileSet(content []byte) (ControlProfileSet, error) {
	var set ControlProfileSet
	if err := yaml.Unmarshal(content, &set); err != nil {
		return ControlProfileSet{}, err
	}
	return set, nil
}

func ResolveControlProfiles(index *CatalogIndex, set ControlProfileSet) (ControlProfileResolution, []ValidationIssue) {
	result := ControlProfileResolution{Version: strings.TrimSpace(set.Version)}
	issues := validateControlProfileSet(set)
	profilesByID := controlProfilesByID(set.Profiles)
	for _, profile := range set.Profiles {
		resolution, resolutionIssues := resolveControlProfile(index, profilesByID, profile, nil)
		for _, issue := range resolutionIssues {
			issue.Path = profileIssuePath(profile.ID, issue.Path)
			issues = append(issues, issue)
		}
		result.Profiles = append(result.Profiles, ResolvedControlProfile{
			Profile:    profile,
			Resolution: resolution,
		})
	}
	sort.Slice(result.Profiles, func(i, j int) bool {
		return strings.TrimSpace(result.Profiles[i].Profile.ID) < strings.TrimSpace(result.Profiles[j].Profile.ID)
	})
	return result, issues
}

func resolveControlProfile(index *CatalogIndex, profilesByID map[string]ControlSelection, profile ControlSelection, stack []string) (SelectionResolution, []ValidationIssue) {
	id := strings.TrimSpace(profile.ID)
	if profileIDInStack(stack, id) {
		return SelectionResolution{SelectionID: id}, []ValidationIssue{{
			Path:    "include_profiles",
			Message: "profile include cycle detected: " + strings.Join(append(stack, id), " -> "),
		}}
	}
	stack = append(stack, id)
	selected := map[string]ResolvedControl{}
	issues := []ValidationIssue{}

	direct := profile
	direct.IncludeProfiles = nil
	direct.ExcludeControls = nil
	direct.ExcludeTags = nil
	if !selectionEmpty(direct) || len(profile.IncludeProfiles) == 0 {
		resolution, resolutionIssues := ResolveControlSelection(index, direct)
		issues = append(issues, resolutionIssues...)
		addResolvedControls(selected, resolution.Controls)
	}

	for idx, includeID := range profile.IncludeProfiles {
		includeID = strings.TrimSpace(includeID)
		path := fmt.Sprintf("include_profiles[%d]", idx)
		if includeID == "" {
			issues = append(issues, ValidationIssue{Path: path, Message: "profile id is required"})
			continue
		}
		if profileIDInStack(stack, includeID) {
			cycle := append(append([]string(nil), stack...), includeID)
			issues = append(issues, ValidationIssue{Path: path, Message: "profile include cycle detected: " + strings.Join(cycle, " -> ")})
			continue
		}
		included, ok := profilesByID[includeID]
		if !ok {
			issues = append(issues, ValidationIssue{Path: path, Message: fmt.Sprintf("profile %q is not declared", includeID)})
			continue
		}
		resolution, resolutionIssues := resolveControlProfile(index, profilesByID, included, stack)
		for _, issue := range resolutionIssues {
			issue.Path = nestedProfileIssuePath(path, issue.Path)
			issues = append(issues, issue)
		}
		addResolvedControls(selected, resolution.Controls)
	}

	issues = append(issues, applyControlSelectionExclusions(index, selected, profile)...)
	return controlSelectionResolution(id, selected), issues
}

func BuildControlCoverageIndex(index *CatalogIndex, set ControlProfileSet, rules []RuleControlMapping) (ControlCoverageIndex, []ValidationIssue) {
	resolution, issues := ResolveControlProfiles(index, set)
	result := ControlCoverageIndex{Version: resolution.Version}
	for _, profile := range resolution.Profiles {
		coverage := ResolveRuleCoverage(profile.Resolution, rules)
		result.Profiles = append(result.Profiles, BuildControlCoverageProfile(profile.Profile, profile.Resolution, coverage))
	}
	sort.Slice(result.Profiles, func(i, j int) bool {
		return result.Profiles[i].ID < result.Profiles[j].ID
	})
	return result, issues
}

func controlProfilesByID(profiles []ControlSelection) map[string]ControlSelection {
	result := map[string]ControlSelection{}
	for _, profile := range profiles {
		id := strings.TrimSpace(profile.ID)
		if id == "" {
			continue
		}
		if _, ok := result[id]; ok {
			continue
		}
		result[id] = profile
	}
	return result
}

func addResolvedControls(selected map[string]ResolvedControl, controls []ResolvedControl) {
	for _, control := range controls {
		selected[ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID})] = control
	}
}

func profileIDInStack(stack []string, id string) bool {
	if id == "" {
		return false
	}
	for _, existing := range stack {
		if existing == id {
			return true
		}
	}
	return false
}

func nestedProfileIssuePath(prefix, path string) string {
	prefix = strings.TrimSpace(prefix)
	path = strings.TrimSpace(path)
	if path == "" {
		return prefix
	}
	if prefix == "" {
		return path
	}
	return prefix + "." + path
}

func BuildControlCoverageProfile(selection ControlSelection, resolution SelectionResolution, coverage RuleCoverage) ControlCoverageProfile {
	profile := ControlCoverageProfile{
		ID:               strings.TrimSpace(selection.ID),
		Name:             strings.TrimSpace(selection.Name),
		Description:      strings.TrimSpace(selection.Description),
		UnmappedControls: append([]ControlRef(nil), coverage.UnmappedControls...),
	}
	for _, control := range resolution.Controls {
		key := ControlKey(ControlRef{FrameworkName: control.FrameworkName, ControlID: control.Control.ID})
		mappedRules := sortedUniqueStrings(coverage.RulesByControl[key])
		if len(mappedRules) != 0 {
			profile.Summary.MappedControls++
		}
		expectationIDs, _ := evidenceExpectationIDs(control.Evidence)
		coverageStatus := "unmapped"
		if len(mappedRules) != 0 {
			coverageStatus = "mapped"
		}
		profile.Controls = append(profile.Controls, ControlCoverageControl{
			FrameworkID:            strings.TrimSpace(control.FrameworkID),
			FrameworkName:          strings.TrimSpace(control.FrameworkName),
			FrameworkVersion:       strings.TrimSpace(control.FrameworkVersion),
			FamilyID:               strings.TrimSpace(control.FamilyID),
			FamilyName:             strings.TrimSpace(control.FamilyName),
			ControlID:              strings.TrimSpace(control.Control.ID),
			Title:                  strings.TrimSpace(control.Control.Title),
			OwnerDomain:            strings.TrimSpace(control.Control.OwnerDomain),
			Tags:                   sortedUniqueStrings(control.EffectiveTags),
			EvidenceExpectationIDs: expectationIDs,
			AuditPlan:              controlCoverageAuditPlan(control.Control),
			EvidencePlan:           controlCoverageEvidencePlan(control.Evidence, control.Control.FreshnessSLA),
			MappedControlRefs:      sortedControlRefs(control.Control.MapsTo),
			CoverageStatus:         coverageStatus,
			RuleCount:              len(mappedRules),
			MappedRules:            mappedRules,
		})
	}
	profile.Rules = controlCoverageRules(coverage)
	profile.Summary.SelectedControls = coverage.SelectedControls
	profile.Summary.UnmappedControls = len(coverage.UnmappedControls)
	profile.Summary.MappedRules = len(coverage.MappedRules)
	sortControlCoverageProfile(&profile)
	return profile
}

func validateControlProfileSet(set ControlProfileSet) []ValidationIssue {
	issues := []ValidationIssue{}
	if strings.TrimSpace(set.Version) == "" {
		issues = append(issues, ValidationIssue{Path: "version", Message: "control profile set version is required"})
	}
	if len(set.Profiles) == 0 {
		issues = append(issues, ValidationIssue{Path: "profiles", Message: "at least one control profile is required"})
	}
	ids := map[string]struct{}{}
	for idx, profile := range set.Profiles {
		path := profileIndexPath(idx)
		id := strings.TrimSpace(profile.ID)
		if id == "" {
			issues = append(issues, ValidationIssue{Path: path + ".id", Message: "control profile id is required"})
			continue
		}
		if _, ok := ids[id]; ok {
			issues = append(issues, ValidationIssue{Path: path + ".id", Message: "control profile id is duplicated"})
		}
		ids[id] = struct{}{}
		if strings.TrimSpace(profile.Name) == "" {
			issues = append(issues, ValidationIssue{Path: path + ".name", Message: "control profile name is required"})
		}
	}
	return issues
}

func controlCoverageRules(coverage RuleCoverage) []ControlCoverageRule {
	rules := make([]ControlCoverageRule, 0, len(coverage.ControlsByRule))
	for ruleID, refs := range coverage.ControlsByRule {
		rules = append(rules, ControlCoverageRule{
			RuleID:   strings.TrimSpace(ruleID),
			Controls: sortedControlRefs(refs),
		})
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].RuleID < rules[j].RuleID
	})
	return rules
}

func sortControlCoverageProfile(profile *ControlCoverageProfile) {
	sort.Slice(profile.UnmappedControls, func(i, j int) bool {
		return ControlKey(profile.UnmappedControls[i]) < ControlKey(profile.UnmappedControls[j])
	})
	sort.Slice(profile.Controls, func(i, j int) bool {
		left := ControlKey(ControlRef{FrameworkName: profile.Controls[i].FrameworkName, ControlID: profile.Controls[i].ControlID})
		right := ControlKey(ControlRef{FrameworkName: profile.Controls[j].FrameworkName, ControlID: profile.Controls[j].ControlID})
		return left < right
	})
	for idx := range profile.Controls {
		profile.Controls[idx].Tags = sortedUniqueStrings(profile.Controls[idx].Tags)
		profile.Controls[idx].EvidenceExpectationIDs = sortedUniqueStrings(profile.Controls[idx].EvidenceExpectationIDs)
		normalizeControlCoverageAuditPlan(profile.Controls[idx].AuditPlan)
		sortControlCoverageEvidencePlan(profile.Controls[idx].EvidencePlan)
		profile.Controls[idx].MappedControlRefs = sortedControlRefs(profile.Controls[idx].MappedControlRefs)
		profile.Controls[idx].MappedRules = sortedUniqueStrings(profile.Controls[idx].MappedRules)
	}
}

func sortedControlRefs(refs []ControlRef) []ControlRef {
	result := append([]ControlRef(nil), refs...)
	sort.Slice(result, func(i, j int) bool {
		return ControlKey(result[i]) < ControlKey(result[j])
	})
	return result
}

func controlCoverageAuditPlan(control Control) *ControlCoverageAuditPlan {
	plan := ControlCoverageAuditPlan{
		Objective:              strings.TrimSpace(control.Objective),
		Intent:                 strings.TrimSpace(control.Intent),
		FreshnessSLA:           strings.TrimSpace(control.FreshnessSLA),
		Applicability:          orderedUniqueStrings(control.Applicability),
		AssessmentMethods:      orderedUniqueStrings(control.AssessmentMethods),
		ImplementationGuidance: orderedUniqueStrings(control.ImplementationGuidance),
		AuditProcedure:         orderedUniqueStrings(control.AuditProcedure),
		FailureModes:           orderedUniqueStrings(control.FailureModes),
		RemediationGuidance:    orderedUniqueStrings(control.RemediationGuidance),
		ExceptionGuidance:      strings.TrimSpace(control.ExceptionGuidance),
		Automatable:            cloneBool(control.Automatable),
		ManualEvidenceAllowed:  cloneBool(control.ManualEvidenceAllowed),
	}
	if controlCoverageAuditPlanEmpty(plan) {
		return nil
	}
	return &plan
}

func controlCoverageEvidencePlan(expectations []EvidenceExpectation, fallbackFreshnessSLA string) *ControlCoverageEvidencePlan {
	values := make([]ControlCoverageEvidenceExpectation, 0, len(expectations))
	for _, expectation := range expectations {
		expectation = expectationWithControlFreshness(expectation, fallbackFreshnessSLA)
		values = append(values, ControlCoverageEvidenceExpectation{
			ID:                strings.TrimSpace(expectation.ID),
			Title:             strings.TrimSpace(expectation.Title),
			Type:              strings.TrimSpace(expectation.Type),
			Required:          evidenceExpectationRequired(expectation),
			Description:       strings.TrimSpace(expectation.Description),
			AssessmentMethods: sortedUniqueStrings(expectation.AssessmentMethods),
			FreshnessSLA:      strings.TrimSpace(expectation.FreshnessSLA),
			AcceptedFrom:      sortedUniqueStrings(expectation.AcceptedFrom),
		})
	}
	sort.Slice(values, func(i, j int) bool {
		return values[i].ID < values[j].ID
	})
	if len(values) == 0 {
		return nil
	}
	return &ControlCoverageEvidencePlan{Expectations: values}
}

func normalizeControlCoverageAuditPlan(plan *ControlCoverageAuditPlan) {
	if plan == nil {
		return
	}
	plan.Applicability = orderedUniqueStrings(plan.Applicability)
	plan.AssessmentMethods = orderedUniqueStrings(plan.AssessmentMethods)
	plan.ImplementationGuidance = orderedUniqueStrings(plan.ImplementationGuidance)
	plan.AuditProcedure = orderedUniqueStrings(plan.AuditProcedure)
	plan.FailureModes = orderedUniqueStrings(plan.FailureModes)
	plan.RemediationGuidance = orderedUniqueStrings(plan.RemediationGuidance)
}

func sortControlCoverageEvidencePlan(plan *ControlCoverageEvidencePlan) {
	if plan == nil {
		return
	}
	sort.Slice(plan.Expectations, func(i, j int) bool {
		return plan.Expectations[i].ID < plan.Expectations[j].ID
	})
}

func controlCoverageAuditPlanEmpty(plan ControlCoverageAuditPlan) bool {
	return plan.Objective == "" &&
		plan.Intent == "" &&
		plan.FreshnessSLA == "" &&
		len(plan.Applicability) == 0 &&
		len(plan.AssessmentMethods) == 0 &&
		len(plan.ImplementationGuidance) == 0 &&
		len(plan.AuditProcedure) == 0 &&
		len(plan.FailureModes) == 0 &&
		len(plan.RemediationGuidance) == 0 &&
		plan.ExceptionGuidance == "" &&
		plan.Automatable == nil &&
		plan.ManualEvidenceAllowed == nil
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func profileIssuePath(id, path string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		id = "unknown"
	}
	if strings.TrimSpace(path) == "" {
		return "profiles." + id
	}
	return "profiles." + id + "." + strings.TrimSpace(path)
}

func profileIndexPath(idx int) string {
	return "profiles[" + strconv.Itoa(idx) + "]"
}
