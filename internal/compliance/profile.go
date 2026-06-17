package compliance

import (
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
	FrameworkID            string   `json:"framework_id,omitempty" yaml:"framework_id,omitempty"`
	FrameworkName          string   `json:"framework_name" yaml:"framework_name"`
	FrameworkVersion       string   `json:"framework_version,omitempty" yaml:"framework_version,omitempty"`
	FamilyID               string   `json:"family_id" yaml:"family_id"`
	FamilyName             string   `json:"family_name" yaml:"family_name"`
	ControlID              string   `json:"control_id" yaml:"control_id"`
	Title                  string   `json:"title,omitempty" yaml:"title,omitempty"`
	OwnerDomain            string   `json:"owner_domain,omitempty" yaml:"owner_domain,omitempty"`
	Tags                   []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	EvidenceExpectationIDs []string `json:"evidence_expectation_ids,omitempty" yaml:"evidence_expectation_ids,omitempty"`
	MappedRules            []string `json:"mapped_rules,omitempty" yaml:"mapped_rules,omitempty"`
}

type ControlCoverageRule struct {
	RuleID   string       `json:"rule_id" yaml:"rule_id"`
	Controls []ControlRef `json:"controls" yaml:"controls"`
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
	for _, profile := range set.Profiles {
		resolution, resolutionIssues := ResolveControlSelection(index, profile)
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
