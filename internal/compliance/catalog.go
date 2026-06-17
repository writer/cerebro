package compliance

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultControlCatalogPath = "internal/compliance/control_families.yaml"

type ValidationIssue struct {
	Path    string
	Message string
}

func (i ValidationIssue) Error() string {
	if strings.TrimSpace(i.Path) == "" {
		return i.Message
	}
	return i.Path + ": " + i.Message
}

type ControlCatalog struct {
	Version    string      `json:"version" yaml:"version"`
	Frameworks []Framework `json:"frameworks" yaml:"frameworks"`
}

type Framework struct {
	ID          string   `json:"id,omitempty" yaml:"id,omitempty"`
	Name        string   `json:"name" yaml:"name"`
	Version     string   `json:"framework_version,omitempty" yaml:"framework_version,omitempty"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Tags        []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Families    []Family `json:"families" yaml:"families"`
}

type Family struct {
	ID          string    `json:"id" yaml:"id"`
	Name        string    `json:"name" yaml:"name"`
	Description string    `json:"description,omitempty" yaml:"description,omitempty"`
	Tags        []string  `json:"tags,omitempty" yaml:"tags,omitempty"`
	Controls    []Control `json:"controls" yaml:"controls"`
}

type Control struct {
	ID                    string                `json:"id" yaml:"id"`
	Title                 string                `json:"title,omitempty" yaml:"title,omitempty"`
	Objective             string                `json:"objective,omitempty" yaml:"objective,omitempty"`
	Intent                string                `json:"intent,omitempty" yaml:"intent,omitempty"`
	Applicability         []string              `json:"applicability,omitempty" yaml:"applicability,omitempty"`
	AssessmentMethods     []string              `json:"assessment_methods,omitempty" yaml:"assessment_methods,omitempty"`
	EvidenceExpectations  []EvidenceExpectation `json:"evidence_expectations,omitempty" yaml:"evidence_expectations,omitempty"`
	FreshnessSLA          string                `json:"freshness_sla,omitempty" yaml:"freshness_sla,omitempty"`
	OwnerDomain           string                `json:"owner_domain,omitempty" yaml:"owner_domain,omitempty"`
	Automatable           *bool                 `json:"automatable,omitempty" yaml:"automatable,omitempty"`
	ManualEvidenceAllowed *bool                 `json:"manual_evidence_allowed,omitempty" yaml:"manual_evidence_allowed,omitempty"`
	Tags                  []string              `json:"tags,omitempty" yaml:"tags,omitempty"`
	MapsTo                []ControlRef          `json:"maps_to,omitempty" yaml:"maps_to,omitempty"`
}

type EvidenceExpectation struct {
	ID                string   `json:"id" yaml:"id"`
	Title             string   `json:"title,omitempty" yaml:"title,omitempty"`
	Type              string   `json:"type" yaml:"type"`
	Description       string   `json:"description,omitempty" yaml:"description,omitempty"`
	Required          *bool    `json:"required,omitempty" yaml:"required,omitempty"`
	AssessmentMethods []string `json:"assessment_methods,omitempty" yaml:"assessment_methods,omitempty"`
	FreshnessSLA      string   `json:"freshness_sla,omitempty" yaml:"freshness_sla,omitempty"`
	AcceptedFrom      []string `json:"accepted_from,omitempty" yaml:"accepted_from,omitempty"`
}

type ControlRef struct {
	FrameworkID   string `json:"framework_id,omitempty" yaml:"framework_id,omitempty"`
	FrameworkName string `json:"framework_name,omitempty" yaml:"framework_name,omitempty"`
	Framework     string `json:"framework,omitempty" yaml:"framework,omitempty"`
	ControlID     string `json:"control_id" yaml:"control_id"`
}

type ResolvedControl struct {
	FrameworkID      string                `json:"framework_id,omitempty"`
	FrameworkName    string                `json:"framework_name"`
	FrameworkVersion string                `json:"framework_version,omitempty"`
	FamilyID         string                `json:"family_id"`
	FamilyName       string                `json:"family_name"`
	Control          Control               `json:"control"`
	EffectiveTags    []string              `json:"effective_tags,omitempty"`
	Evidence         []EvidenceExpectation `json:"evidence_expectations,omitempty"`
}

type CatalogIndex struct {
	frameworksByName map[string]*Framework
	frameworksByID   map[string]*Framework
	families         map[string]map[string]*Family
	controls         map[string]map[string]*ResolvedControl
	controlKeys      []string
}

func LoadControlCatalogFile(path string) (ControlCatalog, error) {
	content, err := readLocalYAMLFile(path) // #nosec G304 -- control pack path is an operator-provided local YAML file; readLocalYAMLFile rejects symlinks.
	if err != nil {
		return ControlCatalog{}, err
	}
	return LoadControlCatalog(content)
}

func LoadControlCatalogFiles(paths ...string) (ControlCatalog, error) {
	catalogs := make([]ControlCatalog, 0, len(paths))
	for _, path := range paths {
		catalog, err := LoadControlCatalogFile(path)
		if err != nil {
			return ControlCatalog{}, err
		}
		catalogs = append(catalogs, catalog)
	}
	return MergeControlCatalogs(catalogs...), nil
}

func LoadControlCatalog(content []byte) (ControlCatalog, error) {
	var catalog ControlCatalog
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return ControlCatalog{}, err
	}
	return catalog, nil
}

func readLocalYAMLFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("symlinked YAML files are not allowed: %s", path)
	}
	return os.ReadFile(path) // #nosec G304 -- control packs and selections are operator-provided local YAML files; symlinks are rejected above.
}

func MergeControlCatalogs(catalogs ...ControlCatalog) ControlCatalog {
	var merged ControlCatalog
	for _, catalog := range catalogs {
		if strings.TrimSpace(merged.Version) == "" {
			merged.Version = strings.TrimSpace(catalog.Version)
		}
		merged.Frameworks = append(merged.Frameworks, catalog.Frameworks...)
	}
	return merged
}

func BuildCatalogIndex(catalog ControlCatalog) (*CatalogIndex, []ValidationIssue) {
	index := &CatalogIndex{
		frameworksByName: map[string]*Framework{},
		frameworksByID:   map[string]*Framework{},
		families:         map[string]map[string]*Family{},
		controls:         map[string]map[string]*ResolvedControl{},
	}
	issues := ValidateControlCatalog(catalog)
	for frameworkIdx := range catalog.Frameworks {
		framework := &catalog.Frameworks[frameworkIdx]
		frameworkName := strings.TrimSpace(framework.Name)
		if frameworkName == "" {
			continue
		}
		frameworkID := strings.TrimSpace(framework.ID)
		index.frameworksByName[frameworkName] = framework
		if frameworkID != "" {
			index.frameworksByID[frameworkID] = framework
		}
		frameworkKey := frameworkCatalogKey(*framework)
		index.families[frameworkKey] = map[string]*Family{}
		index.controls[frameworkKey] = map[string]*ResolvedControl{}
		for familyIdx := range framework.Families {
			family := &framework.Families[familyIdx]
			familyID := strings.TrimSpace(family.ID)
			if familyID == "" {
				continue
			}
			index.families[frameworkKey][familyID] = family
			for controlIdx := range family.Controls {
				control := family.Controls[controlIdx]
				control.ID = strings.TrimSpace(control.ID)
				if control.ID == "" {
					continue
				}
				control = cloneControl(control)
				refKey := controlKey(frameworkName, control.ID)
				resolved := &ResolvedControl{
					FrameworkID:      frameworkID,
					FrameworkName:    frameworkName,
					FrameworkVersion: strings.TrimSpace(framework.Version),
					FamilyID:         familyID,
					FamilyName:       strings.TrimSpace(family.Name),
					Control:          control,
					EffectiveTags:    mergedTags(framework.Tags, family.Tags, control.Tags),
					Evidence:         append([]EvidenceExpectation(nil), control.EvidenceExpectations...),
				}
				index.controls[frameworkKey][control.ID] = resolved
				index.controlKeys = append(index.controlKeys, refKey)
			}
		}
	}
	sort.Strings(index.controlKeys)
	normalizeMappedControlRefs(index)
	mapIssues := validateControlMappings(catalog, index)
	issues = append(issues, mapIssues...)
	return index, issues
}

func ValidateControlCatalog(catalog ControlCatalog) []ValidationIssue {
	var issues []ValidationIssue
	if strings.TrimSpace(catalog.Version) == "" {
		issues = append(issues, ValidationIssue{Message: "version is required"})
	}
	frameworkNames := map[string]struct{}{}
	frameworkIDs := map[string]struct{}{}
	for frameworkIdx, framework := range catalog.Frameworks {
		frameworkPath := fmt.Sprintf("frameworks[%d]", frameworkIdx)
		frameworkName := strings.TrimSpace(framework.Name)
		frameworkID := strings.TrimSpace(framework.ID)
		if frameworkName == "" {
			issues = append(issues, ValidationIssue{Message: frameworkPath + ".name is required"})
			continue
		}
		if _, exists := frameworkNames[frameworkName]; exists {
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("framework %q is duplicated", frameworkName)})
			continue
		}
		frameworkNames[frameworkName] = struct{}{}
		if frameworkID != "" {
			if _, exists := frameworkIDs[frameworkID]; exists {
				issues = append(issues, ValidationIssue{Message: fmt.Sprintf("framework id %q is duplicated", frameworkID)})
			}
			frameworkIDs[frameworkID] = struct{}{}
		}
		if len(framework.Families) == 0 {
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("framework %q requires at least one family", frameworkName)})
		}
		issues = append(issues, validateTags(frameworkPath+".tags", framework.Tags)...)
		familyIDs := map[string]struct{}{}
		controlIDs := map[string]struct{}{}
		for familyIdx, family := range framework.Families {
			familyPath := fmt.Sprintf("%s.families[%d]", frameworkPath, familyIdx)
			familyID := strings.TrimSpace(family.ID)
			if familyID == "" {
				issues = append(issues, ValidationIssue{Message: familyPath + ".id is required"})
			} else if _, exists := familyIDs[familyID]; exists {
				issues = append(issues, ValidationIssue{Message: fmt.Sprintf("framework %q family %q is duplicated", frameworkName, familyID)})
			}
			familyIDs[familyID] = struct{}{}
			if strings.TrimSpace(family.Name) == "" {
				issues = append(issues, ValidationIssue{Message: familyPath + ".name is required"})
			}
			if len(family.Controls) == 0 {
				issues = append(issues, ValidationIssue{Message: fmt.Sprintf("framework %q family %q requires at least one control", frameworkName, familyID)})
			}
			issues = append(issues, validateTags(familyPath+".tags", family.Tags)...)
			for controlIdx, control := range family.Controls {
				controlPath := fmt.Sprintf("%s.controls[%d]", familyPath, controlIdx)
				controlID := strings.TrimSpace(control.ID)
				if controlID == "" {
					issues = append(issues, ValidationIssue{Message: controlPath + ".id is required"})
					continue
				}
				if _, exists := controlIDs[controlID]; exists {
					issues = append(issues, ValidationIssue{Message: fmt.Sprintf("framework %q control %q is duplicated", frameworkName, controlID)})
				}
				controlIDs[controlID] = struct{}{}
				issues = append(issues, validateControl(controlPath, control)...)
			}
		}
	}
	return issues
}

func (index *CatalogIndex) HasControl(frameworkName, controlID string) bool {
	_, ok := index.Control(ControlRef{FrameworkName: frameworkName, ControlID: controlID})
	return ok
}

func (index *CatalogIndex) Control(ref ControlRef) (ResolvedControl, bool) {
	if index == nil {
		return ResolvedControl{}, false
	}
	framework, ok := index.resolveFramework(ref)
	if !ok {
		return ResolvedControl{}, false
	}
	controls := index.controls[frameworkCatalogKey(*framework)]
	if controls == nil {
		return ResolvedControl{}, false
	}
	control, ok := controls[strings.TrimSpace(ref.ControlID)]
	if !ok || control == nil {
		return ResolvedControl{}, false
	}
	return cloneResolvedControl(*control), true
}

func (index *CatalogIndex) Controls() []ResolvedControl {
	if index == nil {
		return nil
	}
	controls := make([]ResolvedControl, 0, len(index.controlKeys))
	for _, key := range index.controlKeys {
		frameworkName, controlID, ok := strings.Cut(key, "\x00")
		if !ok {
			continue
		}
		if control, ok := index.Control(ControlRef{FrameworkName: frameworkName, ControlID: controlID}); ok {
			controls = append(controls, control)
		}
	}
	return controls
}

func (index *CatalogIndex) ControlKeys() []string {
	if index == nil {
		return nil
	}
	return append([]string(nil), index.controlKeys...)
}

func (index *CatalogIndex) FamilyControls(frameworkName, familyID string) ([]ResolvedControl, bool) {
	if index == nil {
		return nil, false
	}
	frameworkName = strings.TrimSpace(frameworkName)
	framework, ok := index.resolveFramework(ControlRef{FrameworkName: frameworkName})
	if !ok {
		framework, ok = index.resolveFramework(ControlRef{FrameworkID: frameworkName})
	}
	if !ok {
		return nil, false
	}
	familyID = strings.TrimSpace(familyID)
	families := index.families[frameworkCatalogKey(*framework)]
	if _, ok := families[familyID]; !ok {
		return nil, false
	}
	controls := make([]ResolvedControl, 0)
	for _, control := range index.controls[frameworkCatalogKey(*framework)] {
		if control.FamilyID == familyID {
			controls = append(controls, cloneResolvedControl(*control))
		}
	}
	sortResolvedControls(controls)
	return controls, true
}

func (index *CatalogIndex) FrameworkControls(ref ControlRef) ([]ResolvedControl, bool) {
	if index == nil {
		return nil, false
	}
	framework, ok := index.resolveFramework(ref)
	if !ok {
		return nil, false
	}
	controlsByID := index.controls[frameworkCatalogKey(*framework)]
	controls := make([]ResolvedControl, 0, len(controlsByID))
	for _, control := range controlsByID {
		controls = append(controls, cloneResolvedControl(*control))
	}
	sortResolvedControls(controls)
	return controls, true
}

func NormalizeControlRef(ref ControlRef) ControlRef {
	ref.FrameworkID = strings.TrimSpace(ref.FrameworkID)
	ref.FrameworkName = strings.TrimSpace(ref.FrameworkName)
	ref.Framework = strings.TrimSpace(ref.Framework)
	ref.ControlID = strings.TrimSpace(ref.ControlID)
	if ref.FrameworkName == "" && ref.Framework != "" {
		ref.FrameworkName = ref.Framework
	}
	return ref
}

func ControlKey(ref ControlRef) string {
	ref = NormalizeControlRef(ref)
	return controlKey(firstNonEmpty(ref.FrameworkName, ref.FrameworkID), ref.ControlID)
}

func (index *CatalogIndex) resolveFramework(ref ControlRef) (*Framework, bool) {
	ref = NormalizeControlRef(ref)
	if ref.FrameworkID != "" {
		framework, ok := index.frameworksByID[ref.FrameworkID]
		if ok {
			return framework, true
		}
	}
	if ref.FrameworkName != "" {
		framework, ok := index.frameworksByName[ref.FrameworkName]
		if ok {
			return framework, true
		}
	}
	return nil, false
}

func validateControl(path string, control Control) []ValidationIssue {
	var issues []ValidationIssue
	issues = append(issues, validateAssessmentMethods(path+".assessment_methods", control.AssessmentMethods)...)
	issues = append(issues, validateTags(path+".tags", control.Tags)...)
	for expectationIdx, expectation := range control.EvidenceExpectations {
		expectationPath := fmt.Sprintf("%s.evidence_expectations[%d]", path, expectationIdx)
		if strings.TrimSpace(expectation.ID) == "" {
			issues = append(issues, ValidationIssue{Message: expectationPath + ".id is required"})
		}
		if strings.TrimSpace(expectation.Type) == "" {
			issues = append(issues, ValidationIssue{Message: expectationPath + ".type is required"})
		}
		issues = append(issues, validateAssessmentMethods(expectationPath+".assessment_methods", expectation.AssessmentMethods)...)
		issues = append(issues, validateStringList(expectationPath+".accepted_from", expectation.AcceptedFrom)...)
	}
	for mapIdx, ref := range control.MapsTo {
		ref = NormalizeControlRef(ref)
		refPath := fmt.Sprintf("%s.maps_to[%d]", path, mapIdx)
		if ref.FrameworkID == "" && ref.FrameworkName == "" {
			issues = append(issues, ValidationIssue{Message: refPath + ".framework_name is required"})
		}
		if ref.ControlID == "" {
			issues = append(issues, ValidationIssue{Message: refPath + ".control_id is required"})
		}
	}
	return issues
}

func validateControlMappings(catalog ControlCatalog, index *CatalogIndex) []ValidationIssue {
	var issues []ValidationIssue
	for frameworkIdx, framework := range catalog.Frameworks {
		for familyIdx, family := range framework.Families {
			for controlIdx, control := range family.Controls {
				controlPath := fmt.Sprintf("frameworks[%d].families[%d].controls[%d]", frameworkIdx, familyIdx, controlIdx)
				for mapIdx, ref := range control.MapsTo {
					ref = NormalizeControlRef(ref)
					if ref.ControlID == "" || (ref.FrameworkID == "" && ref.FrameworkName == "") {
						continue
					}
					if _, ok := index.Control(ref); !ok {
						framework := firstNonEmpty(ref.FrameworkName, ref.FrameworkID)
						issues = append(issues, ValidationIssue{Message: fmt.Sprintf("%s.maps_to[%d] %s %s is not declared", controlPath, mapIdx, framework, ref.ControlID)})
					}
				}
			}
		}
	}
	return issues
}

func normalizeMappedControlRefs(index *CatalogIndex) {
	if index == nil {
		return
	}
	for _, controls := range index.controls {
		for _, control := range controls {
			if control == nil {
				continue
			}
			for idx, ref := range control.Control.MapsTo {
				target, ok := index.Control(ref)
				if !ok {
					continue
				}
				control.Control.MapsTo[idx] = ControlRef{
					FrameworkID:   target.FrameworkID,
					FrameworkName: target.FrameworkName,
					ControlID:     target.Control.ID,
				}
			}
		}
	}
}

func validateAssessmentMethods(path string, values []string) []ValidationIssue {
	var issues []ValidationIssue
	for idx, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		switch normalized {
		case "examine", "interview", "test":
		default:
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("%s[%d] must be one of examine, interview, test", path, idx)})
		}
	}
	return issues
}

func validateTags(path string, values []string) []ValidationIssue {
	return validateStringList(path, values)
}

func validateStringList(path string, values []string) []ValidationIssue {
	var issues []ValidationIssue
	for idx, value := range values {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, ValidationIssue{Message: fmt.Sprintf("%s[%d] must be non-empty", path, idx)})
		}
	}
	return issues
}

func mergedTags(values ...[]string) []string {
	seen := map[string]struct{}{}
	var tags []string
	for _, set := range values {
		for _, value := range set {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			tags = append(tags, value)
		}
	}
	sort.Strings(tags)
	return tags
}

func cloneResolvedControl(control ResolvedControl) ResolvedControl {
	control.Control = cloneControl(control.Control)
	control.EffectiveTags = append([]string(nil), control.EffectiveTags...)
	control.Evidence = cloneEvidenceExpectations(control.Evidence)
	return control
}

func cloneControl(control Control) Control {
	control.Applicability = append([]string(nil), control.Applicability...)
	control.AssessmentMethods = append([]string(nil), control.AssessmentMethods...)
	control.EvidenceExpectations = cloneEvidenceExpectations(control.EvidenceExpectations)
	control.Tags = append([]string(nil), control.Tags...)
	control.MapsTo = append([]ControlRef(nil), control.MapsTo...)
	return control
}

func cloneEvidenceExpectations(expectations []EvidenceExpectation) []EvidenceExpectation {
	if len(expectations) == 0 {
		return nil
	}
	values := make([]EvidenceExpectation, 0, len(expectations))
	for _, expectation := range expectations {
		expectation.AssessmentMethods = append([]string(nil), expectation.AssessmentMethods...)
		expectation.AcceptedFrom = append([]string(nil), expectation.AcceptedFrom...)
		values = append(values, expectation)
	}
	return values
}

func sortResolvedControls(controls []ResolvedControl) {
	sort.Slice(controls, func(i, j int) bool {
		left := controlKey(controls[i].FrameworkName, controls[i].Control.ID)
		right := controlKey(controls[j].FrameworkName, controls[j].Control.ID)
		if left == right {
			return controls[i].FamilyID < controls[j].FamilyID
		}
		return left < right
	})
}

func frameworkCatalogKey(framework Framework) string {
	if id := strings.TrimSpace(framework.ID); id != "" {
		return "id:" + id
	}
	return "name:" + strings.TrimSpace(framework.Name)
}

func controlKey(frameworkName, controlID string) string {
	return strings.TrimSpace(frameworkName) + "\x00" + strings.TrimSpace(controlID)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func IssuesError(issues []ValidationIssue) error {
	if len(issues) == 0 {
		return nil
	}
	lines := make([]string, 0, len(issues))
	for _, issue := range issues {
		lines = append(lines, issue.Error())
	}
	sort.Strings(lines)
	return errors.New(strings.Join(lines, "\n"))
}
