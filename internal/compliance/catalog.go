package compliance

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const DefaultControlCatalogPath = "internal/compliance/control_families.yaml"

const (
	FrameworkLifecycleActive   = "active"
	FrameworkLifecycleUpcoming = "upcoming"
)

const (
	ControlMappingRelationshipUnspecified    = ""
	ControlMappingRelationshipEqualTo        = "equal-to"
	ControlMappingRelationshipEquivalentTo   = "equivalent-to"
	ControlMappingRelationshipSubsetOf       = "subset-of"
	ControlMappingRelationshipSupersetOf     = "superset-of"
	ControlMappingRelationshipIntersectsWith = "intersects-with"
	ControlMappingRelationshipNoRelationship = "no-relationship"
)

const (
	ControlMappingRationaleSyntactic  = "syntactic"
	ControlMappingRationaleSemantic   = "semantic"
	ControlMappingRationaleFunctional = "functional"
)

const (
	ControlMappingReviewStatusComplete    = "complete"
	ControlMappingReviewStatusNotComplete = "not-complete"
	ControlMappingReviewStatusDraft       = "draft"
	ControlMappingReviewStatusDeprecated  = "deprecated"
	ControlMappingReviewStatusSuperseded  = "superseded"
)

type ValidationIssue struct {
	Path    string `json:"path,omitempty" yaml:"path,omitempty"`
	Message string `json:"message" yaml:"message"`
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
	Lifecycle   string   `json:"lifecycle,omitempty" yaml:"lifecycle,omitempty"`
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
	ID                     string                `json:"id" yaml:"id"`
	Title                  string                `json:"title,omitempty" yaml:"title,omitempty"`
	Objective              string                `json:"objective,omitempty" yaml:"objective,omitempty"`
	Intent                 string                `json:"intent,omitempty" yaml:"intent,omitempty"`
	Applicability          []string              `json:"applicability,omitempty" yaml:"applicability,omitempty"`
	AssessmentMethods      []string              `json:"assessment_methods,omitempty" yaml:"assessment_methods,omitempty"`
	ImplementationGuidance []string              `json:"implementation_guidance,omitempty" yaml:"implementation_guidance,omitempty"`
	AuditProcedure         []string              `json:"audit_procedure,omitempty" yaml:"audit_procedure,omitempty"`
	FailureModes           []string              `json:"failure_modes,omitempty" yaml:"failure_modes,omitempty"`
	RemediationGuidance    []string              `json:"remediation_guidance,omitempty" yaml:"remediation_guidance,omitempty"`
	ExceptionGuidance      string                `json:"exception_guidance,omitempty" yaml:"exception_guidance,omitempty"`
	EvidenceExpectations   []EvidenceExpectation `json:"evidence_expectations,omitempty" yaml:"evidence_expectations,omitempty"`
	FreshnessSLA           string                `json:"freshness_sla,omitempty" yaml:"freshness_sla,omitempty"`
	OwnerDomain            string                `json:"owner_domain,omitempty" yaml:"owner_domain,omitempty"`
	Automatable            *bool                 `json:"automatable,omitempty" yaml:"automatable,omitempty"`
	ManualEvidenceAllowed  *bool                 `json:"manual_evidence_allowed,omitempty" yaml:"manual_evidence_allowed,omitempty"`
	Tags                   []string              `json:"tags,omitempty" yaml:"tags,omitempty"`
	MapsTo                 []ControlRef          `json:"maps_to,omitempty" yaml:"maps_to,omitempty"`
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
	FrameworkID        string `json:"framework_id,omitempty" yaml:"framework_id,omitempty"`
	FrameworkName      string `json:"framework_name,omitempty" yaml:"framework_name,omitempty"`
	Framework          string `json:"framework,omitempty" yaml:"framework,omitempty"`
	ControlID          string `json:"control_id" yaml:"control_id"`
	Relationship       string `json:"relationship,omitempty" yaml:"relationship,omitempty"`
	MatchingRationale  string `json:"matching_rationale,omitempty" yaml:"matching_rationale,omitempty"`
	MappingDescription string `json:"mapping_description,omitempty" yaml:"mapping_description,omitempty"`
	MappingAuthority   string `json:"mapping_authority,omitempty" yaml:"mapping_authority,omitempty"`
	MappingSource      string `json:"mapping_source,omitempty" yaml:"mapping_source,omitempty"`
	ReviewStatus       string `json:"review_status,omitempty" yaml:"review_status,omitempty"`
	ReviewedAt         string `json:"reviewed_at,omitempty" yaml:"reviewed_at,omitempty"`
	MappingVersion     string `json:"mapping_version,omitempty" yaml:"mapping_version,omitempty"`
}

type ResolvedControl struct {
	FrameworkID        string                `json:"framework_id,omitempty"`
	FrameworkName      string                `json:"framework_name"`
	FrameworkVersion   string                `json:"framework_version,omitempty"`
	FrameworkLifecycle string                `json:"framework_lifecycle,omitempty"`
	FamilyID           string                `json:"family_id"`
	FamilyName         string                `json:"family_name"`
	Control            Control               `json:"control"`
	EffectiveTags      []string              `json:"effective_tags,omitempty"`
	Evidence           []EvidenceExpectation `json:"evidence_expectations,omitempty"`
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
		frameworkLifecycle := normalizeFrameworkLifecycle(framework.Lifecycle)
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
					FrameworkID:        frameworkID,
					FrameworkName:      frameworkName,
					FrameworkVersion:   strings.TrimSpace(framework.Version),
					FrameworkLifecycle: frameworkLifecycleForJSON(frameworkLifecycle),
					FamilyID:           familyID,
					FamilyName:         strings.TrimSpace(family.Name),
					Control:            control,
					EffectiveTags:      mergedTags(framework.Tags, family.Tags, control.Tags),
					Evidence:           append([]EvidenceExpectation(nil), control.EvidenceExpectations...),
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
			if normalizeFrameworkLifecycle(framework.Lifecycle) != FrameworkLifecycleUpcoming {
				issues = append(issues, ValidationIssue{Message: fmt.Sprintf("framework %q requires at least one family", frameworkName)})
			}
		}
		if lifecycleIssues := validateFrameworkLifecycle(frameworkPath+".lifecycle", framework.Lifecycle); len(lifecycleIssues) != 0 {
			issues = append(issues, lifecycleIssues...)
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
	ref.Relationship = strings.TrimSpace(ref.Relationship)
	ref.MatchingRationale = strings.TrimSpace(ref.MatchingRationale)
	ref.MappingDescription = strings.TrimSpace(ref.MappingDescription)
	ref.MappingAuthority = strings.TrimSpace(ref.MappingAuthority)
	ref.MappingSource = strings.TrimSpace(ref.MappingSource)
	ref.ReviewStatus = strings.TrimSpace(ref.ReviewStatus)
	ref.ReviewedAt = strings.TrimSpace(ref.ReviewedAt)
	ref.MappingVersion = strings.TrimSpace(ref.MappingVersion)
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
	issues = append(issues, validateStringList(path+".applicability", control.Applicability)...)
	issues = append(issues, validateStringList(path+".implementation_guidance", control.ImplementationGuidance)...)
	issues = append(issues, validateStringList(path+".audit_procedure", control.AuditProcedure)...)
	issues = append(issues, validateStringList(path+".failure_modes", control.FailureModes)...)
	issues = append(issues, validateStringList(path+".remediation_guidance", control.RemediationGuidance)...)
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
		issues = append(issues, validateControlMappingMetadata(refPath, ref)...)
	}
	return issues
}

func validateControlMappingMetadata(path string, ref ControlRef) []ValidationIssue {
	var issues []ValidationIssue
	if ref.Relationship != "" && !controlMappingRelationshipAllowed(ref.Relationship) {
		issues = append(issues, ValidationIssue{Message: path + ".relationship must be one of equal-to, equivalent-to, subset-of, superset-of, intersects-with, no-relationship"})
	}
	if ref.MatchingRationale != "" && !controlMappingRationaleAllowed(ref.MatchingRationale) {
		issues = append(issues, ValidationIssue{Message: path + ".matching_rationale must be one of syntactic, semantic, functional"})
	}
	if (ref.Relationship == "") != (ref.MatchingRationale == "") {
		issues = append(issues, ValidationIssue{Message: path + ".relationship and matching_rationale must be provided together"})
	}
	if ref.Relationship != "" && ref.MappingDescription == "" {
		issues = append(issues, ValidationIssue{Message: path + ".mapping_description is required when relationship is set"})
	}
	if ref.Relationship != "" && ref.ReviewStatus == "" {
		issues = append(issues, ValidationIssue{Message: path + ".review_status is required when relationship is set"})
	}
	if ref.ReviewStatus != "" && !controlMappingReviewStatusAllowed(ref.ReviewStatus) {
		issues = append(issues, ValidationIssue{Message: path + ".review_status must be one of complete, not-complete, draft, deprecated, superseded"})
	}
	if ref.ReviewedAt != "" && !validControlMappingReviewTime(ref.ReviewedAt) {
		issues = append(issues, ValidationIssue{Message: path + ".reviewed_at must be an ISO 8601 date or RFC 3339 timestamp"})
	}
	if ref.MappingSource != "" && !absoluteControlMappingSource(ref.MappingSource) {
		issues = append(issues, ValidationIssue{Message: path + ".mapping_source must be an absolute URI"})
	}
	if ref.ReviewStatus == ControlMappingReviewStatusComplete {
		if ref.MappingAuthority == "" {
			issues = append(issues, ValidationIssue{Message: path + ".mapping_authority is required when review_status is complete"})
		}
		if ref.MappingSource == "" {
			issues = append(issues, ValidationIssue{Message: path + ".mapping_source is required when review_status is complete"})
		}
		if ref.ReviewedAt == "" {
			issues = append(issues, ValidationIssue{Message: path + ".reviewed_at is required when review_status is complete"})
		}
		if ref.MappingVersion == "" {
			issues = append(issues, ValidationIssue{Message: path + ".mapping_version is required when review_status is complete"})
		}
	}
	return issues
}

func controlMappingRelationshipAllowed(value string) bool {
	switch value {
	case ControlMappingRelationshipEqualTo,
		ControlMappingRelationshipEquivalentTo,
		ControlMappingRelationshipSubsetOf,
		ControlMappingRelationshipSupersetOf,
		ControlMappingRelationshipIntersectsWith,
		ControlMappingRelationshipNoRelationship:
		return true
	default:
		return false
	}
}

func controlMappingRationaleAllowed(value string) bool {
	switch value {
	case ControlMappingRationaleSyntactic, ControlMappingRationaleSemantic, ControlMappingRationaleFunctional:
		return true
	default:
		return false
	}
}

func controlMappingReviewStatusAllowed(value string) bool {
	switch value {
	case ControlMappingReviewStatusComplete,
		ControlMappingReviewStatusNotComplete,
		ControlMappingReviewStatusDraft,
		ControlMappingReviewStatusDeprecated,
		ControlMappingReviewStatusSuperseded:
		return true
	default:
		return false
	}
}

func validControlMappingReviewTime(value string) bool {
	if _, err := time.Parse("2006-01-02", value); err == nil {
		return true
	}
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}

func absoluteControlMappingSource(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.IsAbs()
}

func normalizeFrameworkLifecycle(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", FrameworkLifecycleActive:
		return FrameworkLifecycleActive
	case FrameworkLifecycleUpcoming:
		return FrameworkLifecycleUpcoming
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func frameworkLifecycleForJSON(value string) string {
	value = normalizeFrameworkLifecycle(value)
	if value == FrameworkLifecycleActive {
		return ""
	}
	return value
}

func validateFrameworkLifecycle(path, value string) []ValidationIssue {
	switch normalizeFrameworkLifecycle(value) {
	case FrameworkLifecycleActive, FrameworkLifecycleUpcoming:
		return nil
	default:
		return []ValidationIssue{{Message: fmt.Sprintf("%s must be one of active, upcoming", path)}}
	}
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
				ref = NormalizeControlRef(ref)
				ref.FrameworkID = target.FrameworkID
				ref.FrameworkName = target.FrameworkName
				ref.Framework = ""
				ref.ControlID = target.Control.ID
				control.Control.MapsTo[idx] = ref
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
	control.ImplementationGuidance = append([]string(nil), control.ImplementationGuidance...)
	control.AuditProcedure = append([]string(nil), control.AuditProcedure...)
	control.FailureModes = append([]string(nil), control.FailureModes...)
	control.RemediationGuidance = append([]string(nil), control.RemediationGuidance...)
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
