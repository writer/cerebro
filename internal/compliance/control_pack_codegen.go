package compliance

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type ControlArchetypeSet struct {
	Version    string             `json:"version" yaml:"version"`
	Archetypes []ControlArchetype `json:"archetypes" yaml:"archetypes"`
}

type ControlArchetype struct {
	ID                string  `json:"id" yaml:"id"`
	FamilyID          string  `json:"family_id" yaml:"family_id"`
	FamilyName        string  `json:"family_name" yaml:"family_name"`
	FamilyDescription string  `json:"family_description,omitempty" yaml:"family_description,omitempty"`
	Recommended       bool    `json:"recommended,omitempty" yaml:"recommended,omitempty"`
	Control           Control `json:"control" yaml:"control"`
}

type ControlPackBuildRequest struct {
	ExtensionID      string   `json:"extension_id,omitempty" yaml:"extension_id,omitempty"`
	ExtensionName    string   `json:"extension_name,omitempty" yaml:"extension_name,omitempty"`
	Description      string   `json:"description,omitempty" yaml:"description,omitempty"`
	FrameworkID      string   `json:"framework_id,omitempty" yaml:"framework_id,omitempty"`
	FrameworkName    string   `json:"framework_name,omitempty" yaml:"framework_name,omitempty"`
	FrameworkVersion string   `json:"framework_version,omitempty" yaml:"framework_version,omitempty"`
	ProfileID        string   `json:"profile_id,omitempty" yaml:"profile_id,omitempty"`
	ProfileName      string   `json:"profile_name,omitempty" yaml:"profile_name,omitempty"`
	ArchetypeIDs     []string `json:"archetype_ids,omitempty" yaml:"archetype_ids,omitempty"`
	IncludeProfiles  []string `json:"include_profiles,omitempty" yaml:"include_profiles,omitempty"`
	Tags             []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

type ControlPackPreview struct {
	Version     string                 `json:"version" yaml:"version"`
	Extension   ControlExtensionPack   `json:"extension" yaml:"extension"`
	Catalog     ControlCatalog         `json:"catalog" yaml:"catalog"`
	Profiles    ControlProfileSet      `json:"profiles" yaml:"profiles"`
	Coverage    ControlCoverageProfile `json:"coverage" yaml:"coverage"`
	Summary     ControlPackSummary     `json:"summary" yaml:"summary"`
	Files       map[string]string      `json:"files" yaml:"files"`
	GeneratedAt string                 `json:"generated_at,omitempty" yaml:"generated_at,omitempty"`
}

type ControlPackSummary struct {
	Archetypes              int `json:"archetypes" yaml:"archetypes"`
	Controls                int `json:"controls" yaml:"controls"`
	Families                int `json:"families" yaml:"families"`
	MappedControls          int `json:"mapped_controls" yaml:"mapped_controls"`
	UnmappedControls        int `json:"unmapped_controls" yaml:"unmapped_controls"`
	MappedRules             int `json:"mapped_rules" yaml:"mapped_rules"`
	AuditorReadyControls    int `json:"auditor_ready_controls" yaml:"auditor_ready_controls"`
	NeedsEnrichmentControls int `json:"needs_enrichment_controls" yaml:"needs_enrichment_controls"`
	PlaceholderControls     int `json:"placeholder_controls" yaml:"placeholder_controls"`
}

func LoadControlArchetypeSet(content []byte) (ControlArchetypeSet, error) {
	var set ControlArchetypeSet
	if err := yaml.Unmarshal(content, &set); err != nil {
		return ControlArchetypeSet{}, err
	}
	return set, nil
}

func LoadControlCoverageIndex(content []byte) (ControlCoverageIndex, error) {
	var index ControlCoverageIndex
	if err := yaml.Unmarshal(content, &index); err != nil {
		return ControlCoverageIndex{}, err
	}
	return index, nil
}

func BuildControlPackPreview(request ControlPackBuildRequest, archetypes ControlArchetypeSet, baseCatalog ControlCatalog, baseProfiles ControlProfileSet, rules []RuleControlMapping) (ControlPackPreview, []ValidationIssue, error) {
	normalized := normalizeControlPackBuildRequest(request)
	selected, selectionIssues := selectControlArchetypes(archetypes, normalized.ArchetypeIDs)
	if len(selectionIssues) != 0 {
		return ControlPackPreview{}, selectionIssues, nil
	}
	extension, catalog, profiles := buildControlPackFiles(normalized, archetypes.Version, selected)

	mergedCatalog := MergeControlCatalogs(baseCatalog, catalog)
	catalogIndex, catalogIssues := BuildCatalogIndex(mergedCatalog)
	mergedProfiles := MergeControlProfileSets(baseProfiles, profiles)
	coverageIndex, profileIssues := BuildControlCoverageIndex(catalogIndex, mergedProfiles, rules)
	issues := append(selectionIssues, catalogIssues...)
	issues = append(issues, profileIssues...)
	if len(issues) != 0 {
		return ControlPackPreview{}, issues, nil
	}

	coverage, ok := controlCoverageProfileByID(coverageIndex, normalized.ProfileID)
	if !ok {
		return ControlPackPreview{}, []ValidationIssue{{Path: "profile_id", Message: fmt.Sprintf("generated profile %q was not resolved", normalized.ProfileID)}}, nil
	}
	files, err := marshalControlPackFiles(extension, catalog, profiles, coverage)
	if err != nil {
		return ControlPackPreview{}, nil, err
	}
	preview := ControlPackPreview{
		Version:   strings.TrimSpace(firstNonEmpty(archetypes.Version, baseCatalog.Version, baseProfiles.Version)),
		Extension: extension,
		Catalog:   catalog,
		Profiles:  profiles,
		Coverage:  coverage,
		Summary:   controlPackSummary(selected, catalog, coverage),
		Files:     files,
	}
	return preview, nil, nil
}

func normalizeControlPackBuildRequest(request ControlPackBuildRequest) ControlPackBuildRequest {
	frameworkID := slugValue(firstNonEmpty(request.FrameworkID, request.ExtensionID, request.FrameworkName, "custom-framework"))
	if frameworkID == "" {
		frameworkID = "custom-framework"
	}
	extensionID := slugValue(firstNonEmpty(request.ExtensionID, frameworkID+"-controls"))
	if extensionID == "" {
		extensionID = frameworkID + "-controls"
	}
	profileID := slugValue(firstNonEmpty(request.ProfileID, frameworkID+"-audit"))
	if profileID == "" {
		profileID = frameworkID + "-audit"
	}
	frameworkName := strings.TrimSpace(firstNonEmpty(request.FrameworkName, titleValue(frameworkID)+" Framework"))
	extensionName := strings.TrimSpace(firstNonEmpty(request.ExtensionName, titleValue(extensionID)))
	profileName := strings.TrimSpace(firstNonEmpty(request.ProfileName, titleValue(profileID)))
	return ControlPackBuildRequest{
		ExtensionID:      extensionID,
		ExtensionName:    extensionName,
		Description:      strings.TrimSpace(firstNonEmpty(request.Description, "Custom auditor-facing control framework generated from reusable control archetypes.")),
		FrameworkID:      frameworkID,
		FrameworkName:    frameworkName,
		FrameworkVersion: strings.TrimSpace(firstNonEmpty(request.FrameworkVersion, "2026")),
		ProfileID:        profileID,
		ProfileName:      profileName,
		ArchetypeIDs:     sortedUniqueStrings(request.ArchetypeIDs),
		IncludeProfiles:  sortedUniqueStrings(request.IncludeProfiles),
		Tags:             sortedUniqueStrings(append([]string{"custom_framework"}, request.Tags...)),
	}
}

func selectControlArchetypes(set ControlArchetypeSet, ids []string) ([]ControlArchetype, []ValidationIssue) {
	byID := map[string]ControlArchetype{}
	for _, archetype := range set.Archetypes {
		id := strings.TrimSpace(archetype.ID)
		if id == "" {
			continue
		}
		byID[id] = archetype
	}
	var selected []ControlArchetype
	var issues []ValidationIssue
	if len(ids) == 0 {
		for _, archetype := range set.Archetypes {
			if archetype.Recommended {
				selected = append(selected, normalizeControlArchetype(archetype))
			}
		}
		if len(selected) == 0 {
			for _, archetype := range set.Archetypes {
				selected = append(selected, normalizeControlArchetype(archetype))
			}
		}
		return selected, nil
	}
	seen := map[string]struct{}{}
	for idx, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			issues = append(issues, ValidationIssue{Path: fmt.Sprintf("archetype_ids[%d]", idx), Message: "archetype id is required"})
			continue
		}
		archetype, ok := byID[id]
		if !ok {
			issues = append(issues, ValidationIssue{Path: fmt.Sprintf("archetype_ids[%d]", idx), Message: fmt.Sprintf("archetype %q is not declared", id)})
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		selected = append(selected, normalizeControlArchetype(archetype))
	}
	if len(selected) == 0 && len(issues) == 0 {
		issues = append(issues, ValidationIssue{Path: "archetype_ids", Message: "at least one archetype is required"})
	}
	return selected, issues
}

func normalizeControlArchetype(archetype ControlArchetype) ControlArchetype {
	archetype.ID = strings.TrimSpace(archetype.ID)
	archetype.FamilyID = strings.TrimSpace(archetype.FamilyID)
	archetype.FamilyName = strings.TrimSpace(archetype.FamilyName)
	archetype.FamilyDescription = strings.TrimSpace(archetype.FamilyDescription)
	archetype.Control = cloneControl(archetype.Control)
	archetype.Control.ID = strings.TrimSpace(archetype.Control.ID)
	return archetype
}

func buildControlPackFiles(request ControlPackBuildRequest, version string, archetypes []ControlArchetype) (ControlExtensionPack, ControlCatalog, ControlProfileSet) {
	version = strings.TrimSpace(firstNonEmpty(version, "2026-06-17"))
	extension := ControlExtensionPack{
		Version:     version,
		ID:          strings.TrimSpace(request.ExtensionID),
		Name:        strings.TrimSpace(request.ExtensionName),
		Description: strings.TrimSpace(request.Description),
		Catalogs:    []string{"controls.yaml"},
		Profiles:    []string{"profiles.yaml"},
	}
	framework := Framework{
		ID:          strings.TrimSpace(request.FrameworkID),
		Name:        strings.TrimSpace(request.FrameworkName),
		Version:     strings.TrimSpace(request.FrameworkVersion),
		Description: strings.TrimSpace(request.Description),
		Tags:        sortedUniqueStrings(request.Tags),
	}
	familyOrder := []string{}
	familiesByID := map[string]*Family{}
	for _, archetype := range archetypes {
		familyID := strings.TrimSpace(archetype.FamilyID)
		if familyID == "" {
			familyID = "CUSTOM"
		}
		family := familiesByID[familyID]
		if family == nil {
			family = &Family{
				ID:          familyID,
				Name:        strings.TrimSpace(firstNonEmpty(archetype.FamilyName, titleValue(familyID))),
				Description: strings.TrimSpace(archetype.FamilyDescription),
				Tags:        sortedUniqueStrings([]string{strings.ToLower(familyID)}),
			}
			familiesByID[familyID] = family
			familyOrder = append(familyOrder, familyID)
		}
		control := cloneControl(archetype.Control)
		control.Tags = sortedUniqueStrings(append(control.Tags, archetype.ID))
		family.Controls = append(family.Controls, control)
	}
	sort.Strings(familyOrder)
	for _, familyID := range familyOrder {
		family := familiesByID[familyID]
		sort.Slice(family.Controls, func(i, j int) bool {
			return family.Controls[i].ID < family.Controls[j].ID
		})
		framework.Families = append(framework.Families, *family)
	}
	catalog := ControlCatalog{
		Version:    version,
		Frameworks: []Framework{framework},
	}
	profile := ControlSelection{
		ID:              strings.TrimSpace(request.ProfileID),
		Name:            strings.TrimSpace(request.ProfileName),
		Description:     "Generated audit profile for " + strings.TrimSpace(request.FrameworkName) + ".",
		IncludeProfiles: sortedUniqueStrings(request.IncludeProfiles),
		Frameworks: []FrameworkSelection{{
			ID:       strings.TrimSpace(request.FrameworkID),
			Controls: generatedControlIDs(archetypes),
		}},
	}
	profiles := ControlProfileSet{
		Version:  version,
		Profiles: []ControlSelection{profile},
	}
	return extension, catalog, profiles
}

func generatedControlIDs(archetypes []ControlArchetype) []string {
	ids := make([]string, 0, len(archetypes))
	for _, archetype := range archetypes {
		if id := strings.TrimSpace(archetype.Control.ID); id != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

func controlCoverageProfileByID(index ControlCoverageIndex, id string) (ControlCoverageProfile, bool) {
	id = strings.TrimSpace(id)
	for _, profile := range index.Profiles {
		if strings.TrimSpace(profile.ID) == id {
			return profile, true
		}
	}
	return ControlCoverageProfile{}, false
}

func marshalControlPackFiles(extension ControlExtensionPack, catalog ControlCatalog, profiles ControlProfileSet, coverage ControlCoverageProfile) (map[string]string, error) {
	values := map[string]any{
		"extension.yaml": extension,
		"controls.yaml":  catalog,
		"profiles.yaml":  profiles,
		"coverage.yaml": ControlCoverageIndex{
			Version:  catalog.Version,
			Profiles: []ControlCoverageProfile{coverage},
		},
	}
	names := []string{"extension.yaml", "controls.yaml", "profiles.yaml", "coverage.yaml"}
	files := map[string]string{}
	for _, name := range names {
		content, err := yaml.Marshal(values[name])
		if err != nil {
			return nil, fmt.Errorf("encode %s: %w", name, err)
		}
		files[name] = string(content)
	}
	return files, nil
}

func controlPackSummary(archetypes []ControlArchetype, catalog ControlCatalog, coverage ControlCoverageProfile) ControlPackSummary {
	familyCount := 0
	controlCount := 0
	for _, framework := range catalog.Frameworks {
		familyCount += len(framework.Families)
		for _, family := range framework.Families {
			controlCount += len(family.Controls)
		}
	}
	return ControlPackSummary{
		Archetypes:              len(archetypes),
		Controls:                controlCount,
		Families:                familyCount,
		MappedControls:          coverage.Summary.MappedControls,
		UnmappedControls:        coverage.Summary.UnmappedControls,
		MappedRules:             coverage.Summary.MappedRules,
		AuditorReadyControls:    coverage.Summary.AuditorReadyControls,
		NeedsEnrichmentControls: coverage.Summary.NeedsEnrichmentControls,
		PlaceholderControls:     coverage.Summary.PlaceholderControls,
	}
}

func slugValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastHyphen := false
	for _, char := range value {
		isAlphaNumeric := (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')
		if isAlphaNumeric {
			builder.WriteRune(char)
			lastHyphen = false
			continue
		}
		if builder.Len() == 0 || lastHyphen {
			continue
		}
		builder.WriteByte('-')
		lastHyphen = true
	}
	return strings.Trim(builder.String(), "-")
}

func titleValue(value string) string {
	parts := strings.Split(slugValue(value), "-")
	words := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		words = append(words, strings.ToUpper(part[:1])+part[1:])
	}
	if len(words) == 0 {
		return "Custom Controls"
	}
	return strings.Join(words, " ")
}
