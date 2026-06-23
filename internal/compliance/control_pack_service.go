package compliance

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type FrameworkSummary struct {
	ID           string   `json:"id,omitempty"`
	Name         string   `json:"name"`
	Version      string   `json:"framework_version,omitempty"`
	Lifecycle    string   `json:"lifecycle"`
	Description  string   `json:"description,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	FamilyCount  int      `json:"family_count"`
	ControlCount int      `json:"control_count"`
}

type FrameworksResponse struct {
	Version     string             `json:"version"`
	Frameworks  []FrameworkSummary `json:"frameworks"`
	GeneratedAt time.Time          `json:"generated_at"`
}

type ControlArchetypesResponse struct {
	Version     string             `json:"version"`
	Archetypes  []ControlArchetype `json:"archetypes"`
	GeneratedAt time.Time          `json:"generated_at"`
}

type ControlProfilesResponse struct {
	Profiles    []ControlCoverageProfile `json:"profiles"`
	GeneratedAt time.Time                `json:"generated_at"`
}

type ControlCoverageResponse struct {
	Version     string                   `json:"version"`
	Profiles    []ControlCoverageProfile `json:"profiles"`
	GeneratedAt time.Time                `json:"generated_at"`
}

type ControlPackResponse struct {
	Preview     ControlPackPreview `json:"preview"`
	GeneratedAt time.Time          `json:"generated_at"`
}

type ControlPackIssueResponse struct {
	Issues      []ValidationIssue `json:"issues"`
	GeneratedAt time.Time         `json:"generated_at"`
}

func BuiltinFrameworks(generatedAt time.Time) (FrameworksResponse, error) {
	catalog, err := LoadBuiltinControlCatalog()
	if err != nil {
		return FrameworksResponse{}, fmt.Errorf("load control catalog: %w", err)
	}
	frameworks := make([]FrameworkSummary, 0, len(catalog.Frameworks))
	for _, framework := range catalog.Frameworks {
		summary := FrameworkSummary{
			ID:          strings.TrimSpace(framework.ID),
			Name:        strings.TrimSpace(framework.Name),
			Version:     strings.TrimSpace(framework.Version),
			Lifecycle:   normalizeFrameworkLifecycle(framework.Lifecycle),
			Description: strings.TrimSpace(framework.Description),
			Tags:        sortedUniqueStrings(framework.Tags),
			FamilyCount: len(framework.Families),
		}
		for _, family := range framework.Families {
			summary.ControlCount += len(family.Controls)
		}
		frameworks = append(frameworks, summary)
	}
	sort.Slice(frameworks, func(i, j int) bool {
		if frameworks[i].Lifecycle != frameworks[j].Lifecycle {
			return frameworks[i].Lifecycle < frameworks[j].Lifecycle
		}
		return frameworks[i].Name < frameworks[j].Name
	})
	return FrameworksResponse{
		Version:     strings.TrimSpace(catalog.Version),
		Frameworks:  frameworks,
		GeneratedAt: generatedAt,
	}, nil
}

func BuiltinControlArchetypes(generatedAt time.Time) (ControlArchetypesResponse, error) {
	archetypes, err := LoadBuiltinControlArchetypeSet()
	if err != nil {
		return ControlArchetypesResponse{}, fmt.Errorf("load control archetypes: %w", err)
	}
	return ControlArchetypesResponse{
		Version:     strings.TrimSpace(archetypes.Version),
		Archetypes:  archetypes.Archetypes,
		GeneratedAt: generatedAt,
	}, nil
}

func BuiltinControlProfiles(profileIDs []string, generatedAt time.Time) (ControlProfilesResponse, error) {
	index, err := LoadBuiltinControlCoverageIndex()
	if err != nil {
		return ControlProfilesResponse{}, fmt.Errorf("load control coverage index: %w", err)
	}
	return ControlProfilesResponse{
		Profiles:    filterControlCoverageProfiles(index.Profiles, profileIDs),
		GeneratedAt: generatedAt,
	}, nil
}

func BuiltinControlCoverage(profileIDs []string, generatedAt time.Time) (ControlCoverageResponse, error) {
	index, err := LoadBuiltinControlCoverageIndex()
	if err != nil {
		return ControlCoverageResponse{}, fmt.Errorf("load control coverage index: %w", err)
	}
	return ControlCoverageResponse{
		Version:     strings.TrimSpace(index.Version),
		Profiles:    filterControlCoverageProfiles(index.Profiles, profileIDs),
		GeneratedAt: generatedAt,
	}, nil
}

func BuildBuiltinControlPackResponse(request ControlPackBuildRequest, ruleMappings []RuleControlMapping, generatedAt time.Time) (ControlPackResponse, []ValidationIssue, error) {
	archetypes, err := LoadBuiltinControlArchetypeSet()
	if err != nil {
		return ControlPackResponse{}, nil, fmt.Errorf("load control archetypes: %w", err)
	}
	baseCatalog, err := LoadBuiltinControlCatalog()
	if err != nil {
		return ControlPackResponse{}, nil, fmt.Errorf("load control catalog: %w", err)
	}
	baseProfiles, err := LoadBuiltinControlProfileSet()
	if err != nil {
		return ControlPackResponse{}, nil, fmt.Errorf("load control profiles: %w", err)
	}
	preview, issues, err := BuildControlPackPreview(request, archetypes, baseCatalog, baseProfiles, ruleMappings)
	if err != nil {
		return ControlPackResponse{}, nil, err
	}
	if len(issues) != 0 {
		return ControlPackResponse{}, issues, nil
	}
	return ControlPackResponse{Preview: preview, GeneratedAt: generatedAt}, nil, nil
}

func filterControlCoverageProfiles(profiles []ControlCoverageProfile, ids []string) []ControlCoverageProfile {
	wanted := map[string]struct{}{}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			wanted[id] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return profiles
	}
	filtered := []ControlCoverageProfile{}
	for _, profile := range profiles {
		if _, ok := wanted[strings.TrimSpace(profile.ID)]; ok {
			filtered = append(filtered, profile)
		}
	}
	return filtered
}
