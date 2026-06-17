package compliance

import (
	"fmt"
	"strings"
	"time"
)

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
