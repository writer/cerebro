package compliance

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ControlExtensionPack is a small manifest for shipping custom control catalogs
// and reusable profile selections together.
type ControlExtensionPack struct {
	Version     string   `json:"version" yaml:"version"`
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	Catalogs    []string `json:"catalogs,omitempty" yaml:"catalogs,omitempty"`
	Profiles    []string `json:"profiles,omitempty" yaml:"profiles,omitempty"`
}

func LoadControlExtensionPackFile(path string) (ControlExtensionPack, error) {
	content, err := readLocalYAMLFile(path) // #nosec G304 -- control extension path is an operator-provided local YAML file; readLocalYAMLFile rejects symlinks.
	if err != nil {
		return ControlExtensionPack{}, err
	}
	return LoadControlExtensionPack(content)
}

func LoadControlExtensionPack(content []byte) (ControlExtensionPack, error) {
	var pack ControlExtensionPack
	if err := yaml.Unmarshal(content, &pack); err != nil {
		return ControlExtensionPack{}, err
	}
	return pack, nil
}

func ValidateControlExtensionPack(pack ControlExtensionPack) []ValidationIssue {
	var issues []ValidationIssue
	if strings.TrimSpace(pack.Version) == "" {
		issues = append(issues, ValidationIssue{Path: "version", Message: "control extension version is required"})
	}
	if strings.TrimSpace(pack.ID) == "" {
		issues = append(issues, ValidationIssue{Path: "id", Message: "control extension id is required"})
	}
	if strings.TrimSpace(pack.Name) == "" {
		issues = append(issues, ValidationIssue{Path: "name", Message: "control extension name is required"})
	}
	if len(pack.Catalogs) == 0 && len(pack.Profiles) == 0 {
		issues = append(issues, ValidationIssue{Path: "catalogs", Message: "control extension requires at least one catalog or profile path"})
	}
	issues = append(issues, validateExtensionPaths("catalogs", pack.Catalogs)...)
	issues = append(issues, validateExtensionPaths("profiles", pack.Profiles)...)
	return issues
}

func MergeControlProfileSets(sets ...ControlProfileSet) ControlProfileSet {
	var merged ControlProfileSet
	for _, set := range sets {
		if strings.TrimSpace(merged.Version) == "" {
			merged.Version = strings.TrimSpace(set.Version)
		}
		merged.Profiles = append(merged.Profiles, set.Profiles...)
	}
	return merged
}

func validateExtensionPaths(path string, values []string) []ValidationIssue {
	var issues []ValidationIssue
	for idx, value := range values {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, ValidationIssue{Path: fmt.Sprintf("%s[%d]", path, idx), Message: "path is required"})
		}
	}
	return issues
}
