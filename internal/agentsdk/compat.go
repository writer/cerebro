package agentsdk

import (
	"encoding/json"
	"strings"
	"time"
)

type CompatibilityIssue struct {
	ContractType    string `json:"contract_type"`
	ContractID      string `json:"contract_id"`
	ChangeType      string `json:"change_type"`
	Detail          string `json:"detail,omitempty"`
	PreviousVersion string `json:"previous_version,omitempty"`
	CurrentVersion  string `json:"current_version,omitempty"`
}

type CompatibilityReport struct {
	GeneratedAt          time.Time            `json:"generated_at,omitempty"`
	BaselineTools        int                  `json:"baseline_tools"`
	CurrentTools         int                  `json:"current_tools"`
	BaselineResources    int                  `json:"baseline_resources"`
	CurrentResources     int                  `json:"current_resources"`
	AddedTools           []string             `json:"added_tools,omitempty"`
	RemovedTools         []string             `json:"removed_tools,omitempty"`
	AddedResources       []string             `json:"added_resources,omitempty"`
	RemovedResources     []string             `json:"removed_resources,omitempty"`
	BreakingChanges      []CompatibilityIssue `json:"breaking_changes,omitempty"`
	VersioningViolations []CompatibilityIssue `json:"versioning_violations,omitempty"`
}

func CompareCatalogs(baseline, current Catalog, generatedAt time.Time) CompatibilityReport {
	report := CompatibilityReport{
		GeneratedAt:       generatedAt.UTC(),
		BaselineTools:     len(baseline.Tools),
		CurrentTools:      len(current.Tools),
		BaselineResources: len(baseline.Resources),
		CurrentResources:  len(current.Resources),
	}
	baselineTools := make(map[string]ToolDefinition, len(baseline.Tools))
	currentTools := make(map[string]ToolDefinition, len(current.Tools))
	for _, tool := range baseline.Tools {
		baselineTools[strings.TrimSpace(tool.ID)] = tool
	}
	for _, tool := range current.Tools {
		currentTools[strings.TrimSpace(tool.ID)] = tool
	}
	for id, previous := range baselineTools {
		next, ok := currentTools[id]
		if !ok {
			report.RemovedTools = append(report.RemovedTools, id)
			report.BreakingChanges = append(report.BreakingChanges, CompatibilityIssue{
				ContractType:    "tool",
				ContractID:      id,
				ChangeType:      "removed",
				Detail:          "public tool contract removed",
				PreviousVersion: previous.Version,
			})
			continue
		}
		if !equalToolContract(previous, next) {
			issue := CompatibilityIssue{
				ContractType:    "tool",
				ContractID:      id,
				ChangeType:      "changed",
				Detail:          "public tool contract changed",
				PreviousVersion: previous.Version,
				CurrentVersion:  next.Version,
			}
			report.BreakingChanges = append(report.BreakingChanges, issue)
			if strings.TrimSpace(previous.Version) == strings.TrimSpace(next.Version) {
				report.VersioningViolations = append(report.VersioningViolations, issue)
			}
		}
	}
	for id := range currentTools {
		if _, ok := baselineTools[id]; !ok {
			report.AddedTools = append(report.AddedTools, id)
		}
	}

	baselineResources := make(map[string]ResourceDefinition, len(baseline.Resources))
	currentResources := make(map[string]ResourceDefinition, len(current.Resources))
	for _, resource := range baseline.Resources {
		baselineResources[strings.TrimSpace(resource.URI)] = resource
	}
	for _, resource := range current.Resources {
		currentResources[strings.TrimSpace(resource.URI)] = resource
	}
	for uri, previous := range baselineResources {
		next, ok := currentResources[uri]
		if !ok {
			report.RemovedResources = append(report.RemovedResources, uri)
			report.BreakingChanges = append(report.BreakingChanges, CompatibilityIssue{
				ContractType:    "resource",
				ContractID:      uri,
				ChangeType:      "removed",
				Detail:          "public resource contract removed",
				PreviousVersion: previous.Version,
			})
			continue
		}
		if !equalResourceContract(previous, next) {
			issue := CompatibilityIssue{
				ContractType:    "resource",
				ContractID:      uri,
				ChangeType:      "changed",
				Detail:          "public resource contract changed",
				PreviousVersion: previous.Version,
				CurrentVersion:  next.Version,
			}
			report.BreakingChanges = append(report.BreakingChanges, issue)
			if strings.TrimSpace(previous.Version) == strings.TrimSpace(next.Version) {
				report.VersioningViolations = append(report.VersioningViolations, issue)
			}
		}
	}
	for uri := range currentResources {
		if _, ok := baselineResources[uri]; !ok {
			report.AddedResources = append(report.AddedResources, uri)
		}
	}
	return report
}

func equalToolContract(a, b ToolDefinition) bool {
	a.ExampleInput = nil
	b.ExampleInput = nil
	return equalJSON(a, b)
}

func equalResourceContract(a, b ResourceDefinition) bool {
	return equalJSON(a, b)
}

func equalJSON(a, b any) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(left) == string(right)
}
