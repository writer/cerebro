package graphingest

import (
	"testing"
	"time"

	"github.com/evalops/cerebro/internal/events"
	"github.com/evalops/cerebro/internal/graph"
)

func TestBuildMappingContracts(t *testing.T) {
	config := MappingConfig{
		APIVersion: "cerebro.graphingest/v1alpha1",
		Kind:       "MappingConfig",
		Mappings: []EventMapping{
			{
				Name:   "service_updated",
				Source: "ensemble.tap.test.service.updated",
				DataEnums: map[string][]string{
					"status": []string{"open", "closed"},
				},
				Nodes: []NodeMapping{
					{
						ID:       "service:{{data.service.id}}",
						Kind:     "service",
						Name:     "{{data.name}}",
						Provider: "test",
						Properties: map[string]any{
							"actor": "{{resolve(data.actor_email)}}",
						},
					},
				},
				Edges: []EdgeMapping{
					{
						Source: "{{resolve(data.actor_email)}}",
						Target: "service:{{data.service.id}}",
						Kind:   "interacted_with",
						Effect: "allow",
					},
				},
			},
		},
	}

	contracts := BuildMappingContracts(config)
	if len(contracts) != 1 {
		t.Fatalf("expected 1 contract row, got %d", len(contracts))
	}
	row := contracts[0]
	if row.APIVersion != "cerebro.graphingest/v1alpha1" {
		t.Fatalf("expected apiVersion to be inherited, got %q", row.APIVersion)
	}
	if row.ContractVersion != defaultMappingContractVersion {
		t.Fatalf("expected default contract version %q, got %q", defaultMappingContractVersion, row.ContractVersion)
	}
	if !containsContractString(row.RequiredDataKeys, "service.id") || !containsContractString(row.RequiredDataKeys, "actor_email") {
		t.Fatalf("expected required keys service.id + actor_email, got %#v", row.RequiredDataKeys)
	}
	if !containsContractString(row.OptionalDataKeys, "name") {
		t.Fatalf("expected optional key name, got %#v", row.OptionalDataKeys)
	}
	if !containsContractString(row.ResolveKeys, "actor_email") {
		t.Fatalf("expected resolve key actor_email, got %#v", row.ResolveKeys)
	}
	if statusValues := row.DataEnums["status"]; len(statusValues) != 2 {
		t.Fatalf("expected normalized status enum values, got %#v", statusValues)
	}
	if schemaType, _ := row.DataSchema["type"].(string); schemaType != "object" {
		t.Fatalf("expected data_schema.type=object, got %#v", row.DataSchema["type"])
	}
}

func TestValidateEventAgainstMappingContract(t *testing.T) {
	config := MappingConfig{
		Mappings: []EventMapping{
			{
				Name:            "contract_checked",
				Source:          "ensemble.tap.test.event.updated",
				ContractVersion: "1.0.0",
				SchemaURL:       "https://example.com/schemas/event.json",
				DataEnums: map[string][]string{
					"status": []string{"open", "closed"},
				},
				Nodes: []NodeMapping{
					{
						ID:       "service:{{data.service}}",
						Kind:     "service",
						Name:     "{{data.service}}",
						Provider: "test",
					},
				},
			},
		},
	}
	normalizeMappingConfig(&config)
	contracts := BuildMappingContracts(config)
	if len(contracts) != 1 {
		t.Fatalf("expected contract row")
	}

	issues := ValidateEventAgainstMappingContract(events.CloudEvent{
		ID:            "evt-1",
		Type:          "ensemble.tap.test.event.updated",
		Source:        "urn:ensemble:tap",
		Time:          time.Date(2026, 3, 9, 22, 0, 0, 0, time.UTC),
		SchemaVersion: "0.9.0",
		DataSchema:    "https://example.com/schemas/other.json",
		Data: map[string]any{
			"status": "invalid_status",
		},
	}, config.Mappings[0], contracts[0])
	if len(issues) < 3 {
		t.Fatalf("expected multiple contract issues, got %#v", issues)
	}
	for _, issue := range issues {
		if issue.Code != graph.SchemaIssueInvalidEventContract {
			t.Fatalf("expected invalid_event_contract code, got %#v", issues)
		}
	}
}

func TestCompareContractCatalogs(t *testing.T) {
	baseline := ContractCatalog{
		Mappings: []MappingContract{
			{
				Name:            "github_pr",
				ContractVersion: "1.0.0",
				RequiredDataKeys: []string{
					"repository",
				},
				DataEnums: map[string][]string{
					"state": []string{"open", "closed"},
				},
			},
		},
	}

	currentNoMajor := ContractCatalog{
		Mappings: []MappingContract{
			{
				Name:            "github_pr",
				ContractVersion: "1.1.0",
				RequiredDataKeys: []string{
					"repository",
					"number",
				},
				DataEnums: map[string][]string{
					"state": []string{"open"},
				},
			},
		},
	}
	report := CompareContractCatalogs(baseline, currentNoMajor, time.Time{})
	if report.Compatible {
		t.Fatalf("expected no-major breaking change to be incompatible, got %#v", report)
	}
	if len(report.VersioningViolations) == 0 {
		t.Fatalf("expected versioning violations, got %#v", report)
	}

	currentMajor := ContractCatalog{
		Mappings: []MappingContract{
			{
				Name:            "github_pr",
				ContractVersion: "2.0.0",
				RequiredDataKeys: []string{
					"repository",
					"number",
				},
				DataEnums: map[string][]string{
					"state": []string{"open"},
				},
			},
		},
	}
	majorReport := CompareContractCatalogs(baseline, currentMajor, time.Time{})
	if !majorReport.Compatible {
		t.Fatalf("expected major bump to satisfy compatibility checker, got %#v", majorReport)
	}
	if len(majorReport.BreakingChanges) == 0 {
		t.Fatalf("expected breaking changes to still be reported, got %#v", majorReport)
	}
}

func containsContractString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
