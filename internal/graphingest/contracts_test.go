package graphingest

import (
	"testing"
	"time"

	"github.com/writer/cerebro/internal/events"
	"github.com/writer/cerebro/internal/graph"
	"github.com/writer/cerebro/internal/platformevents"
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

func TestBuildContractCatalogIncludesLifecycleEvents(t *testing.T) {
	catalog := BuildContractCatalog(MappingConfig{}, time.Date(2026, 3, 9, 22, 0, 0, 0, time.UTC))
	if len(catalog.LifecycleEvents) == 0 {
		t.Fatal("expected lifecycle event contracts to be present")
	}
	first := catalog.LifecycleEvents[0]
	if first.EventType == "" {
		t.Fatalf("expected lifecycle event type, got %#v", first)
	}
	if first.SchemaURL == "" {
		t.Fatalf("expected lifecycle schema URL, got %#v", first)
	}
	if schemaType, _ := first.DataSchema["type"].(string); schemaType != "object" {
		t.Fatalf("expected lifecycle data_schema.type=object, got %#v", first.DataSchema["type"])
	}
}

func TestBuildContractCatalogIncludesEvaluationMappings(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}

	catalog := BuildContractCatalog(config, time.Date(2026, 3, 9, 22, 0, 0, 0, time.UTC))
	required := map[string][]string{
		"evaluation_conversation_completed": {"conversation_id", "evaluation_run_id"},
		"evaluation_turn_completed":         {"conversation_id", "turn_id", "evaluation_run_id"},
		"evaluation_agent_tool_call":        {"conversation_id", "turn_id", "tool_call_id", "evaluation_run_id"},
		"evaluation_agent_cost":             {"conversation_id", "cost_id", "evaluation_run_id"},
	}
	optional := map[string][]string{
		"evaluation_conversation_completed": {"verdict", "summary", "target_ids", "final_stage_id"},
		"evaluation_turn_completed": {
			"decision_type",
			"rationale",
			"target_ids",
			"stage_id",
			"stage_name",
			"stage_order",
			"previous_stage_id",
			"supersedes_stage_id",
			"contradicts_stage_id",
		},
		"evaluation_agent_tool_call": {"tool_name", "status", "target_ids", "stage_id", "stage_name"},
		"evaluation_agent_cost":      {"amount_usd", "currency", "target_ids", "stage_id"},
	}

	for mappingName, requiredKeys := range required {
		contract := findMappingContract(catalog.Mappings, mappingName)
		if contract == nil {
			t.Fatalf("expected mapping contract %q", mappingName)
		}
		for _, key := range requiredKeys {
			if !containsContractString(contract.RequiredDataKeys, key) {
				t.Fatalf("expected %q required keys to include %q, got %#v", mappingName, key, contract.RequiredDataKeys)
			}
		}
		for _, key := range optional[mappingName] {
			if !containsContractString(contract.OptionalDataKeys, key) {
				t.Fatalf("expected %q optional keys to include %q, got %#v", mappingName, key, contract.OptionalDataKeys)
			}
		}
	}
}

func TestBuildContractCatalogIncludesPlaybookMappings(t *testing.T) {
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("load default config failed: %v", err)
	}

	catalog := BuildContractCatalog(config, time.Date(2026, 3, 23, 1, 0, 0, 0, time.UTC))
	required := map[string][]string{
		"platform_playbook_run_started":     {"playbook_run_id"},
		"platform_playbook_stage_completed": {"playbook_run_id", "stage_id"},
		"platform_playbook_action_executed": {"playbook_run_id", "stage_id", "action_id"},
		"platform_playbook_run_completed":   {"playbook_run_id"},
	}
	optional := map[string][]string{
		"platform_playbook_run_started":     {"playbook_id", "playbook_name", "operator_email", "automation_id", "target_ids"},
		"platform_playbook_stage_completed": {"stage_name", "stage_order", "previous_stage_id", "retry_of_stage_id", "approval_status", "target_ids"},
		"platform_playbook_action_executed": {"action_type", "title", "summary", "operator_email", "target_ids"},
		"platform_playbook_run_completed":   {"playbook_id", "playbook_name", "verdict", "final_stage_id", "rollback_state", "target_ids"},
	}

	for mappingName, requiredKeys := range required {
		contract := findMappingContract(catalog.Mappings, mappingName)
		if contract == nil {
			t.Fatalf("expected mapping contract %q", mappingName)
		}
		for _, key := range requiredKeys {
			if !containsContractString(contract.RequiredDataKeys, key) {
				t.Fatalf("expected %q required keys to include %q, got %#v", mappingName, key, contract.RequiredDataKeys)
			}
		}
		for _, key := range optional[mappingName] {
			if !containsContractString(contract.OptionalDataKeys, key) {
				t.Fatalf("expected %q optional keys to include %q, got %#v", mappingName, key, contract.OptionalDataKeys)
			}
		}
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
		LifecycleEvents: []platformevents.LifecycleEventContract{
			{
				EventType:        "platform.claim.written",
				SchemaURL:        "urn:cerebro:events/platform.claim.written/v1",
				RequiredDataKeys: []string{"claim_id", "subject_id"},
				DataSchema: map[string]any{
					"properties": map[string]any{
						"claim_id":   map[string]any{"type": "string"},
						"subject_id": map[string]any{"type": "string"},
					},
				},
			},
		},
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
		LifecycleEvents: []platformevents.LifecycleEventContract{
			{
				EventType:        "platform.claim.written",
				SchemaURL:        "urn:cerebro:events/platform.claim.written/v1",
				RequiredDataKeys: []string{"claim_id", "subject_id", "predicate"},
				DataSchema: map[string]any{
					"properties": map[string]any{
						"claim_id":   map[string]any{"type": "string"},
						"subject_id": map[string]any{"type": "integer"},
						"predicate":  map[string]any{"type": "string"},
					},
				},
			},
		},
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
	if report.BaselineLifecycleEvents != 1 || report.CurrentLifecycleEvents != 1 {
		t.Fatalf("expected lifecycle counts to be tracked, got %#v", report)
	}

	currentMajor := ContractCatalog{
		LifecycleEvents: []platformevents.LifecycleEventContract{
			{
				EventType:        "platform.claim.written",
				SchemaURL:        "urn:cerebro:events/platform.claim.written/v2",
				RequiredDataKeys: []string{"claim_id", "subject_id", "predicate"},
				DataSchema: map[string]any{
					"properties": map[string]any{
						"claim_id":   map[string]any{"type": "string"},
						"subject_id": map[string]any{"type": "integer"},
						"predicate":  map[string]any{"type": "string"},
					},
				},
			},
		},
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

func findMappingContract(contracts []MappingContract, name string) *MappingContract {
	for i := range contracts {
		if contracts[i].Name == name {
			return &contracts[i]
		}
	}
	return nil
}
