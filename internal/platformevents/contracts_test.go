package platformevents

import (
	"testing"

	"github.com/writer/cerebro/internal/webhooks"
)

func TestLifecycleContractsIncludeEvaluationEvents(t *testing.T) {
	contracts := LifecycleContracts()
	required := map[webhooks.EventType][]string{
		webhooks.EventEvaluationTurnCompleted: {
			"conversation_id",
			"turn_id",
			"evaluation_run_id",
			"decision_type",
			"source_system",
			"source_event_id",
			"observed_at",
			"valid_from",
		},
		webhooks.EventEvaluationConversationCompleted: {
			"conversation_id",
			"evaluation_run_id",
			"verdict",
			"source_system",
			"source_event_id",
			"observed_at",
			"valid_from",
		},
		webhooks.EventEvaluationAgentToolCall: {
			"conversation_id",
			"turn_id",
			"tool_call_id",
			"tool_name",
			"status",
			"source_system",
			"source_event_id",
			"observed_at",
			"valid_from",
		},
		webhooks.EventEvaluationAgentCost: {
			"conversation_id",
			"cost_id",
			"amount_usd",
			"currency",
			"source_system",
			"source_event_id",
			"observed_at",
			"valid_from",
		},
	}
	optional := map[webhooks.EventType][]string{
		webhooks.EventEvaluationTurnCompleted: {
			"target_ids",
			"stage_id",
			"stage_name",
			"stage_order",
			"previous_stage_id",
			"supersedes_stage_id",
			"contradicts_stage_id",
		},
		webhooks.EventEvaluationConversationCompleted: {"target_ids", "final_stage_id"},
		webhooks.EventEvaluationAgentToolCall:         {"target_ids", "stage_id", "stage_name"},
		webhooks.EventEvaluationAgentCost:             {"target_ids", "stage_id"},
	}

	for eventType, keys := range required {
		contract := findLifecycleContract(contracts, eventType)
		if contract == nil {
			t.Fatalf("expected lifecycle contract for %q", eventType)
		}
		if contract.SchemaURL == "" {
			t.Fatalf("expected schema URL for %q", eventType)
		}
		for _, key := range keys {
			if !containsString(contract.RequiredDataKeys, key) {
				t.Fatalf("expected %q required keys to include %q, got %#v", eventType, key, contract.RequiredDataKeys)
			}
		}
		for _, key := range optional[eventType] {
			if !containsString(contract.OptionalDataKeys, key) {
				t.Fatalf("expected %q optional keys to include %q, got %#v", eventType, key, contract.OptionalDataKeys)
			}
		}
	}
}

func TestLifecycleContractsIncludePlaybookEvents(t *testing.T) {
	contracts := LifecycleContracts()
	required := map[webhooks.EventType][]string{
		webhooks.EventPlatformPlaybookRunStarted: {
			"playbook_run_id",
			"playbook_id",
			"playbook_name",
			"status",
			"source_system",
			"source_event_id",
			"observed_at",
			"valid_from",
		},
		webhooks.EventPlatformPlaybookStageCompleted: {
			"playbook_run_id",
			"stage_id",
			"stage_name",
			"stage_order",
			"status",
			"source_system",
			"source_event_id",
			"observed_at",
			"valid_from",
		},
		webhooks.EventPlatformPlaybookActionExecuted: {
			"playbook_run_id",
			"stage_id",
			"action_id",
			"action_type",
			"status",
			"source_system",
			"source_event_id",
			"observed_at",
			"valid_from",
		},
		webhooks.EventPlatformPlaybookRunCompleted: {
			"playbook_run_id",
			"playbook_id",
			"playbook_name",
			"verdict",
			"status",
			"source_system",
			"source_event_id",
			"observed_at",
			"valid_from",
		},
	}
	optional := map[webhooks.EventType][]string{
		webhooks.EventPlatformPlaybookRunStarted:     {"operator_email", "automation_id", "target_ids"},
		webhooks.EventPlatformPlaybookStageCompleted: {"previous_stage_id", "retry_of_stage_id", "approval_status", "approver_email", "target_ids"},
		webhooks.EventPlatformPlaybookActionExecuted: {"title", "summary", "operator_email", "automation_id", "target_ids"},
		webhooks.EventPlatformPlaybookRunCompleted:   {"final_stage_id", "rollback_state", "completed_stage_count", "target_ids"},
	}

	for eventType, keys := range required {
		contract := findLifecycleContract(contracts, eventType)
		if contract == nil {
			t.Fatalf("expected lifecycle contract for %q", eventType)
		}
		if contract.SchemaURL == "" {
			t.Fatalf("expected schema URL for %q", eventType)
		}
		for _, key := range keys {
			if !containsString(contract.RequiredDataKeys, key) {
				t.Fatalf("expected %q required keys to include %q, got %#v", eventType, key, contract.RequiredDataKeys)
			}
		}
		for _, key := range optional[eventType] {
			if !containsString(contract.OptionalDataKeys, key) {
				t.Fatalf("expected %q optional keys to include %q, got %#v", eventType, key, contract.OptionalDataKeys)
			}
		}
	}
}

func findLifecycleContract(contracts []LifecycleEventContract, eventType webhooks.EventType) *LifecycleEventContract {
	for i := range contracts {
		if contracts[i].EventType == eventType {
			return &contracts[i]
		}
	}
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
