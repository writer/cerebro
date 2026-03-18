package sync

import "testing"

func TestAzureScopeFilter(t *testing.T) {
	rows := []map[string]interface{}{
		{"subscription_id": "sub-b"},
		{"subscription_id": "sub-a"},
		{"subscription_id": "sub-a"},
	}

	column, values := azureScopeFilter([]string{"subscription_id", "id"}, rows, "")
	if column != "SUBSCRIPTION_ID" {
		t.Fatalf("expected SUBSCRIPTION_ID column, got %q", column)
	}
	if len(values) != 2 || values[0] != "sub-a" || values[1] != "sub-b" {
		t.Fatalf("unexpected values: %#v", values)
	}
}

func TestAzureScopeFilterFallsBackToEngineSubscription(t *testing.T) {
	column, values := azureScopeFilter([]string{"subscription_id"}, nil, "sub-123")
	if column != "SUBSCRIPTION_ID" {
		t.Fatalf("expected SUBSCRIPTION_ID column, got %q", column)
	}
	if len(values) != 1 || values[0] != "sub-123" {
		t.Fatalf("unexpected values: %#v", values)
	}
}

func TestAzureScopeWhereClause(t *testing.T) {
	where, args := scopedWhereClause("SUBSCRIPTION_ID", []string{"sub-1", "sub-2"})
	if where != " WHERE SUBSCRIPTION_ID IN (?,?)" {
		t.Fatalf("unexpected where clause: %q", where)
	}
	if len(args) != 2 || args[0] != "sub-1" || args[1] != "sub-2" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestNormalizeAzureSubscriptionIDs(t *testing.T) {
	got := NormalizeAzureSubscriptionIDs([]string{" sub-b ", "SUB-A", "sub-a", "", "sub-c"})
	want := []string{"SUB-A", "sub-b", "sub-c"}
	if len(got) != len(want) {
		t.Fatalf("expected %d subscriptions, got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

func TestExtractAzureManagementGroupSubscriptionIDs(t *testing.T) {
	payload := map[string]any{
		"id":   "/providers/Microsoft.Management/managementGroups/root",
		"type": "Microsoft.Management/managementGroups",
		"properties": map[string]any{
			"children": []any{
				map[string]any{
					"childType": "Subscription",
					"id":        "/subscriptions/sub-b",
					"name":      "sub-b",
				},
				map[string]any{
					"childType": "ManagementGroup",
					"name":      "platform",
					"children": []any{
						map[string]any{
							"type": "Microsoft.Management/managementGroups/subscriptions",
							"id":   "/subscriptions/sub-a",
							"name": "sub-a",
						},
					},
				},
			},
		},
	}

	got := extractAzureManagementGroupSubscriptionIDs(payload)
	if len(got) != 2 || got[0] != "sub-a" || got[1] != "sub-b" {
		t.Fatalf("unexpected subscription discovery result: %#v", got)
	}
}
