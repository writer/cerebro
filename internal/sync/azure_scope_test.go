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
