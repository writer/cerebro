package sync

import (
	"strings"
	"testing"
	"time"
)

type testTag struct {
	Key   *string
	Value *string
}

func TestNormalizeRowValuesTime(t *testing.T) {
	now := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	row := map[string]interface{}{
		"created_at": now,
		"updated_at": &now,
		"empty_time": time.Time{},
	}

	normalizeRowValues(row)

	if row["created_at"] != now.Format(time.RFC3339) {
		t.Fatalf("expected created_at to be normalized, got %#v", row["created_at"])
	}
	if row["updated_at"] != now.Format(time.RFC3339) {
		t.Fatalf("expected updated_at to be normalized, got %#v", row["updated_at"])
	}
	if row["empty_time"] != "" {
		t.Fatalf("expected empty_time to be empty string, got %#v", row["empty_time"])
	}
}

func TestNormalizeRowValuesTags(t *testing.T) {
	key := "env"
	val := "prod"
	row := map[string]interface{}{
		"tags": []testTag{{Key: &key, Value: &val}},
	}

	normalizeRowValues(row)
	parsed, ok := row["tags"].(map[string]string)
	if !ok {
		t.Fatalf("expected tags to normalize to map, got %#v", row["tags"])
	}
	if parsed["env"] != "prod" {
		t.Fatalf("expected tag env=prod, got %#v", parsed)
	}
}

func TestNormalizeAWSRowsDerivesCQID(t *testing.T) {
	engine := &SyncEngine{accountID: "123456789012"}
	table := TableSpec{
		Name:    "aws_autoscaling_lifecycle_hooks",
		Columns: []string{"account_id", "region", "id"},
	}
	rows := []map[string]interface{}{
		{
			"auto_scaling_group_name": "asg",
			"lifecycle_hook_name":     "hook",
		},
	}

	normalized := engine.normalizeAWSRows(table, "us-west-2", rows)
	row := normalized[0]
	if row["_cq_id"] != "123456789012:us-west-2:asg:hook" {
		t.Fatalf("expected _cq_id to be derived, got %#v", row["_cq_id"])
	}
	if row["id"] != "asg:hook" {
		t.Fatalf("expected id to be derived, got %#v", row["id"])
	}
	if row["account_id"] != "123456789012" {
		t.Fatalf("expected account_id to be filled, got %#v", row["account_id"])
	}
	if row["region"] != "us-west-2" {
		t.Fatalf("expected region to be filled, got %#v", row["region"])
	}
}

func TestAWSTableSchemaConsistency(t *testing.T) {
	tables := (&SyncEngine{}).getAWSTables()
	for _, table := range tables {
		seen := make(map[string]struct{})
		for _, column := range table.Columns {
			name := strings.ToLower(column)
			if _, exists := seen[name]; exists {
				t.Fatalf("duplicate column %q in %s", name, table.Name)
			}
			seen[name] = struct{}{}
		}

		if _, ok := seen["account_id"]; !ok {
			t.Fatalf("missing account_id in %s", table.Name)
		}
		if _, ok := seen["region"]; !ok {
			t.Fatalf("missing region in %s", table.Name)
		}
		if _, ok := seen["arn"]; !ok {
			if _, ok := seen["id"]; !ok {
				t.Fatalf("missing arn/id in %s", table.Name)
			}
		}
	}
}
