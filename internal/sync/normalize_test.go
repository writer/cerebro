package sync

import (
	"reflect"
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

func TestNormalizeRowValuesTimestampFormats(t *testing.T) {
	row := map[string]interface{}{
		"create_time": int64(1735689600),
		"update_time": "2025-01-02 03:04:05",
		"note":        "2025-01-02 03:04:05",
	}

	normalizeRowValues(row)

	if row["create_time"] != "2025-01-01T00:00:00Z" {
		t.Fatalf("expected epoch create_time to normalize, got %#v", row["create_time"])
	}
	if row["update_time"] != "2025-01-02T03:04:05Z" {
		t.Fatalf("expected string update_time to normalize, got %#v", row["update_time"])
	}
	if row["note"] != "2025-01-02 03:04:05" {
		t.Fatalf("expected non-time field to remain unchanged, got %#v", row["note"])
	}
}

func TestNormalizeRowValuesLabels(t *testing.T) {
	row := map[string]interface{}{
		"labels": map[string]interface{}{
			"env":  "prod",
			"tier": 3,
		},
	}

	normalizeRowValues(row)
	labels, ok := row["labels"].(map[string]string)
	if !ok {
		t.Fatalf("expected labels to normalize to map[string]string, got %#v", row["labels"])
	}
	if labels["env"] != "prod" || labels["tier"] != "3" {
		t.Fatalf("unexpected labels normalization result: %#v", labels)
	}
}

func TestNormalizeRowsEnforcesSchema(t *testing.T) {
	rows := []map[string]interface{}{
		{
			"_cq_id":      "project-a/logging-sinks",
			"project_id":  "project-a",
			"id":          "project-a/logging-sinks",
			"labels":      `{"team":"platform"}`,
			"create_time": int64(1735689600),
			"unexpected":  "drop-me",
		},
	}

	normalized := normalizeRows("gcp_logging_project_sinks", []string{"project_id", "id", "labels", "create_time"}, rows, nil)
	if len(normalized) != 1 {
		t.Fatalf("expected one normalized row, got %d", len(normalized))
	}

	row := normalized[0]
	if _, ok := row["unexpected"]; ok {
		t.Fatalf("expected unexpected column to be dropped, row=%#v", row)
	}
	if row["create_time"] != "2025-01-01T00:00:00Z" {
		t.Fatalf("expected create_time normalization, got %#v", row["create_time"])
	}
	if labels, ok := row["labels"].(map[string]string); !ok || !reflect.DeepEqual(labels, map[string]string{"team": "platform"}) {
		t.Fatalf("expected normalized labels map, got %#v", row["labels"])
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
		seen := assertUniqueColumns(t, table.Name, table.Columns)

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

func TestProviderTableSchemaConsistency(t *testing.T) {
	t.Run("gcp", func(t *testing.T) {
		tables := (&GCPSyncEngine{}).getGCPTables()
		for _, table := range tables {
			assertUniqueColumns(t, table.Name, table.Columns)
			if !hasColumn(table.Columns, "project_id") {
				t.Fatalf("missing project_id in %s", table.Name)
			}
			if !hasColumn(table.Columns, "id") && !hasColumn(table.Columns, "name") {
				t.Fatalf("missing id/name identity column in %s", table.Name)
			}
		}
	})

	t.Run("azure", func(t *testing.T) {
		tables := (&AzureSyncEngine{}).getAzureTables()
		for _, table := range tables {
			assertUniqueColumns(t, table.Name, table.Columns)
			if !hasColumn(table.Columns, "subscription_id") {
				t.Fatalf("missing subscription_id in %s", table.Name)
			}
			if !hasColumn(table.Columns, "id") {
				t.Fatalf("missing id in %s", table.Name)
			}
		}
	})

	t.Run("k8s", func(t *testing.T) {
		tables := (&K8sSyncEngine{}).getK8sTables()
		for _, table := range tables {
			assertUniqueColumns(t, table.Name, table.Columns)
			if !hasColumn(table.Columns, "cluster_name") {
				t.Fatalf("missing cluster_name in %s", table.Name)
			}
		}
	})
}

func assertUniqueColumns(t *testing.T, tableName string, columns []string) map[string]struct{} {
	t.Helper()
	seen := make(map[string]struct{}, len(columns))
	for _, column := range columns {
		name := strings.ToLower(column)
		if _, exists := seen[name]; exists {
			t.Fatalf("duplicate column %q in %s", name, tableName)
		}
		seen[name] = struct{}{}
	}
	return seen
}
