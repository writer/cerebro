package cloudquery

import (
	"strings"
	"testing"
)

func TestTableDefinition_Fields(t *testing.T) {
	table := TableDefinition{
		Name:        "test_table",
		Description: "A test table",
		Columns: []Column{
			{Name: "id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "name", Type: "VARCHAR"},
		},
		Relations: []string{"child_table"},
	}

	if table.Name != "test_table" {
		t.Error("Name field incorrect")
	}

	if table.Description != "A test table" {
		t.Error("Description field incorrect")
	}

	if len(table.Columns) != 2 {
		t.Error("Columns count incorrect")
	}

	if len(table.Relations) != 1 {
		t.Error("Relations count incorrect")
	}
}

func TestColumn_Fields(t *testing.T) {
	col := Column{
		Name:        "test_col",
		Type:        "VARCHAR",
		Description: "A test column",
		PrimaryKey:  true,
	}

	if col.Name != "test_col" {
		t.Error("Name field incorrect")
	}
	if col.Type != "VARCHAR" {
		t.Error("Type field incorrect")
	}
	if col.Description != "A test column" {
		t.Error("Description field incorrect")
	}
	if !col.PrimaryKey {
		t.Error("PrimaryKey should be true")
	}
}

func TestAWSIAMTables_Exists(t *testing.T) {
	expectedTables := []string{
		"aws_iam_accounts",
		"aws_iam_credential_reports",
		"aws_iam_policies",
		"aws_iam_roles",
		"aws_iam_users",
	}

	for _, name := range expectedTables {
		if _, ok := AWSIAMTables[name]; !ok {
			t.Errorf("expected table %s to exist", name)
		}
	}
}

func TestAWSIAMTables_HasRequiredColumns(t *testing.T) {
	for name, table := range AWSIAMTables {
		hasCQID := false

		for _, col := range table.Columns {
			if col.Name == "_cq_id" {
				hasCQID = true
			}
		}

		if !hasCQID {
			t.Errorf("table %s missing _cq_id column", name)
		}
	}
}

func TestAWSS3Tables_Exists(t *testing.T) {
	expectedTables := []string{
		"aws_s3_buckets",
	}

	for _, name := range expectedTables {
		if _, ok := AWSS3Tables[name]; !ok {
			t.Errorf("expected table %s to exist", name)
		}
	}
}

func TestAWSEC2Tables_Exists(t *testing.T) {
	expectedTables := []string{
		"aws_ec2_instances",
		"aws_ec2_security_groups",
		"aws_ec2_vpcs",
	}

	for _, name := range expectedTables {
		if _, ok := AWSEC2Tables[name]; !ok {
			t.Errorf("expected table %s to exist", name)
		}
	}
}

func TestGenerateCreateTableSQL(t *testing.T) {
	table := TableDefinition{
		Name:        "test_table",
		Description: "Test table",
		Columns: []Column{
			{Name: "id", Type: "VARCHAR", PrimaryKey: true},
			{Name: "name", Type: "VARCHAR"},
			{Name: "count", Type: "NUMBER"},
		},
	}

	sql := GenerateCreateTableSQL(table)

	if !strings.Contains(sql, "CREATE TABLE IF NOT EXISTS test_table") {
		t.Error("SQL should contain CREATE TABLE statement")
	}

	if !strings.Contains(sql, "id VARCHAR") {
		t.Error("SQL should contain id column")
	}

	if !strings.Contains(sql, "name VARCHAR") {
		t.Error("SQL should contain name column")
	}

	if !strings.Contains(sql, "count NUMBER") {
		t.Error("SQL should contain count column")
	}

	if !strings.Contains(sql, "_cq_sync_time TIMESTAMP_NTZ") {
		t.Error("SQL should contain _cq_sync_time column")
	}
}

func TestGetAllTables(t *testing.T) {
	tables := GetAllTables()

	if len(tables) == 0 {
		t.Error("GetAllTables should return tables")
	}

	// Check that we have IAM tables
	hasIAM := false
	for _, table := range tables {
		if strings.HasPrefix(table.Name, "aws_iam_") {
			hasIAM = true
			break
		}
	}

	if !hasIAM {
		t.Error("GetAllTables should include IAM tables")
	}
}

func TestGetTableByName(t *testing.T) {
	table, ok := GetTableByName("aws_iam_users")
	if !ok {
		t.Fatal("aws_iam_users table should exist")
	}

	if table.Name != "aws_iam_users" {
		t.Error("table name incorrect")
	}

	// Non-existent table
	_, ok = GetTableByName("nonexistent_table")
	if ok {
		t.Error("nonexistent table should return false")
	}
}
