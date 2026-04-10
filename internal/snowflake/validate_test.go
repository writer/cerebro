package snowflake

import (
	"testing"
)

func TestValidateTableName_SQLInjection(t *testing.T) {
	injections := []string{
		"users; DROP TABLE users",
		"users--comment",
		"users/*comment*/",
		"users' OR '1'='1",
		"users OR 1=1",
		"users UNION SELECT *",
		"users; DELETE FROM users",
		"users; INSERT INTO evil",
	}
	for _, name := range injections {
		if err := ValidateTableName(name); err == nil {
			t.Errorf("ValidateTableName(%q) should reject SQL injection", name)
		}
	}
}

func TestValidateTableName_LengthLimit(t *testing.T) {
	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	if err := ValidateTableName(string(long)); err == nil {
		t.Error("should reject 256 char table name")
	}

	// 255 is OK
	ok255 := make([]byte, 255)
	ok255[0] = 'a'
	for i := 1; i < len(ok255); i++ {
		ok255[i] = 'a'
	}
	if err := ValidateTableName(string(ok255)); err != nil {
		t.Errorf("255 char name should be valid: %v", err)
	}
}

func TestValidateColumnName_AcceptsValid(t *testing.T) {
	valid := []string{"column_name", "_id", "Region", "account_id"}
	for _, c := range valid {
		if err := ValidateColumnName(c); err != nil {
			t.Errorf("ValidateColumnName(%q) = %v, want nil", c, err)
		}
	}
}

func TestValidateTableNameStrict_AllPrefixes(t *testing.T) {
	prefixes := []struct {
		table string
		valid bool
	}{
		{"aws_iam_roles", true},
		{"gcp_compute_instances", true},
		{"azure_storage_accounts", true},
		{"k8s_pods", true},
		{"okta_users", true},
		{"github_repos", true},
		{"snyk_vulns", true},
		{"crowdstrike_detections", true},
		{"sentinelone_agents", true},
		{"tenable_findings", true},
		{"datadog_monitors", true},
		{"qualys_hosts", true},
		{"entra_users", true},
		{"identity_user_accounts", true},
		{"mdm_devices", true},
		{"ai_models", true},
		{"telemetry_secret_scan_findings", true},
		{"security_issues", true},
		{"infrastructure_inventory", true},
		{"backups", true},
		{"employees", true},
		{"cerebro_findings", true},
		{"unknown_prefix_table", false},
		{"my_custom_table", false},
	}

	for _, tc := range prefixes {
		err := ValidateTableNameStrict(tc.table)
		if tc.valid && err != nil {
			t.Errorf("ValidateTableNameStrict(%q) = %v, want nil", tc.table, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("ValidateTableNameStrict(%q) = nil, want error", tc.table)
		}
	}
}

func TestQuoteIdentifier_SpecialChars(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", `"simple"`},
		{`has"quote`, `"has""quote"`},
		{`two""quotes`, `"two""""quotes"`},
	}
	for _, tc := range tests {
		got := QuoteIdentifier(tc.input)
		if got != tc.expected {
			t.Errorf("QuoteIdentifier(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestSafeTableRef_Normalization(t *testing.T) {
	ref, err := SafeTableRef("mydb", "myschema", "aws_iam_roles")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref != "MYDB.MYSCHEMA.AWS_IAM_ROLES" {
		t.Errorf("expected uppercase normalization, got %q", ref)
	}
}

func TestSafeTableRef_Rejects(t *testing.T) {
	tests := []struct {
		db, schema, table string
	}{
		{"bad;db", "schema", "table"},
		{"db", "bad schema", "table"},
		{"db", "schema", "bad;table"},
	}
	for _, tc := range tests {
		_, err := SafeTableRef(tc.db, tc.schema, tc.table)
		if err == nil {
			t.Errorf("SafeTableRef(%q, %q, %q) should fail", tc.db, tc.schema, tc.table)
		}
	}
}

func TestValidateTableName_AcceptsValidDatabaseNames(t *testing.T) {
	valid := []string{"CEREBRO", "my_database", "DB1", "_internal", "Production_DB_2"}
	for _, name := range valid {
		if err := ValidateTableName(name); err != nil {
			t.Errorf("ValidateTableName(%q) = %v, want nil", name, err)
		}
	}
}

func TestValidateTableName_RejectsInvalidDatabaseNames(t *testing.T) {
	invalid := []struct {
		name   string
		reason string
	}{
		{"", "empty"},
		{"db; DROP DATABASE cerebro", "sql injection semicolon"},
		{"db--comment", "sql comment"},
		{"db' OR '1'='1", "sql injection quote"},
		{"my database", "contains space"},
		{"db.schema", "contains dot"},
	}
	for _, tc := range invalid {
		if err := ValidateTableName(tc.name); err == nil {
			t.Errorf("ValidateTableName(%q) should reject (%s)", tc.name, tc.reason)
		}
	}
}

func TestValidateTableName_Empty(t *testing.T) {
	err := ValidateTableName("")
	if err == nil {
		t.Error("ValidateTableName('') should return error")
	}
}

func TestValidateQualifiedSchemaRef(t *testing.T) {
	ref, err := ValidateQualifiedSchemaRef(" cerebro . app ")
	if err != nil {
		t.Fatalf("ValidateQualifiedSchemaRef returned error: %v", err)
	}
	if ref != "CEREBRO.APP" {
		t.Fatalf("unexpected normalized schema ref %q", ref)
	}

	if _, err := ValidateQualifiedSchemaRef("justdb"); err == nil {
		t.Fatal("expected malformed schema ref to fail")
		return
	}
	if _, err := ValidateQualifiedSchemaRef("db.bad schema"); err == nil {
		t.Fatal("expected invalid schema name to fail")
		return
	}
}

func TestSafeQualifiedTableRef(t *testing.T) {
	ref, err := SafeQualifiedTableRef("cerebro.app", "risk_engine_state")
	if err != nil {
		t.Fatalf("SafeQualifiedTableRef returned error: %v", err)
	}
	if ref != "CEREBRO.APP.RISK_ENGINE_STATE" {
		t.Fatalf("unexpected qualified table ref %q", ref)
	}

	if _, err := SafeQualifiedTableRef("bad schema", "risk_engine_state"); err == nil {
		t.Fatal("expected invalid schema ref to fail")
		return
	}
	if _, err := SafeQualifiedTableRef("cerebro.app", "bad;table"); err == nil {
		t.Fatal("expected invalid table name to fail")
		return
	}
}
