package sync

import (
	"testing"
)

func TestNormalizeTableFilter(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect int
	}{
		{"nil", nil, 0},
		{"empty", []string{}, 0},
		{"whitespace only", []string{"  ", "\t"}, 0},
		{"single", []string{"aws_s3_buckets"}, 1},
		{"multiple", []string{"aws_s3_buckets", "gcp_compute_instances"}, 2},
		{"dedupes", []string{"aws_s3_buckets", "aws_s3_buckets"}, 1},
		{"lowercases", []string{"AWS_S3_BUCKETS"}, 1},
		{"trims", []string{"  aws_s3_buckets  "}, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeTableFilter(tc.input)
			if tc.expect == 0 {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if len(got) != tc.expect {
				t.Errorf("expected %d entries, got %d", tc.expect, len(got))
			}
		})
	}
}

func TestNormalizeTableFilter_LowercaseKey(t *testing.T) {
	f := normalizeTableFilter([]string{"AWS_S3_BUCKETS"})
	if _, ok := f["aws_s3_buckets"]; !ok {
		t.Error("expected lowercase key")
	}
}

func TestFilterNames(t *testing.T) {
	f := normalizeTableFilter([]string{"c_table", "a_table", "b_table"})
	names := filterNames(f)
	if len(names) != 3 {
		t.Fatalf("expected 3, got %d", len(names))
	}
	// Should be sorted
	if names[0] != "a_table" || names[1] != "b_table" || names[2] != "c_table" {
		t.Errorf("expected sorted, got %v", names)
	}
}

func TestFilterNames_Nil(t *testing.T) {
	names := filterNames(nil)
	if names != nil {
		t.Errorf("expected nil, got %v", names)
	}
}

func TestMatchesFilter(t *testing.T) {
	f := normalizeTableFilter([]string{"aws_s3_buckets", "aws_iam_roles"})

	if !matchesFilter(f, "aws_s3_buckets") {
		t.Error("should match aws_s3_buckets")
	}
	if !matchesFilter(f, "AWS_IAM_ROLES") {
		t.Error("should match uppercase")
	}
	if matchesFilter(f, "gcp_compute_instances") {
		t.Error("should not match gcp_compute_instances")
	}
	if matchesFilter(f, "") {
		t.Error("should not match empty string")
	}
}

func TestMatchesFilter_NilPassesAll(t *testing.T) {
	if !matchesFilter(nil, "anything") {
		t.Error("nil filter should pass all")
	}
}

func TestFilterTableSpecs(t *testing.T) {
	tables := []TableSpec{
		{Name: "aws_s3_buckets"},
		{Name: "aws_iam_roles"},
		{Name: "aws_ec2_instances"},
	}

	f := normalizeTableFilter([]string{"aws_s3_buckets", "aws_ec2_instances"})
	filtered := filterTableSpecs(tables, f)
	if len(filtered) != 2 {
		t.Fatalf("expected 2, got %d", len(filtered))
	}
}

func TestFilterTableSpecs_NilFilter(t *testing.T) {
	tables := []TableSpec{{Name: "a"}, {Name: "b"}}
	filtered := filterTableSpecs(tables, nil)
	if len(filtered) != 2 {
		t.Error("nil filter should return all tables")
	}
}

func TestFilterGCPTables(t *testing.T) {
	tables := []GCPTableSpec{
		{Name: "gcp_storage_buckets"},
		{Name: "gcp_compute_instances"},
	}
	f := normalizeTableFilter([]string{"gcp_storage_buckets"})
	filtered := filterGCPTables(tables, f)
	if len(filtered) != 1 {
		t.Fatalf("expected 1, got %d", len(filtered))
	}
	if filtered[0].Name != "gcp_storage_buckets" {
		t.Errorf("unexpected: %s", filtered[0].Name)
	}
}

func TestFilterAzureTables(t *testing.T) {
	tables := []AzureTableSpec{
		{Name: "azure_storage_accounts"},
		{Name: "azure_compute_vms"},
	}
	f := normalizeTableFilter([]string{"azure_storage_accounts"})
	filtered := filterAzureTables(tables, f)
	if len(filtered) != 1 {
		t.Fatalf("expected 1, got %d", len(filtered))
	}
}

func TestFilterK8sTables(t *testing.T) {
	tables := []K8sTableSpec{
		{Name: "k8s_core_pods"},
		{Name: "k8s_core_services"},
	}
	f := normalizeTableFilter([]string{"k8s_core_pods"})
	filtered := filterK8sTables(tables, f)
	if len(filtered) != 1 {
		t.Fatalf("expected 1, got %d", len(filtered))
	}
	if filtered[0].Name != "k8s_core_pods" {
		t.Errorf("unexpected: %s", filtered[0].Name)
	}
}
