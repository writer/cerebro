package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestCheckRepositoryAcceptsMinimalCatalogs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/github/test.json", `{
  "id": "github-test",
  "name": "GitHub Test",
  "description": "Test policy",
  "effect": "forbid",
  "resource": "github::repository",
  "conditions": ["cmp_eq(path(resource, \"visibility\"), \"public\")"],
  "condition_format": "cel",
  "severity": "high",
  "tags": ["github"],
  "frameworks": [{"name": "SOC 2", "controls": ["CC6"]}]
}`)
	writeFile(t, root, "policies/cerebro/control-mapping.json", `{"version":"1.0.0","controls":{}}`)
	writeFile(t, root, "sources/github/catalog.yaml", `
id: github
name: GitHub
description: GitHub source
emitted_kinds:
  - github.audit
kind_lifecycle:
  - kind: github.secret_scanning
    status: planned
`)

	issues, err := checkRepository(root)
	if err != nil {
		t.Fatalf("checkRepository() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none", issues)
	}
}

func TestCheckRepositoryRejectsPolicyMissingMetadata(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/github/test.json", `{"id":"github-test","conditions":["true"]}`)
	writeFile(t, root, "sources/sdk/catalog.yaml", `id: sdk
name: SDK
emitted_kinds: []
`)

	issues, err := checkRepository(root)
	if err != nil {
		t.Fatalf("checkRepository() error = %v", err)
	}
	if len(issues) == 0 {
		t.Fatal("issues = 0, want policy metadata issue")
	}
}

func TestCheckRepositoryRejectsUnprojectedEmittedKind(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/github/test.json", `{
  "id": "github-test",
  "name": "GitHub Test",
  "description": "Test policy",
  "query": "SELECT 1",
  "severity": "LOW"
}`)
	writeFile(t, root, "sources/custom/catalog.yaml", `
id: custom
name: Custom
emitted_kinds:
  - custom.audit
`)

	issues, err := checkRepository(root)
	if err != nil {
		t.Fatalf("checkRepository() error = %v", err)
	}
	if len(issues) == 0 {
		t.Fatal("issues = 0, want unprojected emitted kind issue")
	}
}

func TestCheckCloudPolicyCoverageRejectsUnmappedCloudPolicyResource(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/cloud/test.json", `{"resource":"aws::unknown::thing"}`)
	writeFile(t, root, "sources/aws/catalog.yaml", `
id: aws
name: AWS
description: AWS source
emitted_kinds:
  - aws.access_key
`)

	issues, err := checkCloudPolicyCoverage(root)
	if err != nil {
		t.Fatalf("checkCloudPolicyCoverage() error = %v", err)
	}
	if !issueMessagesContain(issues, "has no source coverage mapping") {
		t.Fatalf("issues = %#v, want missing source coverage mapping issue", issues)
	}
}

func TestCloudPolicyCoverageMapsLegacyGCPResources(t *testing.T) {
	tests := map[string]string{
		"gcp_container_clusters":        "gke_cluster",
		"gcp_container_node_pools":      "gke_node_pool",
		"gcp_container_vulnerabilities": "container_vulnerability",
		"gcp_ids_endpoints":             "cloud_ids_endpoint",
	}
	for resource, wantDimension := range tests {
		if !isCloudPolicyResource(resource) {
			t.Fatalf("isCloudPolicyResource(%q) = false, want true", resource)
		}
		alias, ok := cloudPolicyCoverageAliases[resource]
		if !ok {
			t.Fatalf("cloudPolicyCoverageAliases[%q] missing", resource)
		}
		if alias.SourceID != "gcp" || alias.DimensionID != wantDimension {
			t.Fatalf("cloudPolicyCoverageAliases[%q] = %#v, want gcp/%s", resource, alias, wantDimension)
		}
	}
}

func TestCloudPolicyCoverageMapsGCPExpansionTargets(t *testing.T) {
	tests := map[string]string{
		"gcp::certificate_manager::certificate":           "certificate_manager_certificate",
		"gcp::certificate_manager::certificate_map":       "certificate_manager_certificate_map",
		"gcp::certificate_manager::certificate_map_entry": "certificate_manager_certificate_map_entry",
		"gcp::certificate_manager::dns_authorization":     "certificate_manager_dns_authorization",
		"gcp::certificatemanager::certificate":            "certificate_manager_certificate",
		"gcp::certificatemanager::certificate_map":        "certificate_manager_certificate_map",
		"gcp::certificatemanager::certificate_map_entry":  "certificate_manager_certificate_map_entry",
		"gcp::certificatemanager::dns_authorization":      "certificate_manager_dns_authorization",
		"gcp::vpcaccess::connector":                       "vpc_access_connector",
	}
	for resource, wantDimension := range tests {
		alias, ok := cloudPolicyCoverageAliases[resource]
		if !ok {
			t.Fatalf("cloudPolicyCoverageAliases[%q] missing", resource)
		}
		if alias.SourceID != "gcp" || alias.DimensionID != wantDimension {
			t.Fatalf("cloudPolicyCoverageAliases[%q] = %#v, want gcp/%s", resource, alias, wantDimension)
		}
	}
}

func TestCheckRequiredCloudCoverageDimensionsRejectsMissingMinimum(t *testing.T) {
	issues := checkRequiredCloudCoverageDimensions(map[string]map[string]sourcecdk.CoverageDimension{
		"azure": {
			"aks_cluster": {ID: "aks_cluster", Support: sourcecdk.CoverageSupportSupported},
		},
	})
	if !issueMessagesContain(issues, `minimum cloud coverage dimension "activity_log_alert" is missing`) {
		t.Fatalf("issues = %#v, want missing minimum cloud coverage dimension issue", issues)
	}
}

func TestValidateFixtureContractsSkipsSymlinkFixtures(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "sources", "custom")
	if err := os.MkdirAll(filepath.Join(sourceDir, "testdata"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	linkPath := filepath.Join(sourceDir, "testdata", "outside.json")
	if err := os.Symlink(filepath.Join(root, "missing.json"), linkPath); err != nil {
		t.Skipf("Symlink() unsupported: %v", err)
	}
	issues := validateFixtureContracts(root, sourceDir, []sourcecdk.EventContract{
		{Kind: "custom.event", RequiredAttributes: []string{"required_attribute"}},
	})
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none for symlink fixture", issues)
	}
}

func TestValidateFixtureContractsRejectsSymlinkTestdataRoot(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "sources", "custom")
	targetDir := filepath.Join(root, "fixtures", "custom")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(sourceDir) error = %v", err)
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(targetDir) error = %v", err)
	}
	if err := os.Symlink(targetDir, filepath.Join(sourceDir, "testdata")); err != nil {
		t.Skipf("Symlink() unsupported: %v", err)
	}
	issues := validateFixtureContracts(root, sourceDir, []sourcecdk.EventContract{
		{Kind: "custom.event", RequiredAttributes: []string{"required_attribute"}},
	})
	if len(issues) == 0 || !strings.Contains(issues[0].message, "symlinked testdata") {
		t.Fatalf("issues = %#v, want symlinked testdata issue", issues)
	}
}

func TestValidateFixtureContractsRejectsMalformedEventFixture(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "sources/custom/testdata/read.json", `[{
  "id": "event-1",
  "tenant_id": "example",
  "source_id": "custom",
  "occurred_at": "2026-05-21T12:00:00Z",
  "schema_ref": "custom/event/v1",
  "payload": {}
}]`)
	sourceDir := filepath.Join(root, "sources", "custom")
	issues := validateFixtureContracts(root, sourceDir, []sourcecdk.EventContract{
		{Kind: "custom.event", RequiredAttributes: []string{"required_attribute"}},
	})
	if len(issues) == 0 {
		t.Fatal("issues = 0, want malformed event fixture issue")
	}
	if got := issues[0].message; !strings.Contains(got, "kind is required") {
		t.Fatalf("issue = %q, want kind validation error", got)
	}
}

func TestCheckPoliciesRejectsSymlinkedPolicyFiles(t *testing.T) {
	root := t.TempDir()
	policiesDir := filepath.Join(root, "policies", "custom")
	if err := os.MkdirAll(policiesDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "missing.json"), filepath.Join(policiesDir, "policy.json")); err != nil {
		t.Skipf("Symlink() unsupported: %v", err)
	}
	issues, err := checkPolicies(root)
	if err != nil {
		t.Fatalf("checkPolicies() error = %v", err)
	}
	if len(issues) == 0 || !strings.Contains(issues[0].message, "symlinked policy") {
		t.Fatalf("issues = %#v, want symlinked policy issue", issues)
	}
}

func TestCheckSourceCatalogsRejectsSymlinkedCatalogs(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "sources", "custom")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "missing.yaml"), filepath.Join(sourceDir, "catalog.yaml")); err != nil {
		t.Skipf("Symlink() unsupported: %v", err)
	}
	issues, err := checkSourceCatalogs(root)
	if err != nil {
		t.Fatalf("checkSourceCatalogs() error = %v", err)
	}
	if len(issues) == 0 || !strings.Contains(issues[0].message, "symlinked source catalog") {
		t.Fatalf("issues = %#v, want symlinked source catalog issue", issues)
	}
}

func writeFile(t *testing.T, root string, rel string, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}

func issueMessagesContain(issues []issue, substring string) bool {
	for _, issue := range issues {
		if strings.Contains(issue.message, substring) {
			return true
		}
	}
	return false
}
