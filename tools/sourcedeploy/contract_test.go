package sourcedeploy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRenderContractIncludesCatalogsSecretsFamiliesAndRoles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mkSource(t, root, "aws", "id: aws\nemitted_kinds:\n  - aws.public_endpoint\n  - aws.iam_role\n", "")
	mkSource(t, root, "okta", "id: okta\nemitted_kinds:\n  - okta.audit\n  - okta.user\n", `
sourceId: okta
secretKeys:
  - OKTA_API_TOKEN
  - OKTA_DOMAIN
runtimes:
  - localId: audit
    config:
      domain: env:OKTA_DOMAIN
      family: audit
      token: env:OKTA_API_TOKEN
`)

	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	contract, err := RenderContract(root, manifests, ContractOptions{
		Environment: "sec-dev",
		TenantID:    "writer",
		ImageTag:    "v2.1.60",
	})
	if err != nil {
		t.Fatalf("RenderContract: %v", err)
	}

	if contract.SchemaVersion != ContractSchemaVersion {
		t.Fatalf("schema version = %q", contract.SchemaVersion)
	}
	if contract.ImageTag != "v2.1.60" {
		t.Fatalf("image tag = %q", contract.ImageTag)
	}
	if len(contract.Sources) != 2 {
		t.Fatalf("sources = %d, want 2", len(contract.Sources))
	}
	aws := contract.Sources[0]
	if aws.SourceID != "aws" || !equalStrings(aws.SupportedFamilies, []string{"iam_role", "public_endpoint"}) {
		t.Fatalf("aws source = %#v", aws)
	}
	if !equalStrings(aws.RoleAssumptionConfigKeys, []string{"role_arn"}) {
		t.Fatalf("aws role keys = %v", aws.RoleAssumptionConfigKeys)
	}
	okta := contract.Sources[1]
	if !equalStrings(okta.RequiredSecrets, []string{"OKTA_API_TOKEN", "OKTA_DOMAIN"}) {
		t.Fatalf("okta secrets = %v", okta.RequiredSecrets)
	}
	if len(okta.Runtimes) != 1 || okta.Runtimes[0].ID != "writer-okta-audit" {
		t.Fatalf("okta runtimes = %#v", okta.Runtimes)
	}
	if !equalStrings(okta.Runtimes[0].RequiredSecrets, []string{"OKTA_API_TOKEN", "OKTA_DOMAIN"}) {
		t.Fatalf("runtime secrets = %v", okta.Runtimes[0].RequiredSecrets)
	}
}

func TestContractMarshalJSONStable(t *testing.T) {
	t.Parallel()
	contract := Contract{
		SchemaVersion: ContractSchemaVersion,
		Environment:   "sec-dev",
		TenantID:      "writer",
		Sources:       []ContractSource{{SourceID: "aws"}},
	}
	data, err := contract.MarshalJSONStable()
	if err != nil {
		t.Fatalf("MarshalJSONStable: %v", err)
	}
	var decoded Contract
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v\n%s", err, data)
	}
	if decoded.SchemaVersion != ContractSchemaVersion {
		t.Fatalf("decoded schema = %q", decoded.SchemaVersion)
	}
}

func mkSource(t *testing.T, root string, name string, catalog string, deploy string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte(catalog), 0o644); err != nil {
		t.Fatalf("WriteFile(catalog): %v", err)
	}
	if deploy != "" {
		if err := os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte(deploy), 0o644); err != nil {
			t.Fatalf("WriteFile(deploy): %v", err)
		}
	}
}
