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
	mkSource(t, root, "okta", `id: okta
emitted_kinds:
  - okta.audit
  - okta.user
coverage_contract:
  owner_domain: identity
  authority_domain: okta
  dimensions:
    - id: users
      type: entity_family
      title: Users
      families: [user]
      support: supported
      high_value: true
    - id: remediation
      type: remediation_state
      title: Remediation lifecycle
      support: unsupported
      known_unsupported_fields: [inline remediation state]
`, `
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
	mkSourceHealthReceipt(t, root, "okta", `{
  "receipt_kind": "source_health.receipt",
  "source_id": "okta",
  "source_type": "json_api",
  "auth_model": "bearer_token",
  "adapter_health_path": "/healthz",
  "expected_cadence_seconds": 3600,
  "stale_after_seconds": 7200,
  "evidence_cas_reference_kind": "okta.evidence_cas_reference"
}`)

	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	contract, err := RenderContract(root, manifests, ContractOptions{
		Environment: "dev",
		TenantID:    "example",
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
	if len(okta.Runtimes) != 1 || okta.Runtimes[0].ID != "example-okta-audit" {
		t.Fatalf("okta runtimes = %#v", okta.Runtimes)
	}
	if !equalStrings(okta.Runtimes[0].RequiredSecrets, []string{"OKTA_API_TOKEN", "OKTA_DOMAIN"}) {
		t.Fatalf("runtime secrets = %v", okta.Runtimes[0].RequiredSecrets)
	}
	if got := okta.SourceHealthReceipt["receipt_kind"]; got != "source_health.receipt" {
		t.Fatalf("source health receipt kind = %v", got)
	}
	if got := okta.SourceHealthReceipt["source_id"]; got != "okta" {
		t.Fatalf("source health receipt source_id = %v", got)
	}
	if got := okta.SourceHealthReceipt["expected_cadence_seconds"]; got != float64(3600) {
		t.Fatalf("source health receipt cadence = %v", got)
	}
	if okta.CoverageContract == nil || okta.CoverageContract.OwnerDomain != "identity" {
		t.Fatalf("coverage contract = %#v, want identity coverage", okta.CoverageContract)
	}
	if len(okta.CoverageContract.Dimensions) != 2 || okta.CoverageContract.Dimensions[1].Support != "unsupported" {
		t.Fatalf("coverage dimensions = %#v", okta.CoverageContract.Dimensions)
	}
}

func TestContractMarshalJSONStable(t *testing.T) {
	t.Parallel()
	contract := Contract{
		SchemaVersion: ContractSchemaVersion,
		Environment:   "dev",
		TenantID:      "example",
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

func TestRenderContractUsesRuntimeFamilyCatalogOverrides(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mkSource(t, root, "sentinelone", "id: sentinelone\nemitted_kinds:\n  - sentinelone.application_inventory\nruntime_families:\n  - application\n", "")

	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	contract, err := RenderContract(root, manifests, ContractOptions{Environment: "dev", TenantID: "example"})
	if err != nil {
		t.Fatalf("RenderContract: %v", err)
	}
	if len(contract.Sources) != 1 {
		t.Fatalf("sources = %d, want 1", len(contract.Sources))
	}
	if !equalStrings(contract.Sources[0].SupportedFamilies, []string{"application"}) {
		t.Fatalf("supported families = %v", contract.Sources[0].SupportedFamilies)
	}
}

func TestRenderContractRejectsInvalidSourceHealthReceipt(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mkSource(t, root, "okta", "id: okta\nemitted_kinds:\n  - okta.audit\n", `
sourceId: okta
secretKeys:
  - OKTA_API_TOKEN
runtimes:
  - localId: audit
    config:
      family: audit
      token: env:OKTA_API_TOKEN
`)
	mkSourceHealthReceipt(t, root, "okta", `{"receipt_kind":"wrong","source_id":"okta"}`)

	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := RenderContract(root, manifests, ContractOptions{Environment: "dev", TenantID: "example"}); err == nil {
		t.Fatal("RenderContract error = nil, want invalid source health receipt error")
	}
}

func TestRenderContractRejectsRelativeJSONAPIHealthPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mkSource(t, root, "okta", "id: okta\nemitted_kinds:\n  - okta.audit\n", "")
	mkSourceHealthReceipt(t, root, "okta", `{
  "receipt_kind": "source_health.receipt",
  "source_type": "json_api",
  "adapter_health_path": "healthz",
  "expected_cadence_seconds": 3600,
  "stale_after_seconds": 7200
}`)

	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := RenderContract(root, manifests, ContractOptions{Environment: "dev", TenantID: "example"}); err == nil {
		t.Fatal("RenderContract error = nil, want json_api adapter health path error")
	}
}

func TestRenderContractAllowsCloudAPIOperationHealthPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mkSource(t, root, "aws", "id: aws\nemitted_kinds:\n  - aws.public_endpoint\n", "")
	mkSourceHealthReceipt(t, root, "aws", `{
  "receipt_kind": "source_health.receipt",
  "source_type": "cloud_api",
  "adapter_health_path": "sts:GetCallerIdentity",
  "expected_cadence_seconds": 86400,
  "stale_after_seconds": 86400
}`)

	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	contract, err := RenderContract(root, manifests, ContractOptions{Environment: "dev", TenantID: "example"})
	if err != nil {
		t.Fatalf("RenderContract: %v", err)
	}
	if got := contract.Sources[0].SourceHealthReceipt["adapter_health_path"]; got != "sts:GetCallerIdentity" {
		t.Fatalf("adapter_health_path = %v, want sts:GetCallerIdentity", got)
	}
}

func TestRenderContractAllowsJSONAPIReceiptWithoutHealthPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mkSource(t, root, "okta", "id: okta\nemitted_kinds:\n  - okta.audit\n", "")
	mkSourceHealthReceipt(t, root, "okta", `{
  "receipt_kind": "source_health.receipt",
  "source_type": "json_api",
  "expected_cadence_seconds": 3600,
  "stale_after_seconds": 7200
}`)

	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := RenderContract(root, manifests, ContractOptions{Environment: "dev", TenantID: "example"}); err != nil {
		t.Fatalf("RenderContract: %v", err)
	}
}

func TestRenderContractStampsMissingSourceHealthReceiptSourceID(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mkSource(t, root, "okta", "id: okta\nemitted_kinds:\n  - okta.audit\n", `
sourceId: okta
secretKeys:
  - OKTA_API_TOKEN
runtimes:
  - localId: audit
    config:
      family: audit
      token: env:OKTA_API_TOKEN
`)
	mkSourceHealthReceipt(t, root, "okta", `{"receipt_kind":"source_health.receipt","expected_cadence_seconds":3600}`)

	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	contract, err := RenderContract(root, manifests, ContractOptions{Environment: "dev", TenantID: "example"})
	if err != nil {
		t.Fatalf("RenderContract: %v", err)
	}
	if got := contract.Sources[0].SourceHealthReceipt["source_id"]; got != "okta" {
		t.Fatalf("source health receipt source_id = %v", got)
	}
}

func TestAWSCatalogDeclaresAssetMetadataSupportedFamily(t *testing.T) {
	t.Parallel()
	catalogs, err := discoverCatalogs(filepath.Join("..", "..", "sources"))
	if err != nil {
		t.Fatalf("discoverCatalogs: %v", err)
	}
	var aws *contractCatalog
	for i := range catalogs {
		if catalogs[i].ID == "aws" {
			aws = &catalogs[i]
			break
		}
	}
	if aws == nil {
		t.Fatal("aws catalog not found under sources/")
	}
	families := supportedFamilies(aws.ID, aws.EmittedKinds, aws.RuntimeFamilies, nil)
	found := false
	for _, family := range families {
		if family == "asset_metadata" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("aws supported families %v missing asset_metadata", families)
	}
}

func FuzzRenderContractSourceHealthReceipt(f *testing.F) {
	f.Add(`{"receipt_kind":"source_health.receipt","source_id":"fuzz_source","expected_cadence_seconds":3600,"stale_after_seconds":7200}`)
	f.Add(`{"receipt_kind":"source_health.receipt","source_id":"","adapter_health_path":"/readyz"}`)
	f.Add(`{"receipt_kind":"source_health.receipt","adapter_health_path":"/readyz"}`)
	f.Add(`{"receipt_kind":"wrong","source_id":"fuzz_source"}`)
	f.Add(`null`)
	f.Add(`not-json`)

	f.Fuzz(func(t *testing.T, receipt string) {
		if len(receipt) > 4096 {
			return
		}
		root := t.TempDir()
		mkSource(t, root, "fuzz_source", "id: fuzz_source\nemitted_kinds:\n  - fuzz_source.audit\n", `
sourceId: fuzz_source
secretKeys:
  - FUZZ_SOURCE_TOKEN
runtimes:
  - localId: audit
    config:
      family: audit
      token: env:FUZZ_SOURCE_TOKEN
`)
		if receipt != "" {
			mkSourceHealthReceipt(t, root, "fuzz_source", receipt)
		}

		manifests, err := Discover(root)
		if err != nil {
			t.Fatalf("Discover: %v", err)
		}
		contract, err := RenderContract(root, manifests, ContractOptions{Environment: "dev", TenantID: "example"})
		if err != nil {
			return
		}
		if len(contract.Sources) != 1 {
			t.Fatalf("sources = %d, want 1", len(contract.Sources))
		}
		source := contract.Sources[0]
		if source.SourceID != "fuzz_source" {
			t.Fatalf("source_id = %q", source.SourceID)
		}
		if source.SourceHealthReceipt != nil {
			if got := source.SourceHealthReceipt["receipt_kind"]; got != "source_health.receipt" {
				t.Fatalf("receipt_kind = %v", got)
			}
			if got := source.SourceHealthReceipt["source_id"]; got != "fuzz_source" {
				t.Fatalf("receipt source_id = %v", got)
			}
		}
		if _, err := contract.MarshalJSONStable(); err != nil {
			t.Fatalf("MarshalJSONStable: %v", err)
		}
	})
}

func mkSourceHealthReceipt(t *testing.T, root string, name string, receipt string) {
	t.Helper()
	path := filepath.Join(root, name, "source_health_receipt.json")
	if err := os.WriteFile(path, []byte(receipt), 0o644); err != nil {
		t.Fatalf("WriteFile(source_health_receipt): %v", err)
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
