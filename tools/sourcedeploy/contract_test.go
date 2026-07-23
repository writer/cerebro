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
      failure_modes: auth_error,rate_limit
      health_path: /healthz
      expected_cadence_seconds: "3600"
      stale_after_seconds: "7200"
      token: env:OKTA_API_TOKEN
`)

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
	if !contractHasProfile(contract.RuntimeProfiles, "graph-enabled") {
		t.Fatalf("runtime profiles = %#v, want graph-enabled", contract.RuntimeProfiles)
	}
	if !contractHasEnvVar(contract.RequiredEnvVars, "CEREBRO_POSTGRES_DSN", true) {
		t.Fatalf("required env vars = %#v, want secret CEREBRO_POSTGRES_DSN", contract.RequiredEnvVars)
	}
	if !contractHasEnvVar(contract.RequiredEnvVars, "CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", true) {
		t.Fatalf("required env vars = %#v, want secret CEREBRO_MCP_OAUTH_UPSTREAM_CLIENT_SECRET", contract.RequiredEnvVars)
	}
	if !contractHasEnvVar(contract.RequiredEnvVars, "CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON", true) {
		t.Fatalf("required env vars = %#v, want secret CEREBRO_DEVICE_AUTH_SIGNING_KEYS_JSON", contract.RequiredEnvVars)
	}
	if !contractHasBackingService(contract.RequiredBackingServices, "nats-jetstream") {
		t.Fatalf("required backing services = %#v, want nats-jetstream", contract.RequiredBackingServices)
	}
	if !contractHasBackingService(contract.RequiredBackingServices, "upstream-oauth-provider") {
		t.Fatalf("required backing services = %#v, want upstream-oauth-provider", contract.RequiredBackingServices)
	}
	if !contractHasCapability(contract.OptionalCapabilities, "mcp-oauth") {
		t.Fatalf("optional capabilities = %#v, want mcp-oauth", contract.OptionalCapabilities)
	}
	if !contractHasHealthCheck(contract.PostDeployHealthChecks, "deploy preflight") {
		t.Fatalf("post deploy checks = %#v, want deploy preflight", contract.PostDeployHealthChecks)
	}
	if len(contract.CompatibilityNotes) == 0 {
		t.Fatal("compatibility notes are empty")
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
	if got := okta.SourceHealthReceipt["expected_cadence_seconds"]; got != int64(3600) {
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

func TestDerivedHealthReceiptIncludesCatalogProviderMetadata(t *testing.T) {
	t.Parallel()
	receipt, err := deriveSourceHealthReceipt(contractCatalog{
		ID:              "example",
		RuntimeFamilies: []string{"users", "groups"},
		ProviderAPI: contractProviderAPI{
			Status:        "verified",
			Transport:     "rest",
			AuthMechanics: "Authorization: Bearer",
			BaseURL:       "https://api.example.test",
			Pagination:    contractProviderPagination{Type: "cursor"},
			Families:      []contractProviderAPIFamily{{ID: "users", Path: "/users"}, {ID: "groups", Path: "/groups"}},
		},
		ProviderDisproof: contractProviderDisproof{AffectedFamilies: []string{"legacy"}},
	}, Manifest{}, nil)
	if err != nil {
		t.Fatalf("deriveSourceHealthReceipt: %v", err)
	}
	if receipt["auth_mechanics"] != "Authorization: Bearer" || receipt["provider_api_status"] != "verified" {
		t.Fatalf("provider metadata = %#v", receipt)
	}
	if !equalStrings(receipt["runtime_families"].([]string), []string{"groups", "users"}) {
		t.Fatalf("runtime families = %#v", receipt["runtime_families"])
	}
	if !equalStrings(receipt["provider_api_verified_families"].([]string), []string{"groups", "users"}) {
		t.Fatalf("verified families = %#v", receipt["provider_api_verified_families"])
	}
	if !equalStrings(receipt["provider_api_invalidated_families"].([]string), []string{"legacy"}) {
		t.Fatalf("invalidated families = %#v", receipt["provider_api_invalidated_families"])
	}
	providerAPI := receipt["provider_api"].(map[string]any)
	if providerAPI["base_url"] != "https://api.example.test" || providerAPI["pagination"] != "cursor" {
		t.Fatalf("provider api = %#v", providerAPI)
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

func TestRenderContractRejectsInvalidDerivedHealthCadence(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mkSource(t, root, "okta", "id: okta\nemitted_kinds:\n  - okta.audit\n", `
sourceId: okta
secretKeys:
  - OKTA_API_TOKEN
runtimes:
  - localId: audit
    config:
      expected_cadence_seconds: never
      family: audit
      token: env:OKTA_API_TOKEN
`)

	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := RenderContract(root, manifests, ContractOptions{Environment: "dev", TenantID: "example"}); err == nil {
		t.Fatal("RenderContract error = nil, want invalid derived health cadence error")
	}
}

func TestRenderContractRejectsRelativeJSONAPIHealthPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mkSource(t, root, "okta", "id: okta\nemitted_kinds:\n  - okta.audit\n", `
sourceId: okta
runtimes:
  - localId: audit
    config:
      family: audit
      health_path: healthz
`)

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
	mkSource(t, root, "aws", "id: aws\nemitted_kinds:\n  - aws.public_endpoint\n", `
sourceId: aws
secretKeys:
  - AWS_ROLE_ARN
runtimes:
  - localId: public-endpoint
    config:
      family: public_endpoint
      health_path: sts:GetCallerIdentity
      role_arn: env:AWS_ROLE_ARN
`)

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

func TestRenderContractUsesConnectorVerificationWhenRuntimeHasNoHealthPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mkSource(t, root, "okta", "id: okta\nemitted_kinds:\n  - okta.audit\n", "")

	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := RenderContract(root, manifests, ContractOptions{Environment: "dev", TenantID: "example"}); err != nil {
		t.Fatalf("RenderContract: %v", err)
	}
}

func TestRenderContractDerivesHealthReceiptIdentity(t *testing.T) {
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

func FuzzPositiveSeconds(f *testing.F) {
	f.Add("3600")
	f.Add("0")
	f.Add("not-a-number")
	f.Fuzz(func(t *testing.T, raw string) {
		value, err := positiveSeconds(raw, 86400)
		if err == nil && value <= 0 {
			t.Fatalf("positiveSeconds(%q) = %d, want positive value", raw, value)
		}
	})
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

func contractHasProfile(profiles []ContractRuntimeProfile, name string) bool {
	for _, profile := range profiles {
		if profile.Name == name {
			return true
		}
	}
	return false
}

func contractHasEnvVar(vars []ContractEnvVar, name string, secret bool) bool {
	for _, variable := range vars {
		if variable.Name == name && variable.Secret == secret {
			return true
		}
	}
	return false
}

func contractHasBackingService(services []ContractBackingService, name string) bool {
	for _, service := range services {
		if service.Name == name {
			return true
		}
	}
	return false
}

func contractHasCapability(capabilities []ContractCapability, name string) bool {
	for _, capability := range capabilities {
		if capability.Name == name {
			return true
		}
	}
	return false
}

func contractHasHealthCheck(checks []ContractHealthCheck, name string) bool {
	for _, check := range checks {
		if check.Name == name {
			return true
		}
	}
	return false
}
