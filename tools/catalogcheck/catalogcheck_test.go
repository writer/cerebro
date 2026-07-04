package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestCheckRepositoryAcceptsMinimalCatalogs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/github/test.yaml", policyDSL("github-test", "github::repository"))
	writeFile(t, root, "policies/cerebro/control-mapping.json", `{"version":"1.0.0","controls":{}}`)
	writeFile(t, root, "internal/compliance/control_families.yaml", `
version: "2026-06-16"
frameworks:
  - name: SOC 2
    families:
      - id: CC6
        name: Logical and Physical Access
        controls:
          - id: CC6
`)
	writeFile(t, root, "sources/github/catalog.yaml", `
id: github
name: GitHub
description: GitHub source
emitted_kinds:
  - github.audit
coverage_contract:
  owner_domain: source_control
  authority_domain: github
  dimensions:
    - id: audit_events
      type: audit_event
      title: Audit events
      families: [audit]
      support: supported
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
	writeFile(t, root, "policies/github/test.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: github-test
spec:
  match:
    conditions: ["true"]
`)
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
	if got := countIssueMessages(issues, "metadata.name is required"); got != 1 {
		t.Fatalf("metadata.name issue count = %d, want 1; issues = %#v", got, issues)
	}
}

func TestCheckPoliciesAcceptsDepthBackedRequirementRefs(t *testing.T) {
	root := t.TempDir()
	writePolicyDepthControlCatalog(t, root)
	writePolicyDepthRequirementCatalog(t, root)
	writeFile(t, root, "policies/cerebro/control-mapping.json", `{"version":"1.0.0","controls":{}}`)
	writeFile(t, root, "policies/identity/depth.yaml", policyDepthDSL("identity-access/okta/identity_user", true))
	controlCatalog, controlIssues, err := loadComplianceControlCatalog(root)
	if err != nil {
		t.Fatalf("loadComplianceControlCatalog() error = %v", err)
	}
	if len(controlIssues) != 0 {
		t.Fatalf("control issues = %#v, want none", controlIssues)
	}
	issues, err := checkPolicies(root, controlCatalog)
	if err != nil {
		t.Fatalf("checkPolicies() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none", issues)
	}
}

func TestCheckPoliciesRejectsUnknownDepthRequirementRef(t *testing.T) {
	root := t.TempDir()
	writePolicyDepthControlCatalog(t, root)
	writePolicyDepthRequirementCatalog(t, root)
	writeFile(t, root, "policies/cerebro/control-mapping.json", `{"version":"1.0.0","controls":{}}`)
	writeFile(t, root, "policies/identity/depth.yaml", policyDepthDSL("identity-access/okta/group", true))
	controlCatalog, controlIssues, err := loadComplianceControlCatalog(root)
	if err != nil {
		t.Fatalf("loadComplianceControlCatalog() error = %v", err)
	}
	if len(controlIssues) != 0 {
		t.Fatalf("control issues = %#v, want none", controlIssues)
	}
	issues, err := checkPolicies(root, controlCatalog)
	if err != nil {
		t.Fatalf("checkPolicies() error = %v", err)
	}
	if !issueMessagesContain(issues, `spec.evidence.requirementRefs "identity-access/okta/group" does not match any resolved requirement for the policy controls`) {
		t.Fatalf("issues = %#v, want unknown requirement ref issue", issues)
	}
}

func TestCheckPoliciesReportsDSLDepthContractIssue(t *testing.T) {
	root := t.TempDir()
	writePolicyDepthControlCatalog(t, root)
	writePolicyDepthRequirementCatalog(t, root)
	writeFile(t, root, "policies/cerebro/control-mapping.json", `{"version":"1.0.0","controls":{}}`)
	writeFile(t, root, "policies/identity/depth.yaml", policyDepthDSL("identity-access/okta/identity_user", false))
	controlCatalog, controlIssues, err := loadComplianceControlCatalog(root)
	if err != nil {
		t.Fatalf("loadComplianceControlCatalog() error = %v", err)
	}
	if len(controlIssues) != 0 {
		t.Fatalf("control issues = %#v, want none", controlIssues)
	}
	issues, err := checkPolicies(root, controlCatalog)
	if err != nil {
		t.Fatalf("checkPolicies() error = %v", err)
	}
	if !issueMessagesContain(issues, "spec.verification.fixtures expect=pass is required when spec.evidence.requirementRefs is set") {
		t.Fatalf("issues = %#v, want depth verification issue", issues)
	}
}

func TestCheckConnectorDefinitionCatalogRejectsProofGateIssues(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "internal/connectorcatalog/catalog/batch.yaml", `
entries:
  - classifier_output: supported
    definition:
      schema_version: cerebro.integration/v1
      id: builtin-incomplete
      tenant_id: builtin_catalog
      source_id: incomplete
      auth:
        model: bearer_token
        credential_fields:
          - key: token
            secret: true
            reference_only: true
      transport:
        base_url: https://api.example.test
      resource_families:
        - id: users
          path: /v1/users
          record_selector: $.data[*]
          id_field: id
          event: {kind: incomplete.user, schema_ref: incomplete/user/v1}
          projection: {template: identity_user}
`)

	issues, err := checkConnectorDefinitionCatalog(root)
	if err != nil {
		t.Fatalf("checkConnectorDefinitionCatalog() error = %v", err)
	}
	if !issueMessagesContain(issues, "verification endpoint is required") {
		t.Fatalf("issues = %#v, want proof gate issue", issues)
	}
}

func TestCheckConnectorDefinitionCatalogRequiresSourcegenReady(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "internal/connectorcatalog/catalog/batch.yaml", `
entries:
  - classifier_output: supported
    definition:
      schema_version: cerebro.integration/v1
      id: builtin-app-entitlement
      tenant_id: builtin_catalog
      source_id: app_entitlement_demo
      auth:
        model: bearer_token
        credential_fields:
          - key: token
            secret: true
            reference_only: true
      transport:
        base_url: https://api.example.test
        verification:
          path: /healthz
      resource_families:
        - id: entitlements
          path: /v1/entitlements
          record_selector: $.data[*]
          id_field: id
          event: {kind: app_entitlement_demo.entitlements, schema_ref: app_entitlement_demo/entitlements/v1}
          projection: {template: app_entitlement}
          coverage:
            - id: entitlements
              type: app_entitlement
              title: Entitlements
              families: [entitlements]
              support: partial
              high_value: true
        - id: assets
          path: /v1/assets
          record_selector: $.data[*]
          id_field: id
          event: {kind: app_entitlement_demo.assets, schema_ref: app_entitlement_demo/assets/v1}
          projection: {template: asset}
          coverage:
            - id: assets
              type: entity_family
              title: Assets
              families: [assets]
              support: partial
              high_value: true
`)

	issues, err := checkConnectorDefinitionCatalogWithOptions(root, repositoryCheckOptions{requireSourcegenReady: true})
	if err != nil {
		t.Fatalf("checkConnectorDefinitionCatalogWithOptions() error = %v", err)
	}
	if !issueMessagesContain(issues, "want generateable") {
		t.Fatalf("issues = %#v, want sourcegen-ready issue", issues)
	}
}

func TestCheckConnectorDefinitionCatalogEnforcesRuntimeDepthBudget(t *testing.T) {
	root := t.TempDir()
	writeGenerateableConnectorDefinition(t, root, "example_idp")
	writeRuntimeBackedSource(t, root, "example_idp", []string{"users", "groups"}, []string{"example_idp.user", "example_idp.group"})

	issues, err := checkConnectorDefinitionCatalogWithOptions(root, repositoryCheckOptions{runtimeDepthBudgetEnabled: true, runtimeDepthMaxQueued: 0})
	if err != nil {
		t.Fatalf("checkConnectorDefinitionCatalogWithOptions() error = %v", err)
	}
	if !issueMessagesContain(issues, "connector runtime-depth queue has 1 runtime-backed source(s), budget is 0") {
		t.Fatalf("issues = %#v, want runtime-depth budget issue", issues)
	}
	if !issueMessagesContain(issues, "example_idp") {
		t.Fatalf("issues = %#v, want queued source example", issues)
	}
}

func TestCheckConnectorDefinitionCatalogAllowsRuntimeDepthAtBudget(t *testing.T) {
	root := t.TempDir()
	writeGenerateableConnectorDefinition(t, root, "example_idp")
	writeRuntimeBackedSource(t, root, "example_idp", []string{"users", "groups"}, []string{"example_idp.user", "example_idp.group"})

	issues, err := checkConnectorDefinitionCatalogWithOptions(root, repositoryCheckOptions{runtimeDepthBudgetEnabled: true, runtimeDepthMaxQueued: 1})
	if err != nil {
		t.Fatalf("checkConnectorDefinitionCatalogWithOptions() error = %v", err)
	}
	if issueMessagesContain(issues, "runtime-depth queue") {
		t.Fatalf("issues = %#v, want runtime-depth queue within budget", issues)
	}
}

func TestCheckConnectorDefinitionCatalogDefaultOptionsDisableRuntimeDepthBudget(t *testing.T) {
	root := t.TempDir()
	writeGenerateableConnectorDefinition(t, root, "example_idp")
	writeRuntimeBackedSource(t, root, "example_idp", []string{"users", "groups"}, []string{"example_idp.user", "example_idp.group"})

	issues, err := checkConnectorDefinitionCatalog(root)
	if err != nil {
		t.Fatalf("checkConnectorDefinitionCatalog() error = %v", err)
	}
	if issueMessagesContain(issues, "runtime-depth queue") {
		t.Fatalf("issues = %#v, want default runtime-depth budget disabled", issues)
	}
}

func TestCheckConnectorDefinitionCatalogIgnoresCatalogOnlyRuntimeBacklog(t *testing.T) {
	root := t.TempDir()
	writeGenerateableConnectorDefinition(t, root, "catalog_only")

	issues, err := checkConnectorDefinitionCatalogWithOptions(root, repositoryCheckOptions{runtimeDepthBudgetEnabled: true, runtimeDepthMaxQueued: 0})
	if err != nil {
		t.Fatalf("checkConnectorDefinitionCatalogWithOptions() error = %v", err)
	}
	if issueMessagesContain(issues, "runtime-depth queue") {
		t.Fatalf("issues = %#v, want catalog-only source outside runtime-depth budget", issues)
	}
}

func TestCheckConnectorDefinitionCatalogAcceptsRuntimeBackedBespokeSource(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "internal/connectorcatalog/catalog/batch.yaml", `
entries:
  - classifier_output: bespoke_required
    definition:
      schema_version: cerebro.integration/v1
      id: builtin-custom-bespoke
      tenant_id: builtin_catalog
      source_id: custom_bespoke
      auth:
        model: bearer_token
        credential_fields:
          - key: token
            secret: true
            reference_only: true
      transport:
        base_url: https://api.example.test
        verification:
          path: /healthz
      resource_families:
        - id: users
          path: /v1/users
          id_field: id
          event: {kind: custom_bespoke.users, schema_ref: custom_bespoke/users/v1}
          projection: {template: identity_user}
          coverage:
            - id: users
              type: entity_family
              title: Users
              families: [users]
              support: supported
              high_value: true
              evidence_types: [identity_configuration]
              control_domains: [identity_access]
        - id: applications
          path: /v1/apps
          id_field: id
          event: {kind: custom_bespoke.applications, schema_ref: custom_bespoke/applications/v1}
          projection:
            entity:
              entity_type: custom_bespoke.application
              urn_kind: custom_bespoke_application
              id_attributes: [application_id]
          coverage:
            - id: applications
              type: entity_family
              title: Applications
              families: [applications]
              support: supported
              high_value: true
              evidence_types: [identity_configuration]
              control_domains: [identity_access]
`)
	writeFile(t, root, "sources/custom_bespoke/catalog.yaml", `
id: custom_bespoke
emitted_kinds:
  - custom_bespoke.users
  - custom_bespoke.applications
runtime_families:
  - users
  - applications
coverage_contract: {}
event_contracts:
  - kind: custom_bespoke.users
  - kind: custom_bespoke.applications
`)
	writeFile(t, root, "sources/custom_bespoke/source.go", "package custom_bespoke\n")
	writeFile(t, root, "sources/custom_bespoke/source_test.go", "package custom_bespoke\n")
	writeFile(t, root, "sources/custom_bespoke/deploy.yaml", "sourceId: custom_bespoke\n")
	writeFile(t, root, "sources/custom_bespoke/testdata/discover_users.json", "[]")
	writeFile(t, root, "sources/custom_bespoke/testdata/read_users.json", "[]")
	writeFile(t, root, "sources/custom_bespoke/testdata/discover_applications.json", "[]")
	writeFile(t, root, "sources/custom_bespoke/testdata/read_applications.json", "[]")
	writeFile(t, root, "internal/sourceprojection/custom_bespoke_test.go", `package sourceprojection

var _ = []struct {
	SourceId string
	Kind     string
}{
	{SourceId: "custom_bespoke", Kind: "custom_bespoke.users"},
	{SourceId: "custom_bespoke", Kind: "custom_bespoke.applications"},
}
`)

	issues, err := checkConnectorDefinitionCatalogWithOptions(root, repositoryCheckOptions{requireSourcegenReady: true})
	if err != nil {
		t.Fatalf("checkConnectorDefinitionCatalogWithOptions() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none", issues)
	}
}

func TestBespokeRuntimeReadyUsesPackageReadinessSignals(t *testing.T) {
	entry := connectorcatalog.Entry{
		Status:     connectorcatalog.StatusNeedsBespokeRuntime,
		Definition: connectordefinitions.Definition{SourceID: "custom_bespoke"},
	}
	inventory := connectorcatalog.RuntimeDepthInventory{
		"custom_bespoke": {
			SourceID:                "custom_bespoke",
			Score:                   35,
			HasSourcePackage:        true,
			HasSourceCatalog:        true,
			HasSourceImplementation: true,
			HasSourceTests:          true,
			HasFixturePair:          true,
			HasDeployManifest:       true,
		},
	}

	if !bespokeRuntimeReady(entry, inventory) {
		t.Fatal("bespokeRuntimeReady() = false, want true for complete bespoke package despite reference-depth gaps")
	}
}

func TestBespokeRuntimeReadyRequiresPackageTestFixtures(t *testing.T) {
	entry := connectorcatalog.Entry{
		Status:     connectorcatalog.StatusNeedsBespokeRuntime,
		Definition: connectordefinitions.Definition{SourceID: "custom_bespoke"},
	}
	inventory := connectorcatalog.RuntimeDepthInventory{
		"custom_bespoke": {
			SourceID:                "custom_bespoke",
			Score:                   95,
			HasSourcePackage:        true,
			HasSourceCatalog:        true,
			HasSourceImplementation: true,
			HasDeployManifest:       true,
		},
	}

	if bespokeRuntimeReady(entry, inventory) {
		t.Fatal("bespokeRuntimeReady() = true, want false without tests and fixture pair")
	}
}

func TestCheckRepositoryRejectsUnprojectedEmittedKind(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/github/test.yaml", policyDSL("github-test", "github::repository"))
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

func TestCheckSourceCatalogsRejectsSourceWithoutCoverageContract(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "sources/github/catalog.yaml", `
id: github
name: GitHub
description: GitHub source
emitted_kinds:
  - github.audit
`)

	issues, err := checkSourceCatalogs(root)
	if err != nil {
		t.Fatalf("checkSourceCatalogs() error = %v", err)
	}
	if !issueMessagesContain(issues, "coverage_contract is required for built-in sources") {
		t.Fatalf("issues = %#v, want missing coverage_contract issue", issues)
	}
}

func TestCheckSourceCatalogsAcceptsSourceWithCoverageContract(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "sources/github/catalog.yaml", `
id: github
name: GitHub
description: GitHub source
emitted_kinds:
  - github.audit
coverage_contract:
  owner_domain: source_control
  authority_domain: github
  dimensions:
    - id: audit_events
      type: audit_event
      title: Audit events
      families: [audit]
      support: supported
`)

	issues, err := checkSourceCatalogs(root)
	if err != nil {
		t.Fatalf("checkSourceCatalogs() error = %v", err)
	}
	if issueMessagesContain(issues, "coverage_contract is required for built-in sources") {
		t.Fatalf("issues = %#v, want no coverage_contract issue", issues)
	}
}

func TestCheckSourceCatalogsRejectsUnknownCoverageControlRef(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "internal/compliance/control_families.yaml", `
version: "2026-06-16"
frameworks:
  - name: SOC 2
    families:
      - id: CC6
        name: Logical and Physical Access
        controls:
          - id: CC6
`)
	writeFile(t, root, "sources/github/catalog.yaml", `
id: github
name: GitHub
description: GitHub source
emitted_kinds:
  - github.audit
coverage_contract:
  owner_domain: source_control
  authority_domain: github
  dimensions:
    - id: audit_events
      type: audit_event
      title: Audit events
      families: [audit]
      support: supported
      high_value: true
      evidence_types: [logging_configuration]
      control_domains: [logging_monitoring]
      control_refs:
        - framework_name: SOC 2
          control_id: CC9.9
`)

	issues, err := checkSourceCatalogs(root)
	if err != nil {
		t.Fatalf("checkSourceCatalogs() error = %v", err)
	}
	if !issueMessagesContain(issues, "control ref SOC 2 CC9.9 is not declared") {
		t.Fatalf("issues = %#v, want unknown control ref issue", issues)
	}
}

func TestCheckSourceCatalogsRequiresExplicitHighValueCoverageMetadata(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "sources/github/catalog.yaml", `
id: github
name: GitHub
description: GitHub source
emitted_kinds:
  - github.audit
coverage_contract:
  owner_domain: source_control
  authority_domain: github
  dimensions:
    - id: audit_events
      type: audit_event
      title: Audit events
      families: [audit]
      support: supported
      high_value: true
`)

	issues, err := checkSourceCatalogs(root)
	if err != nil {
		t.Fatalf("checkSourceCatalogs() error = %v", err)
	}
	if !issueMessagesContain(issues, `coverage_contract dimension "audit_events" must declare evidence_types`) {
		t.Fatalf("issues = %#v, want missing evidence_types issue", issues)
	}
	if !issueMessagesContain(issues, `coverage_contract dimension "audit_events" must declare control_domains`) {
		t.Fatalf("issues = %#v, want missing control_domains issue", issues)
	}
}

func TestCheckSourceCatalogsRejectsAuditEventsAsEntityFamily(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "sources/github/catalog.yaml", `
id: github
name: GitHub
description: GitHub source
emitted_kinds:
  - github.audit
coverage_contract:
  owner_domain: source_control
  authority_domain: github
  dimensions:
    - id: audit_events
      type: entity_family
      title: Audit events
      families: [audit]
      support: supported
      high_value: true
      evidence_types: [source_snapshot]
      control_domains: [asset_inventory]
`)

	issues, err := checkSourceCatalogs(root)
	if err != nil {
		t.Fatalf("checkSourceCatalogs() error = %v", err)
	}
	if !issueMessagesContain(issues, `coverage_contract dimension "audit_events" looks like audit event coverage and must use type "audit_event"`) {
		t.Fatalf("issues = %#v, want audit_event type issue", issues)
	}
}

func TestCheckSourceCatalogsSkipsCatalogRuntimeAdapter(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "sources/catalogruntime/catalog.yaml", `
id: catalogruntime
name: Catalog Runtime Adapter
`)

	issues, err := checkSourceCatalogs(root)
	if err != nil {
		t.Fatalf("checkSourceCatalogs() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want adapter package skipped", issues)
	}
}

func TestCheckSourceCatalogsRejectsRuntimeFamilyMissingFixturePair(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "sources/aws/catalog.yaml", `
id: aws
name: AWS
description: AWS source
emitted_kinds:
  - aws.access_key
runtime_families:
  - access_key
coverage_contract:
  owner_domain: cloud
  authority_domain: aws
  dimensions:
    - id: access_key
      type: entity_family
      title: Access keys
      families: [access_key]
      support: supported
`)
	writeFile(t, root, "sources/aws/testdata/discover_access_key.json", `[]`)

	issues, err := checkSourceCatalogs(root)
	if err != nil {
		t.Fatalf("checkSourceCatalogs() error = %v", err)
	}
	if !issueMessagesContain(issues, `runtime family fixture "read_access_key.json" is required`) {
		t.Fatalf("issues = %#v, want missing runtime fixture issue", issues)
	}
}

func TestCheckSourceCatalogsAcceptsRuntimeFamilyFixturePair(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "sources/aws/catalog.yaml", `
id: aws
name: AWS
description: AWS source
emitted_kinds:
  - aws.access_key
runtime_families:
  - access_key
coverage_contract:
  owner_domain: cloud
  authority_domain: aws
  dimensions:
    - id: access_key
      type: entity_family
      title: Access keys
      families: [access_key]
      support: supported
`)
	writeFile(t, root, "sources/aws/testdata/discover_access_key.json", `[]`)
	writeFile(t, root, "sources/aws/testdata/read_access_key.json", `[]`)

	issues, err := checkSourceCatalogs(root)
	if err != nil {
		t.Fatalf("checkSourceCatalogs() error = %v", err)
	}
	if issueMessagesContain(issues, "runtime family fixture") {
		t.Fatalf("issues = %#v, want no runtime fixture issue", issues)
	}
}

func TestCheckCloudPolicyCoverageRejectsUnmappedCloudPolicyResource(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/cloud/test.yaml", policyDSL("cloud-test", "aws::unknown::thing"))
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

func TestCheckCloudPolicyCoverageReportsDSLValidationIssues(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/cloud/test.yaml", `
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: cloud-test
  description: Test policy
  tags: [test]
spec:
  severity: high
  effect: forbid
  resource: aws::s3::bucket
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "visibility"), "public")
  frameworks:
    - name: SOC 2
      controls: [CC6]
`)
	writeFile(t, root, "sources/sdk/catalog.yaml", `
id: sdk
name: SDK
description: SDK source
emitted_kinds: []
`)

	issues, err := checkCloudPolicyCoverage(root)
	if err != nil {
		t.Fatalf("checkCloudPolicyCoverage() error = %v", err)
	}
	if !issueMessagesContain(issues, "metadata.name is required") {
		t.Fatalf("issues = %#v, want DSL validation issue", issues)
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
		"gcp::cloudscheduler::job":                        "cloud_scheduler_job",
		"gcp::dns::record_set":                            "dns_record_set",
		"gcp::iam::effective_permission":                  "effective_permission",
		"gcp::orgpolicy::policy":                          "org_policy",
		"gcp::pubsub::subscription":                       "pubsub_subscription",
		"gcp::pubsub::topic":                              "pubsub_topic",
		"gcp::serviceusage::service":                      "service_usage_service",
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

func TestCloudPolicyCoverageMapsAWSNetworkExpansionTargets(t *testing.T) {
	tests := map[string]string{
		"aws::ec2::network_acl":  "network_acl",
		"aws::ec2::vpc_flow_log": "vpc_flow_log",
	}
	for resource, wantDimension := range tests {
		alias, ok := cloudPolicyCoverageAliases[resource]
		if !ok {
			t.Fatalf("cloudPolicyCoverageAliases[%q] missing", resource)
		}
		if alias.SourceID != "aws" || alias.DimensionID != wantDimension {
			t.Fatalf("cloudPolicyCoverageAliases[%q] = %#v, want aws/%s", resource, alias, wantDimension)
		}
	}
}

func TestCheckCloudPolicyCoverageRejectsUncoveredStrictRuntimeFamily(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/cloud/test.yaml", policyDSL("cloud-test", "gcp::compute::instance"))
	writeFile(t, root, "sources/gcp/catalog.yaml", `
id: gcp
name: GCP
description: GCP source
emitted_kinds:
  - gcp.compute_instance
coverage_contract:
  owner_domain: cloud
  authority_domain: gcp
  dimensions:
    - id: compute_instance
      type: entity_family
      title: Compute instances
      families: [compute_instance]
      support: supported
`)
	writeFile(t, root, "sources/gcp/deploy.yaml", `
runtimes:
  - localId: compute-instance
    config:
      family: compute_instance
  - localId: effective-permission
    config:
      family: effective_permission
`)

	issues, err := checkCloudPolicyCoverage(root)
	if err != nil {
		t.Fatalf("checkCloudPolicyCoverage() error = %v", err)
	}
	if !issueMessagesContain(issues, "coverage_contract does not cover deploy runtime families: effective_permission") {
		t.Fatalf("issues = %#v, want missing strict runtime family coverage issue", issues)
	}
}

func TestCheckCloudPolicyCoverageRejectsUnsupportedStrictRuntimeFamily(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/cloud/test.yaml", policyDSL("cloud-test", "gcp::compute::instance"))
	writeFile(t, root, "sources/gcp/catalog.yaml", `
id: gcp
name: GCP
description: GCP source
emitted_kinds:
  - gcp.effective_permission
coverage_contract:
  owner_domain: cloud
  authority_domain: gcp
  dimensions:
    - id: effective_permission
      type: app_entitlement
      title: Effective IAM permissions
      families: [effective_permission]
      support: planned
`)
	writeFile(t, root, "sources/gcp/deploy.yaml", `
runtimes:
  - localId: effective-permission
    config:
      family: effective_permission
`)

	issues, err := checkCloudPolicyCoverage(root)
	if err != nil {
		t.Fatalf("checkCloudPolicyCoverage() error = %v", err)
	}
	if !issueMessagesContain(issues, "coverage_contract does not cover deploy runtime families: effective_permission") {
		t.Fatalf("issues = %#v, want unsupported strict runtime family coverage issue", issues)
	}
}

func TestCheckCloudPolicyCoverageRejectsUncoveredDeployRuntimeFamilyForAnySource(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policies/custom/test.yaml", policyDSL("custom-test", "custom::thing"))
	writeFile(t, root, "sources/okta/catalog.yaml", `
id: okta
name: Okta
description: Okta source
emitted_kinds:
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
`)
	writeFile(t, root, "sources/okta/deploy.yaml", `
runtimes:
  - localId: user
    config:
      family: user
  - localId: authenticator
    config:
      family: authenticator
`)

	issues, err := checkCloudPolicyCoverage(root)
	if err != nil {
		t.Fatalf("checkCloudPolicyCoverage() error = %v", err)
	}
	if !issueMessagesContain(issues, "coverage_contract does not cover deploy runtime families: authenticator") {
		t.Fatalf("issues = %#v, want uncovered deploy runtime family issue", issues)
	}
}

func TestCheckStrictDeployRuntimeCoverageAllowsExplicitRuntimeFamily(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "sources/addigy/deploy.yaml", `
runtimes:
  - localId: devices
    config:
      family: devices
`)
	writeFile(t, root, "sources/custom/deploy.yaml", `
runtimes:
  - localId: devices
    config:
      family: devices
`)
	dimensions := map[string]map[string]sourcecdk.CoverageDimension{
		"addigy": {
			"devices": {
				ID:      "devices",
				Support: sourcecdk.CoverageSupportPartial,
				Families: []string{
					"device",
				},
				RuntimeFamilies: []string{
					"devices",
				},
			},
		},
		"custom": {
			"devices": {
				ID:      "devices",
				Support: sourcecdk.CoverageSupportPartial,
				Families: []string{
					"device",
				},
			},
		},
	}

	issues := checkStrictDeployRuntimeCoverage(root, dimensions)
	if len(issues) != 1 || issues[0].path != "sources/custom/catalog.yaml" {
		t.Fatalf("issues = %#v, want explicit runtime family to cover only addigy deploy runtime family", issues)
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
	issues, err := checkPolicies(root, nil)
	if err != nil {
		t.Fatalf("checkPolicies() error = %v", err)
	}
	if len(issues) == 0 || !strings.Contains(issues[0].message, "symlinked policy") {
		t.Fatalf("issues = %#v, want symlinked policy issue", issues)
	}
}

func TestCheckPolicyAssetContractsAcceptsSupportedGraphBackedResource(t *testing.T) {
	rule := graphBackedResourceRule("github.code.repository")

	issues := checkPolicyAssetContracts([]findingdsl.PolicyFindingRule{rule})
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none", issues)
	}
}

func TestCheckPolicyAssetContractsRejectsUnsupportedGraphBackedResource(t *testing.T) {
	rule := graphBackedResourceRule("github.unprojected")

	issues := checkPolicyAssetContracts([]findingdsl.PolicyFindingRule{rule})
	if !issueMessagesContain(issues, `graph-backed policy resource "github.unprojected" has no projected asset contract`) {
		t.Fatalf("issues = %#v, want unsupported resource issue", issues)
	}
}

func TestCheckPolicyAssetContractsRejectsUnsupportedProjectedField(t *testing.T) {
	rule := graphBackedResourceRule("github.code.repository")
	rule.Spec.Match.Conditions = []string{`cmp_eq(path(resource, "not_projected"), true)`}

	issues := checkPolicyAssetContracts([]findingdsl.PolicyFindingRule{rule})
	if !issueMessagesContain(issues, `spec.match.conditions references "not_projected"`) {
		t.Fatalf("issues = %#v, want unsupported field issue", issues)
	}
}

func TestCheckPolicyAssetContractsRejectsWrongEventKind(t *testing.T) {
	rule := graphBackedResourceRule("github.code.repository")
	rule.Spec.Input.EventKinds = []string{"github.secret_scanning_alert"}

	issues := checkPolicyAssetContracts([]findingdsl.PolicyFindingRule{rule})
	if !issueMessagesContain(issues, `declares unsupported event kinds github.secret_scanning_alert`) {
		t.Fatalf("issues = %#v, want wrong event kind issue", issues)
	}
}

func TestCheckPolicyAssetContractsRejectsMixedSupportedAndUnsupportedEventKinds(t *testing.T) {
	rule := graphBackedResourceRule("github.code.repository")
	rule.Spec.Input.EventKinds = []string{"github.code.repository", "github.secret_scanning_alert"}

	issues := checkPolicyAssetContracts([]findingdsl.PolicyFindingRule{rule})
	if !issueMessagesContain(issues, `declares unsupported event kinds github.secret_scanning_alert`) {
		t.Fatalf("issues = %#v, want mixed event kind issue", issues)
	}
}

func TestCheckPolicyAssetContractsRejectsMissingFixturePair(t *testing.T) {
	rule := graphBackedResourceRule("github.code.repository")
	rule.Spec.Verification.Fixtures = []findingdsl.PolicyRuleVerificationFixture{{Name: "finding", Expect: "finding"}}

	issues := checkPolicyAssetContracts([]findingdsl.PolicyFindingRule{rule})
	if !issueMessagesContain(issues, `graph-backed policy verification fixtures must include an expect=pass case`) {
		t.Fatalf("issues = %#v, want missing pass fixture issue", issues)
	}
}

func TestCheckPolicyAssetContractsRejectsMissingResourceURNAnchors(t *testing.T) {
	rule := graphBackedResourceRule("github.code.repository")
	rule.Spec.Context.Graph.Anchors = nil
	rule.Spec.Evidence.FingerprintFields = []string{"tenant_id", "policy_id"}

	issues := checkPolicyAssetContracts([]findingdsl.PolicyFindingRule{rule})
	for _, want := range []string{
		`graph-backed policy must include resource_urn in spec.context.graph.anchors`,
		`graph-backed policy must include resource_urn in spec.evidence.fingerprintFields`,
	} {
		if !issueMessagesContain(issues, want) {
			t.Fatalf("issues = %#v, want %q", issues, want)
		}
	}
}

func TestCheckPolicyAssetContractsRejectsGraphQueryMissingAssetColumns(t *testing.T) {
	rule := graphBackedGraphQueryRule([]string{"primary_urn", "fingerprint_key", "summary"})

	issues := checkPolicyAssetContracts([]findingdsl.PolicyFindingRule{rule})
	if !issueMessagesContain(issues, `graph-backed graph policy must include "resource_urns"`) {
		t.Fatalf("issues = %#v, want missing graph asset column issue", issues)
	}
}

func TestCheckPolicyAssetContractsAcceptsGraphQueryAssetColumns(t *testing.T) {
	rule := graphBackedGraphQueryRule([]string{"primary_urn", "fingerprint_key", "summary", "resource_urns"})

	issues := checkPolicyAssetContracts([]findingdsl.PolicyFindingRule{rule})
	if len(issues) != 0 {
		t.Fatalf("issues = %#v, want none", issues)
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

func graphBackedResourceRule(resource string) findingdsl.PolicyFindingRule {
	return findingdsl.PolicyFindingRule{
		RelPath: "policies/github/test.yaml",
		Metadata: findingdsl.PolicyRuleMetadata{
			Tags: []string{"github", "graph-backed"},
		},
		Spec: findingdsl.PolicyFindingRuleSpec{
			Resource: resource,
			Input: findingdsl.PolicyRuleInput{
				EventKinds: []string{"github.code.repository"},
			},
			Match: findingdsl.PolicyRuleMatch{
				Conditions: []string{`cmp_eq(path(resource, "visibility"), "public")`},
			},
			Assert: findingdsl.PolicyRuleAssert{
				All: []findingdsl.PolicyRuleAssertion{
					{Field: "repository", Op: "exists"},
				},
			},
			Context: findingdsl.PolicyRuleContext{
				Graph: findingdsl.PolicyRuleGraphContext{
					Anchors: []string{"resource_urn"},
				},
			},
			Evidence: findingdsl.PolicyRuleEvidence{
				FingerprintFields: []string{"tenant_id", "policy_id", "resource_urn"},
			},
			Verification: findingdsl.PolicyRuleVerification{
				Fixtures: []findingdsl.PolicyRuleVerificationFixture{
					{Name: "finding", Expect: "finding"},
					{Name: "pass", Expect: "pass"},
				},
			},
		},
	}
}

func graphBackedGraphQueryRule(requiredColumns []string) findingdsl.PolicyFindingRule {
	return findingdsl.PolicyFindingRule{
		RelPath: "policies/graph/test.yaml",
		Metadata: findingdsl.PolicyRuleMetadata{
			Tags: []string{"graph-backed"},
		},
		Spec: findingdsl.PolicyFindingRuleSpec{
			Graph: findingdsl.PolicyRuleGraphFinding{
				Query:           "MATCH (entity:Entity) RETURN entity.urn AS primary_urn",
				RequiredColumns: requiredColumns,
			},
			Verification: findingdsl.PolicyRuleVerification{
				Fixtures: []findingdsl.PolicyRuleVerificationFixture{
					{Name: "finding", Expect: "finding"},
					{Name: "pass", Expect: "pass"},
				},
			},
		},
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

func writeGenerateableConnectorDefinition(t *testing.T, root string, sourceID string) {
	t.Helper()
	writeFile(t, root, "internal/connectorcatalog/catalog/identity/"+sourceID+".yaml", fmt.Sprintf(`
entries:
  - classifier_output: supported
    definition:
      schema_version: cerebro.integration/v1
      id: builtin-%[1]s
      tenant_id: builtin_catalog
      source_id: %[1]s
      display_name: Example IDP
      auth:
        model: bearer_token
        credential_fields:
          - key: token
            secret: true
            reference_only: true
      transport:
        base_url: https://api.example.test
        verification:
          path: /v1/me
      resource_families:
        - id: users
          path: /v1/users
          record_selector: $.data[*]
          id_field: id
          event: {kind: %[1]s.user, schema_ref: %[1]s/user/v1}
          projection: {template: identity_user}
          coverage:
            - {type: entity_family, support: partial, high_value: true, evidence_types: [source_snapshot], control_domains: [asset_inventory]}
        - id: groups
          path: /v1/groups
          record_selector: $.data[*]
          id_field: id
          event: {kind: %[1]s.group, schema_ref: %[1]s/group/v1}
          projection: {template: identity_group}
          coverage:
            - {type: entity_family, support: partial, high_value: true, evidence_types: [source_snapshot], control_domains: [asset_inventory]}
`, sourceID))
}

func writeRuntimeBackedSource(t *testing.T, root string, sourceID string, families []string, kinds []string) {
	t.Helper()
	var catalog strings.Builder
	fmt.Fprintf(&catalog, "id: %s\nname: Example IDP\nemitted_kinds:\n", sourceID)
	for _, kind := range kinds {
		fmt.Fprintf(&catalog, "  - %s\n", kind)
	}
	fmt.Fprintf(&catalog, "families:\n")
	for _, family := range families {
		fmt.Fprintf(&catalog, "  - id: %s\n", family)
	}
	fmt.Fprintf(&catalog, "coverage_contract:\n  dimensions:\n")
	for _, family := range families {
		fmt.Fprintf(&catalog, "    - id: %s\n      type: entity_family\n      families: [%s]\n      support: partial\n", family, family)
	}
	fmt.Fprintf(&catalog, "event_contracts:\n")
	for _, kind := range kinds {
		fmt.Fprintf(&catalog, "  - kind: %s\n    schema_ref: %s/v1\n", kind, strings.ReplaceAll(kind, ".", "/"))
	}

	writeFile(t, root, "sources/"+sourceID+"/catalog.yaml", catalog.String())
	writeFile(t, root, "sources/"+sourceID+"/source.go", "package "+sourceID+"\n")
	writeFile(t, root, "sources/"+sourceID+"/source_test.go", "package "+sourceID+"\n")
	writeFile(t, root, "sources/"+sourceID+"/deploy.yaml", "sourceId: "+sourceID+"\n")
	writeFile(t, root, "sources/"+sourceID+"/testdata/read_users.json", "[]\n")
}

func policyDSL(id string, resource string) string {
	return fmt.Sprintf(`
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: %s
  name: Test Policy
  description: Test policy
  tags: [test]
spec:
  severity: high
  effect: forbid
  resource: %s
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "visibility"), "public")
  frameworks:
    - name: SOC 2
      controls: [CC6]
`, id, resource)
}

func policyDepthDSL(requirementRef string, complete bool) string {
	fixtures := `
      - name: missing-mfa
        expect: finding
      - name: mfa-present
        expect: pass`
	if !complete {
		fixtures = `
      - name: missing-mfa
        expect: finding`
	}
	return fmt.Sprintf(`
apiVersion: cerebro.writer.com/v1alpha1
kind: PolicyFindingRule
metadata:
  id: depth-backed
  name: Depth Backed
  description: Depth backed policy
spec:
  severity: high
  effect: forbid
  resource: okta::user
  match:
    conditionFormat: cel
    conditions:
      - cmp_eq(path(resource, "mfa_enrolled"), false)
  frameworks:
    - name: SOC 2
      controls: [CC6.1]
  input:
    sourceKinds: [okta]
    eventKinds: [okta.identity_user]
    requiredFields: [user_id, mfa_enrolled]
    freshnessSLA: 24h
  evidence:
    type: identity_configuration
    requirementRefs: [%s]
    assessmentMethods: [examine, test]
    requiredForAudit: true
    freshnessSLA: 24h
    acceptableSources: [okta]
    requiredFields: [user_id, mfa_enrolled]
    fingerprintFields: [tenant_id, policy_id, resource_urn]
  audit:
    auditorStatement: Identity evidence shows MFA state for the user.
    riskStatement: Users without MFA weaken access controls.
    remediationIntent: Require MFA for the affected user.
    claimStrength: source_backed
    sufficiencyRule: source_period_state_exception
    coverageClaim: supports_control
    overclaimGuard: Do not claim broader framework coverage from this requirement alone.
    adjacentControlRationale: Use adjacent controls as review context until they have their own evidence.
    acceptableEvidence:
      - source: okta
        fields: [user_id, mfa_enrolled]
    exceptionPolicy:
      maxAge: 14d
      requiresApproval: true
    exceptionGuidance:
      - Document compensating monitoring.
  verification:
    fixtures:%s
    mutationChecks: [missing_required_field]
    remediationCheck:
      rerunAfter: source_sync
      expectedStatus: pass
  actions:
    owner:
      from: graph.owner
    remediation:
      steps:
        - Require MFA for the affected user.
    effort: low
    verification:
      rerunPolicy: true
`, requirementRef, fixtures)
}

func writePolicyDepthControlCatalog(t *testing.T, root string) {
	t.Helper()
	writeFile(t, root, "internal/compliance/control_families.yaml", `
version: "2026-07-04"
frameworks:
  - name: SOC 2
    families:
      - id: CC6
        name: Logical and Physical Access
        controls:
          - id: CC6.1
            title: Logical access is restricted
`)
}

func writePolicyDepthRequirementCatalog(t *testing.T, root string) {
	t.Helper()
	writeFile(t, root, "internal/compliance/control_evidence_requirements.yaml", `
version: "2026-07-04"
defaults:
  freshness_window: 24h
  assessment_methods: [examine]
  auditor_grade_evidence: Evidence identifies the source object and current control state.
  claim_strength: source_backed
  sufficiency_rule: source_period_state_exception
  coverage_claim: supports_control
  overclaim_guard: Do not claim broader framework coverage from this requirement alone.
  adjacent_control_rationale: Use adjacent controls as review context until they have their own evidence.
profiles:
  - profile_id: identity-access
    name: Identity Access Evidence
    applies_to:
      frameworks: [SOC 2]
    source_requirements:
      - source_id: okta
        entity_type: identity_user
        required_fields: [user_id, mfa_enrolled]
  - profile_id: baseline-control-review
    name: Baseline Control Review
    fallback: true
    source_requirements:
      - source_id: control_owner_review
        entity_type: control_evidence_packet
        required_fields: [control_ref, reviewer]
`)
}

func issueMessagesContain(issues []issue, substring string) bool {
	for _, issue := range issues {
		if strings.Contains(issue.message, substring) {
			return true
		}
	}
	return false
}

func countIssueMessages(issues []issue, substring string) int {
	count := 0
	for _, issue := range issues {
		if strings.Contains(issue.message, substring) {
			count++
		}
	}
	return count
}
