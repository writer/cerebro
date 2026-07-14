package sourcegen

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/tools/sourcedeploy"
)

func TestGenerateWritesSourceRuntimeSDKScaffold(t *testing.T) {
	outputDir := t.TempDir()
	result, err := Generate(Request{
		SourceID:             "demo_source",
		SourceType:           SourceTypeJSONAPI,
		AuthModel:            AuthModelBearerToken,
		AssetSchemas:         []string{"host"},
		FindingSchemas:       []string{"vulnerability"},
		FreshnessExpectation: "2h",
		FailureModes:         []string{"auth_error", "rate_limit"},
		OutputDir:            outputDir,
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if result.DryRun {
		t.Fatal("DryRun = true, want false")
	}
	for _, path := range []string{
		"sources/demo_source/catalog.yaml",
		"sources/demo_source/deploy.yaml",
		"sources/demo_source/fixture.go",
		"sources/demo_source/source.go",
		"sources/demo_source/source_test.go",
		"sources/demo_source/testdata/discover_asset_host.json",
		"sources/demo_source/testdata/read_asset_host.json",
		"sources/demo_source/testdata/discover_finding_vulnerability.json",
		"sources/demo_source/testdata/read_finding_vulnerability.json",
		"sources/demo_source/testdata/discover_evidence_cas_reference.json",
		"sources/demo_source/testdata/read_evidence_cas_reference.json",
		"sources/demo_source/source_health_receipt.json",
		"sources/demo_source/SOURCE_RUNTIME.md",
		"sources/demo_source/PR_BODY.md",
		"internal/sourceprojection/demo_source.go",
		"internal/sourceprojection/demo_source_test.go",
	} {
		if _, err := os.Stat(filepath.Join(outputDir, path)); err != nil {
			t.Fatalf("generated %s: %v", path, err)
		}
	}
	catalog := readGeneratedFile(t, outputDir, "sources/demo_source/catalog.yaml")
	for _, want := range []string{
		"id: demo_source",
		"- demo_source.asset_host",
		"- demo_source.finding_vulnerability",
		"- demo_source.evidence_cas_reference",
		"runtime_families:",
		"- asset_host",
		"kind_lifecycle:",
		"status: active",
		"coverage_contract:",
		"authority_domain: demo_source",
		"families: [asset_host]",
		"id: incremental_sync",
		"schema_ref: demo_source/asset_host/v1",
	} {
		if !strings.Contains(catalog, want) {
			t.Fatalf("catalog missing %q:\n%s", want, catalog)
		}
	}
	if _, err := sourcecdk.LoadSourceCatalog([]byte(catalog)); err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v\n%s", err, catalog)
	}
	receipt := map[string]any{}
	if err := json.Unmarshal([]byte(readGeneratedFile(t, outputDir, "sources/demo_source/source_health_receipt.json")), &receipt); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	if got := receipt["health_endpoint"]; got != "/source-runtimes/health?source_id=demo_source" {
		t.Fatalf("health_endpoint = %#v", got)
	}
	if got := receipt["stale_after_seconds"]; got != float64(7200) {
		t.Fatalf("stale_after_seconds = %#v, want 7200", got)
	}
	discoverFixture := readGeneratedFile(t, outputDir, "sources/demo_source/testdata/discover_finding_vulnerability.json")
	for _, want := range []string{"urn:cerebro:tenant:runtime_finding_vulnerability:source-demo_source-finding_vulnerability-1"} {
		if !strings.Contains(discoverFixture, want) {
			t.Fatalf("discover fixture missing %q:\n%s", want, discoverFixture)
		}
	}
	readFixture := readGeneratedFile(t, outputDir, "sources/demo_source/testdata/read_asset_host.json")
	for _, want := range []string{`"family": "asset_host"`, `"record_class": "asset"`, `"resource_type": "host"`} {
		if !strings.Contains(readFixture, want) {
			t.Fatalf("read fixture missing %q:\n%s", want, readFixture)
		}
	}
	deploy, err := sourcedeploy.Parse([]byte(readGeneratedFile(t, outputDir, "sources/demo_source/deploy.yaml")), "generated")
	if err != nil {
		t.Fatalf("parse deploy manifest: %v", err)
	}
	if len(deploy.Runtimes) != 3 {
		t.Fatalf("deploy runtimes = %d, want 3", len(deploy.Runtimes))
	}
	deployFamilies := map[string]bool{}
	for _, runtime := range deploy.Runtimes {
		deployFamilies[runtime.Config["family"]] = true
		if runtime.Config["expected_cadence_seconds"] != "7200" || runtime.Config["stale_after_seconds"] != "7200" {
			t.Fatalf("deploy freshness config = %#v", runtime.Config)
		}
	}
	for _, family := range []string{"asset_host", "finding_vulnerability", "evidence_cas_reference"} {
		if !deployFamilies[family] {
			t.Fatalf("deploy manifest missing family %q: %#v", family, deploy.Runtimes)
		}
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/demo_source/source_test.go")
	authCheck := strings.Index(sourceTest, `r.Header.Get("Authorization")`)
	healthCheck := strings.Index(sourceTest, `r.URL.RequestURI() == `)
	if authCheck < 0 || healthCheck < 0 || authCheck > healthCheck {
		t.Fatalf("generated source test must assert health auth before health short-circuit:\n%s", sourceTest)
	}
	for _, want := range []string{
		"familyAssetHost",
		"familyFindingVulnerability",
		"familyEvidenceCasReference",
		`"/assets/host"`,
		`"/findings/vulnerability"`,
		`"/evidence-cas/references"`,
		"for _, tc := range familyCases",
		`readCfgValues["family"] = tc.name`,
		`"finding_id":`,
		`"evidence_cas_uri":`,
	} {
		if !strings.Contains(sourceTest, want) {
			t.Fatalf("generated source test missing %q:\n%s", want, sourceTest)
		}
	}
	if got, want := strings.Count(sourceTest, "json.RawMessage(`"), 3; got != want {
		t.Fatalf("generated source test response cases = %d, want %d:\n%s", got, want, sourceTest)
	}
	if strings.Contains(sourceTest, "Record One") {
		t.Fatalf("generated source test still uses generic synthetic record:\n%s", sourceTest)
	}
	for _, forbidden := range []string{
		`t.Fatalf("Authorization"+" = %q"`,
		`t.Fatalf("path = %q", r.URL.Path)`,
	} {
		if strings.Contains(sourceTest, forbidden) {
			t.Fatalf("generated source test handler still calls %q:\n%s", forbidden, sourceTest)
		}
	}
}

func TestGenerateDryRunDoesNotWriteFiles(t *testing.T) {
	outputDir := t.TempDir()
	result, err := Generate(Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host"},
		OutputDir:    outputDir,
		DryRun:       true,
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !result.DryRun {
		t.Fatal("DryRun = false, want true")
	}
	if len(result.Files) == 0 {
		t.Fatal("dry run did not report generated files")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "sources/demo_source/source.go")); !os.IsNotExist(err) {
		t.Fatalf("source.go exists after dry run, err=%v", err)
	}
}

func TestGenerateDefinitionWritesIdentitySource(t *testing.T) {
	outputDir := t.TempDir()
	result, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
			ID:            "tenant-a-example_idp",
			TenantID:      "tenant-a",
			SourceID:      "example_idp",
			DisplayName:   "Example IDP",
			Auth: connectordefinitions.AuthSpec{ // #nosec G101 -- credential field names only, not secret values.
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/v1/me",
				},
			},
			ProviderAPI: &connectordefinitions.ProviderAPISpec{
				Status:        "verified",
				Basis:         "detected",
				VerifiedAt:    "2026-07-04T00:00:00Z",
				Transport:     "rest",
				Auth:          "bearer_token",
				AuthMechanics: "Authorization: Bearer token",
				BaseURL:       "https://api.example.test",
				SpecURL:       "https://docs.example.test/openapi.yaml",
				SpecKind:      "openapi",
				References:    []string{"https://docs.example.test/openapi.yaml"},
				AuthEvidence:  []string{"https://docs.example.test/auth"},
				ScopeEvidence: []string{"https://docs.example.test/scopes"},
				Families: []connectordefinitions.ProviderAPIFamilySpec{{
					ID:     "users",
					Method: "GET",
					Path:   "/v1/users",
				}},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "users",
				Path:           "/v1/users",
				RecordSelector: "$.data[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "example_idp.user",
					SchemaRef: "example_idp/user/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "identity_user",
					Fields: map[string]string{
						"id":    "id",
						"email": "email",
						"name":  "email",
					},
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{
					Type:    "entity_family",
					Support: "supported",
				}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	if result.SourceID != "example_idp" || result.AuthModel != AuthModelBearerToken {
		t.Fatalf("result = %#v", result)
	}
	catalog := readGeneratedFile(t, outputDir, "sources/example_idp/catalog.yaml")
	for _, want := range []string{
		"provider_api:",
		"status: \"verified\"",
		"basis: \"detected\"",
		"verified_at: \"2026-07-04T00:00:00Z\"",
		"auth_mechanics: \"Authorization: Bearer token\"",
		"base_url: \"https://api.example.test\"",
		"spec_url: \"https://docs.example.test/openapi.yaml\"",
		"spec_kind: \"openapi\"",
		"- \"https://docs.example.test/openapi.yaml\"",
		"auth_evidence:",
		"- \"https://docs.example.test/auth\"",
		"scope_evidence:",
		"- \"https://docs.example.test/scopes\"",
		"path: \"/v1/users\"",
		"- example_idp.user",
		"families: [users]",
		"schema_ref: example_idp/user/v1",
	} {
		if !strings.Contains(catalog, want) {
			t.Fatalf("catalog missing %q:\n%s", want, catalog)
		}
	}
	if _, err := sourcecdk.LoadSourceCatalog([]byte(catalog)); err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v\n%s", err, catalog)
	}
	projection := readGeneratedFile(t, outputDir, "internal/sourceprojection/example_idp.go")
	for _, want := range []string{"exampleIdpUsersProjections", "identityUserProjections", `Provider: "example_idp"`} {
		if !strings.Contains(projection, want) {
			t.Fatalf("projection missing %q:\n%s", want, projection)
		}
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/example_idp/source_test.go")
	if strings.Contains(sourceTest, "evidence_cas_uri") {
		t.Fatalf("definition generated source test should not assume EvidenceCAS fields:\n%s", sourceTest)
	}
	fixtureGo := readGeneratedFile(t, outputDir, "sources/example_idp/fixture.go")
	for _, want := range []string{
		"// Code generated by sourcegen; DO NOT EDIT.",
		"func NewFixture() (sourcecdk.Source, error)",
		"sourcecdk.LoadFixtureEventsWithContracts",
		"Contracts:     catalog.EventContracts",
	} {
		if !strings.Contains(fixtureGo, want) {
			t.Fatalf("fixture.go missing %q:\n%s", want, fixtureGo)
		}
	}
	readFixture := readGeneratedFile(t, outputDir, "sources/example_idp/testdata/read_users.json")
	for _, want := range []string{
		`"kind": "example_idp.user"`,
		`"record_selector": "$.data[*]"`,
		`"schema_ref": "example_idp/user/v1"`,
		`"source_id": "example_idp"`,
		`"user_id":`,
		`example_idp-users-001`,
	} {
		if !strings.Contains(readFixture, want) {
			t.Fatalf("read fixture missing %q:\n%s", want, readFixture)
		}
	}
	if strings.Contains(readFixture, "Record One") {
		t.Fatalf("read fixture still uses generic synthetic name:\n%s", readFixture)
	}
	if strings.Contains(readFixture, `"api_path"`) || strings.Contains(readFixture, " Fixture") {
		t.Fatalf("verified provider fixture still contains generator markers:\n%s", readFixture)
	}
	var events []struct {
		Payload    map[string]any    `json:"payload"`
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.Unmarshal([]byte(readFixture), &events); err != nil {
		t.Fatalf("decode read fixture: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("read fixture events = %d, want 1", len(events))
	}
	if got, want := events[0].Payload["email"], events[0].Attributes["email"]; got != want {
		t.Fatalf("read fixture email mismatch: payload=%q attributes=%q\n%s", got, want, readFixture)
	}
	discoverFixture := readGeneratedFile(t, outputDir, "sources/example_idp/testdata/discover_users.json")
	if !strings.Contains(discoverFixture, "urn:cerebro:tenant:") {
		t.Fatalf("discover fixture missing urn:\n%s", discoverFixture)
	}
}

func TestGenerateDefinitionSourceTestUsesEveryFamilyProviderResponses(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
			ID:            "tenant-a-provider_shapes",
			TenantID:      "tenant-a",
			SourceID:      "provider_shapes",
			DisplayName:   "Provider Shapes",
			Auth: connectordefinitions.AuthSpec{
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/v1/health",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "users",
				Path:           "/v1/users",
				RecordSelector: "$.members[*]",
				IDField:        "uuid",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "provider_shapes.user",
					SchemaRef: "provider_shapes/user/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "identity_user",
					Fields: map[string]string{
						"user_id":      "uuid",
						"email":        "profile.email",
						"display_name": "profile.name",
					},
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "supported"}},
			}, {
				ID:             "groups",
				Path:           "/v1/groups",
				RecordSelector: "$[*]",
				IDField:        "group_id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "provider_shapes.group",
					SchemaRef: "provider_shapes/group/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "identity_group",
					Fields: map[string]string{
						"group_id":   "group.id",
						"group_name": "group.name",
					},
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "supported"}},
			}, {
				ID:             "audit_events",
				Path:           "/v1/audit/events",
				RecordSelector: "$.logs[*]",
				IDField:        "event_id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "provider_shapes.audit",
					SchemaRef: "provider_shapes/audit/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "audit_event",
					Fields: map[string]string{
						"event_type":  "action",
						"actor_id":    "actor.id",
						"actor_email": "actor.email",
						"resource_id": "target.id",
					},
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "audit_event", Support: "supported"}},
			}, {
				ID:        "settings",
				Path:      "/v1/settings",
				Singleton: true,
				IDField:   "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "provider_shapes.settings",
					SchemaRef: "provider_shapes/settings/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "asset",
					Fields: map[string]string{
						"resource_id":   "id",
						"resource_type": "kind",
						"resource_name": "display_name",
					},
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "supported"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/provider_shapes/source_test.go")
	for _, want := range []string{
		"familyUsers",
		"familyGroups",
		"familyAuditEvents",
		"familySettings",
		`"/v1/users"`,
		`"/v1/groups"`,
		`"/v1/audit/events"`,
		`"/v1/settings"`,
		`"members":[`,
		`"logs":[`,
		`"profile":{"email":`,
		`"group":{"id":`,
		`"actor":{"email":`,
		`"kind":"settings"`,
		`"uuid":`,
		`readCfgValues["family"] = tc.name`,
	} {
		if !strings.Contains(sourceTest, want) {
			t.Fatalf("generated source test missing %q:\n%s", want, sourceTest)
		}
	}
	if got, want := strings.Count(sourceTest, "json.RawMessage(`"), 4; got != want {
		t.Fatalf("generated source test response cases = %d, want %d:\n%s", got, want, sourceTest)
	}
	if strings.Contains(sourceTest, "Record One") {
		t.Fatalf("generated source test still uses generic synthetic record:\n%s", sourceTest)
	}
}

func TestFixtureEmailLocalPartForPayloadPath(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "email", want: "email"},
		{path: "primary_email", want: "primary"},
		{path: "login", want: "login"},
		{path: "actor_email", want: "actor"},
		{path: "actor.email", want: "actor"},
		{path: "group.email", want: "group"},
		{path: "member.email", want: "member"},
		{path: "resource.email", want: "resource"},
		{path: "user.email", want: "user"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			got, ok := fixtureEmailLocalPartForPayloadPath(tc.path)
			if !ok || got != tc.want {
				t.Fatalf("fixtureEmailLocalPartForPayloadPath(%q) = %q, %v; want %q, true", tc.path, got, ok, tc.want)
			}
		})
	}

	request := normalizedRequest{Request: Request{SourceID: "example_idp"}}
	if got, want := fixtureAttributeValue(request, "actor_email", familyData{}), "actor@example-idp.example.test"; got != want {
		t.Fatalf("fixtureAttributeValue(actor_email) = %q, want %q", got, want)
	}
}

func TestFixturePayloadValueUsesRecordIDForFamilyIDField(t *testing.T) {
	request := normalizedRequest{Request: Request{SourceID: "elevenlabs"}}
	family := familyData{
		Name:   "service_account_api_keys",
		IDKeys: []string{"key_id", "name"},
	}

	if got, want := fixturePayloadValue(request, "key_id", family), "source-elevenlabs-service_account_api_keys-1"; got != want {
		t.Fatalf("fixturePayloadValue(key_id) = %q, want %q", got, want)
	}
	if got := fixturePayloadValue(request, "config_file", family); got == "source-elevenlabs-service_account_api_keys-1" {
		t.Fatalf("fixturePayloadValue(config_file) unexpectedly used record ID: %q", got)
	}

	emailFamily := familyData{
		Name:   "users",
		IDKeys: []string{"email"},
	}
	if got, want := fixturePayloadValue(request, "email", emailFamily), "email@elevenlabs.example.test"; got != want {
		t.Fatalf("fixturePayloadValue(email ID field) = %q, want %q", got, want)
	}
}

func TestPlanDefinitionBuildsPromotionChecklist(t *testing.T) {
	plan, err := PlanDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
			ID:            "tenant-a-example_idp",
			TenantID:      "tenant-a",
			SourceID:      "example_idp",
			DisplayName:   "Example IDP",
			Auth: connectordefinitions.AuthSpec{
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL:      "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{Path: "/v1/me"},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "users",
				Path:           "/v1/users",
				RecordSelector: "$.data[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "example_idp.user",
					SchemaRef: "example_idp/user/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{Template: "identity_user"},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{
					Type:    "entity_family",
					Support: "supported",
				}},
			}},
		},
		OutputDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("PlanDefinition() error = %v", err)
	}
	if plan.Status != PlanStatusReady || plan.NextStage != connectordefinitions.StageSandbox {
		t.Fatalf("plan status/next = %q/%q, want ready/sandbox", plan.Status, plan.NextStage)
	}
	if plan.Scaffold == nil || len(plan.Scaffold.Files) == 0 || plan.Metrics.GeneratedFiles == 0 {
		t.Fatalf("plan scaffold = %#v, metrics = %#v", plan.Scaffold, plan.Metrics)
	}
	if len(plan.Checklist) == 0 || len(plan.Commands) == 0 {
		t.Fatalf("plan checklist/commands empty: %#v", plan)
	}
	for _, step := range plan.Checklist {
		if step.ID == "source_cdk.scaffold" && step.Status == PlanStatusReady {
			return
		}
	}
	t.Fatalf("plan missing ready source_cdk.scaffold step: %#v", plan.Checklist)
}

func TestPlanDefinitionAddsRuntimeDepthChecklist(t *testing.T) {
	definition := connectordefinitions.Definition{
		SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
		ID:            "tenant-a-example_idp",
		TenantID:      "tenant-a",
		SourceID:      "example_idp",
		DisplayName:   "Example IDP",
		Auth: connectordefinitions.AuthSpec{
			Model: "bearer_token",
			CredentialFields: []connectordefinitions.Field{{
				Key:           "token",
				Secret:        true,
				ReferenceOnly: true,
			}},
		},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL:      "https://api.example.test",
			Verification: &connectordefinitions.VerificationSpec{Path: "/v1/me"},
		},
		ProviderAPI: &connectordefinitions.ProviderAPISpec{
			Status:        "verified",
			Basis:         "detected",
			VerifiedAt:    "2026-07-04T00:00:00Z",
			Transport:     "rest",
			Auth:          "bearer_token",
			AuthMechanics: "Authorization: Bearer token",
			BaseURL:       "https://api.example.test",
			SpecURL:       "https://docs.example.test/openapi.yaml",
			SpecKind:      "openapi",
			References:    []string{"https://docs.example.test/openapi.yaml"},
			Families: []connectordefinitions.ProviderAPIFamilySpec{{
				ID:     "users",
				Method: "GET",
				Path:   "/v1/users",
			}},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "users",
			Path:           "/v1/users",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event: connectordefinitions.EventMappingSpec{
				Kind:      "example_idp.user",
				SchemaRef: "example_idp/user/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "identity_user"},
			Coverage: []connectordefinitions.CoverageDimensionSpec{{
				Type:    "entity_family",
				Support: "supported",
			}},
		}},
	}
	plan, err := PlanDefinition(DefinitionRequest{
		Definition: definition,
		OutputDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("PlanDefinition() error = %v", err)
	}
	if plan.Status != PlanStatusReady {
		t.Fatalf("plan status = %q, want ready: %#v", plan.Status, plan.Warnings)
	}
	proof := requirePlanStep(t, plan, "runtime_depth.provider_api_proof")
	if proof.Status != PlanStatusReady || !strings.Contains(proof.Detail, "maps 1 of 1 resource families") {
		t.Fatalf("provider proof step = %#v", proof)
	}
	fixtures := requirePlanStep(t, plan, "source_cdk.fixture_suite")
	if !strings.Contains(fixtures.Detail, "read and discover fixture pairs for 1 resource families: users") {
		t.Fatalf("fixture detail = %q", fixtures.Detail)
	}
	projectors := requirePlanStep(t, plan, "source_cdk.projector_tests")
	if !strings.Contains(projectors.Detail, "example_idp.user") {
		t.Fatalf("projector detail = %q", projectors.Detail)
	}

	definition.ProviderAPI.Families = nil
	warningPlan, err := PlanDefinition(DefinitionRequest{
		Definition: definition,
		OutputDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("PlanDefinition() warning path error = %v", err)
	}
	if warningPlan.Status != PlanStatusWarning {
		t.Fatalf("warning plan status = %q, want warning", warningPlan.Status)
	}
	proof = requirePlanStep(t, warningPlan, "runtime_depth.provider_api_proof")
	if proof.Status != PlanStatusWarning || !strings.Contains(proof.Detail, "family:users") {
		t.Fatalf("warning provider proof step = %#v", proof)
	}

	definition.ProviderAPI.Families = []connectordefinitions.ProviderAPIFamilySpec{{
		ID:   "users",
		Path: "/v1/users",
	}}
	pathOnlyPlan, err := PlanDefinition(DefinitionRequest{
		Definition: definition,
		OutputDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("PlanDefinition() partial family path error = %v", err)
	}
	proof = requirePlanStep(t, pathOnlyPlan, "runtime_depth.provider_api_proof")
	if proof.Status != PlanStatusReady {
		t.Fatalf("path-only provider proof step = %#v", proof)
	}

	definition.ProviderAPI.Families = []connectordefinitions.ProviderAPIFamilySpec{{
		ID:     "users",
		Method: "GET",
	}}
	warningPlan, err = PlanDefinition(DefinitionRequest{
		Definition: definition,
		OutputDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("PlanDefinition() partial family method error = %v", err)
	}
	proof = requirePlanStep(t, warningPlan, "runtime_depth.provider_api_proof")
	if proof.Status != PlanStatusWarning || !strings.Contains(proof.Detail, "family:users.path") {
		t.Fatalf("partial provider proof step = %#v", proof)
	}
}

func TestPlanDefinitionAcceptsGraphQLProviderProof(t *testing.T) {
	definition := connectordefinitions.Definition{
		SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
		ID:            "tenant-a-example_graph",
		TenantID:      "tenant-a",
		SourceID:      "example_graph",
		DisplayName:   "Example Graph",
		Auth: connectordefinitions.AuthSpec{
			Model: "bearer_token",
			CredentialFields: []connectordefinitions.Field{{
				Key:           "token",
				Secret:        true,
				ReferenceOnly: true,
			}},
		},
		Transport: &connectordefinitions.TransportSpec{
			BaseURL:      "https://api.example.test/graphql",
			Verification: &connectordefinitions.VerificationSpec{Path: "/graphql"},
		},
		ProviderAPI: &connectordefinitions.ProviderAPISpec{
			Status:        "verified",
			Basis:         "detected",
			VerifiedAt:    "2026-07-04T00:00:00Z",
			Transport:     "graphql",
			Auth:          "bearer_token",
			AuthMechanics: "Authorization: Bearer token",
			BaseURL:       "https://api.example.test/graphql",
			SpecKind:      "graphql_introspection",
			References:    []string{"https://docs.example.test/graphql"},
			Families: []connectordefinitions.ProviderAPIFamilySpec{{
				ID:        "users",
				Operation: "query Users { users { id email } }",
			}},
		},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "users",
			Path:           "/graphql",
			RecordSelector: "$.data.users[*]",
			IDField:        "id",
			Event: connectordefinitions.EventMappingSpec{
				Kind:      "example_graph.user",
				SchemaRef: "example_graph/user/v1",
			},
			Projection: &connectordefinitions.ProjectionSpec{Template: "identity_user"},
			Coverage: []connectordefinitions.CoverageDimensionSpec{{
				Type:    "entity_family",
				Support: "supported",
			}},
		}},
	}
	plan, err := PlanDefinition(DefinitionRequest{
		Definition: definition,
		OutputDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("PlanDefinition() error = %v", err)
	}
	if plan.Status != PlanStatusReady {
		t.Fatalf("plan status = %q, want ready: %#v", plan.Status, plan.Warnings)
	}
	proof := requirePlanStep(t, plan, "runtime_depth.provider_api_proof")
	if proof.Status != PlanStatusReady || strings.Contains(proof.Detail, "machine_readable_spec") {
		t.Fatalf("provider proof step = %#v", proof)
	}

	definition.ProviderAPI.Families[0].Operation = ""
	warningPlan, err := PlanDefinition(DefinitionRequest{
		Definition: definition,
		OutputDir:  t.TempDir(),
	})
	if err != nil {
		t.Fatalf("PlanDefinition() warning path error = %v", err)
	}
	if warningPlan.Status != PlanStatusWarning {
		t.Fatalf("warning plan status = %q, want warning", warningPlan.Status)
	}
	proof = requirePlanStep(t, warningPlan, "runtime_depth.provider_api_proof")
	if proof.Status != PlanStatusWarning || !strings.Contains(proof.Detail, "family:users.operation") || strings.Contains(proof.Detail, "machine_readable_spec") {
		t.Fatalf("warning provider proof step = %#v", proof)
	}
}

func TestPlanDefinitionReportsGrammarBlockers(t *testing.T) {
	plan, err := PlanDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			ID:          "tenant-a-example_api",
			TenantID:    "tenant-a",
			SourceID:    "example_api",
			DisplayName: "Example API",
			Auth:        connectordefinitions.AuthSpec{Model: "none"},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL:      "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{Path: "/v1/me"},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:      "assets",
				Path:    "/v1/assets",
				Method:  "DELETE",
				IDField: "id",
			}},
		},
		OutputDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("PlanDefinition() error = %v", err)
	}
	if plan.Status != PlanStatusBlocked {
		t.Fatalf("plan status = %q, want blocked", plan.Status)
	}
	if len(plan.Blockers) == 0 {
		t.Fatalf("plan blockers empty: %#v", plan)
	}
}

func requirePlanStep(t *testing.T, plan *PromotionPlan, id string) PromotionPlanStep {
	t.Helper()
	for _, step := range plan.Checklist {
		if step.ID == id {
			return step
		}
	}
	t.Fatalf("plan missing step %q: %#v", id, plan.Checklist)
	return PromotionPlanStep{}
}

func TestGenerateDefinitionCarriesProjectionRelationships(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
			ID:            "tenant-a-example_vault",
			TenantID:      "tenant-a",
			SourceID:      "example_vault",
			DisplayName:   "Example Vault",
			Auth: connectordefinitions.AuthSpec{
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/v1/health",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "secrets",
				Path:           "/v1/secrets",
				RecordSelector: "$.data[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "example_vault.secrets",
					SchemaRef: "example_vault/secrets/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "secret",
					Fields: map[string]string{
						"owner_user_id": "created_by.id",
						"vault_id":      "mount_accessor",
					},
					Entity: &connectordefinitions.ProjectionEntitySpec{
						EntityType:     "secret",
						URNKind:        "secret",
						IDAttributes:   []string{"secret_id"},
						LabelAttribute: "secret_name",
					},
					Relationships: []connectordefinitions.ProjectionRelationshipSpec{{
						Relation: "belongs_to",
						To: connectordefinitions.ProjectionEntitySpec{
							EntityType:   "example_vault.vault",
							URNKind:      "example_vault_vault",
							IDAttributes: []string{"vault_id"},
						},
						MatchType: "secret_vault",
					}},
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "supported"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/example_vault/source.go")
	for _, want := range []string{`"owner_user_id": "created_by.id"`, `"vault_id": "mount_accessor"`} {
		if !strings.Contains(source, want) {
			t.Fatalf("generated source missing relationship attribute path %q:\n%s", want, source)
		}
	}
	projection := readGeneratedFile(t, outputDir, "internal/sourceprojection/example_vault.go")
	for _, want := range []string{
		`"github.com/writer/cerebro/internal/connectordefinitions"`,
		"projectCatalogRuntimeWithRelationships",
		"connectordefinitions.ProjectionRelationshipSpec",
		`MatchType: "secret_vault"`,
	} {
		if !strings.Contains(projection, want) {
			t.Fatalf("generated projection missing %q:\n%s", want, projection)
		}
	}
}

func TestGenerateDefinitionCarriesAuditEventProjectionEntity(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
			ID:            "tenant-a-example_audit",
			TenantID:      "tenant-a",
			SourceID:      "example_audit",
			DisplayName:   "Example Audit",
			Auth: connectordefinitions.AuthSpec{
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/v1/health",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "audit_events",
				Path:           "/v1/audit",
				RecordSelector: "$.data[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "example_audit.audit_events",
					SchemaRef: "example_audit/audit_events/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "audit_event",
					Fields:   map[string]string{"audit_id": "id"},
					Entity: &connectordefinitions.ProjectionEntitySpec{
						EntityType:   "example_audit.audit_event",
						URNKind:      "example_audit_event",
						IDAttributes: []string{"audit_id"},
					},
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "audit_event", Support: "supported"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	projection := readGeneratedFile(t, outputDir, "internal/sourceprojection/example_audit.go")
	for _, want := range []string{
		"projectCatalogRuntimeWithRelationships",
		"identityAuditProjections",
		`EntityType:`,
		`"example_audit.audit_event"`,
	} {
		if !strings.Contains(projection, want) {
			t.Fatalf("generated audit projection missing %q:\n%s", want, projection)
		}
	}
}

func TestGenerateDefinitionHealthPathWithQueryUsesRequestURI(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
			ID:            "tenant-a-query_health",
			TenantID:      "tenant-a",
			SourceID:      "query_health",
			DisplayName:   "Query Health",
			Auth: connectordefinitions.AuthSpec{
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/about?fields=user",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "users",
				Path:           "/users",
				RecordSelector: "$.data[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "query_health.user",
					SchemaRef: "query_health/user/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{Template: "identity_user"},
				Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "supported"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/query_health/source.go")
	if !strings.Contains(source, `"/about?fields=user"`) {
		t.Fatalf("generated source missing query health path:\n%s", source)
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/query_health/source_test.go")
	if !strings.Contains(sourceTest, `r.URL.RequestURI() == "/about?fields=user"`) {
		t.Fatalf("generated source test does not compare RequestURI:\n%s", sourceTest)
	}
}

func TestGenerateDefinitionWritesOAuthClientCredentialsSource(t *testing.T) {
	outputDir := t.TempDir()
	result, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
			ID:            "tenant-a-auth0",
			TenantID:      "tenant-a",
			SourceID:      "auth0",
			DisplayName:   "Auth0",
			ConfigFields: []connectordefinitions.Field{{
				Key:      "domain",
				Required: true,
			}},
			Auth: connectordefinitions.AuthSpec{ // #nosec G101 -- Test-only OAuth credential field names, not live secrets.
				Model:    AuthModelOAuthClientCredentials,
				TokenURL: "https://${config.domain}/oauth/token",
				Scopes:   []string{"read:users"},
				TokenParams: map[string]string{
					"audience": "https://${config.domain}/api/v2/",
				},
				CredentialFields: []connectordefinitions.Field{{
					Key:           "client_id",
					ReferenceOnly: true,
				}, {
					Key:           "client_secret",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://${config.domain}/api/v2",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/users",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "users",
				Path:           "/users",
				RecordSelector: "$[*]",
				IDField:        "user_id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "auth0.users",
					SchemaRef: "auth0/users/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "identity_user",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{
					Type:      "entity_family",
					Support:   "supported",
					HighValue: true,
				}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	if result.SourceID != "auth0" || result.AuthModel != AuthModelOAuthClientCredentials {
		t.Fatalf("result = %#v", result)
	}
	source := readGeneratedFile(t, outputDir, "sources/auth0/source.go")
	for _, want := range []string{
		"oauthTokenURLTemplate",
		"sourcehttp.ClientCredentialsRuntimeConfigOptions",
		"TokenURLTemplate:",
		"oauthTokenURLTemplate",
		"sourcehttp.ClientCredentialsCache",
		"oauthTokenExpirationBuffer",
		"sourcehttp.ResolveClientCredentialsRuntimeConfig(ctx, cfg, options)",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
	}
	deploy := readGeneratedFile(t, outputDir, "sources/auth0/deploy.yaml")
	for _, want := range []string{
		"domain: env:AUTH0_DOMAIN",
		"client_id: env:AUTH0_CLIENT_ID",
		"client_secret: env:AUTH0_CLIENT_SECRET",
	} {
		if !strings.Contains(deploy, want) {
			t.Fatalf("deploy.yaml missing %q:\n%s", want, deploy)
		}
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/auth0/source_test.go")
	for _, want := range []string{
		`r.URL.Path == "/oauth/token"`,
		`tokenRequests < 1 || tokenRequests > len(familyCases)`,
		`"token_url": server.URL + "/oauth/token"`,
	} {
		if !strings.Contains(sourceTest, want) {
			t.Fatalf("source_test.go missing %q:\n%s", want, sourceTest)
		}
	}
	for _, forbidden := range []string{
		`t.Fatalf("token method = %s"`,
		`t.Fatalf("ParseForm() error = %v"`,
		`t.Fatalf("grant_type = %q"`,
	} {
		if strings.Contains(sourceTest, forbidden) {
			t.Fatalf("source_test.go token handler still calls %q:\n%s", forbidden, sourceTest)
		}
	}
}

func TestGenerateDefinitionSupportsOAuthAuthorizationCode(t *testing.T) {
	outputDir := t.TempDir()
	result, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			ID:          "tenant-a-example",
			TenantID:    "tenant-a",
			SourceID:    "example",
			DisplayName: "Example",
			//nolint:gosec // Test auth descriptor only; no credential value is stored.
			Auth: connectordefinitions.AuthSpec{
				Model:            "oauth_authorization_code",
				AuthorizationURL: "https://example.test/oauth/authorize",
				TokenURL:         "https://example.test/oauth/token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "oauth_client_reference",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/v1/me",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "users",
				Path:           "/v1/users",
				RecordSelector: "$.data[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "example.user",
					SchemaRef: "example/user/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "identity_user",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "supported"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	if result.AuthModel != AuthModelOAuthAuthorizationCode {
		t.Fatalf("AuthModel = %q, want %q", result.AuthModel, AuthModelOAuthAuthorizationCode)
	}
	source := readGeneratedFile(t, outputDir, "sources/example/source.go")
	for _, want := range []string{`AuthModel:`, `"oauth_authorization_code"`, `OAuthTokenURL:`, `"https://example.test/oauth/token"`} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
	}
}

func TestGenerateDefinitionCatalogUsesProjectionCoverageDimensions(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
			ID:            "tenant-a-demo_runtime",
			TenantID:      "tenant-a",
			SourceID:      "demo_runtime",
			DisplayName:   "Demo Runtime",
			Auth: connectordefinitions.AuthSpec{
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/v1/me",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{
				projectionCoverageFamily("repositories", "repository"),
				projectionCoverageFamily("findings", "finding"),
				projectionCoverageFamily("policies", "policy"),
				projectionCoverageFamily("deployments", "deployment"),
				projectionCoverageFamily("alerts", "alert"),
				projectionCoverageFamily("audit_events", "audit_event"),
			},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	catalog, err := sourcecdk.LoadSourceCatalog([]byte(readGeneratedFile(t, outputDir, "sources/demo_runtime/catalog.yaml")))
	if err != nil {
		t.Fatalf("LoadSourceCatalog() error = %v", err)
	}
	if catalog.CoverageContract == nil {
		t.Fatal("CoverageContract = nil")
	}
	dimensions := map[string]sourcecdk.CoverageDimension{}
	for _, dimension := range catalog.CoverageContract.Dimensions {
		dimensions[dimension.ID] = dimension
	}
	tests := []struct {
		id            string
		dimensionType string
		evidenceTypes []string
		controlDomain []string
	}{
		{id: "repositories", dimensionType: "entity_family", evidenceTypes: []string{"source_snapshot"}, controlDomain: []string{"asset_inventory"}},
		{id: "findings", dimensionType: "remediation_state", evidenceTypes: []string{"remediation_state"}, controlDomain: []string{"remediation"}},
		{id: "policies", dimensionType: "lifecycle_state", evidenceTypes: []string{"configuration_state"}, controlDomain: []string{"security_operations"}},
		{id: "deployments", dimensionType: "deployment_state", evidenceTypes: []string{"change_management"}, controlDomain: []string{"secure_delivery"}},
		{id: "alerts", dimensionType: "alert_state", evidenceTypes: []string{"security_monitoring"}, controlDomain: []string{"logging_monitoring", "security_operations"}},
		{id: "audit_events", dimensionType: "audit_event", evidenceTypes: []string{"logging_configuration"}, controlDomain: []string{"logging_monitoring"}},
	}
	for _, test := range tests {
		t.Run(test.id, func(t *testing.T) {
			dimension, ok := dimensions[test.id]
			if !ok {
				t.Fatalf("coverage dimension %q missing: %#v", test.id, dimensions)
			}
			if dimension.Type != test.dimensionType {
				t.Fatalf("dimension type = %q, want %q", dimension.Type, test.dimensionType)
			}
			if !slices.Equal(dimension.EvidenceTypes, test.evidenceTypes) {
				t.Fatalf("evidence types = %#v, want %#v", dimension.EvidenceTypes, test.evidenceTypes)
			}
			if !slices.Equal(dimension.ControlDomains, test.controlDomain) {
				t.Fatalf("control domains = %#v, want %#v", dimension.ControlDomains, test.controlDomain)
			}
		})
	}
}

func projectionCoverageFamily(id string, template string) connectordefinitions.ResourceFamily {
	return connectordefinitions.ResourceFamily{
		ID:             id,
		Path:           "/v1/" + id,
		RecordSelector: "$.data[*]",
		IDField:        "id",
		Event: connectordefinitions.EventMappingSpec{
			Kind:      "demo_runtime." + id,
			SchemaRef: "demo_runtime/" + id + "/v1",
		},
		Projection: &connectordefinitions.ProjectionSpec{
			Template: template,
		},
		Coverage: []connectordefinitions.CoverageDimensionSpec{{
			Type:    coverageDimensionType(template),
			Support: "partial",
		}},
	}
}

func TestGenerateDefinitionSupportsFamilyQueryBindings(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			ID:          "tenant-huggingface",
			TenantID:    "tenant",
			SourceID:    "huggingface",
			DisplayName: "Hugging Face",
			Auth: connectordefinitions.AuthSpec{
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			ConfigFields: []connectordefinitions.Field{{
				Key:      "organization",
				Required: true,
			}},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://huggingface.co/api",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/whoami-v2",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "repositories",
				Path:           "/models",
				RecordSelector: "$[*]",
				IDField:        "id",
				StaticQuery:    map[string]string{"full": "true"},
				ConfigQuery:    map[string]string{"author": "organization"},
				StaticHeaders:  map[string]string{"Accept": "application/json;version=2"},
				Config: &connectordefinitions.FamilyConfigSpec{
					BaseURL:          "https://huggingface.co/api/models",
					ConfigAttributes: map[string]string{"owner": "organization"},
					IdentityKeys:     []string{"id"},
				},
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "huggingface.repositories",
					SchemaRef: "huggingface/repositories/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "repository",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
				Pagination: &connectordefinitions.PaginationSpec{
					Type:            "cursor",
					CursorParam:     "after",
					CursorJSONPath:  "$.paging.continuation",
					DisablePageSize: true,
				},
			}, {
				ID:             "files",
				Path:           "/files",
				RecordSelector: "$[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "huggingface.files",
					SchemaRef: "huggingface/files/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "asset",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
				Pagination: &connectordefinitions.PaginationSpec{
					Type:          "link",
					CursorParam:   "cursor",
					LinkHeader:    "Link",
					PageSizeParam: "limit",
				},
			}, {
				ID:             "deployments",
				Path:           "/deployments",
				RecordSelector: "$.value[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "huggingface.deployments",
					SchemaRef: "huggingface/deployments/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "deployment",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "deployment_state", Support: "partial"}},
				Pagination: &connectordefinitions.PaginationSpec{
					Type:            "next_url",
					NextURLJSONPath: "$.nextLink",
					DisablePageSize: true,
				},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/huggingface/source.go")
	for _, want := range []string{
		`Path:             "/models"`,
		`CursorParam:      "after"`,
		`NextCursorKeys:   []string{"paging.continuation"}`,
		`NextCursorKeys:   []string{"nextLink"}`,
		`LinkHeader:       "Link"`,
		`DisablePageSize:  true`,
		`Config: jsonapi.FamilyConfig{`,
		`BaseURL:          "https://huggingface.co/api/models"`,
		`StaticQuery:      map[string]string{"full": "true"}`,
		`ConfigQuery:      map[string]string{"author": "organization"}`,
		`ConfigAttributes: map[string]string{"owner": "organization"}`,
		`StaticHeaders:    map[string]string{"Accept": "application/json;version=2"}`,
		`IdentityKeys:     []string{"id"}`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
	}
}

func TestGenerateDefinitionCarriesPathParams(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			SchemaVersion: connectordefinitions.SchemaVersionIntegrationV1,
			ID:            "tenant-a-example_idp",
			TenantID:      "tenant-a",
			SourceID:      "example_idp",
			DisplayName:   "Example IDP",
			Auth: connectordefinitions.AuthSpec{
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/v1/me",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "workspace_members",
				Path:           "/v1/workspaces/{workspace_id}/members",
				RecordSelector: "$.data[*]",
				Read:           &connectordefinitions.ResourceReadSpec{PathParams: []string{"workspace_id"}},
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "example_idp.workspace_members",
					SchemaRef: "example_idp/workspace_members/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{Template: "identity_user"},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{
					Type:    "entity_family",
					Support: "supported",
				}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/example_idp/source.go")
	for _, want := range []string{
		`Path:             "/v1/workspaces/{workspace_id}/members"`,
		`PathParams:       []string{"workspace_id"}`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/example_idp/source_test.go")
	for _, want := range []string{
		`path:               "/v1/workspaces/test-workspace_id/members"`,
		`"workspace_id": "test-workspace_id"`,
	} {
		if !strings.Contains(sourceTest, want) {
			t.Fatalf("source_test.go missing %q:\n%s", want, sourceTest)
		}
	}
	deploy := readGeneratedFile(t, outputDir, "sources/example_idp/deploy.yaml")
	for _, want := range []string{
		`- EXAMPLE_IDP_WORKSPACE_ID`,
		`workspace_id: env:EXAMPLE_IDP_WORKSPACE_ID`,
	} {
		if !strings.Contains(deploy, want) {
			t.Fatalf("deploy.yaml missing %q:\n%s", want, deploy)
		}
	}
}

func TestGenerateDefinitionCarriesDetailReadMetadata(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			ID:          "tenant-example_assets",
			TenantID:    "tenant",
			SourceID:    "example_assets",
			DisplayName: "Example Assets",
			Auth: connectordefinitions.AuthSpec{
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/v1/me",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "devices",
				Path:           "/v1/workspaces/{workspace_id}/devices",
				RecordSelector: "$.data[*]",
				IDField:        "id",
				Read: &connectordefinitions.ResourceReadSpec{
					DetailPath:            "/v1/devices/{id}/detail",
					AllowBareDetailRecord: true,
					PathParams:            []string{"workspace_id"},
					MapRecords:            map[string]string{"groups": "members"},
					Singleton:             true,
					DisablePageSize:       true,
				},
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "example_assets.device",
					SchemaRef: "example_assets/device/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "asset",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/example_assets/source.go")
	for _, want := range []string{
		`Path:                  "/v1/workspaces/{workspace_id}/devices"`,
		`PathParams:            []string{"workspace_id"}`,
		`DetailPath:            "/v1/devices/{id}/detail"`,
		`AllowBareDetailRecord: true`,
		`DisablePageSize:       true`,
		`Singleton:             true`,
		`MapRecords:`,
		`"groups": "members"`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/example_assets/source_test.go")
	for _, want := range []string{
		`path:               "/v1/workspaces/test-workspace_id/devices"`,
		`"workspace_id": "test-workspace_id"`,
	} {
		if !strings.Contains(sourceTest, want) {
			t.Fatalf("source_test.go missing %q:\n%s", want, sourceTest)
		}
	}
	deploy := readGeneratedFile(t, outputDir, "sources/example_assets/deploy.yaml")
	for _, want := range []string{
		"- EXAMPLE_ASSETS_WORKSPACE_ID",
		"workspace_id: env:EXAMPLE_ASSETS_WORKSPACE_ID",
	} {
		if !strings.Contains(deploy, want) {
			t.Fatalf("deploy.yaml missing %q:\n%s", want, deploy)
		}
	}
}

func TestGenerateDefinitionSupportsCustomTokenHeader(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			ID:          "tenant-anthropic",
			TenantID:    "tenant",
			SourceID:    "anthropic",
			DisplayName: "Anthropic",
			Auth: connectordefinitions.AuthSpec{
				Model:       "api_key",
				TokenHeader: "x-api-key",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "api_key",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api.anthropic.com",
				Headers: map[string]string{
					"anthropic-version": "2023-06-01",
				},
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/v1/organizations/users",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "organization_members",
				Path:           "/v1/organizations/users",
				RecordSelector: "$.data[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "anthropic.organization_members",
					SchemaRef: "anthropic/organization_members/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "identity_user",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/anthropic/source.go")
	for _, want := range []string{`tokenHeader`, `"x-api-key"`, `TokenHeader:`, `tokenHeader`, `StaticHeaders:`, `"anthropic-version": "2023-06-01"`} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/anthropic/source_test.go")
	if !strings.Contains(sourceTest, `r.Header.Get("x-api-key")`) {
		t.Fatalf("source_test.go missing custom header assertion:\n%s", sourceTest)
	}
}

func TestGenerateDefinitionSupportsAWSSigV4Auth(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			ID:          "tenant-aws-bedrock",
			TenantID:    "tenant",
			SourceID:    "aws_bedrock",
			DisplayName: "AWS Bedrock",
			ConfigFields: []connectordefinitions.Field{{
				Key:      "region",
				Required: true,
			}, {
				Key:      "service",
				Required: true,
			}},
			Auth: connectordefinitions.AuthSpec{ //nolint:gosec // Test auth descriptor only; no credential value is stored.
				Model: "aws_sigv4",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "access_key",
					Secret:        true,
					ReferenceOnly: true,
				}, {
					Key:           "secret_key",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://bedrock.${config.region}.amazonaws.com",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/foundation-models",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "foundation_models",
				Path:           "/foundation-models",
				RecordSelector: "$.modelSummaries[*]",
				IDField:        "modelId",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "aws_bedrock.foundation_models",
					SchemaRef: "aws_bedrock/foundation_models/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "asset",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/aws_bedrock/source_test.go")
	for _, want := range []string{`strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ")`, `strings.Contains(auth, "Credential=test-access-key/")`, `"access_key": "test-access-key"`, `"secret_key": "test-secret-key"`} {
		if !strings.Contains(sourceTest, want) {
			t.Fatalf("source_test.go missing %q:\n%s", want, sourceTest)
		}
	}
	for _, forbidden := range []string{
		`t.Fatalf("Authorization"+" = %q"`,
		`t.Fatalf("Authorization"+" missing credential scope: %q"`,
	} {
		if strings.Contains(sourceTest, forbidden) {
			t.Fatalf("source_test.go SigV4 handler still calls %q:\n%s", forbidden, sourceTest)
		}
	}
	if strings.Contains(sourceTest, `"AWS4-HMAC-SHA256 test-token"`) {
		t.Fatalf("source_test.go contains static SigV4 authorization assertion:\n%s", sourceTest)
	}
	deploy := readGeneratedFile(t, outputDir, "sources/aws_bedrock/deploy.yaml")
	for _, want := range []string{`access_key: env:AWS_BEDROCK_ACCESS_KEY`, `secret_key: env:AWS_BEDROCK_SECRET_KEY`} {
		if !strings.Contains(deploy, want) {
			t.Fatalf("deploy.yaml missing %q:\n%s", want, deploy)
		}
	}
}

func TestGenerateDefinitionSupportsDuoHMACAuth(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			ID:          "tenant-duo",
			TenantID:    "tenant",
			SourceID:    "duo",
			DisplayName: "Duo",
			Auth: connectordefinitions.AuthSpec{
				Model: "duo_hmac",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "client_id",
					Secret:        true,
					ReferenceOnly: true,
				}, {
					Key:           "client_secret",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api-tenant.duosecurity.com",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/admin/v1/users",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "user",
				Path:           "/admin/v1/users",
				RecordSelector: "$.response[*]",
				IDField:        "user_id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "duo.user",
					SchemaRef: "duo/user/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "identity_user",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}, {
				ID:             "application",
				Path:           "/admin/v3/integrations",
				Config:         &connectordefinitions.FamilyConfigSpec{AuthModel: "duo_hmac_v5"},
				RecordSelector: "$.response[*]",
				IDField:        "integration_key",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "duo.application",
					SchemaRef: "duo/application/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "asset",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/duo/source.go")
	for _, want := range []string{`AuthModel:`, `"duo_hmac"`, `"duo_hmac_v5"`} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/duo/source_test.go")
	for _, want := range []string{`encoding/base64`, `username != "DIXXXXXXXXXXXXXXXXXX"`, `duoSignatureLength: 40`, `duoSignatureLength: 128`, `len(signature) != wantSignatureLength`, `"client_secret": "deadbeefsecret"`} {
		if !strings.Contains(sourceTest, want) {
			t.Fatalf("source_test.go missing %q:\n%s", want, sourceTest)
		}
	}
	deploy := readGeneratedFile(t, outputDir, "sources/duo/deploy.yaml")
	for _, want := range []string{`client_id: env:DUO_CLIENT_ID`, `client_secret: env:DUO_CLIENT_SECRET`} {
		if !strings.Contains(deploy, want) {
			t.Fatalf("deploy.yaml missing %q:\n%s", want, deploy)
		}
	}
}

func TestGenerateDefinitionSupportsFamilyLevelDuoHMACAuth(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			ID:          "tenant-mixed-auth",
			TenantID:    "tenant",
			SourceID:    "mixed_auth",
			DisplayName: "Mixed Auth",
			Auth: connectordefinitions.AuthSpec{
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}, {
					Key:           "client_id",
					Secret:        true,
					ReferenceOnly: true,
				}, {
					Key:           "client_secret",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api.example.test",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/v1/health",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "users",
				Path:           "/v1/users",
				RecordSelector: "$.data[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "mixed_auth.user",
					SchemaRef: "mixed_auth/user/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "identity_user",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}, {
				ID:             "applications",
				Path:           "/admin/v3/integrations",
				Config:         &connectordefinitions.FamilyConfigSpec{AuthModel: "duo_hmac_v5"},
				RecordSelector: "$.response[*]",
				IDField:        "integration_key",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "mixed_auth.application",
					SchemaRef: "mixed_auth/application/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "asset",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/mixed_auth/source.go")
	for _, want := range []string{`AuthModel:`, `"bearer_token"`, `"duo_hmac_v5"`} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/mixed_auth/source_test.go")
	for _, want := range []string{
		`wantSignatureLength := 0`,
		`expectedAuthHeaderName := "Authorization"`,
		`expectedAuthHeaderValue := "Bearer test-token"`,
		`authHeaderValue:`,
		`"Bearer test-token"`,
		`duoSignatureLength: 0`,
		`duoSignatureLength: 128`,
		`if wantSignatureLength == 0 {`,
		`r.Header.Get(expectedAuthHeaderName) != expectedAuthHeaderValue`,
		`base64.StdEncoding.DecodeString`,
		`"token": "test-token"`,
		`"client_id": "DIXXXXXXXXXXXXXXXXXX"`,
		`"client_secret": "deadbeefsecret"`,
	} {
		if !strings.Contains(sourceTest, want) {
			t.Fatalf("source_test.go missing %q:\n%s", want, sourceTest)
		}
	}
	if strings.Contains(sourceTest, "&& tc.duoSignatureLength != 0") {
		t.Fatalf("source_test.go still skips zero-length family auth overrides:\n%s", sourceTest)
	}
	deploy := readGeneratedFile(t, outputDir, "sources/mixed_auth/deploy.yaml")
	for _, want := range []string{`token: env:MIXED_AUTH_TOKEN`, `client_id: env:MIXED_AUTH_CLIENT_ID`, `client_secret: env:MIXED_AUTH_CLIENT_SECRET`} {
		if !strings.Contains(deploy, want) {
			t.Fatalf("deploy.yaml missing %q:\n%s", want, deploy)
		}
	}
}

func TestGenerateDefinitionSupportsFamilyLevelBearerOverrideUnderDuoHMACAuth(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			ID:          "tenant-duo-mixed-auth",
			TenantID:    "tenant",
			SourceID:    "duo_mixed_auth",
			DisplayName: "Duo Mixed Auth",
			Auth: connectordefinitions.AuthSpec{
				Model: "duo_hmac",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "client_id",
					Secret:        true,
					ReferenceOnly: true,
				}, {
					Key:           "client_secret",
					Secret:        true,
					ReferenceOnly: true,
				}, {
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api-tenant.duosecurity.com",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/admin/v1/users",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "users",
				Path:           "/admin/v1/users",
				RecordSelector: "$.response[*]",
				IDField:        "user_id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "duo_mixed_auth.user",
					SchemaRef: "duo_mixed_auth/user/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "identity_user",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}, {
				ID:             "account",
				Path:           "/v1/account",
				Config:         &connectordefinitions.FamilyConfigSpec{AuthModel: "bearer_token"},
				RecordSelector: "$.data[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "duo_mixed_auth.account",
					SchemaRef: "duo_mixed_auth/account/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "asset",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/duo_mixed_auth/source.go")
	for _, want := range []string{`AuthModel:`, `"duo_hmac"`, `"bearer_token"`} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/duo_mixed_auth/source_test.go")
	for _, want := range []string{
		`wantSignatureLength := 40`,
		`authHeaderValue:`,
		`"Bearer test-token"`,
		`duoSignatureLength: 40`,
		`duoSignatureLength: 0`,
		`if r.URL.Path == tc.path {`,
		`r.Header.Get(expectedAuthHeaderName) != expectedAuthHeaderValue`,
		`"token": "test-token"`,
		`"client_id": "DIXXXXXXXXXXXXXXXXXX"`,
		`"client_secret": "deadbeefsecret"`,
	} {
		if !strings.Contains(sourceTest, want) {
			t.Fatalf("source_test.go missing %q:\n%s", want, sourceTest)
		}
	}
	if strings.Contains(sourceTest, "&& tc.duoSignatureLength != 0") {
		t.Fatalf("source_test.go still skips zero-length family auth overrides:\n%s", sourceTest)
	}
}

func TestGenerateDefinitionUsesDefaultFamilyAuthForDuoHealthCheck(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			ID:          "tenant-duo-default-bearer",
			TenantID:    "tenant",
			SourceID:    "duo_default_bearer",
			DisplayName: "Duo Default Bearer",
			Auth: connectordefinitions.AuthSpec{
				Model: "duo_hmac",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "client_id",
					Secret:        true,
					ReferenceOnly: true,
				}, {
					Key:           "client_secret",
					Secret:        true,
					ReferenceOnly: true,
				}, {
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL: "https://api-tenant.duosecurity.com",
				Verification: &connectordefinitions.VerificationSpec{
					Path: "/admin/v1/health",
				},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:             "account",
				Path:           "/v1/account",
				Config:         &connectordefinitions.FamilyConfigSpec{AuthModel: "bearer_token"},
				RecordSelector: "$.data[*]",
				IDField:        "id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "duo_default_bearer.account",
					SchemaRef: "duo_default_bearer/account/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "asset",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}, {
				ID:             "users",
				Path:           "/admin/v1/users",
				RecordSelector: "$.response[*]",
				IDField:        "user_id",
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "duo_default_bearer.user",
					SchemaRef: "duo_default_bearer/user/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "identity_user",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/duo_default_bearer/source_test.go")
	for _, want := range []string{
		`wantSignatureLength := 0`,
		`expectedAuthHeaderValue := "Bearer test-token"`,
		`duoSignatureLength: 0`,
		`duoSignatureLength: 40`,
		`"token": "test-token"`,
		`"client_id": "DIXXXXXXXXXXXXXXXXXX"`,
		`"client_secret": "deadbeefsecret"`,
	} {
		if !strings.Contains(sourceTest, want) {
			t.Fatalf("source_test.go missing %q:\n%s", want, sourceTest)
		}
	}
}

func TestGenerateDefinitionSupportsSingletonFamily(t *testing.T) {
	outputDir := t.TempDir()
	_, err := GenerateDefinition(DefinitionRequest{
		Definition: connectordefinitions.Definition{
			ID:          "tenant-stability",
			TenantID:    "tenant",
			SourceID:    "stability_ai",
			DisplayName: "Stability AI",
			Auth: connectordefinitions.AuthSpec{
				Model: "bearer_token",
				CredentialFields: []connectordefinitions.Field{{
					Key:           "token",
					Secret:        true,
					ReferenceOnly: true,
				}},
			},
			Transport: &connectordefinitions.TransportSpec{
				BaseURL:      "https://api.stability.ai",
				Verification: &connectordefinitions.VerificationSpec{Path: "/v1/user/account"},
			},
			ResourceFamilies: []connectordefinitions.ResourceFamily{{
				ID:        "account",
				Path:      "/v1/user/account",
				IDField:   "id",
				Singleton: true,
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "stability_ai.account",
					SchemaRef: "stability_ai/account/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{Template: "asset"},
				Coverage:   []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
			}},
		},
		OutputDir: outputDir,
	})
	if err != nil {
		t.Fatalf("GenerateDefinition() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/stability_ai/source.go")
	if !strings.Contains(source, `Singleton:`) || !strings.Contains(source, `true`) {
		t.Fatalf("source.go missing singleton family:\n%s", source)
	}
}

func TestGenerateRejectsMissingSchemas(t *testing.T) {
	_, err := Generate(Request{SourceID: "demo_source"})
	if err == nil {
		t.Fatal("Generate() error = nil, want error")
	}
	if !errors.Is(err, errMissingSchemas) {
		t.Fatalf("Generate() error = %v, want errMissingSchemas", err)
	}
}

func TestGenerateRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		request Request
	}{
		{
			name:    "bad source id",
			request: Request{SourceID: "Demo", AssetSchemas: []string{"host"}},
		},
		{
			name:    "unsupported source type",
			request: Request{SourceID: "demo_source", SourceType: "webhook", AssetSchemas: []string{"host"}},
		},
		{
			name:    "unsupported auth model",
			request: Request{SourceID: "demo_source", AuthModel: "oauth", AssetSchemas: []string{"host"}},
		},
		{
			name:    "bad schema",
			request: Request{SourceID: "demo_source", AssetSchemas: []string{"Host"}},
		},
		{
			name:    "too fresh",
			request: Request{SourceID: "demo_source", AssetSchemas: []string{"host"}, FreshnessExpectation: "30s"},
		},
		{
			name:    "bad health path",
			request: Request{SourceID: "demo_source", AssetSchemas: []string{"host"}, HealthPath: "/readyz bad"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Generate(test.request); err == nil {
				t.Fatal("Generate() error = nil, want error")
			}
		})
	}
}

func TestGenerateRejectsGeneratedIdentifierCollision(t *testing.T) {
	_, err := Generate(Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host-name", "host_name"},
		OutputDir:    t.TempDir(),
	})
	if err == nil {
		t.Fatal("Generate() error = nil, want collision error")
	}
	if !errors.Is(err, errGeneratedNameCollision) {
		t.Fatalf("Generate() error = %v, want errGeneratedNameCollision", err)
	}
}

func TestGenerateQuotesCatalogText(t *testing.T) {
	outputDir := t.TempDir()
	name := "Demo: Source # One"
	description := "line one\nline two: yes"
	if _, err := Generate(Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host"},
		Name:         name,
		Description:  description,
		OutputDir:    outputDir,
	}); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	spec, err := sourcecdk.LoadCatalog([]byte(readGeneratedFile(t, outputDir, "sources/demo_source/catalog.yaml")))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	if spec.GetName() != name || spec.GetDescription() != description {
		t.Fatalf("catalog spec = %#v", spec)
	}
}

func TestGeneratePreflightsExistingFilesBeforeWriting(t *testing.T) {
	outputDir := t.TempDir()
	existing := filepath.Join(outputDir, "sources", "demo_source", "source.go")
	if err := os.MkdirAll(filepath.Dir(existing), 0o750); err != nil {
		t.Fatalf("mkdir existing fixture: %v", err)
	}
	if err := os.WriteFile(existing, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing fixture: %v", err)
	}
	if _, err := Generate(Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host"},
		OutputDir:    outputDir,
	}); err == nil {
		t.Fatal("Generate() error = nil, want existing file error")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "sources", "demo_source", "catalog.yaml")); !os.IsNotExist(err) {
		t.Fatalf("catalog.yaml was written before preflight completed, err=%v", err)
	}
}

func TestGenerateRegeneratesUnmodifiedOutputsWithoutForce(t *testing.T) {
	outputDir := t.TempDir()
	request := Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host", "server"},
		Name:         "Demo Source",
		OutputDir:    outputDir,
	}
	first, err := Generate(request)
	if err != nil {
		t.Fatalf("first Generate() error = %v", err)
	}
	if _, err := os.Stat(first.GenerationManifest); err != nil {
		t.Fatalf("generation manifest stat: %v", err)
	}

	request.Name = "Renamed Demo Source"
	request.AssetSchemas = []string{"host"}
	second, err := Generate(request)
	if err != nil {
		t.Fatalf("second Generate() error = %v", err)
	}
	if second.GenerationManifest != first.GenerationManifest {
		t.Fatalf("manifest path changed from %q to %q", first.GenerationManifest, second.GenerationManifest)
	}
	if source := readGeneratedFile(t, outputDir, "sources/demo_source/catalog.yaml"); !strings.Contains(source, "Renamed Demo Source") {
		t.Fatalf("regenerated catalog missing updated name:\n%s", source)
	}
	for _, stale := range []string{
		"sources/demo_source/testdata/discover_asset_server.json",
		"sources/demo_source/testdata/read_asset_server.json",
	} {
		if _, err := os.Stat(filepath.Join(outputDir, stale)); !os.IsNotExist(err) {
			t.Fatalf("stale output %s still exists, err=%v", stale, err)
		}
	}
}

func TestGenerateRefusesToOverwriteOutputChangedAfterGeneration(t *testing.T) {
	outputDir := t.TempDir()
	request := Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host"},
		OutputDir:    outputDir,
	}
	if _, err := Generate(request); err != nil {
		t.Fatalf("first Generate() error = %v", err)
	}
	sourcePath := filepath.Join(outputDir, "sources", "demo_source", "source.go")
	if err := os.WriteFile(sourcePath, []byte("package demosource\n\n// operator change\n"), 0o600); err != nil {
		t.Fatalf("write operator change: %v", err)
	}
	request.Name = "Changed Input"
	if _, err := Generate(request); !errors.Is(err, ErrGeneratedOutputModified) {
		t.Fatalf("second Generate() error = %v, want ownership error", err)
	}
	current, err := os.ReadFile(sourcePath) // #nosec G304 -- sourcePath is inside the test-owned temporary directory.
	if err != nil {
		t.Fatalf("read operator change: %v", err)
	}
	if !strings.Contains(string(current), "operator change") {
		t.Fatalf("operator change was overwritten:\n%s", current)
	}
}

func TestGenerateFindingOnlyScaffold(t *testing.T) {
	outputDir := t.TempDir()
	if _, err := Generate(Request{
		SourceID:       "demo_source",
		FindingSchemas: []string{"vulnerability"},
		OutputDir:      outputDir,
	}); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/demo_source/source.go")
	for _, want := range []string{"familyFindingVulnerability", `"/findings/vulnerability"`, `"finding_id": "finding_id|id"`} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
	}
	projection := readGeneratedFile(t, outputDir, "internal/sourceprojection/demo_source.go")
	for _, want := range []string{"demoSourceFindingVulnerabilityProjections", "demoSourceGenericFindingProjections", "relationAffects", "relationSupports", `EntityType: "runtime_evidence"`} {
		if !strings.Contains(projection, want) {
			t.Fatalf("projection missing %q:\n%s", want, projection)
		}
	}
	if strings.Contains(projection, "demoSourceGenericAssetProjections") {
		t.Fatalf("finding-only projection emitted unused asset helper:\n%s", projection)
	}
	projectionTest := readGeneratedFile(t, outputDir, "internal/sourceprojection/demo_source_test.go")
	if !strings.Contains(projectionTest, "TestDemoSourceFindingProjection") {
		t.Fatalf("finding-only projection test missing finding dispatcher coverage:\n%s", projectionTest)
	}
}

func TestGenerateAssetOnlySkipsUnusedFindingHelper(t *testing.T) {
	outputDir := t.TempDir()
	if _, err := Generate(Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host"},
		OutputDir:    outputDir,
	}); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	projection := readGeneratedFile(t, outputDir, "internal/sourceprojection/demo_source.go")
	for _, want := range []string{"demoSourceAssetHostProjections", "demoSourceGenericAssetProjections", "relationHasEvidence"} {
		if !strings.Contains(projection, want) {
			t.Fatalf("projection missing %q:\n%s", want, projection)
		}
	}
	if strings.Contains(projection, "demoSourceGenericFindingProjections") {
		t.Fatalf("asset-only projection emitted unused finding helper:\n%s", projection)
	}
}

func TestGenerateProjectionTestsEveryFamily(t *testing.T) {
	outputDir := t.TempDir()
	if _, err := Generate(Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host", "database"},
		OutputDir:    outputDir,
	}); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	projectionTest := readGeneratedFile(t, outputDir, "internal/sourceprojection/demo_source_test.go")
	for _, want := range []string{
		"TestDemoSourceAssetProjection",
		"TestDemoSourceAssetDatabaseProjection",
		"demoSourceAssetHostProjections",
		"demoSourceAssetDatabaseProjections",
	} {
		if !strings.Contains(projectionTest, want) {
			t.Fatalf("projection test missing %q:\n%s", want, projectionTest)
		}
	}
}

func FuzzGenerateDryRun(f *testing.F) {
	f.Add("demo_source", AuthModelBearerToken, "host", "vulnerability", "2h", "/readyz", "auth_error")
	f.Add("demo-source", AuthModelAPIToken, "asset", "", "24h", "/healthz", "rate_limit")
	f.Add("bad source", "oauth", "Host", "Finding", "30s", "/bad path", "schema_drift")

	f.Fuzz(func(t *testing.T, sourceID string, authModel string, assetSchema string, findingSchema string, freshness string, healthPath string, failureMode string) {
		if len(sourceID) > 64 || len(authModel) > 32 || len(assetSchema) > 64 || len(findingSchema) > 64 || len(freshness) > 32 || len(healthPath) > 128 || len(failureMode) > 64 {
			return
		}

		result, err := Generate(Request{
			SourceID:             sourceID,
			SourceType:           SourceTypeJSONAPI,
			AuthModel:            authModel,
			AssetSchemas:         []string{assetSchema},
			FindingSchemas:       []string{findingSchema},
			FreshnessExpectation: freshness,
			FailureModes:         []string{failureMode},
			HealthPath:           healthPath,
			OutputDir:            "out",
			DryRun:               true,
		})
		if err != nil {
			return
		}
		if result == nil {
			t.Fatal("Generate() returned nil result with nil error")
		}
		if !result.DryRun {
			t.Fatal("DryRun = false, want true")
		}
		if result.SourceID == "" || result.SourceType != SourceTypeJSONAPI || result.AuthModel == "" {
			t.Fatalf("incomplete result = %#v", result)
		}
		if len(result.Files) == 0 {
			t.Fatal("successful dry run reported no files")
		}
		for _, path := range result.Files {
			clean := filepath.Clean(path)
			if filepath.IsAbs(clean) || !strings.HasPrefix(clean, "out"+string(os.PathSeparator)) {
				t.Fatalf("generated path escaped output dir: %q", path)
			}
		}
		if !strings.Contains(result.SourceHealthReceipt, result.SourceID) || !strings.Contains(result.PRBody, result.SourceID) {
			t.Fatalf("receipt/PR paths do not include source id: %#v", result)
		}
	})
}

func TestFixtureAttributeValueKeepsAlertSeverityCritical(t *testing.T) {
	request := normalizedRequest{Request: Request{SourceID: "demo_source"}}
	if got := fixtureAttributeValue(request, "severity", familyData{Name: "alerts"}); got != "high" {
		t.Fatalf("severity = %q, want high", got)
	}
	if got := fixtureAttributeValue(request, "alert_severity", familyData{Name: "alerts"}); got != "critical" {
		t.Fatalf("alert_severity = %q, want critical", got)
	}
}

func readGeneratedFile(t *testing.T, root string, path string) string {
	t.Helper()
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("abs root: %v", err)
	}
	fullPath := filepath.Join(cleanRoot, filepath.Clean(path))
	payload, err := os.ReadFile(fullPath) // #nosec G304 -- generated file path is under this test's temporary output directory.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(payload)
}
