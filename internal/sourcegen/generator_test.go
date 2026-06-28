package sourcegen

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
		"sources/demo_source/source.go",
		"sources/demo_source/source_test.go",
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
	deploy, err := sourcedeploy.Parse([]byte(readGeneratedFile(t, outputDir, "sources/demo_source/deploy.yaml")), "generated")
	if err != nil {
		t.Fatalf("parse deploy manifest: %v", err)
	}
	if len(deploy.Runtimes) != 1 {
		t.Fatalf("deploy runtimes = %d, want 1", len(deploy.Runtimes))
	}
	config := deploy.Runtimes[0].Config
	if config["expected_cadence_seconds"] != "7200" || config["stale_after_seconds"] != "7200" {
		t.Fatalf("deploy freshness config = %#v", config)
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/demo_source/source_test.go")
	authCheck := strings.Index(sourceTest, `r.Header.Get("Authorization")`)
	healthCheck := strings.Index(sourceTest, `r.URL.RequestURI() == `)
	if authCheck < 0 || healthCheck < 0 || authCheck > healthCheck {
		t.Fatalf("generated source test must assert health auth before health short-circuit:\n%s", sourceTest)
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
	for _, want := range []string{"- example_idp.user", "families: [users]", "schema_ref: example_idp/user/v1"} {
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
		"sourcehttp.ClientCredentialsOptions",
		"TokenURLTemplate: oauthTokenURLTemplate",
		"sourcehttp.ClientCredentialsCache",
		"oauthTokenExpirationBuffer",
		"sourcecdk.RenderConfigTemplate(sourceID, defaultBaseURLTemplate",
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
		`tokenRequests != 1`,
		`"token_url": server.URL + "/oauth/token"`,
	} {
		if !strings.Contains(sourceTest, want) {
			t.Fatalf("source_test.go missing %q:\n%s", want, sourceTest)
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
				Event: connectordefinitions.EventMappingSpec{
					Kind:      "huggingface.repositories",
					SchemaRef: "huggingface/repositories/v1",
				},
				Projection: &connectordefinitions.ProjectionSpec{
					Template: "repository",
				},
				Coverage: []connectordefinitions.CoverageDimensionSpec{{Type: "entity_family", Support: "partial"}},
				Pagination: &connectordefinitions.PaginationSpec{
					Type:            "none",
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
		`DisablePageSize:  true`,
		`Config: jsonapi.FamilyConfig{`,
		`StaticQuery: map[string]string{"full": "true"}`,
		`ConfigQuery: map[string]string{"author": "organization"}`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
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
	for _, want := range []string{"demoSourceFindingVulnerabilityProjections", "demoSourceFindingProjections", "relationAffects", "relationSupports"} {
		if !strings.Contains(projection, want) {
			t.Fatalf("projection missing %q:\n%s", want, projection)
		}
	}
	if strings.Contains(projection, "demoSourceAssetProjections") {
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
	for _, want := range []string{"demoSourceAssetHostProjections", "demoSourceAssetProjections", "relationHasEvidence"} {
		if !strings.Contains(projection, want) {
			t.Fatalf("projection missing %q:\n%s", want, projection)
		}
	}
	if strings.Contains(projection, "demoSourceFindingProjections") {
		t.Fatalf("asset-only projection emitted unused finding helper:\n%s", projection)
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
