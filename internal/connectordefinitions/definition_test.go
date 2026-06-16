package connectordefinitions

import "testing"

func TestNormalizeBuildsValidatedDefinition(t *testing.T) {
	definition, err := Normalize(Definition{
		TenantID:    "tenant-a",
		SourceID:    "Example API",
		DisplayName: "Example API",
		ConfigFields: []Field{{
			Key:      "base url",
			Label:    "Base URL",
			Required: true,
		}},
		Auth: AuthSpec{
			Model:             "bearer_token",
			SupportedStoreIDs: []string{"hashicorp_vault", "cerebro_vault"},
			CredentialFields: []Field{{
				Key:           "Token",
				Secret:        true,
				ReferenceOnly: true,
			}},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:        "Assets",
			Path:      "/v1/assets",
			IDField:   "id",
			NameField: "name",
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if definition.ID != "tenant-a-example_api" {
		t.Fatalf("definition id = %q, want tenant-a-example_api", definition.ID)
	}
	if definition.Runtime != RuntimeJSONAPI || definition.Stage != StageDraft {
		t.Fatalf("runtime/stage = %q/%q, want json_api/draft", definition.Runtime, definition.Stage)
	}
	if definition.Validation.Status != ValidationReady {
		t.Fatalf("validation status = %q, want ready: %#v", definition.Validation.Status, definition.Validation.Checks)
	}
	if len(definition.Promotion.EligibleStages) != 1 || definition.Promotion.EligibleStages[0] != StageSandbox {
		t.Fatalf("eligible stages = %#v, want sandbox", definition.Promotion.EligibleStages)
	}
	if len(definition.ScopeOptions) != 1 || definition.ScopeOptions[0].ID != "assets" {
		t.Fatalf("scope options = %#v, want generated assets scope option", definition.ScopeOptions)
	}
}

func TestNormalizeBackfillsEventKindFromLegacyField(t *testing.T) {
	definition, err := Normalize(Definition{
		TenantID:    "tenant-a",
		SourceID:    "example",
		DisplayName: "Example",
		Auth: AuthSpec{
			Model: "none",
		},
		ResourceFamilies: []ResourceFamily{{
			ID:        "assets",
			Path:      "/v1/assets",
			IDField:   "id",
			EventKind: "example.assets",
			Event: EventMappingSpec{
				SchemaRef: "example/asset/v1",
			},
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	family := definition.ResourceFamilies[0]
	if family.Event.Kind != "example.assets" {
		t.Fatalf("event kind = %q, want legacy event_kind fallback", family.Event.Kind)
	}
	if definition.Validation.Status == ValidationBlocked {
		t.Fatalf("family unexpectedly blocked: %#v", definition.Validation.Checks)
	}
	renormalized, err := Normalize(definition)
	if err != nil {
		t.Fatalf("Normalize(renormalized) error = %v", err)
	}
	if renormalized.ResourceFamilies[0].Event.Kind != "example.assets" {
		t.Fatalf("renormalized event kind = %q, want stable legacy fallback", renormalized.ResourceFamilies[0].Event.Kind)
	}
}

func TestValidateBlocksUnsafeDynamicDefinition(t *testing.T) {
	definition, err := Normalize(Definition{
		ID:          "example",
		TenantID:    "tenant-a",
		SourceID:    "example",
		DisplayName: "Example",
		Runtime:     RuntimeJSONAPI,
		Auth: AuthSpec{
			Model: "api_key",
			CredentialFields: []Field{{
				Key:    "api_key",
				Secret: true,
			}},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:      "assets",
			Path:    "https://api.example.test/v1/assets",
			Method:  "POST",
			IDField: "id",
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if definition.Validation.Status != ValidationBlocked {
		t.Fatalf("validation status = %q, want blocked", definition.Validation.Status)
	}
	var blocked []string
	for _, check := range definition.Validation.Checks {
		if check.Blocking {
			blocked = append(blocked, check.ID)
		}
	}
	if len(blocked) < 2 {
		t.Fatalf("blocking checks = %#v, want secret/path blockers", blocked)
	}
}

func TestValidateBlocksUnsupportedResourceMethods(t *testing.T) {
	definition, err := Normalize(Definition{
		ID:          "example",
		TenantID:    "tenant-a",
		SourceID:    "example",
		DisplayName: "Example",
		Runtime:     RuntimeJSONAPI,
		Auth: AuthSpec{
			Model: "none",
		},
		ResourceFamilies: []ResourceFamily{{
			ID:      "assets",
			Path:    "/v1/assets",
			Method:  "DELETE",
			IDField: "id",
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if !hasBlockingCheck(definition.Validation.Checks, "method_assets") {
		t.Fatalf("validation checks = %#v, want method_assets blocker", definition.Validation.Checks)
	}
}

func TestValidateBlocksProtocolRelativeResourcePaths(t *testing.T) {
	for _, path := range []string{"//evil.example/v1/assets", `/\evil.example\v1\assets`} {
		t.Run(path, func(t *testing.T) {
			definition, err := Normalize(Definition{
				ID:          "example",
				TenantID:    "tenant-a",
				SourceID:    "example",
				DisplayName: "Example",
				Runtime:     RuntimeJSONAPI,
				Auth: AuthSpec{
					Model: "none",
				},
				ResourceFamilies: []ResourceFamily{{
					ID:      "assets",
					Path:    path,
					IDField: "id",
				}},
			})
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if definition.Validation.Status != ValidationBlocked {
				t.Fatalf("validation status = %q, want blocked", definition.Validation.Status)
			}
			if !hasBlockingCheck(definition.Validation.Checks, "path_assets") {
				t.Fatalf("validation checks = %#v, want path_assets blocker", definition.Validation.Checks)
			}
		})
	}
}

func TestPromoteMovesOneStageWhenReady(t *testing.T) {
	definition, err := Normalize(Definition{
		ID:          "example",
		TenantID:    "tenant-a",
		SourceID:    "example",
		DisplayName: "Example",
		Auth: AuthSpec{
			Model: "bearer_token",
			CredentialFields: []Field{{
				Key:           "token",
				Secret:        true,
				ReferenceOnly: true,
			}},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:      "assets",
			Path:    "/v1/assets",
			IDField: "id",
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	result, err := Promote(definition, PromotionRequest{TargetStage: StageSandbox})
	if err != nil {
		t.Fatalf("Promote() error = %v", err)
	}
	if !result.Promoted || result.Definition.Stage != StageSandbox {
		t.Fatalf("promotion = %#v, want sandbox promotion", result)
	}
	if _, err := Promote(result.Definition, PromotionRequest{TargetStage: StageApproved}); err == nil {
		t.Fatal("Promote() error = nil, want one-stage transition error")
	}
}

func TestNormalizeIntegrationDefinition(t *testing.T) {
	definition, err := Normalize(Definition{
		SchemaVersion: SchemaVersionIntegrationV1,
		ID:            "example",
		TenantID:      "tenant-a",
		SourceID:      "example",
		DisplayName:   "Example",
		Categories:    []string{"identity", "identity", "audit"},
		//nolint:gosec // Test auth descriptor only; no credential value is stored.
		Auth: AuthSpec{
			Model:            "oauth_authorization_code",
			AuthorizationURL: "https://example.test/oauth/authorize",
			TokenURL:         "https://example.test/oauth/token",
			Scopes:           []string{"users.read", "audit.read"},
			CredentialFields: []Field{{
				Key:           "oauth_client_reference",
				Secret:        true,
				ReferenceOnly: true,
			}},
		},
		Transport: &TransportSpec{
			BaseURL: "https://${connection.domain}/api",
			Verification: &VerificationSpec{
				Path:         "/v1/me",
				ExpectStatus: []int{200, 204},
			},
			Retry: &RetrySpec{
				Statuses:         []int{429, 500},
				RetryAfterHeader: "Retry-After",
			},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:             "users",
			Path:           "/v1/users",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event: EventMappingSpec{
				Kind:      "example.user",
				SchemaRef: "example/user/v1",
			},
			Pagination: &PaginationSpec{
				Type:           "cursor",
				CursorParam:    "cursor",
				CursorJSONPath: "$.next_cursor",
			},
			Incremental: &IncrementalSpec{
				CursorField: "updated_at",
			},
			Projection: &ProjectionSpec{
				Template: "identity_user",
				Fields:   map[string]string{"entity_id": "$.id"},
			},
			Coverage: []CoverageDimensionSpec{{
				Type:    "entity_family",
				Support: "supported",
			}},
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if definition.Validation.Status != ValidationReady {
		t.Fatalf("validation status = %q, want ready: %#v", definition.Validation.Status, definition.Validation.Checks)
	}
	if len(definition.Categories) != 2 || definition.Categories[0] != "audit" || definition.Categories[1] != "identity" {
		t.Fatalf("categories = %#v", definition.Categories)
	}
	if got := definition.ResourceFamilies[0].Coverage[0].ID; got != "users_entity_family" {
		t.Fatalf("coverage id = %q, want users_entity_family", got)
	}
}

func TestClassifyReportsSupportedDefinition(t *testing.T) {
	report, err := Classify(Definition{
		SchemaVersion: SchemaVersionIntegrationV1,
		ID:            "example",
		TenantID:      "tenant-a",
		SourceID:      "example",
		DisplayName:   "Example",
		Auth: AuthSpec{
			Model: "bearer_token",
			CredentialFields: []Field{{
				Key:           "token",
				Secret:        true,
				ReferenceOnly: true,
			}},
		},
		Transport: &TransportSpec{
			BaseURL: "https://api.example.test",
			Verification: &VerificationSpec{
				Path: "/v1/me",
			},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:             "users",
			Path:           "/v1/users",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event: EventMappingSpec{
				Kind:      "example.user",
				SchemaRef: "example/user/v1",
			},
			Pagination: &PaginationSpec{
				Type: "cursor",
			},
			Projection: &ProjectionSpec{
				Template: "identity_user",
			},
			Coverage: []CoverageDimensionSpec{{
				Type:    "entity_family",
				Support: "supported",
			}},
		}},
	}, DefaultGrammar())
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if report.Verdict != SupportVerdictSupported {
		t.Fatalf("verdict = %q, want supported; missing=%#v checks=%#v", report.Verdict, report.MissingFeatures, report.Checks)
	}
	if len(report.MissingFeatures) != 0 {
		t.Fatalf("missing features = %#v, want none", report.MissingFeatures)
	}
}

func TestClassifyReportsMissingFeatures(t *testing.T) {
	report, err := Classify(Definition{
		SchemaVersion: SchemaVersionIntegrationV1,
		ID:            "example",
		TenantID:      "tenant-a",
		SourceID:      "example",
		DisplayName:   "Example",
		Runtime:       RuntimeJSONAPI,
		Auth: AuthSpec{
			Model: "bearer_token",
			CredentialFields: []Field{{
				Key:           "token",
				Secret:        true,
				ReferenceOnly: true,
			}},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:      "users",
			Path:    "/v1/users",
			Method:  "GET",
			IDField: "id",
		}},
	}, DefaultGrammar())
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}
	if report.Verdict != SupportVerdictBespokeRequired {
		t.Fatalf("verdict = %q, want bespoke_required", report.Verdict)
	}
	for _, want := range []string{
		"transport.base_url_template",
		"transport.verification",
		"record_selector.jsonpath_or_list_key",
		"projection.template",
		"coverage.dimensions",
	} {
		if !containsString(report.MissingFeatures, want) {
			t.Fatalf("missing features = %#v, want %q", report.MissingFeatures, want)
		}
	}
}

func TestClassifyAllSummarizesTargetSet(t *testing.T) {
	supported := Definition{
		SchemaVersion: SchemaVersionIntegrationV1,
		ID:            "example",
		TenantID:      "tenant-a",
		SourceID:      "example",
		DisplayName:   "Example",
		Auth: AuthSpec{
			Model: "bearer_token",
			CredentialFields: []Field{{
				Key:           "token",
				Secret:        true,
				ReferenceOnly: true,
			}},
		},
		Transport: &TransportSpec{
			BaseURL: "https://api.example.test",
			Verification: &VerificationSpec{
				Path: "/v1/me",
			},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:             "users",
			Path:           "/v1/users",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Event: EventMappingSpec{
				Kind:      "example.user",
				SchemaRef: "example/user/v1",
			},
			Projection: &ProjectionSpec{
				Template: "identity_user",
			},
			Coverage: []CoverageDimensionSpec{{
				Type:    "entity_family",
				Support: "supported",
			}},
		}},
	}
	missing := supported
	missing.ID = "missing"
	missing.SourceID = "missing"
	missing.Transport = nil
	summary, err := ClassifyAll([]Definition{supported, missing}, DefaultGrammar())
	if err != nil {
		t.Fatalf("ClassifyAll() error = %v", err)
	}
	if summary.Targets != 2 || summary.Supported != 1 || summary.BespokeRequired != 1 {
		t.Fatalf("summary = %#v", summary)
	}
	if summary.ByAuthModel["bearer_token"] != 2 {
		t.Fatalf("ByAuthModel = %#v, want bearer_token count", summary.ByAuthModel)
	}
	if summary.MissingFeatures["transport.base_url_template"] != 1 {
		t.Fatalf("MissingFeatures = %#v, want missing transport count", summary.MissingFeatures)
	}
}

func hasBlockingCheck(checks []ValidationCheck, id string) bool {
	for _, check := range checks {
		if check.ID == id && check.Blocking {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
