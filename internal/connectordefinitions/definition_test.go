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

func TestValidateBlocksResourcePathQuery(t *testing.T) {
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
			Path:    "/v1/assets?owner=team",
			Method:  "GET",
			IDField: "id",
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if !hasBlockingCheck(definition.Validation.Checks, "path_assets") {
		t.Fatalf("validation checks = %#v, want path_assets blocker", definition.Validation.Checks)
	}
}

func TestValidateDepositFamilyAllowsOmittedPullPath(t *testing.T) {
	definition, err := Normalize(Definition{
		TenantID: "tenant-a",
		SourceID: "example",
		Auth:     AuthSpec{Model: "none"},
		Ingest: IngestSpec{
			Mode: IngestModeDeposit,
			Deposit: &DepositIngestSpec{
				ResourceFamilies: []string{"assets"},
			},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:      "assets",
			IDField: "id",
			Event:   EventMappingSpec{Kind: "example.assets"},
			Projection: &ProjectionSpec{
				Entity: &ProjectionEntitySpec{
					EntityType:   "example.asset",
					URNKind:      "example_asset",
					IDAttributes: []string{"id"},
				},
			},
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if definition.Validation.Status != ValidationReady {
		t.Fatalf("validation status = %q, want ready: %#v", definition.Validation.Status, definition.Validation.Checks)
	}
}

func TestValidateDepositFamilyReferencesNormalizeWithFamilyIDs(t *testing.T) {
	definition, err := Normalize(Definition{
		TenantID: "tenant-a",
		SourceID: "example",
		Auth:     AuthSpec{Model: "none"},
		Ingest: IngestSpec{
			Mode: IngestModeDeposit,
			Deposit: &DepositIngestSpec{
				ResourceFamilies: []string{"Assets"},
			},
		},
		ResourceFamilies: []ResourceFamily{{
			ID:      "Assets",
			IDField: "id",
			Event:   EventMappingSpec{Kind: "example.assets"},
			Projection: &ProjectionSpec{
				Entity: &ProjectionEntitySpec{
					EntityType:   "example.asset",
					URNKind:      "example_asset",
					IDAttributes: []string{"id"},
				},
			},
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if got := definition.Ingest.Deposit.ResourceFamilies; len(got) != 1 || got[0] != "assets" {
		t.Fatalf("deposit resource families = %#v, want [assets]", got)
	}
	if definition.Validation.Status != ValidationReady {
		t.Fatalf("validation status = %q, want ready: %#v", definition.Validation.Status, definition.Validation.Checks)
	}
}

func TestValidateDepositBlocksUnknownFamily(t *testing.T) {
	definition, err := Normalize(Definition{
		TenantID: "tenant-a",
		SourceID: "example",
		Auth:     AuthSpec{Model: "none"},
		Ingest: IngestSpec{
			Mode:    IngestModeDeposit,
			Deposit: &DepositIngestSpec{ResourceFamilies: []string{"missing"}},
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
	if !hasBlockingCheck(definition.Validation.Checks, "ingest_deposit_family_missing") {
		t.Fatalf("validation checks = %#v, want ingest_deposit_family_missing blocker", definition.Validation.Checks)
	}
}

func TestValidateAcceptsProjectionRelationships(t *testing.T) {
	definition, err := Normalize(Definition{
		TenantID: "tenant-a",
		SourceID: "example",
		Auth:     AuthSpec{Model: "none"},
		ResourceFamilies: []ResourceFamily{{
			ID:      "secrets",
			Path:    "/v1/secrets",
			IDField: "id",
			Event: EventMappingSpec{
				Kind:      "example.secrets",
				SchemaRef: "example/secrets/v1",
			},
			Projection: &ProjectionSpec{
				Template: "secret",
				Fields: map[string]string{
					"vault_id": "mount_accessor|mount_path",
				},
				Relationships: []ProjectionRelationshipSpec{{
					Relation: "belongs_to",
					To: ProjectionEntitySpec{
						EntityType:   "example.vault",
						URNKind:      "example_vault",
						IDAttributes: []string{"vault_id"},
					},
					MatchType: "secret_vault",
				}},
			},
		}},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if definition.Validation.Status != ValidationReady {
		t.Fatalf("validation status = %q, want ready: %#v", definition.Validation.Status, definition.Validation.Checks)
	}
	relationship := definition.ResourceFamilies[0].Projection.Relationships[0]
	if relationship.Relation != "belongs_to" || relationship.MatchType != "secret_vault" {
		t.Fatalf("relationship normalization = %#v", relationship)
	}
}

func TestValidateBlocksUnsafeProjectionRelationships(t *testing.T) {
	definition, err := Normalize(Definition{
		TenantID: "tenant-a",
		SourceID: "example",
		Auth:     AuthSpec{Model: "none"},
		ResourceFamilies: []ResourceFamily{
			{
				ID:      "assets",
				Path:    "/v1/assets",
				IDField: "id",
				Event: EventMappingSpec{
					Kind:      "example.assets",
					SchemaRef: "example/assets/v1",
				},
				Projection: &ProjectionSpec{
					Template: "asset",
					Fields:   map[string]string{"eventID": "eventID"},
					Relationships: []ProjectionRelationshipSpec{{
						Relation: "depends_on",
						To: ProjectionEntitySpec{
							EntityType:   "example.run",
							URNKind:      "example_run",
							IDAttributes: []string{"eventID"},
						},
					}},
				},
			},
			{
				ID:      "audit_events",
				Path:    "/v1/audit",
				IDField: "id",
				Event: EventMappingSpec{
					Kind:      "example.audit_events",
					SchemaRef: "example/audit_events/v1",
				},
				Projection: &ProjectionSpec{
					Template: "audit-event",
					Fields:   map[string]string{"actor_user_id": "actor.id"},
					Relationships: []ProjectionRelationshipSpec{{
						Relation: "owned_by",
						To: ProjectionEntitySpec{
							EntityType:   "example.user",
							URNKind:      "example_user",
							IDAttributes: []string{"actor_user_id"},
						},
						MatchType: "audit_owner",
					}},
				},
			},
			{
				ID:      "policies",
				Path:    "/v1/policies",
				IDField: "id",
				Event: EventMappingSpec{
					Kind:      "example.policies",
					SchemaRef: "example/policies/v1",
					URNKind:   "policy_urn_kind",
				},
				Projection: &ProjectionSpec{
					Template: "policy",
					Relationships: []ProjectionRelationshipSpec{{
						Relation: "owned_by",
						To: ProjectionEntitySpec{
							EntityType:   "example.owner",
							URNKind:      "example_owner",
							IDAttributes: []string{"policy_urn_kind"},
						},
						MatchType: "policy_owner",
					}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	for _, want := range []string{
		"projection_relationship_assets_0_relation",
		"projection_relationship_assets_0_match_type",
		"projection_relationship_assets_0_to_assets_unstable_eventid",
		"projection_relationships_audit_events",
		"projection_relationship_policies_0_to_policies_attribute_policy_urn_kind",
	} {
		if !hasBlockingCheck(definition.Validation.Checks, want) {
			t.Fatalf("validation checks = %#v, want blocker %q", definition.Validation.Checks, want)
		}
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

func TestPromoteRequiresGateEvidenceForLaterStages(t *testing.T) {
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

	sandbox, err := Promote(definition, PromotionRequest{TargetStage: StageSandbox})
	if err != nil {
		t.Fatalf("Promote() to sandbox error = %v", err)
	}
	if !sandbox.Promoted {
		t.Fatalf("sandbox promotion = %#v, want promoted without gate evidence", sandbox)
	}

	blocked, err := Promote(sandbox.Definition, PromotionRequest{TargetStage: StagePilot})
	if err != nil {
		t.Fatalf("Promote() to pilot error = %v", err)
	}
	if blocked.Promoted || blocked.Definition.Stage != StageSandbox {
		t.Fatalf("pilot promotion without evidence = %#v, want held at sandbox", blocked)
	}

	// Evidence without an attesting actor is not sufficient.
	unsigned, err := Promote(sandbox.Definition, PromotionRequest{
		TargetStage:  StagePilot,
		GateEvidence: []GateEvidence{{Gate: GateSandboxProbe}},
	})
	if err != nil {
		t.Fatalf("Promote() to pilot error = %v", err)
	}
	if unsigned.Promoted {
		t.Fatalf("pilot promotion with unsigned evidence = %#v, want held", unsigned)
	}

	pilot, err := Promote(sandbox.Definition, PromotionRequest{
		TargetStage:  StagePilot,
		GateEvidence: []GateEvidence{{Gate: GateSandboxProbe, Actor: "sandbox-runner", Detail: "probe passed"}},
	})
	if err != nil {
		t.Fatalf("Promote() to pilot error = %v", err)
	}
	if !pilot.Promoted || pilot.Definition.Stage != StagePilot {
		t.Fatalf("pilot promotion with evidence = %#v, want pilot", pilot)
	}
	if len(pilot.AcceptedGates) != 1 || pilot.AcceptedGates[0].Gate != GateSandboxProbe || pilot.AcceptedGates[0].ObservedAt == "" {
		t.Fatalf("accepted gates = %#v, want normalized sandbox_probe evidence", pilot.AcceptedGates)
	}

	if held, err := Promote(pilot.Definition, PromotionRequest{TargetStage: StageApproved}); err != nil {
		t.Fatalf("Promote() to approved error = %v", err)
	} else if held.Promoted {
		t.Fatalf("approved promotion without admin review = %#v, want held", held)
	}

	approved, err := Promote(pilot.Definition, PromotionRequest{
		TargetStage:  StageApproved,
		GateEvidence: []GateEvidence{{Gate: GateAdminReview, Actor: "security-admin"}},
	})
	if err != nil {
		t.Fatalf("Promote() to approved error = %v", err)
	}
	if !approved.Promoted || approved.Definition.Stage != StageApproved {
		t.Fatalf("approved promotion with admin review = %#v, want approved", approved)
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
				Type:           "entity_family",
				Support:        "supported",
				EvidenceTypes:  []string{"identity_configuration"},
				ControlDomains: []string{"identity_access"},
				ControlRefs: []CoverageControlRefSpec{{
					FrameworkName: "SOC 2",
					ControlID:     "CC6.1",
				}},
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
	coverage := definition.ResourceFamilies[0].Coverage[0]
	if len(coverage.EvidenceTypes) != 1 || coverage.EvidenceTypes[0] != "identity_configuration" {
		t.Fatalf("evidence types = %#v, want identity_configuration", coverage.EvidenceTypes)
	}
	if len(coverage.ControlDomains) != 1 || coverage.ControlDomains[0] != "identity_access" {
		t.Fatalf("control domains = %#v, want identity_access", coverage.ControlDomains)
	}
	if len(coverage.ControlRefs) != 1 || coverage.ControlRefs[0].FrameworkName != "SOC 2" || coverage.ControlRefs[0].ControlID != "CC6.1" {
		t.Fatalf("control refs = %#v, want SOC 2 CC6.1", coverage.ControlRefs)
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

func TestClassifyReportsDisjointSupportedAndMissingFeatures(t *testing.T) {
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
		ResourceFamilies: []ResourceFamily{
			{
				ID:             "users",
				Path:           "/v1/users",
				RecordSelector: "$.data.users[*]",
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
			},
			{
				ID:      "groups",
				Path:    "/v1/groups",
				IDField: "id",
				Event: EventMappingSpec{
					Kind:      "example.group",
					SchemaRef: "example/group/v1",
				},
				Projection: &ProjectionSpec{
					Template: "identity_group",
				},
				Coverage: []CoverageDimensionSpec{{
					Type:    "entity_family",
					Support: "supported",
				}},
			},
		},
	}, DefaultGrammar())
	if err != nil {
		t.Fatalf("Classify() error = %v", err)
	}

	const feature = "record_selector.jsonpath_or_list_key"
	if !containsString(report.MissingFeatures, feature) {
		t.Fatalf("missing features = %#v, want %q", report.MissingFeatures, feature)
	}
	if containsString(report.SupportedFeatures, feature) {
		t.Fatalf("supported features = %#v, must not include missing feature %q", report.SupportedFeatures, feature)
	}
	for _, supported := range report.SupportedFeatures {
		if containsString(report.MissingFeatures, supported) {
			t.Fatalf("supported and missing features overlap on %q; supported=%#v missing=%#v", supported, report.SupportedFeatures, report.MissingFeatures)
		}
	}
	if !hasSupportCheckStatus(report.Checks, feature, SupportStatusReady) {
		t.Fatalf("checks = %#v, want ready check for %q", report.Checks, feature)
	}
	if !hasSupportCheckStatus(report.Checks, feature, SupportStatusMissing) {
		t.Fatalf("checks = %#v, want missing check for %q", report.Checks, feature)
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

func hasSupportCheckStatus(checks []SupportCheck, id string, status string) bool {
	for _, check := range checks {
		if check.ID == id && check.Status == status {
			return true
		}
	}
	return false
}
