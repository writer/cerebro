package connectorcatalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

const wantBuiltinCatalogEntries = 794
const wantBuiltinCatalogBespokeRuntimeEntries = 1

func TestAnalyzeDirAcceptsGenerateableCatalogEntry(t *testing.T) {
	root := t.TempDir()
	writeCatalogFile(t, root, `
entries:
  - classifier_output: supported
    definition:
      schema_version: cerebro.integration/v1
      id: builtin-example_idp
      tenant_id: builtin_catalog
      source_id: example_idp
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
          event: {kind: example_idp.user, schema_ref: example_idp/user/v1}
          projection: {template: identity_user}
          coverage:
            - {type: entity_family, support: partial, high_value: true, evidence_types: [source_snapshot], control_domains: [asset_inventory]}
        - id: groups
          path: /v1/groups
          record_selector: $.data[*]
          id_field: id
          event: {kind: example_idp.group, schema_ref: example_idp/group/v1}
          projection: {template: identity_group}
          coverage:
            - {type: entity_family, support: partial, high_value: true, evidence_types: [source_snapshot], control_domains: [asset_inventory]}
`)

	analysis, err := AnalyzeDir(root, Options{DryRunSourcegen: true})
	if err != nil {
		t.Fatalf("AnalyzeDir() error = %v", err)
	}
	if len(analysis.Issues) != 0 {
		t.Fatalf("issues = %#v, want none", analysis.Issues)
	}
	if analysis.Summary.Total != 1 || analysis.Summary.Generateable != 1 {
		t.Fatalf("summary = %#v, want one generateable entry", analysis.Summary)
	}
	if got := analysis.Entries[0].Status; got != StatusGenerateable {
		t.Fatalf("status = %q, want %q", got, StatusGenerateable)
	}
}

func TestAnalyzeDirRejectsClassifierMismatch(t *testing.T) {
	root := t.TempDir()
	writeCatalogFile(t, root, strings.ReplaceAll(minimalDefinitionYAML(), "classifier_output: supported", "classifier_output: bespoke_required"))

	analysis, err := AnalyzeDir(root, Options{})
	if err != nil {
		t.Fatalf("AnalyzeDir() error = %v", err)
	}
	if !issuesContain(analysis.Issues, `classifier_output "bespoke_required" does not match classifier verdict "supported"`) {
		t.Fatalf("issues = %#v, want classifier mismatch", analysis.Issues)
	}
}

func TestAnalyzeDirRequiresProofGateFields(t *testing.T) {
	root := t.TempDir()
	writeCatalogFile(t, root, `
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

	analysis, err := AnalyzeDir(root, Options{})
	if err != nil {
		t.Fatalf("AnalyzeDir() error = %v", err)
	}
	for _, want := range []string{
		"verification endpoint is required",
		"definition must include at least 2 resource families and at most 12 high-value resource families",
		`resource family "users" must declare coverage dimensions`,
		"at least one high-value coverage dimension is required",
	} {
		if !issuesContain(analysis.Issues, want) {
			t.Fatalf("issues = %#v, want %q", analysis.Issues, want)
		}
	}
}

func TestAnalyzeDirRequiresExplicitHighValueCoverageMetadata(t *testing.T) {
	root := t.TempDir()
	writeCatalogFile(t, root, strings.ReplaceAll(minimalDefinitionYAML(), "evidence_types: [source_snapshot], control_domains: [asset_inventory]", ""))

	analysis, err := AnalyzeDir(root, Options{})
	if err != nil {
		t.Fatalf("AnalyzeDir() error = %v", err)
	}
	if !issuesContain(analysis.Issues, `high-value coverage dimension "users_entity_family" must declare evidence types`) {
		t.Fatalf("issues = %#v, want missing evidence types issue", analysis.Issues)
	}
	if !issuesContain(analysis.Issues, `high-value coverage dimension "users_entity_family" must declare control domains`) {
		t.Fatalf("issues = %#v, want missing control domains issue", analysis.Issues)
	}
}

func TestAnalyzeDirCountsHighValueFamiliesOnce(t *testing.T) {
	root := t.TempDir()
	writeCatalogFile(t, root, strings.ReplaceAll(minimalDefinitionYAML(),
		"- {type: entity_family, support: partial, high_value: true, evidence_types: [source_snapshot], control_domains: [asset_inventory]}",
		"- {type: entity_family, support: partial, high_value: true, evidence_types: [source_snapshot], control_domains: [asset_inventory]}\n            - {type: permission_state, support: partial, high_value: true, evidence_types: [source_snapshot], control_domains: [access_control]}"))

	analysis, err := AnalyzeDir(root, Options{DryRunSourcegen: true})
	if err != nil {
		t.Fatalf("AnalyzeDir() error = %v", err)
	}
	if len(analysis.Issues) != 0 {
		t.Fatalf("issues = %#v, want none", analysis.Issues)
	}
	if got := analysis.Entries[0].Status; got != StatusGenerateable {
		t.Fatalf("status = %q, want %q", got, StatusGenerateable)
	}
}

func TestAnalyzeDirMarksOAuthClientCredentialsDefinitionAsGenerateable(t *testing.T) {
	root := t.TempDir()
	writeCatalogFile(t, root, strings.ReplaceAll(strings.ReplaceAll(minimalDefinitionYAML(),
		"model: bearer_token", "model: oauth_client_credentials\n        token_url: https://api.example.test/oauth/token"),
		"key: token", "key: client_id\n            reference_only: true\n          - key: client_secret"))

	analysis, err := AnalyzeDir(root, Options{DryRunSourcegen: true})
	if err != nil {
		t.Fatalf("AnalyzeDir() error = %v", err)
	}
	if len(analysis.Issues) != 0 {
		t.Fatalf("issues = %#v, want none", analysis.Issues)
	}
	if got := analysis.Entries[0].Status; got != StatusGenerateable {
		t.Fatalf("status = %q, want %q", got, StatusGenerateable)
	}
	if analysis.Summary.Generateable != 1 {
		t.Fatalf("summary = %#v, want generateable count", analysis.Summary)
	}
}

func TestBuiltinCatalogSeedSummary(t *testing.T) {
	analysis, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin() error = %v; issues = %#v", err, analysis.Issues)
	}
	if len(analysis.Issues) != 0 {
		t.Fatalf("issues = %#v, want none", analysis.Issues)
	}
	if analysis.Summary.Total != wantBuiltinCatalogEntries {
		t.Fatalf("summary total = %d, want %d", analysis.Summary.Total, wantBuiltinCatalogEntries)
	}
	if len(analysis.Entries) != wantBuiltinCatalogEntries {
		t.Fatalf("entries len = %d, want %d", len(analysis.Entries), wantBuiltinCatalogEntries)
	}
	if analysis.Summary.Generateable != wantBuiltinCatalogEntries-wantBuiltinCatalogBespokeRuntimeEntries {
		t.Fatalf("summary = %#v, want non-bespoke entries generateable", analysis.Summary)
	}
	if analysis.Summary.NeedsAuthExtension != 0 {
		t.Fatalf("summary = %#v, want no auth-extension entries", analysis.Summary)
	}
	if analysis.Summary.NeedsBespokeRuntime != wantBuiltinCatalogBespokeRuntimeEntries {
		t.Fatalf("summary = %#v, want one bespoke-runtime entry", analysis.Summary)
	}
	counted := analysis.Summary.CatalogReady + analysis.Summary.Generateable + analysis.Summary.NeedsAuthExtension + analysis.Summary.NeedsBespokeRuntime
	if counted != analysis.Summary.Total {
		t.Fatalf("status counts = %d, want total %d: %#v", counted, analysis.Summary.Total, analysis.Summary)
	}
	for _, entry := range analysis.Entries {
		for _, family := range entry.Definition.ResourceFamilies {
			if family.Projection != nil && family.Projection.Template == "app_entitlement" {
				t.Fatalf("builtin catalog entry %s family %s uses retired app_entitlement projection template", entry.Definition.SourceID, family.ID)
			}
		}
	}
	t.Logf("builtin connector catalog summary: total=%d generateable=%d needs_auth_extension=%d needs_bespoke_runtime=%d catalog_ready=%d",
		analysis.Summary.Total,
		analysis.Summary.Generateable,
		analysis.Summary.NeedsAuthExtension,
		analysis.Summary.NeedsBespokeRuntime,
		analysis.Summary.CatalogReady,
	)
}

func TestBuiltinOktaCatalogDeclaresComplianceIdentityEvidenceDepth(t *testing.T) {
	analysis, err := BuiltinRuntime()
	if err != nil {
		t.Fatalf("BuiltinRuntime() error = %v; issues = %#v", err, analysis.Issues)
	}
	var okta *Entry
	for index := range analysis.Entries {
		if analysis.Entries[index].Definition.SourceID == "okta" {
			okta = &analysis.Entries[index]
			break
		}
	}
	if okta == nil {
		t.Fatal("okta connector catalog entry not found")
	}
	dimensions := map[string]connectordefinitions.CoverageDimensionSpec{}
	for _, family := range okta.Definition.ResourceFamilies {
		for _, dimension := range family.Coverage {
			dimensions[dimension.ID] = dimension
		}
	}
	for _, want := range []struct {
		id             string
		dimensionType  string
		support        string
		evidenceType   string
		controlDomain  string
		requiredFamily string
	}{
		{id: "user_lifecycle", dimensionType: "lifecycle_state", support: "partial", evidenceType: "identity_configuration", controlDomain: "identity_access", requiredFamily: "dormant_user"},
		{id: "mfa_posture", dimensionType: "app_entitlement", support: "partial", evidenceType: "identity_configuration", controlDomain: "identity_access", requiredFamily: "mfa"},
		{id: "external_accounts", dimensionType: "entity_family", support: "partial", evidenceType: "access_review", controlDomain: "identity_access", requiredFamily: "external_user"},
		{id: "group_memberships", dimensionType: "relationship", support: "partial", evidenceType: "access_review", controlDomain: "identity_access", requiredFamily: "group_membership"},
		{id: "admin_membership", dimensionType: "relationship", support: "partial", evidenceType: "identity_configuration", controlDomain: "identity_access", requiredFamily: "privileged_role"},
		{id: "app_access", dimensionType: "app_entitlement", support: "partial", evidenceType: "identity_configuration", controlDomain: "identity_access", requiredFamily: "app_assignment"},
		{id: "identity_audit_events", dimensionType: "audit_event", support: "partial", evidenceType: "logging_configuration", controlDomain: "logging_monitoring", requiredFamily: "session"},
	} {
		dimension, ok := dimensions[want.id]
		if !ok {
			t.Fatalf("okta coverage dimension %q not found; got %#v", want.id, dimensions)
		}
		if dimension.Type != want.dimensionType || dimension.Support != want.support {
			t.Fatalf("dimension %s type/support = %s/%s, want %s/%s", want.id, dimension.Type, dimension.Support, want.dimensionType, want.support)
		}
		if !hasString(dimension.EvidenceTypes, want.evidenceType) {
			t.Fatalf("dimension %s evidence types = %#v, want %q", want.id, dimension.EvidenceTypes, want.evidenceType)
		}
		if !hasString(dimension.ControlDomains, want.controlDomain) {
			t.Fatalf("dimension %s control domains = %#v, want %q", want.id, dimension.ControlDomains, want.controlDomain)
		}
		if !hasString(dimension.Families, want.requiredFamily) {
			t.Fatalf("dimension %s families = %#v, want %q", want.id, dimension.Families, want.requiredFamily)
		}
	}
	groupMemberships := dimensions["group_memberships"]
	if !hasString(groupMemberships.Notes, "The declarative groups endpoint does not enumerate memberships; dedicated okta.group_membership events in the hand-written Okta source runtime provide full membership projection support.") {
		t.Fatalf("group_memberships notes = %#v, want source projection support note", groupMemberships.Notes)
	}
}

func TestBuiltinOneLoginCatalogUsesVerifiedProviderAPI(t *testing.T) {
	analysis, err := BuiltinRuntime()
	if err != nil {
		t.Fatalf("BuiltinRuntime() error = %v; issues = %#v", err, analysis.Issues)
	}
	var onelogin *Entry
	for index := range analysis.Entries {
		if analysis.Entries[index].Definition.SourceID == "onelogin" {
			onelogin = &analysis.Entries[index]
			break
		}
	}
	if onelogin == nil {
		t.Fatal("onelogin connector catalog entry not found")
	}
	definition := onelogin.Definition
	if definition.Auth.TokenURL != "https://${config.subdomain}.onelogin.com/auth/oauth2/v2/token" {
		t.Fatalf("token URL = %q, want OneLogin OAuth v2 token URL", definition.Auth.TokenURL)
	}
	if definition.Transport == nil || definition.Transport.BaseURL != "https://${config.subdomain}.onelogin.com" {
		t.Fatalf("base URL = %#v, want subdomain OneLogin API base URL", definition.Transport)
	}
	wantPaths := map[string]string{
		"users":        "/api/2/users",
		"groups":       "/api/1/groups",
		"roles":        "/api/2/roles",
		"apps":         "/api/2/apps",
		"audit_events": "/api/1/events",
		"privileges":   "/api/1/privileges",
		"mappings":     "/api/2/mappings",
		"mfa_devices":  "/api/2/mfa/users/${config.user_id}/devices",
		"role_users":   "/api/2/roles/${config.role_id}/users",
		"role_admins":  "/api/2/roles/${config.role_id}/admins",
		"app_users":    "/api/2/apps/${config.app_id}/users",
		"app_rules":    "/api/2/apps/${config.app_id}/rules",
	}
	if len(definition.ResourceFamilies) != len(wantPaths) {
		t.Fatalf("resource families = %d, want %d", len(definition.ResourceFamilies), len(wantPaths))
	}
	gotPaths := map[string]string{}
	dimensions := map[string]connectordefinitions.CoverageDimensionSpec{}
	for _, family := range definition.ResourceFamilies {
		gotPaths[family.ID] = family.Path
		if strings.HasPrefix(strings.TrimSpace(family.Path), "/v1/") {
			t.Fatalf("family %s uses stale path %q", family.ID, family.Path)
		}
		for _, dimension := range family.Coverage {
			dimensions[dimension.ID] = dimension
		}
	}
	for familyID, wantPath := range wantPaths {
		if gotPaths[familyID] != wantPath {
			t.Fatalf("family %s path = %q, want %q", familyID, gotPaths[familyID], wantPath)
		}
	}
	for _, dimensionID := range []string{"privileges", "mfa_devices", "role_users", "role_admins", "app_users", "app_rules"} {
		dimension, ok := dimensions[dimensionID]
		if !ok {
			t.Fatalf("coverage dimension %q not found; got %#v", dimensionID, dimensions)
		}
		foundSourceCDKNote := false
		for _, note := range dimension.Notes {
			if strings.Contains(note, "promoted Source CDK adapter") {
				foundSourceCDKNote = true
				break
			}
		}
		if !foundSourceCDKNote {
			t.Fatalf("coverage dimension %q notes = %#v, want promoted Source CDK adapter note", dimensionID, dimension.Notes)
		}
	}
}

func TestBuiltinRuntimeSkipsSourcegenDryRun(t *testing.T) {
	analysis, err := BuiltinRuntime()
	if err != nil {
		t.Fatalf("BuiltinRuntime() error = %v; issues = %#v", err, analysis.Issues)
	}
	if analysis.Summary.Total != wantBuiltinCatalogEntries || len(analysis.Entries) != wantBuiltinCatalogEntries {
		t.Fatalf("runtime catalog size = total %d entries %d, want %d", analysis.Summary.Total, len(analysis.Entries), wantBuiltinCatalogEntries)
	}
	if analysis.Summary.CatalogReady != wantBuiltinCatalogEntries-wantBuiltinCatalogBespokeRuntimeEntries || analysis.Summary.Generateable != 0 || analysis.Summary.NeedsBespokeRuntime != wantBuiltinCatalogBespokeRuntimeEntries {
		t.Fatalf("runtime summary = %#v, want catalog-ready supported entries and one bespoke runtime entry", analysis.Summary)
	}
	for _, entry := range analysis.Entries {
		wantStatus := StatusCatalogReady
		if entry.Definition.SourceID == "auth0" {
			wantStatus = StatusNeedsBespokeRuntime
		}
		if entry.SourcegenDryRun || entry.Generateable || entry.Status != wantStatus {
			t.Fatalf("entry %s status=%q sourcegen=%v generateable=%v, want %s without dry-run", entry.Definition.SourceID, entry.Status, entry.SourcegenDryRun, entry.Generateable, wantStatus)
		}
	}
}

func TestBuiltinEntryFindsNormalizedSourceID(t *testing.T) {
	entry, ok, err := BuiltinEntry("JumpCloud")
	if err != nil {
		t.Fatalf("BuiltinEntry() error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry() ok = false, want true")
	}
	if entry.Definition.SourceID != "jumpcloud" || entry.Status != StatusGenerateable {
		t.Fatalf("entry = %#v, want generateable jumpcloud", entry)
	}
}

func TestBuiltinCatalogHashicorpVaultFamiliesMirrorRuntimeConfig(t *testing.T) {
	entry, ok, err := BuiltinEntry("hashicorp_vault")
	if err != nil {
		t.Fatalf("BuiltinEntry() error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(hashicorp_vault) ok = false, want true")
	}

	wantStaticFields := map[string]map[string]string{
		"users": {
			"resource_type": "vault_identity_entity",
		},
		"secrets": {
			"resource_type": "vault_secret_engine",
			"secret_status": "enabled",
		},
		"audit_events": {
			"actor_id":      "vault",
			"event_type":    "vault.audit_device.enabled",
			"resource_type": "vault_audit_device",
		},
	}

	for _, familyID := range []string{"users", "secrets", "audit_events"} {
		family := catalogFamily(t, entry.Definition.ResourceFamilies, familyID)
		if family.Config == nil || family.Config.ConfigAttributes["tenant_id"] != "tenant_id" {
			t.Fatalf("%s config = %#v, want tenant_id config attribute", familyID, family.Config)
		}
		if family.Projection == nil {
			t.Fatalf("%s projection = nil, want static fields", familyID)
		}
		for key, want := range wantStaticFields[familyID] {
			if got := family.Projection.StaticFields[key]; got != want {
				t.Fatalf("%s static field %s = %q, want %q", familyID, key, got, want)
			}
		}
	}
}

func TestBuiltinCatalogAuth0UsesManagementAPIShape(t *testing.T) {
	entry, ok, err := BuiltinEntry("auth0")
	if err != nil {
		t.Fatalf("BuiltinEntry() error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(auth0) ok = false, want true")
	}
	definition := entry.Definition
	if definition.Transport == nil || definition.Transport.BaseURL != "https://${config.domain}/api/v2" {
		t.Fatalf("auth0 transport = %#v, want Management API v2 base", definition.Transport)
	}
	if definition.Transport.Verification == nil || definition.Transport.Verification.Path != "/users" {
		t.Fatalf("auth0 verification = %#v, want /users", definition.Transport.Verification)
	}
	if got := definition.Auth.TokenParams["audience"]; got != "https://${config.domain}/api/v2/" {
		t.Fatalf("auth0 audience token param = %q", got)
	}
	if entry.Status != StatusNeedsBespokeRuntime {
		t.Fatalf("auth0 status = %q, want %q", entry.Status, StatusNeedsBespokeRuntime)
	}
	configFields := map[string]connectordefinitions.Field{}
	for _, field := range definition.ConfigFields {
		configFields[field.Key] = field
	}
	if !configFields["domain"].Required {
		t.Fatalf("auth0 config fields = %#v, want required domain", definition.ConfigFields)
	}
	for _, key := range []string{"organization_ids", "user_ids"} {
		if _, ok := configFields[key]; !ok {
			t.Fatalf("auth0 config fields = %#v, want %s fanout config", definition.ConfigFields, key)
		}
	}
	if len(definition.ResourceFamilies) != 13 {
		t.Fatalf("auth0 resource families = %d, want 13", len(definition.ResourceFamilies))
	}
	assertCatalogFamily(t, definition.ResourceFamilies, "users", "/users", "user_id")
	assertCatalogFamily(t, definition.ResourceFamilies, "roles", "/roles", "id")
	assertCatalogFamily(t, definition.ResourceFamilies, "audit_events", "/logs", "log_id")
	assertCatalogFamilyPath(t, definition.ResourceFamilies, "organizations", "/organizations", "id")
	assertCatalogFamilyPath(t, definition.ResourceFamilies, "clients", "/clients", "client_id")
	assertCatalogFamilyPath(t, definition.ResourceFamilies, "resource_servers", "/resource-servers", "id")
	familiesByID := map[string]connectordefinitions.ResourceFamily{}
	for _, family := range definition.ResourceFamilies {
		familiesByID[family.ID] = family
	}
	for _, familyID := range []string{"users", "roles", "organizations", "organization_members", "clients", "connections", "resource_servers", "client_grants", "grants", "user_roles", "user_authentication_methods", "audit_events", "guardian_factors"} {
		family, ok := familiesByID[familyID]
		if !ok {
			t.Fatalf("auth0 family %s not found", familyID)
		}
		if family.RecordSelector != "$[*]" || family.ListKey != "" {
			t.Fatalf("auth0 %s selector/list_key = %q/%q, want bare array selector without list key", familyID, family.RecordSelector, family.ListKey)
		}
	}
	for _, familyID := range []string{"organizations", "organization_members", "connections", "client_grants"} {
		family := familiesByID[familyID]
		if family.Pagination == nil || family.Pagination.Type != "page" || family.Pagination.PageParam != "page" || family.Pagination.PageSizeParam != "per_page" || family.Pagination.StartPage != 0 {
			t.Fatalf("auth0 %s pagination = %#v, want page/per_page starting at 0", familyID, family.Pagination)
		}
	}
}

func TestBuiltinCatalogSailPointIdentitySecurityCloudUsesV2025API(t *testing.T) {
	entry, ok, err := BuiltinEntry("sailpoint_identitynow")
	if err != nil {
		t.Fatalf("BuiltinEntry() error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(sailpoint_identitynow) ok = false, want true")
	}
	definition := entry.Definition
	if definition.DisplayName != "SailPoint Identity Security Cloud" {
		t.Fatalf("display name = %q, want SailPoint Identity Security Cloud", definition.DisplayName)
	}
	if definition.Auth.Model != "oauth_client_credentials" || definition.Auth.TokenURL != "https://${config.tenant}.api.identitynow.com/oauth/token" {
		t.Fatalf("auth = %#v, want tenant-scoped OAuth client credentials", definition.Auth)
	}
	if !hasString(definition.Auth.Scopes, "sp:scopes:all") {
		t.Fatalf("scopes = %#v, want sp:scopes:all", definition.Auth.Scopes)
	}
	if definition.Transport == nil || definition.Transport.BaseURL != "https://${config.tenant}.api.identitynow.com/v2025" {
		t.Fatalf("transport = %#v, want ISC v2025 base URL", definition.Transport)
	}
	if definition.Transport.Verification == nil || definition.Transport.Verification.Path != "/identities" {
		t.Fatalf("verification = %#v, want /identities", definition.Transport.Verification)
	}
	if len(definition.ResourceFamilies) != 12 {
		t.Fatalf("resource families = %d, want 12", len(definition.ResourceFamilies))
	}
	for _, test := range []struct {
		familyID   string
		path       string
		projection string
	}{
		{"identities", "/identities", "identity_user"},
		{"accounts", "/accounts", "asset"},
		{"sources", "/sources", "asset"},
		{"access_profiles", "/access-profiles", "policy"},
		{"roles", "/roles", "policy"},
		{"entitlements", "/entitlements", "policy"},
		{"identity_profiles", "/identity-profiles", "policy"},
		{"workgroups", "/workgroups", "identity_group"},
		{"certifications", "/certifications", "policy"},
		{"access_request_status", "/access-request-status", "audit_event"},
		{"account_activities", "/account-activities", "audit_event"},
		{"personal_access_tokens", "/personal-access-tokens", "secret"},
	} {
		family := catalogFamily(t, definition.ResourceFamilies, test.familyID)
		if family.Path != test.path || family.RecordSelector != "$[*]" || family.IDField != "id" {
			t.Fatalf("%s family = %#v, want path=%s selector=$[*] id_field=id", test.familyID, family, test.path)
		}
		if family.Pagination == nil || family.Pagination.Type != "offset" || family.Pagination.LimitParam != "limit" || family.Pagination.OffsetParam != "offset" {
			t.Fatalf("%s pagination = %#v, want offset pagination", test.familyID, family.Pagination)
		}
		if family.Projection == nil || family.Projection.Template != test.projection {
			t.Fatalf("%s projection = %#v, want %s", test.familyID, family.Projection, test.projection)
		}
	}
}

func TestBuiltinCatalogKnowBe4SecurityAwarenessShape(t *testing.T) {
	entry, ok, err := BuiltinEntry("knowbe4")
	if err != nil {
		t.Fatalf("BuiltinEntry() error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(knowbe4) ok = false, want true")
	}
	definition := entry.Definition
	if definition.Transport == nil || definition.Transport.BaseURL != "https://${config.region}.api.knowbe4.com/v1" {
		t.Fatalf("knowbe4 transport = %#v, want regional Reporting API base", definition.Transport)
	}
	if definition.Transport.Verification == nil || definition.Transport.Verification.Path != "/users" {
		t.Fatalf("knowbe4 verification = %#v, want /users", definition.Transport.Verification)
	}
	if definition.Auth.Model != "bearer_token" {
		t.Fatalf("knowbe4 auth model = %q, want bearer_token", definition.Auth.Model)
	}
	if len(definition.ConfigFields) != 1 || definition.ConfigFields[0].Key != "region" || !definition.ConfigFields[0].Required {
		t.Fatalf("knowbe4 config fields = %#v, want required region", definition.ConfigFields)
	}
	if !hasString(definition.Categories, "security_training") {
		t.Fatalf("knowbe4 categories = %#v, want security_training", definition.Categories)
	}
	assertCatalogFamily(t, definition.ResourceFamilies, "users", "/users", "id")
	assertCatalogFamily(t, definition.ResourceFamilies, "groups", "/groups", "id")
	assertCatalogFamily(t, definition.ResourceFamilies, "training_enrollments", "/training/enrollments", "id")
	assertCatalogFamily(t, definition.ResourceFamilies, "phishing_campaigns", "/phishing/campaigns", "id")
	enrollments := catalogFamily(t, definition.ResourceFamilies, "training_enrollments")
	if enrollments.Pagination == nil || enrollments.Pagination.Type != "page" || enrollments.Pagination.PageParam != "page" || enrollments.Pagination.PageSizeParam != "per_page" || enrollments.Pagination.StartPage != 1 {
		t.Fatalf("training enrollments pagination = %#v, want page/per_page starting at 1", enrollments.Pagination)
	}
	if len(enrollments.Coverage) != 1 || !hasString(enrollments.Coverage[0].Families, "training_enrollments") {
		t.Fatalf("training enrollments coverage = %#v, want family reference to training_enrollments", enrollments.Coverage)
	}
}

func TestBuiltinSlackAccessLogStartsAtPageOne(t *testing.T) {
	entry, ok, err := BuiltinEntry("slack")
	if err != nil {
		t.Fatalf("BuiltinEntry() error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(slack) ok = false, want true")
	}
	accessLog := catalogFamily(t, entry.Definition.ResourceFamilies, "access_log")
	if accessLog.Pagination == nil || accessLog.Pagination.Type != "page" || accessLog.Pagination.PageParam != "page" || accessLog.Pagination.PageSizeParam != "count" || accessLog.Pagination.StartPage != 1 {
		t.Fatalf("access_log pagination = %#v, want page/count starting at 1", accessLog.Pagination)
	}
	if accessLog.Config == nil || len(accessLog.Config.IdentityKeys) != 1 || accessLog.Config.IdentityKeys[0] != "ip" {
		t.Fatalf("access_log config = %#v, want ip identity key", accessLog.Config)
	}
}

func TestBuiltinSlackMembershipFamiliesCarryContainerContext(t *testing.T) {
	entry, ok, err := BuiltinEntry("slack")
	if err != nil {
		t.Fatalf("BuiltinEntry() error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(slack) ok = false, want true")
	}
	channelMember := catalogFamily(t, entry.Definition.ResourceFamilies, "channel_member")
	if channelMember.ConfigQuery["channel"] != "channel_id" {
		t.Fatalf("channel_member config_query = %#v, want channel from channel_id", channelMember.ConfigQuery)
	}
	if channelMember.Read == nil || len(channelMember.Read.PathParams) != 1 || channelMember.Read.PathParams[0] != "channel_id" {
		t.Fatalf("channel_member read = %#v, want channel_id path param", channelMember.Read)
	}
	userGroupMember := catalogFamily(t, entry.Definition.ResourceFamilies, "user_group_member")
	if userGroupMember.ConfigQuery["usergroup"] != "usergroup_id" {
		t.Fatalf("user_group_member config_query = %#v, want usergroup from usergroup_id", userGroupMember.ConfigQuery)
	}
	if userGroupMember.Read == nil || len(userGroupMember.Read.PathParams) != 1 || userGroupMember.Read.PathParams[0] != "usergroup_id" {
		t.Fatalf("user_group_member read = %#v, want usergroup_id path param", userGroupMember.Read)
	}
	if userGroupMember.StaticQuery["include_disabled"] != "true" {
		t.Fatalf("user_group_member static_query = %#v, want include_disabled=true", userGroupMember.StaticQuery)
	}
}

func TestBuiltinFivetranV2FamiliesCarryAcceptHeader(t *testing.T) {
	entry, ok, err := BuiltinEntry("fivetran")
	if err != nil {
		t.Fatalf("BuiltinEntry() error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(fivetran) ok = false, want true")
	}
	for _, familyID := range []string{"destinations", "connections"} {
		family := catalogFamily(t, entry.Definition.ResourceFamilies, familyID)
		if family.StaticHeaders["Accept"] != "application/json;version=2" {
			t.Fatalf("%s static_headers = %#v, want Fivetran v2 Accept header", familyID, family.StaticHeaders)
		}
	}
}

func TestBuiltinFivetranConfigPayloadsAreSensitive(t *testing.T) {
	entry, ok, err := BuiltinEntry("fivetran")
	if err != nil {
		t.Fatalf("BuiltinEntry() error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(fivetran) ok = false, want true")
	}
	for _, familyID := range []string{"destinations", "connections", "account_log_service", "log_services"} {
		family := catalogFamily(t, entry.Definition.ResourceFamilies, familyID)
		if !stringsContain(family.SensitivePayloadPaths, "$.config") {
			t.Fatalf("%s sensitive_payload_paths = %#v, want $.config", familyID, family.SensitivePayloadPaths)
		}
	}
}

func TestBuiltinFivetranServiceAccountProjectionDoesNotReadCredentialAsResourceType(t *testing.T) {
	entry, ok, err := BuiltinEntry("fivetran")
	if err != nil {
		t.Fatalf("BuiltinEntry() error = %v", err)
	}
	if !ok {
		t.Fatal("BuiltinEntry(fivetran) ok = false, want true")
	}
	family := catalogFamily(t, entry.Definition.ResourceFamilies, "group_service_accounts")
	if family.Projection == nil {
		t.Fatal("group_service_accounts projection missing")
	}
	if got := family.Projection.Fields["resource_type"]; got != "credential_type|type" {
		t.Fatalf("group_service_accounts resource_type projection = %q, want credential_type|type", got)
	}
}

func assertCatalogFamily(t *testing.T, families []connectordefinitions.ResourceFamily, id string, path string, idField string) {
	t.Helper()
	for _, family := range families {
		if family.ID != id {
			continue
		}
		if family.Path != path || family.RecordSelector != "$[*]" || family.IDField != idField {
			t.Fatalf("family %s = %#v, want path=%s selector=$[*] id_field=%s", id, family, path, idField)
		}
		return
	}
	t.Fatalf("family %s not found in %#v", id, families)
}

func assertCatalogFamilyPath(t *testing.T, families []connectordefinitions.ResourceFamily, id string, path string, idField string) {
	t.Helper()
	for _, family := range families {
		if family.ID != id {
			continue
		}
		if family.Path != path || family.IDField != idField {
			t.Fatalf("family %s = %#v, want path=%s id_field=%s", id, family, path, idField)
		}
		return
	}
	t.Fatalf("family %s not found in %#v", id, families)
}

func stringsContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestBuiltinCatalogIncludesAdditionalGapEntries(t *testing.T) {
	for sourceID, wantStatus := range map[string]string{
		"checkr":        StatusGenerateable,
		"ethena":        StatusGenerateable,
		"google_drive":  StatusGenerateable,
		"hitrust_mycsf": StatusGenerateable,
		"knowbe4":       StatusGenerateable,
		"ramp":          StatusGenerateable,
		"rippling":      StatusGenerateable,
		"segment":       StatusGenerateable,
		"swif_ai":       StatusGenerateable,
	} {
		entry, ok, err := BuiltinEntry(sourceID)
		if err != nil {
			t.Fatalf("BuiltinEntry(%q) error = %v", sourceID, err)
		}
		if !ok {
			t.Fatalf("BuiltinEntry(%q) ok = false, want true", sourceID)
		}
		if entry.Status != wantStatus {
			t.Fatalf("BuiltinEntry(%q) status = %q, want %q", sourceID, entry.Status, wantStatus)
		}
	}
}

func TestBuiltinCatalogPreviouslyBlockedEntriesAreGenerateable(t *testing.T) {
	cases := []struct {
		sourceID string
		family   string
	}{
		{"argo_cd", "findings"},
		{"jenkins", "findings"},
		{"netsuite", "assets"},
		{"linear", "projects"},
		{"microsoft_teams", "content_assets"},
		{"monday_com", "projects"},
		{"mend_io", "findings"},
		{"qualys_vmdr", "findings"},
		{"wiz", "findings"},
		{"cortex_xsoar", "findings"},
		{"new_relic", "findings"},
		{"panther", "findings"},
		{"splunk_cloud", "findings"},
		{"tines", "findings"},
		{"torq", "findings"},
	}
	for _, test := range cases {
		t.Run(test.sourceID+"/"+test.family, func(t *testing.T) {
			entry, ok, err := BuiltinEntry(test.sourceID)
			if err != nil {
				t.Fatalf("BuiltinEntry() error = %v", err)
			}
			if !ok {
				t.Fatal("BuiltinEntry() ok = false, want true")
			}
			if entry.Status != StatusGenerateable || !entry.Generateable {
				t.Fatalf("status = %q generateable=%v, want generateable", entry.Status, entry.Generateable)
			}
			family := catalogFamily(t, entry.Definition.ResourceFamilies, test.family)
			if family.RecordSelector == "" && family.ListKey == "" {
				t.Fatalf("family %s selector/list key is empty: %#v", test.family, family)
			}
		})
	}
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func minimalDefinitionYAML() string {
	return `
entries:
  - classifier_output: supported
    definition:
      schema_version: cerebro.integration/v1
      id: builtin-example
      tenant_id: builtin_catalog
      source_id: example
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
          event: {kind: example.user, schema_ref: example/user/v1}
          projection: {template: identity_user}
          coverage:
            - {type: entity_family, support: partial, high_value: true, evidence_types: [source_snapshot], control_domains: [asset_inventory]}
        - id: groups
          path: /v1/groups
          record_selector: $.data[*]
          id_field: id
          event: {kind: example.group, schema_ref: example/group/v1}
          projection: {template: identity_group}
          coverage:
            - {type: entity_family, support: partial, high_value: true, evidence_types: [source_snapshot], control_domains: [asset_inventory]}
`
}

func catalogFamily(t *testing.T, families []connectordefinitions.ResourceFamily, id string) connectordefinitions.ResourceFamily {
	t.Helper()
	for _, family := range families {
		if family.ID == id {
			return family
		}
	}
	t.Fatalf("family %s not found in %#v", id, families)
	return connectordefinitions.ResourceFamily{}
}

func writeCatalogFile(t *testing.T, root string, content string) {
	t.Helper()
	path := filepath.Join(root, "identity-access-secrets.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func issuesContain(issues []Issue, want string) bool {
	for _, issue := range issues {
		if strings.Contains(issue.Message, want) {
			return true
		}
	}
	return false
}
