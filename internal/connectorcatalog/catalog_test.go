package connectorcatalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

const wantBuiltinCatalogEntries = 780

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
		"definition must include 2-12 high-value resource families",
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
	if analysis.Summary.Generateable != wantBuiltinCatalogEntries {
		t.Fatalf("summary = %#v, want all entries generateable", analysis.Summary)
	}
	if analysis.Summary.NeedsAuthExtension != 0 {
		t.Fatalf("summary = %#v, want no auth-extension entries", analysis.Summary)
	}
	if analysis.Summary.NeedsBespokeRuntime != 0 {
		t.Fatalf("summary = %#v, want no bespoke-runtime entries", analysis.Summary)
	}
	counted := analysis.Summary.CatalogReady + analysis.Summary.Generateable + analysis.Summary.NeedsAuthExtension + analysis.Summary.NeedsBespokeRuntime
	if counted != analysis.Summary.Total {
		t.Fatalf("status counts = %d, want total %d: %#v", counted, analysis.Summary.Total, analysis.Summary)
	}
	t.Logf("builtin connector catalog summary: total=%d generateable=%d needs_auth_extension=%d needs_bespoke_runtime=%d catalog_ready=%d",
		analysis.Summary.Total,
		analysis.Summary.Generateable,
		analysis.Summary.NeedsAuthExtension,
		analysis.Summary.NeedsBespokeRuntime,
		analysis.Summary.CatalogReady,
	)
}

func TestBuiltinRuntimeSkipsSourcegenDryRun(t *testing.T) {
	analysis, err := BuiltinRuntime()
	if err != nil {
		t.Fatalf("BuiltinRuntime() error = %v; issues = %#v", err, analysis.Issues)
	}
	if analysis.Summary.Total != wantBuiltinCatalogEntries || len(analysis.Entries) != wantBuiltinCatalogEntries {
		t.Fatalf("runtime catalog size = total %d entries %d, want %d", analysis.Summary.Total, len(analysis.Entries), wantBuiltinCatalogEntries)
	}
	if analysis.Summary.CatalogReady != wantBuiltinCatalogEntries || analysis.Summary.Generateable != 0 {
		t.Fatalf("runtime summary = %#v, want catalog-ready entries without sourcegen dry-run", analysis.Summary)
	}
	for _, entry := range analysis.Entries {
		if entry.SourcegenDryRun || entry.Generateable || entry.Status != StatusCatalogReady {
			t.Fatalf("entry %s status=%q sourcegen=%v generateable=%v, want runtime catalog-ready only", entry.Definition.SourceID, entry.Status, entry.SourcegenDryRun, entry.Generateable)
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
	if len(definition.ConfigFields) != 1 || definition.ConfigFields[0].Key != "domain" || !definition.ConfigFields[0].Required {
		t.Fatalf("auth0 config fields = %#v, want required domain", definition.ConfigFields)
	}
	assertCatalogFamily(t, definition.ResourceFamilies, "users", "/users", "user_id")
	assertCatalogFamily(t, definition.ResourceFamilies, "roles", "/roles", "id")
	assertCatalogFamily(t, definition.ResourceFamilies, "audit_events", "/logs", "log_id")
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
