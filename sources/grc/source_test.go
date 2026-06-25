package grc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/sourceconfig"
)

const (
	testClientID     = "test-client"
	testClientSecret = "test-secret"
)

func TestNewLoadsCatalog(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if source.Spec().Id != "grc" {
		t.Fatalf("Spec().Id = %q, want grc", source.Spec().Id)
	}
	if source.Spec().Name != "GRC" {
		t.Fatalf("Spec().Name = %q, want GRC", source.Spec().Name)
	}
}

func TestParseSettingsRequiresTenant(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"client_id":     testClientID,
		"client_secret": testClientSecret,
		"family":        familyVendor,
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want tenant_id error")
	}
}

func TestParseSettingsUsesRuntimeTenantFallback(t *testing.T) {
	settings, err := parseSettings(sourcecdk.NewConfig(map[string]string{
		"client_id":                     testClientID,
		"client_secret":                 testClientSecret,
		"family":                        familyVendor,
		sourceconfig.RuntimeTenantIDKey: "writer",
	}), true)
	if err != nil {
		t.Fatalf("parseSettings() error = %v", err)
	}
	if settings.tenantID != "writer" {
		t.Fatalf("tenantID = %q, want writer", settings.tenantID)
	}
}

func TestParseSettingsRejectsUnknownProvider(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"client_id":     testClientID,
		"client_secret": testClientSecret,
		"family":        familyVendor,
		"provider":      "drata",
		"tenant_id":     "writer",
	}))
	if err == nil {
		t.Fatal("Check() error = nil, want unknown provider error")
	}
}

func TestParseSettingsRejectsUntrustedVantaHosts(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	base := map[string]string{
		"client_id":     testClientID,
		"client_secret": testClientSecret,
		"family":        familyVendor,
		"provider":      "vanta",
		"tenant_id":     "writer",
	}
	cases := map[string]map[string]string{
		"base url":  {"base_url": "https://attacker.example"},
		"token url": {"token_url": "https://attacker.example/oauth/token"}, // #nosec G101 -- key name is a URL fixture, not credential material.
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			values := map[string]string{}
			for key, value := range base {
				values[key] = value
			}
			for key, value := range overrides {
				values[key] = value
			}
			err := source.Check(context.Background(), sourcecdk.NewConfig(values))
			if err == nil {
				t.Fatal("Check() error = nil, want untrusted host error")
			}
		})
	}
}

func TestReadVantaVendorPagesAsCanonicalGRCEvents(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyVendor)

	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	discover, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(discover) != 1 {
		t.Fatalf("len(Discover()) = %d, want 1", len(discover))
	}
	if got := discover[0].String(); !strings.Contains(got, "grc_vendor:vanta:vendor-1") {
		t.Fatalf("Discover()[0] = %q, want vendor-1 grc urn", got)
	}

	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first) error = %v", err)
	}
	if len(first.Events) != 1 {
		t.Fatalf("len(Read(first).Events) = %d, want 1", len(first.Events))
	}
	if first.NextCursor == nil || first.NextCursor.Opaque != "cursor-2" {
		t.Fatalf("first.NextCursor = %#v, want cursor-2", first.NextCursor)
	}
	event := first.Events[0]
	if event.Kind != "grc.vendor" {
		t.Fatalf("event.Kind = %q, want grc.vendor", event.Kind)
	}
	if event.SourceId != "grc" {
		t.Fatalf("event.SourceId = %q, want grc", event.SourceId)
	}
	if got := event.Attributes["provider"]; got != "vanta" {
		t.Fatalf("event provider = %q, want vanta", got)
	}
	if got := event.Attributes["inherent_risk_level"]; got != "HIGH" {
		t.Fatalf("event inherent_risk_level = %q, want HIGH", got)
	}
	var payload map[string]any
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		t.Fatalf("unmarshal event payload: %v", err)
	}
	if got := payload["name"]; got != "Acme SaaS" {
		t.Fatalf("payload name = %#v, want Acme SaaS", got)
	}

	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(second).Events) = %d, want 1", len(second.Events))
	}
	if second.NextCursor != nil {
		t.Fatalf("second.NextCursor = %#v, want nil", second.NextCursor)
	}
	if got := second.Events[0].Attributes["vendor_id"]; got != "vendor-2" {
		t.Fatalf("second vendor_id = %q, want vendor-2", got)
	}
}

func TestPullFromRecordsPreservesNextCursorWithoutEvents(t *testing.T) {
	pull, err := pullFromRecords(settings{provider: "vanta", tenantID: "writer"}, familyVendor, nil, "next-page")
	if err != nil {
		t.Fatalf("pullFromRecords() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Events) = %d, want 0", len(pull.Events))
	}
	if got := pull.NextCursor.GetOpaque(); got != "next-page" {
		t.Fatalf("NextCursor = %q, want next-page", got)
	}
}

func TestReadVantaPersonEmitsEmploymentAttributes(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true

	pull, err := source.Read(context.Background(), testConfig(server.URL, familyPerson), nil)
	if err != nil {
		t.Fatalf("Read(person) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(person).Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "grc.person" {
		t.Fatalf("event.Kind = %q, want grc.person", event.Kind)
	}
	for key, want := range map[string]string{
		"department":      "Design",
		"employee_number": "E-1001",
		"job_title":       "Product Designer",
		"manager":         "manager@example.com",
		"manager_id":      "person-manager",
	} {
		if got := event.Attributes[key]; got != want {
			t.Fatalf("Attributes[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestReadVantaControlTestEmitsControlReferences(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyControlTest)

	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(control_test) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(control_test).Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := attrs["control_id"]; got != "control-1" {
		t.Fatalf("control_id = %q, want first linked control", got)
	}
	if got := attrs["control_ids"]; got != "control-1,control-2" {
		t.Fatalf("control_ids = %q, want linked controls", got)
	}
	if got := attrs["control_external_ids"]; got != "CC6.2,CC7.1" {
		t.Fatalf("control_external_ids = %q, want linked control external ids", got)
	}
}

func TestAttributesForControlTestPreservesControlReferencePairs(t *testing.T) {
	attrs := attributesFor(settings{provider: "vanta", tenantID: "writer"}, familyControlTest, grcRecord{
		Values: map[string]any{
			"id": "test-1",
			"controls": []any{
				map[string]any{"id": "control-1"},
				map[string]any{"id": "control-2", "externalId": "CC7.1"},
				map[string]any{"id": "control-3", "externalId": "CC7.1"},
			},
		},
	})

	if got := attrs["control_references"]; got != "control-1=;control-2=CC7.1;control-3=CC7.1" {
		t.Fatalf("control_references = %q, want stable id/external pairs", got)
	}
}

func TestEventFromRecordScopesIDByTenantAndRuntimeConfig(t *testing.T) {
	record := grcRecord{
		Raw:    json.RawMessage(`{"id":"shared-test"}`),
		Values: map[string]any{"id": "shared-test"},
		ID:     "shared-test",
	}
	base := settings{
		provider: "vanta",
		tenantID: "writer",
		family:   familyControlTest,
		baseURL:  "https://api.vanta.com",
		clientID: "client-a",
		scope:    defaultReadScope,
	}
	first := eventFromRecord(base, familyControlTest, record)
	otherTenant := base
	otherTenant.tenantID = "acme"
	second := eventFromRecord(otherTenant, familyControlTest, record)
	otherRuntime := base
	otherRuntime.baseURL = "https://api.eu.vanta.com"
	third := eventFromRecord(otherRuntime, familyControlTest, record)
	if first.Id == second.Id || first.Id == third.Id {
		t.Fatalf("event IDs must be scoped per tenant/runtime config, got %q, %q, %q", first.Id, second.Id, third.Id)
	}
	if !strings.Contains(first.Id, "writer") || !strings.Contains(second.Id, "acme") {
		t.Fatalf("event IDs should include tenant scope, got %q and %q", first.Id, second.Id)
	}
}

func TestOccurredAtForIgnoresDeadlineOnlyFields(t *testing.T) {
	before := time.Now().UTC()
	vulnerabilityOccurredAt := occurredAtFor(familyVulnerability, map[string]any{
		"remediateByDate": "2099-01-01T00:00:00Z",
	})
	vendorOccurredAt := occurredAtFor(familyVendor, map[string]any{
		"nextSecurityReviewDueDate": "2099-01-01T00:00:00Z",
		"contractRenewalDate":       "2099-02-01T00:00:00Z",
	})
	after := time.Now().UTC()

	for name, occurredAt := range map[string]time.Time{
		"vulnerability": vulnerabilityOccurredAt,
		"vendor":        vendorOccurredAt,
	} {
		if occurredAt.Before(before.Add(-time.Second)) || occurredAt.After(after.Add(time.Second)) {
			t.Fatalf("%s occurredAt = %v, want current sync time in [%v, %v]", name, occurredAt, before, after)
		}
	}
}

func TestReadVantaVulnerabilityNormalizesFields(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyVulnerability)

	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(vulnerability) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(vulnerability).Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := attrs["name"]; got != "CVE-2026-4242" {
		t.Fatalf("vulnerability name = %q, want CVE-2026-4242", got)
	}
	if got := attrs["package"]; got != "pkg:golang/example/module@1.2.3" {
		t.Fatalf("package = %q, want purl", got)
	}
	if got := attrs["package_purl"]; got != "pkg:golang/example/module@1.2.3" {
		t.Fatalf("package_purl = %q, want purl", got)
	}
	if got := attrs["remediate_by_date"]; got != "2026-05-30T00:00:00Z" {
		t.Fatalf("remediate_by_date = %q, want deadline", got)
	}
	if got := attrs["target_id"]; got != "target-1" {
		t.Fatalf("target_id = %q, want target-1", got)
	}
	if got := attrs["integration_id"]; got != "integration-1" {
		t.Fatalf("integration_id = %q, want integration-1", got)
	}
}

func TestReadVantaVulnerableAssetNormalizesFields(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyVulnerableAsset)

	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(vulnerable_asset) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(vulnerable_asset).Events) = %d, want 1", len(pull.Events))
	}
	attrs := pull.Events[0].Attributes
	if got := pull.Events[0].Kind; got != "grc.vulnerable_asset" {
		t.Fatalf("event kind = %q, want grc.vulnerable_asset", got)
	}
	if got := attrs["target_id"]; got != "target-1" {
		t.Fatalf("target_id = %q, want target-1", got)
	}
	if got := attrs["hostname"]; got != "app.writer.com" {
		t.Fatalf("hostname = %q, want app.writer.com", got)
	}
	if got := attrs["ip"]; got != "203.0.113.10" {
		t.Fatalf("ip = %q, want 203.0.113.10", got)
	}
	if got := attrs["target_url"]; got != "https://app.writer.com" {
		t.Fatalf("target_url = %q, want https://app.writer.com", got)
	}
	if got := attrs["vulnerability_ids"]; got != "CVE-2026-4242" {
		t.Fatalf("vulnerability_ids = %q, want CVE-2026-4242", got)
	}
	if got := attrs["package_identifiers"]; got != "pkg:golang/example/module@1.2.3" {
		t.Fatalf("package_identifiers = %q, want purl", got)
	}
	var refs []map[string]string
	if err := json.Unmarshal([]byte(attrs["vulnerability_package_refs"]), &refs); err != nil {
		t.Fatalf("vulnerability_package_refs is invalid JSON: %v", err)
	}
	if len(refs) != 1 || refs[0]["vulnerability_id"] != "CVE-2026-4242" || refs[0]["package_identifier"] != "pkg:golang/example/module@1.2.3" {
		t.Fatalf("vulnerability_package_refs = %#v, want CVE/package tuple", refs)
	}
}

func TestReadVantaMonitoredComputerNormalizesPostureFields(t *testing.T) {
	server := httptest.NewServer(newTestAPIHandler(t))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyMonitoredComputer)

	pull, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(monitored_computer) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(monitored_computer).Events) = %d, want 1", len(pull.Events))
	}
	event := pull.Events[0]
	if event.Kind != "grc.monitored_computer" {
		t.Fatalf("event kind = %q, want grc.monitored_computer", event.Kind)
	}
	attrs := event.Attributes
	for key, want := range map[string]string{
		"computer_id":             "computer-1",
		"device_id":               "computer-1",
		"device_uuid":             "udid-1",
		"serial_number":           "serial-1",
		"integration_id":          "kandji",
		"screenlock_status":       "OK",
		"disk_encryption_status":  "OK",
		"password_manager_status": "NEEDS_ATTENTION",
		"antivirus_status":        "OK",
		"os":                      "MACOS",
		"os_version":              "15.5",
		"owner_id":                "person-1",
		"owner_email":             "designer@example.com",
		"compliance_status":       "needs_attention",
	} {
		if got := attrs[key]; got != want {
			t.Fatalf("Attributes[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestJoinedVulnerableAssetReferencesZipsFlatFields(t *testing.T) {
	raw := joinedVulnerableAssetReferences(map[string]any{
		"vulnerabilityIds":   []any{"CVE-2026-4242", "CVE-2026-4243"},
		"packageIdentifiers": []any{"pkg:golang/example/one@1.0.0", "pkg:golang/example/two@2.0.0"},
	})
	var refs []map[string]string
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		t.Fatalf("joinedVulnerableAssetReferences() produced invalid JSON: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("len(refs) = %d, want 2", len(refs))
	}
	if refs[0]["vulnerability_id"] != "CVE-2026-4242" || refs[0]["package_identifier"] != "pkg:golang/example/one@1.0.0" {
		t.Fatalf("refs[0] = %#v, want first vulnerability/package pair", refs[0])
	}
	if refs[1]["vulnerability_id"] != "CVE-2026-4243" || refs[1]["package_identifier"] != "pkg:golang/example/two@2.0.0" {
		t.Fatalf("refs[1] = %#v, want second vulnerability/package pair", refs[1])
	}
}

func TestCopyVulnerableAssetPlatformReferencesFlattensScannerTargets(t *testing.T) {
	attrs := map[string]string{}
	copyVulnerableAssetPlatformReferences(attrs, map[string]any{
		"id":        "vanta-asset-1",
		"name":      "ip-10-86-43-17.ec2.internal: i-0f359ce073424f8d6",
		"assetType": "SERVER",
		"scanners": []any{map[string]any{
			"resourceId":    "6a0af69035545f545841fe88",
			"integrationId": "aws",
			"targetId":      "arn:aws:ec2:us-east-1:381491964434:instance/i-0f359ce073424f8d6",
			"hostnames":     []any{"ip-10-86-43-17.ec2.internal"},
			"fqdns":         []any{"asset.writer.test"},
			"ipv4s":         []any{"10.86.43.17"},
			"ipv6s":         []any{"2001:db8::1"},
		}},
	})

	if got := attrs["integration_id"]; got != "" {
		t.Fatalf("integration_id = %q, want unset without top-level Vanta integration", got)
	}
	if got := attrs["platform_resource_id"]; got != "arn:aws:ec2:us-east-1:381491964434:instance/i-0f359ce073424f8d6" {
		t.Fatalf("platform_resource_id = %q, want EC2 ARN", got)
	}
	if got := attrs["platform_resource_type"]; got != "SERVER" {
		t.Fatalf("platform_resource_type = %q, want SERVER", got)
	}
	if got := attrs["hostname"]; got != "ip-10-86-43-17.ec2.internal" {
		t.Fatalf("hostname = %q, want scanner hostname", got)
	}
	if got := attrs["hostnames"]; got != "ip-10-86-43-17.ec2.internal,asset.writer.test" {
		t.Fatalf("hostnames = %q, want all scanner host fields", got)
	}
	if got := attrs["ip"]; got != "10.86.43.17" {
		t.Fatalf("ip = %q, want scanner IPv4", got)
	}
	if got := attrs["ip_addresses"]; got != "10.86.43.17,2001:db8::1" {
		t.Fatalf("ip_addresses = %q, want all scanner IP fields", got)
	}
	var refs []map[string]string
	if err := json.Unmarshal([]byte(attrs["platform_asset_refs"]), &refs); err != nil {
		t.Fatalf("platform_asset_refs is invalid JSON: %v", err)
	}
	if len(refs) != 1 || refs[0]["provider"] != "aws" || refs[0]["resource_id"] != "arn:aws:ec2:us-east-1:381491964434:instance/i-0f359ce073424f8d6" {
		t.Fatalf("platform_asset_refs = %#v, want AWS EC2 resource ref", refs)
	}
	if refs[0]["hostnames"] != "ip-10-86-43-17.ec2.internal,asset.writer.test" || refs[0]["ips"] != "10.86.43.17,2001:db8::1" {
		t.Fatalf("platform_asset_refs network fields = %#v, want all scanner host/IP fields", refs[0])
	}
}

func TestJoinedVulnerableAssetReferencesMergesFlatPackages(t *testing.T) {
	raw := joinedVulnerableAssetReferences(map[string]any{
		"vulnerabilities":    []any{map[string]any{"id": "CVE-2026-4242"}, map[string]any{"id": "CVE-2026-4243"}},
		"packageIdentifiers": []any{"pkg:golang/example/one@1.0.0", "pkg:golang/example/two@2.0.0"},
	})
	var refs []map[string]string
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		t.Fatalf("joinedVulnerableAssetReferences() produced invalid JSON: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("len(refs) = %d, want 2", len(refs))
	}
	if refs[0]["vulnerability_id"] != "CVE-2026-4242" || refs[0]["package_identifier"] != "pkg:golang/example/one@1.0.0" {
		t.Fatalf("refs[0] = %#v, want merged first pair", refs[0])
	}
	if refs[1]["vulnerability_id"] != "CVE-2026-4243" || refs[1]["package_identifier"] != "pkg:golang/example/two@2.0.0" {
		t.Fatalf("refs[1] = %#v, want merged second pair", refs[1])
	}
}

func TestJoinedVulnerableAssetReferencesAppendsTrailingFlatTuples(t *testing.T) {
	raw := joinedVulnerableAssetReferences(map[string]any{
		"vulnerabilities":    []any{map[string]any{"id": "CVE-2026-4242"}},
		"vulnerabilityIds":   []any{"CVE-2026-4242", "CVE-2026-4243"},
		"packageIdentifiers": []any{"pkg:golang/example/one@1.0.0", "pkg:golang/example/two@2.0.0"},
	})
	var refs []map[string]string
	if err := json.Unmarshal([]byte(raw), &refs); err != nil {
		t.Fatalf("joinedVulnerableAssetReferences() produced invalid JSON: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("len(refs) = %d, want 2", len(refs))
	}
	if refs[1]["vulnerability_id"] != "CVE-2026-4243" || refs[1]["package_identifier"] != "pkg:golang/example/two@2.0.0" {
		t.Fatalf("refs[1] = %#v, want trailing flat pair", refs[1])
	}
}

func TestVulnerableAssetRecordIDUsesAssetID(t *testing.T) {
	first := recordID(familyVulnerableAsset, map[string]any{
		"assetId":      "asset-1",
		"lastSeenDate": "2026-05-11T00:00:00Z",
	}, json.RawMessage(`{"assetId":"asset-1","lastSeenDate":"2026-05-11T00:00:00Z"}`))
	second := recordID(familyVulnerableAsset, map[string]any{
		"assetId":      "asset-1",
		"lastSeenDate": "2026-05-12T00:00:00Z",
	}, json.RawMessage(`{"assetId":"asset-1","lastSeenDate":"2026-05-12T00:00:00Z"}`))
	if first != "asset-1" || second != "asset-1" {
		t.Fatalf("record IDs = %q and %q, want stable asset-1", first, second)
	}
}

func TestTokenCacheScopesRuntimeSecretsAndBaseURL(t *testing.T) {
	tokenRequests := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode token request: %v", err)
			}
			secret := payload["client_secret"]
			tokenRequests[secret]++
			writeJSON(t, w, map[string]any{
				"access_token": "token-for-" + secret,
				"expires_in":   3599,
				"token_type":   "Bearer",
			})
		case "/tenant-a/v1/vendors":
			if got := r.Header.Get("Authorization"); got != "Bearer token-for-secret-a" {
				t.Fatalf("tenant-a Authorization = %q, want token for secret-a", got)
			}
			writePage(t, w, false, "", []map[string]any{{"id": "vendor-a", "name": "Tenant A"}})
		case "/tenant-b/v1/vendors":
			if got := r.Header.Get("Authorization"); got != "Bearer token-for-secret-b" {
				t.Fatalf("tenant-b Authorization = %q, want token for secret-b", got)
			}
			writePage(t, w, false, "", []map[string]any{{"id": "vendor-b", "name": "Tenant B"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfgA := tokenCacheTestConfig(server.URL, "/tenant-a", "secret-a")
	cfgB := tokenCacheTestConfig(server.URL, "/tenant-b", "secret-b")
	if _, err := source.Read(context.Background(), cfgA, nil); err != nil {
		t.Fatalf("Read(tenant-a) error = %v", err)
	}
	if _, err := source.Read(context.Background(), cfgB, nil); err != nil {
		t.Fatalf("Read(tenant-b) error = %v", err)
	}
	if got := tokenRequests["secret-a"]; got != 1 {
		t.Fatalf("secret-a token requests = %d, want 1", got)
	}
	if got := tokenRequests["secret-b"]; got != 1 {
		t.Fatalf("secret-b token requests = %d, want 1", got)
	}
}

func TestTokenCacheReusesTokenAcrossFamilies(t *testing.T) {
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenRequests++
			writeJSON(t, w, map[string]any{
				"access_token": "shared-token",
				"expires_in":   3599,
				"token_type":   "Bearer",
			})
		case "/v1/controls", "/v1/vendors":
			if got := r.Header.Get("Authorization"); got != "Bearer shared-token" {
				t.Fatalf("Authorization = %q, want shared token", got)
			}
			writePage(t, w, false, "", []map[string]any{{"id": "record-1", "name": "Record"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfgControl := testConfig(server.URL, familyControl)
	cfgVendor := testConfig(server.URL, familyVendor)
	if _, err := source.Read(context.Background(), cfgControl, nil); err != nil {
		t.Fatalf("Read(control) error = %v", err)
	}
	if _, err := source.Read(context.Background(), cfgVendor, nil); err != nil {
		t.Fatalf("Read(vendor) error = %v", err)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want 1", tokenRequests)
	}
}

func TestReadRefreshesTokenAfterUnauthorizedPage(t *testing.T) {
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenRequests++
			token := "token-1"
			if tokenRequests == 2 {
				token = "token-2"
			}
			writeJSON(t, w, map[string]any{
				"access_token": token,
				"expires_in":   3599,
				"token_type":   "Bearer",
			})
		case "/v1/vendors":
			cursor := r.URL.Query().Get("pageCursor")
			switch cursor {
			case "":
				if got := r.Header.Get("Authorization"); got != "Bearer token-1" {
					t.Fatalf("first page Authorization = %q, want token-1", got)
				}
				writePage(t, w, true, "cursor-2", []map[string]any{{"id": "vendor-1", "name": "Acme SaaS"}})
			case "cursor-2":
				switch got := r.Header.Get("Authorization"); got {
				case "Bearer token-1":
					http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
				case "Bearer token-2":
					writePage(t, w, false, "", []map[string]any{{"id": "vendor-2", "name": "Beta SaaS"}})
				default:
					t.Fatalf("second page Authorization = %q, want token-1 retry then token-2", got)
				}
			default:
				t.Fatalf("unexpected pageCursor = %q", cursor)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	cfg := testConfig(server.URL, familyVendor)
	first, err := source.Read(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("Read(first page) error = %v", err)
	}
	if first.NextCursor == nil {
		t.Fatalf("Read(first page).NextCursor is nil")
	}
	second, err := source.Read(context.Background(), cfg, first.NextCursor)
	if err != nil {
		t.Fatalf("Read(second page) error = %v", err)
	}
	if len(second.Events) != 1 {
		t.Fatalf("len(Read(second page).Events) = %d, want 1", len(second.Events))
	}
	if tokenRequests != 2 {
		t.Fatalf("token requests = %d, want 2", tokenRequests)
	}
}

func TestTokenRequestRetriesRateLimit(t *testing.T) {
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			tokenRequests++
			if tokenRequests < 3 {
				http.Error(w, `{"error":"Too Many Requests"}`, http.StatusTooManyRequests)
				return
			}
			writeJSON(t, w, map[string]any{
				"access_token": "retry-token",
				"expires_in":   3599,
				"token_type":   "Bearer",
			})
		case "/v1/vendors":
			if got := r.Header.Get("Authorization"); got != "Bearer retry-token" {
				t.Fatalf("Authorization = %q, want retry-token", got)
			}
			writePage(t, w, false, "", []map[string]any{{"id": "vendor-1", "name": "Acme SaaS"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	source.allowLoopbackBaseURL = true
	source.tokenRetryBackoffs = []time.Duration{0, 0}
	pull, err := source.Read(context.Background(), testConfig(server.URL, familyVendor), nil)
	if err != nil {
		t.Fatalf("Read(vendor) error = %v", err)
	}
	if len(pull.Events) != 1 {
		t.Fatalf("len(Read(vendor).Events) = %d, want 1", len(pull.Events))
	}
	if tokenRequests != 3 {
		t.Fatalf("token requests = %d, want 3", tokenRequests)
	}
}

func testConfig(baseURL string, family string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"base_url":      baseURL,
		"client_id":     testClientID,
		"client_secret": testClientSecret,
		"family":        family,
		"per_page":      "1",
		"provider":      "vanta",
		"tenant_id":     "writer",
	})
}

func tokenCacheTestConfig(baseURL string, basePath string, clientSecret string) sourcecdk.Config {
	return sourcecdk.NewConfig(map[string]string{
		"base_url":      baseURL + basePath,
		"client_id":     testClientID,
		"client_secret": clientSecret,
		"family":        familyVendor,
		"per_page":      "1",
		"provider":      "vanta",
		"tenant_id":     "writer",
		"token_url":     baseURL + "/oauth/token",
	})
}

func newTestAPIHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			if r.Method != http.MethodPost {
				t.Fatalf("token method = %s, want POST", r.Method)
			}
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode token request: %v", err)
			}
			if payload["client_id"] != testClientID || payload["client_secret"] != testClientSecret {
				t.Fatalf("unexpected token credentials: %#v", payload)
			}
			writeJSON(t, w, map[string]any{
				"access_token": "test-token",
				"expires_in":   3599,
				"token_type":   "Bearer",
			})
		case "/v1/vendors":
			requireBearer(t, r)
			if r.URL.Query().Get("pageCursor") == "cursor-2" {
				writePage(t, w, false, "", []map[string]any{{
					"id":                               "vendor-2",
					"name":                             "Beta SaaS",
					"status":                           "APPROVED",
					"residualRiskLevel":                "LOW",
					"lastSecurityReviewCompletionDate": "2026-02-01T00:00:00Z",
				}})
				return
			}
			writePage(t, w, true, "cursor-2", []map[string]any{{
				"id":                               "vendor-1",
				"name":                             "Acme SaaS",
				"websiteUrl":                       "https://acme.example",
				"securityOwnerUserId":              "user-1",
				"status":                           "IN_REVIEW",
				"inherentRiskLevel":                "HIGH",
				"residualRiskLevel":                "MEDIUM",
				"nextSecurityReviewDueDate":        "2026-06-01T00:00:00Z",
				"lastSecurityReviewCompletionDate": "2025-06-01T00:00:00Z",
				"category":                         map[string]any{"displayName": "ai"},
			}})
		case "/v1/people":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":           "person-1",
				"userId":       "user-1",
				"emailAddress": "designer@example.com",
				"employment": map[string]any{
					"department":     "Design",
					"employeeNumber": "E-1001",
					"jobTitle":       "Product Designer",
					"manager":        "manager@example.com",
					"managerId":      "person-manager",
					"status":         "CURRENT",
				},
			}})
		case "/v1/vulnerabilities":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":                "vuln-1",
				"name":              "CVE-2026-4242",
				"packageIdentifier": "pkg:golang/example/module@1.2.3",
				"severity":          "HIGH",
				"cvssSeverityScore": 8.7,
				"targetId":          "target-1",
				"integrationId":     "integration-1",
				"isFixable":         true,
				"remediateByDate":   "2026-05-30T00:00:00Z",
				"lastDetectedDate":  "2026-05-10T00:00:00Z",
			}})
		case "/v1/vulnerable-assets":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":            "target-1",
				"displayName":   "App Server",
				"hostname":      "app.writer.com",
				"ipAddress":     "203.0.113.10",
				"url":           "https://app.writer.com",
				"assetType":     "server",
				"integrationId": "integration-1",
				"vulnerabilities": []map[string]any{{
					"id":                "CVE-2026-4242",
					"name":              "CVE-2026-4242",
					"packageIdentifier": "pkg:golang/example/module@1.2.3",
				}},
				"lastSeenDate": "2026-05-11T00:00:00Z",
			}})
		case "/v1/monitored-computers":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":                    "computer-1",
				"integrationId":         "kandji",
				"lastCheckDate":         "2026-06-24T17:00:00Z",
				"screenlock":            map[string]any{"outcome": "OK"},
				"diskEncryption":        map[string]any{"outcome": "OK"},
				"passwordManager":       map[string]any{"outcome": "NEEDS_ATTENTION"},
				"antivirusInstallation": map[string]any{"outcome": "OK"},
				"operatingSystem":       map[string]any{"type": "MACOS", "version": "15.5"},
				"owner":                 map[string]any{"id": "person-1", "displayName": "Designer One", "emailAddress": "designer@example.com"},
				"serialNumber":          "serial-1",
				"udid":                  "udid-1",
			}})
		case "/v1/tests":
			requireBearer(t, r)
			writePage(t, w, false, "", []map[string]any{{
				"id":     "test-1",
				"name":   "Control test 1",
				"status": "FAIL",
				"controls": []map[string]any{
					{"id": "control-1", "externalId": "CC6.2", "name": "Logical access"},
					{"id": "control-2", "externalId": "CC7.1", "name": "Monitoring"},
				},
			}})
		default:
			http.NotFound(w, r)
		}
	})
}

func requireBearer(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want bearer token", got)
	}
}

func writePage(t *testing.T, w http.ResponseWriter, hasNext bool, endCursor string, data []map[string]any) {
	t.Helper()
	writeJSON(t, w, map[string]any{
		"results": map[string]any{
			"pageInfo": map[string]any{
				"endCursor":   endCursor,
				"hasNextPage": hasNext,
			},
			"data": data,
		},
	})
}

func writeJSON(t *testing.T, w http.ResponseWriter, payload any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
