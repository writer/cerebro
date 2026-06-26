package grc

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

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
