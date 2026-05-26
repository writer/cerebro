package findings

import (
	"context"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestDataSensitiveAssetRiskRule(t *testing.T) {
	rule := newDataSensitiveAssetRiskRule()
	runtime := &cerebrov1.SourceRuntime{Id: "asset-runtime", SourceId: "asset", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "asset-crown-jewel",
		TenantId: "writer",
		SourceId: "asset",
		Kind:     "asset.crown_jewel",
		Attributes: map[string]string{
			"contains_secrets":    "true",
			"crown_jewel":         "true",
			"data_classification": "restricted",
			"internet_exposed":    "true",
			"resource_id":         "prod-secrets",
			"resource_name":       "Production Secrets",
			"resource_type":       "secret_store",
			"source_provider":     "aws",
		},
	}
	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:writer:aws_secret_store:prod-secrets")

	internal := &cerebrov1.EventEnvelope{Id: "asset-internal-sensitive", TenantId: "writer", SourceId: "asset", Kind: "asset.data_sensitivity", Attributes: map[string]string{"data_classification": "restricted", "resource_id": "internal-db", "resource_type": "database", "source_provider": "aws"}}
	records, err = rule.Evaluate(context.Background(), runtime, internal)
	if err != nil {
		t.Fatalf("Evaluate(internal) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(internal records) = %d, want 0", len(records))
	}

	unrestricted := &cerebrov1.EventEnvelope{Id: "asset-unrestricted", TenantId: "writer", SourceId: "asset", Kind: "asset.data_sensitivity", Attributes: map[string]string{"data_classification": "unrestricted", "internet_exposed": "true", "resource_id": "public-docs", "resource_type": "bucket", "source_provider": "aws"}}
	records, err = rule.Evaluate(context.Background(), runtime, unrestricted)
	if err != nil {
		t.Fatalf("Evaluate(unrestricted) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(unrestricted records) = %d, want 0", len(records))
	}

	notSensitive := &cerebrov1.EventEnvelope{Id: "asset-not-sensitive", TenantId: "writer", SourceId: "asset", Kind: "asset.data_sensitivity", Attributes: map[string]string{"data_classification": "not_sensitive", "public": "true", "resource_id": "public-docs", "resource_type": "bucket", "source_provider": "aws"}}
	records, err = rule.Evaluate(context.Background(), runtime, notSensitive)
	if err != nil {
		t.Fatalf("Evaluate(notSensitive) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(notSensitive records) = %d, want 0", len(records))
	}
}

func TestDataSignalRule_PrimaryResourceURNIsAsset(t *testing.T) {
	rule := newDataSensitiveAssetRiskRule()
	runtime := &cerebrov1.SourceRuntime{Id: "asset-runtime", SourceId: "asset", TenantId: "writer"}
	event := &cerebrov1.EventEnvelope{
		Id:       "asset-classification-first",
		TenantId: "writer",
		SourceId: "asset",
		Kind:     "asset.crown_jewel",
		Attributes: map[string]string{
			"contains_secrets":    "true",
			"crown_jewel":         "true",
			"data_classification": "restricted",
			"internet_exposed":    "true",
			"owner":               "security",
			"resource_id":         "prod-secrets",
			"resource_name":       "Production Secrets",
			"resource_type":       "secret_store",
			"source_provider":     "aws",
		},
	}

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d, want 1", len(records))
	}
	wantAssetURN := "urn:cerebro:writer:aws_secret_store:prod-secrets"
	if got := records[0].Attributes["asset_urn"]; got != wantAssetURN {
		t.Fatalf("asset_urn = %q, want %q", got, wantAssetURN)
	}
	if got := records[0].Attributes["primary_resource_urn"]; got != wantAssetURN {
		t.Fatalf("primary_resource_urn = %q, want asset URN %q", got, wantAssetURN)
	}
}

func TestDataSensitiveAssetRisk(t *testing.T) {
	rule := newDataSensitiveAssetRiskRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorGraphAnchored {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorGraphAnchored)
	}
	if len(definition.FingerprintFields) != 1 || definition.FingerprintFields[0] != "asset_urn" {
		t.Fatalf("FingerprintFields = %v, want [asset_urn]", definition.FingerprintFields)
	}
	for _, field := range definition.FingerprintFields {
		if field == "event_id" || field == "matched_at" {
			t.Fatalf("FingerprintFields = %v, must not include event_id or matched_at", definition.FingerprintFields)
		}
	}
	runtime := &cerebrov1.SourceRuntime{Id: "asset-runtime", SourceId: "asset", TenantId: "writer"}
	attrs := map[string]string{
		"contains_secrets":    "true",
		"crown_jewel":         "true",
		"data_classification": "restricted",
		"internet_exposed":    "true",
		"resource_id":         "prod-secrets",
		"resource_name":       "Production Secrets",
		"resource_type":       "secret_store",
		"source_provider":     "aws",
	}
	first := &cerebrov1.EventEnvelope{Id: "asset-first", TenantId: "writer", SourceId: "asset", Kind: "asset.crown_jewel", Attributes: attrs}
	second := &cerebrov1.EventEnvelope{Id: "asset-second", TenantId: "writer", SourceId: "asset", Kind: "asset.crown_jewel", Attributes: attrs}
	records, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(first) = (%v, %v)", records, err)
	}
	firstFinding := records[0]
	records, err = rule.Evaluate(context.Background(), runtime, second)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(second) = (%v, %v)", records, err)
	}
	secondFinding := records[0]
	if firstFinding.Fingerprint != secondFinding.Fingerprint {
		t.Fatalf("fingerprints differ across replays: %q vs %q (should be anchored to asset_urn)", firstFinding.Fingerprint, secondFinding.Fingerprint)
	}
	if strings.Contains(firstFinding.Fingerprint, first.GetId()) {
		t.Fatalf("fingerprint %q contains event id %q", firstFinding.Fingerprint, first.GetId())
	}
	if got := firstFinding.Attributes["asset_urn"]; got == "" {
		t.Fatalf("attributes[asset_urn] = empty, want non-empty URN")
	}

	sensitiveOnly := &cerebrov1.EventEnvelope{Id: "asset-sensitive-only", TenantId: "writer", SourceId: "asset", Kind: "asset.data_sensitivity", Attributes: map[string]string{
		"data_classification": "restricted",
		"resource_id":         "prod-secrets",
		"resource_type":       "secret_store",
		"source_provider":     "aws",
	}}
	records, err = rule.Evaluate(context.Background(), runtime, sensitiveOnly)
	if err != nil {
		t.Fatalf("Evaluate(sensitiveOnly) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(sensitiveOnly) returned %d findings, want 0 when neither public nor privileged_access", len(records))
	}

	exposedOnly := &cerebrov1.EventEnvelope{Id: "asset-exposed-only", TenantId: "writer", SourceId: "asset", Kind: "asset.data_sensitivity", Attributes: map[string]string{
		"data_classification": "public",
		"internet_exposed":    "true",
		"resource_id":         "public-docs",
		"resource_type":       "bucket",
		"source_provider":     "aws",
	}}
	records, err = rule.Evaluate(context.Background(), runtime, exposedOnly)
	if err != nil {
		t.Fatalf("Evaluate(exposedOnly) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(exposedOnly) returned %d findings, want 0 when not sensitive", len(records))
	}

	privilegedOnly := &cerebrov1.EventEnvelope{Id: "asset-privileged", TenantId: "writer", SourceId: "asset", Kind: "asset.crown_jewel", Attributes: map[string]string{
		"contains_secrets":    "true",
		"crown_jewel":         "true",
		"data_classification": "restricted",
		"privileged_access":   "true",
		"resource_id":         "prod-secrets-2",
		"resource_type":       "secret_store",
		"source_provider":     "aws",
	}}
	records, err = rule.Evaluate(context.Background(), runtime, privilegedOnly)
	if err != nil || len(records) != 1 {
		t.Fatalf("Evaluate(privilegedOnly) = (%v, %v), want one finding with privileged_access", records, err)
	}
}
