package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestDataSensitiveAssetRiskRule(t *testing.T) {
	rule := newDataSensitiveAssetRiskRule()
	runtime := &cerebrov1.SourceRuntime{Id: "asset-runtime", SourceId: "asset", TenantId: "example"}
	event := &cerebrov1.EventEnvelope{
		Id:       "asset-crown-jewel",
		TenantId: "example",
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
	assertFindingResourceURN(t, records[0].ResourceURNs, "urn:cerebro:example:aws_secret_store:prod-secrets")

	internal := &cerebrov1.EventEnvelope{Id: "asset-internal-sensitive", TenantId: "example", SourceId: "asset", Kind: "asset.data_sensitivity", Attributes: map[string]string{"data_classification": "restricted", "resource_id": "internal-db", "resource_type": "database", "source_provider": "aws"}}
	records, err = rule.Evaluate(context.Background(), runtime, internal)
	if err != nil {
		t.Fatalf("Evaluate(internal) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(internal records) = %d, want 0", len(records))
	}

	unrestricted := &cerebrov1.EventEnvelope{Id: "asset-unrestricted", TenantId: "example", SourceId: "asset", Kind: "asset.data_sensitivity", Attributes: map[string]string{"data_classification": "unrestricted", "internet_exposed": "true", "resource_id": "public-docs", "resource_type": "bucket", "source_provider": "aws"}}
	records, err = rule.Evaluate(context.Background(), runtime, unrestricted)
	if err != nil {
		t.Fatalf("Evaluate(unrestricted) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(unrestricted records) = %d, want 0", len(records))
	}

	notSensitive := &cerebrov1.EventEnvelope{Id: "asset-not-sensitive", TenantId: "example", SourceId: "asset", Kind: "asset.data_sensitivity", Attributes: map[string]string{"data_classification": "not_sensitive", "public": "true", "resource_id": "public-docs", "resource_type": "bucket", "source_provider": "aws"}}
	records, err = rule.Evaluate(context.Background(), runtime, notSensitive)
	if err != nil {
		t.Fatalf("Evaluate(notSensitive) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("len(notSensitive records) = %d, want 0", len(records))
	}
}
