package dspm

import (
	"context"
	"testing"
)

func TestMetadataFetcher_FetchSample(t *testing.T) {
	fetcher := NewMetadataFetcher()
	target := &ScanTarget{
		ID:          "bucket-1",
		Type:        "s3_bucket",
		Provider:    "aws",
		Name:        "prod-bucket",
		IsPublic:    true,
		IsEncrypted: false,
		Properties: map[string]any{
			"owner": "security@example.com",
		},
	}

	samples, err := fetcher.FetchSample(context.Background(), target, 4096)
	if err != nil {
		t.Fatalf("FetchSample returned error: %v", err)
	}
	if len(samples) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(samples))
	}
	if samples[0].Size == 0 {
		t.Fatal("expected non-empty metadata sample")
	}
	if len(samples[0].Data) == 0 {
		t.Fatal("expected sample data bytes")
	}
}

func TestMetadataFetcher_ListObjects(t *testing.T) {
	fetcher := NewMetadataFetcher()
	target := &ScanTarget{
		ID:   "bucket-1",
		Name: "prod-bucket",
	}

	objects, err := fetcher.ListObjects(context.Background(), target, 10)
	if err != nil {
		t.Fatalf("ListObjects returned error: %v", err)
	}
	if len(objects) != 1 {
		t.Fatalf("expected 1 object, got %d", len(objects))
	}
	if objects[0].Key != "prod-bucket" {
		t.Fatalf("expected object key prod-bucket, got %s", objects[0].Key)
	}
}
