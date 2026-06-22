package findingmemory

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/writer/cerebro/internal/ports"
)

func TestHashEmbedderProducesNormalizedStableVectors(t *testing.T) {
	embedder := HashEmbedder{Dimensions: 16}
	left, err := embedder.EmbedText(context.Background(), "privileged identity missing mfa")
	if err != nil {
		t.Fatal(err)
	}
	right, err := embedder.EmbedText(context.Background(), "privileged identity missing mfa")
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 16 || len(right) != 16 {
		t.Fatalf("vector dims = %d/%d, want 16", len(left), len(right))
	}
	if score := CosineSimilarity(left, right); score < 0.99 {
		t.Fatalf("self similarity = %.4f, want near 1", score)
	}
}

func TestMemoryFromFindingBuildsTenantScopedRecord(t *testing.T) {
	finding := &ports.FindingRecord{
		ID:           "finding-1",
		TenantID:     "tenant-a",
		RuleID:       "identity-risk",
		Fingerprint:  "fp-1",
		Title:        "Privileged identity without MFA",
		Summary:      "A privileged account lacks MFA.",
		Status:       "open",
		Severity:     "high",
		FindingRisk:  ports.FindingRisk{ConfidenceScore: 80},
		ResourceURNs: []string{"urn:cerebro:tenant-a:identity:user:alice"},
		EventIDs:     []string{"event-1"},
		Attributes:   map[string]string{"primary_resource_urn": "urn:cerebro:tenant-a:identity:user:alice"},
	}
	record, err := MemoryFromFinding(context.Background(), HashEmbedder{Dimensions: 8}, finding, TypePriorInvestigation, "", time.Unix(10, 0))
	if err != nil {
		t.Fatalf("MemoryFromFinding() error = %v", err)
	}
	if record.TenantID != "tenant-a" || record.Type != TypePriorInvestigation || record.FindingID != "finding-1" {
		t.Fatalf("record = %#v", record)
	}
	if record.SourceURN != "urn:cerebro:tenant-a:identity:user:alice" {
		t.Fatalf("source urn = %q", record.SourceURN)
	}
	if len(record.Embedding) != 8 {
		t.Fatalf("embedding dims = %d, want 8", len(record.Embedding))
	}
	if record.Confidence != 0.8 {
		t.Fatalf("confidence = %v, want 0.8", record.Confidence)
	}
}

func TestTruncateKeepsValidUTF8AtRuneBoundary(t *testing.T) {
	// Each "é" is two bytes, so cutting at byte 11 lands mid-rune.
	value := strings.Repeat("é", 100)
	got := truncate(value, 11)
	if !utf8.ValidString(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
	if len(got) > 11 {
		t.Fatalf("truncate returned %d bytes, want <= 11", len(got))
	}
	if want := strings.Repeat("é", 5); got != want {
		t.Fatalf("truncate = %q, want %q", got, want)
	}
}
