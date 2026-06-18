package catalogruntime

import (
	"testing"

	"github.com/writer/cerebro/internal/connectordefinitions"
)

func TestNewDefinition(t *testing.T) {
	source, err := NewDefinition(connectordefinitions.Definition{
		ID:          "tenant-example",
		TenantID:    "tenant",
		SourceID:    "example",
		DisplayName: "Example",
		Auth:        connectordefinitions.AuthSpec{Model: "bearer_token"},
		Transport:   &connectordefinitions.TransportSpec{BaseURL: "https://example.com"},
		ResourceFamilies: []connectordefinitions.ResourceFamily{{
			ID:             "users",
			Path:           "/users",
			RecordSelector: "$.data[*]",
			IDField:        "id",
			Projection:     &connectordefinitions.ProjectionSpec{Template: "identity_user"},
		}},
	})
	if err != nil {
		t.Fatalf("NewDefinition() error = %v", err)
	}
	if source.Spec().Id != "example" {
		t.Fatalf("Spec().Id = %q", source.Spec().Id)
	}
}
