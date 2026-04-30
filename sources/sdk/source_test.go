package sdk

import (
	"context"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceCheckRequiresIntegration(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(nil)); err == nil {
		t.Fatal("Check() error = nil, want non-nil")
	}
	if err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"integration": "jira"})); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
}

func TestSourceReadAndDiscoverReturnEmptyResults(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(map[string]string{"integration": "jira"}))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 0 {
		t.Fatalf("len(Discover()) = %d, want 0", len(urns))
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(map[string]string{"integration": "jira"}), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Read().Events) = %d, want 0", len(pull.Events))
	}
}
