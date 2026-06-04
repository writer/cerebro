package trustedendpoint

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func TestSourceSpecDeclaresTrustedEndpointSource(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	spec := source.Spec()
	if spec.GetId() != "trusted_endpoint" {
		t.Fatalf("Spec().Id = %q, want trusted_endpoint", spec.GetId())
	}
	if len(spec.GetEmittedKinds()) == 0 {
		t.Fatal("Spec().EmittedKinds is empty")
	}
}

func TestSourceCheckValidatesIntegrationMarker(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	for _, integration := range []string{"", "trusted-endpoint", "trusted_endpoint"} {
		t.Run("integration="+integration, func(t *testing.T) {
			err := source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
				"integration": integration,
			}))
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
		})
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{
		"integration": "jira",
	}))
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("Check() error = %v, want ErrInvalidConfig", err)
	}
}

func TestSourceReadAndDiscoverReturnEmptyResults(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	urns, err := source.Discover(context.Background(), sourcecdk.NewConfig(nil))
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(urns) != 0 {
		t.Fatalf("len(Discover()) = %d, want 0", len(urns))
	}
	pull, err := source.Read(context.Background(), sourcecdk.NewConfig(nil), nil)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if len(pull.Events) != 0 {
		t.Fatalf("len(Read().Events) = %d, want 0", len(pull.Events))
	}
}
