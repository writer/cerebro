package sdk

import (
	"context"
	"errors"
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

func TestSourceDiscoverReturnsDeclaredInventoryURNs(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := sourcecdk.NewConfig(map[string]string{
		"integration":    "jira",
		"inventory_urns": "urn:cerebro:local:runtime:local-sdk-demo:service:api, urn:cerebro:local:runtime:local-sdk-demo:queue:jobs\nurn:cerebro:local:runtime:local-sdk-demo:service:api",
	})
	if err := source.Check(context.Background(), cfg); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	urns, err := source.Discover(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if got, want := len(urns), 2; got != want {
		t.Fatalf("len(Discover()) = %d, want %d: %#v", got, want, urns)
	}
	if urns[0].String() != "urn:cerebro:local:runtime:local-sdk-demo:service:api" {
		t.Fatalf("urns[0] = %q", urns[0])
	}
	if urns[1].String() != "urn:cerebro:local:runtime:local-sdk-demo:queue:jobs" {
		t.Fatalf("urns[1] = %q", urns[1])
	}
}

func TestSourceCheckRejectsInvalidInventoryURN(t *testing.T) {
	source, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = source.Check(context.Background(), sourcecdk.NewConfig(map[string]string{"integration": "jira", "inventory_urns": "not-a-urn"}))
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("Check() error = %v, want ErrInvalidConfig", err)
	}
}
