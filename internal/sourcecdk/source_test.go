package sourcecdk

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

type stubSource struct {
	spec *cerebrov1.SourceSpec
}

func (s stubSource) Spec() *cerebrov1.SourceSpec { return s.spec }

func (s stubSource) Check(context.Context, Config) error { return nil }

func (s stubSource) Discover(context.Context, Config) ([]URN, error) {
	return []URN{"urn:cerebro:tenant:user:123"}, nil
}

func (s stubSource) Read(context.Context, Config, *cerebrov1.SourceCursor) (Pull, error) {
	return Pull{}, nil
}

func TestParseURN(t *testing.T) {
	urn, err := ParseURN("urn:cerebro:tenant:user:123")
	if err != nil {
		t.Fatalf("ParseURN() error = %v", err)
	}
	if urn.String() != "urn:cerebro:tenant:user:123" {
		t.Fatalf("URN = %q, want %q", urn.String(), "urn:cerebro:tenant:user:123")
	}
}

func TestParseURNRejectsInvalidValue(t *testing.T) {
	for _, value := range []string{
		"user:123",
		"urn:cerebro:",
		"urn:cerebro:tenant::id",
		"urn:cerebro:tenant:user:",
		"urn:cerebro:tenant:user:id:extra",
	} {
		if _, err := ParseURN(value); err == nil {
			t.Fatalf("ParseURN(%q) error = nil, want non-nil", value)
		}
	}
}

func TestConfigClonesValues(t *testing.T) {
	cfg := NewConfig(map[string]string{"token": "abc"})
	values := cfg.Values()
	values["token"] = "mutated"

	if got, _ := cfg.Lookup("token"); got != "abc" {
		t.Fatalf("Lookup(token) = %q, want %q", got, "abc")
	}
}

func TestRegistryIndexesSources(t *testing.T) {
	registry, err := NewRegistry(
		stubSource{spec: &cerebrov1.SourceSpec{Id: "github", Name: "GitHub"}},
		stubSource{spec: &cerebrov1.SourceSpec{Id: "okta", Name: "Okta"}},
	)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	if _, ok := registry.Get("github"); !ok {
		t.Fatal("Get(github) = false, want true")
	}
	specs := registry.List()
	if len(specs) != 2 {
		t.Fatalf("len(List()) = %d, want 2", len(specs))
	}
	if specs[0].Id != "github" || specs[1].Id != "okta" {
		t.Fatalf("List() ids = %q, %q; want github, okta", specs[0].Id, specs[1].Id)
	}
}

func TestRegistryRejectsDuplicateIDs(t *testing.T) {
	_, err := NewRegistry(
		stubSource{spec: &cerebrov1.SourceSpec{Id: "github"}},
		stubSource{spec: &cerebrov1.SourceSpec{Id: "github"}},
	)
	if err == nil {
		t.Fatal("NewRegistry() error = nil, want non-nil")
	}
}

func TestRegistryRejectsNonCanonicalIDs(t *testing.T) {
	_, err := NewRegistry(stubSource{spec: &cerebrov1.SourceSpec{Id: " github "}})
	if err == nil {
		t.Fatal("NewRegistry() error = nil, want non-nil")
	}
}
