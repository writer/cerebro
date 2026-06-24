package grccatalog

import (
	"errors"
	"testing"
)

func TestCatalogIsNonEmptyAndWellFormed(t *testing.T) {
	sources := Catalog()
	if len(sources) == 0 {
		t.Fatal("catalog must not be empty")
	}
	seen := map[string]struct{}{}
	for _, source := range sources {
		if source.ID == "" || source.Path == "" || source.Method == "" {
			t.Fatalf("source %+v missing id, path, or method", source)
		}
		if _, ok := seen[source.ID]; ok {
			t.Fatalf("duplicate source id %q", source.ID)
		}
		seen[source.ID] = struct{}{}
		if _, ok := Lookup(source.ID); !ok {
			t.Fatalf("Lookup(%q) failed for catalogued source", source.ID)
		}
	}
}

func TestValidateWidgetQueryRejectsUnknownSource(t *testing.T) {
	err := ValidateWidgetQuery(WidgetQuery{SourceID: "does-not-exist"})
	if !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("error = %v, want ErrUnknownSource", err)
	}
}

func TestValidateWidgetQueryRejectsUnknownParameter(t *testing.T) {
	err := ValidateWidgetQuery(WidgetQuery{SourceID: "findings", Params: map[string]string{"not_a_param": "x"}})
	if !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("error = %v, want ErrInvalidQuery", err)
	}
}

func TestValidateWidgetQueryEnforcesEnum(t *testing.T) {
	if err := ValidateWidgetQuery(WidgetQuery{SourceID: "trends", Params: map[string]string{"interval": "fortnight"}}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("bad interval error = %v, want ErrInvalidQuery", err)
	}
	if err := ValidateWidgetQuery(WidgetQuery{SourceID: "trends", Params: map[string]string{"interval": "week"}}); err != nil {
		t.Fatalf("valid interval rejected: %v", err)
	}
}

func TestValidateWidgetQueryEnforcesTypes(t *testing.T) {
	if err := ValidateWidgetQuery(WidgetQuery{SourceID: "findings", Params: map[string]string{"age_min_days": "soon"}}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("bad int error = %v, want ErrInvalidQuery", err)
	}
	if err := ValidateWidgetQuery(WidgetQuery{SourceID: "trends", Params: map[string]string{"compare": "maybe"}}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("bad bool error = %v, want ErrInvalidQuery", err)
	}
}

func TestValidateWidgetQueryEnforcesLimit(t *testing.T) {
	if err := ValidateWidgetQuery(WidgetQuery{SourceID: "findings", Limit: MaxLimit + 1}); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("over-limit error = %v, want ErrInvalidQuery", err)
	}
}

// TestCatalogAdvertisesOnlyHonoredParams locks in that the catalog never
// declares a parameter the backing GRC handler ignores: controls hardcodes
// status=open, control-coverage only reads profile, and the inventory reads
// honor source_id but not runtime selection.
func TestCatalogAdvertisesOnlyHonoredParams(t *testing.T) {
	accepted := []struct {
		name  string
		query WidgetQuery
	}{
		{name: "control-coverage profile", query: WidgetQuery{SourceID: "control-coverage", Params: map[string]string{"profile": "soc2"}}},
		{name: "inventory-categories source_id", query: WidgetQuery{SourceID: "inventory-categories", Params: map[string]string{"source_id": "aws"}}},
		{name: "inventory-assets filters", query: WidgetQuery{SourceID: "inventory-assets", Params: map[string]string{"source_id": "aws", "category_id": "compute", "q": "db", "scope_state": "in_scope"}}},
	}
	for _, tc := range accepted {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			if err := ValidateWidgetQuery(tc.query); err != nil {
				t.Fatalf("honored query rejected: %v", err)
			}
		})
	}

	rejected := []struct {
		name  string
		query WidgetQuery
	}{
		{name: "controls status (hardcoded open)", query: WidgetQuery{SourceID: "controls", Params: map[string]string{"status": "closed"}}},
		{name: "control-coverage runtime scope", query: WidgetQuery{SourceID: "control-coverage", Params: map[string]string{"runtime_id": "rt-1"}}},
		{name: "inventory-categories runtime scope", query: WidgetQuery{SourceID: "inventory-categories", Params: map[string]string{"runtime_id": "rt-1"}}},
		{name: "inventory-assets runtime scope", query: WidgetQuery{SourceID: "inventory-assets", Params: map[string]string{"runtime_ids": "rt-1,rt-2"}}},
	}
	for _, tc := range rejected {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			if err := ValidateWidgetQuery(tc.query); !errors.Is(err, ErrInvalidQuery) {
				t.Fatalf("error = %v, want ErrInvalidQuery for unsupported param", err)
			}
		})
	}
}

func TestValidateWidgetQueryAcceptsBoundedQuery(t *testing.T) {
	err := ValidateWidgetQuery(WidgetQuery{
		SourceID: "findings",
		Params:   map[string]string{"status": "open", "severity": "high", "age_min_days": "30", "runtime_id": "rt-1"},
		Limit:    50,
	})
	if err != nil {
		t.Fatalf("valid query rejected: %v", err)
	}
}
