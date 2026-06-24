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
	if err := ValidateWidgetQuery(WidgetQuery{SourceID: "findings", Params: map[string]string{"min_age_days": "soon"}}); !errors.Is(err, ErrInvalidQuery) {
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

func TestValidateWidgetQueryAcceptsBoundedQuery(t *testing.T) {
	err := ValidateWidgetQuery(WidgetQuery{
		SourceID: "findings",
		Params:   map[string]string{"status": "open", "severity": "high", "min_age_days": "30", "runtime_id": "rt-1"},
		Limit:    50,
	})
	if err != nil {
		t.Fatalf("valid query rejected: %v", err)
	}
}
