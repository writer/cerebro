package responseview

import (
	"net/http/httptest"
	"testing"
)

func TestDefaultViewUsesExpandedCatalogCoverage(t *testing.T) {
	request := httptest.NewRequest("GET", "/grc/dashboard", nil)
	view, err := FromRequest(request)
	if err != nil {
		t.Fatalf("FromRequest() error = %v", err)
	}
	scope, err := CoverageScopeFromRequest(request, view)
	if err != nil {
		t.Fatalf("CoverageScopeFromRequest() error = %v", err)
	}
	if view != Expanded || scope != CoverageCatalog {
		t.Fatalf("view/scope = %q/%q, want expanded/catalog", view, scope)
	}
}

func TestSummaryViewDefaultsToConfiguredCoverage(t *testing.T) {
	request := httptest.NewRequest("GET", "/grc/dashboard?view=summary", nil)
	view, err := FromRequest(request)
	if err != nil {
		t.Fatalf("FromRequest() error = %v", err)
	}
	scope, err := CoverageScopeFromRequest(request, view)
	if err != nil {
		t.Fatalf("CoverageScopeFromRequest() error = %v", err)
	}
	if view != Summary || scope != CoverageConfigured {
		t.Fatalf("view/scope = %q/%q, want summary/configured", view, scope)
	}
}

func TestViewRejectsUnsupportedValues(t *testing.T) {
	request := httptest.NewRequest("GET", "/grc/dashboard?view=compact", nil)
	if _, err := FromRequest(request); err == nil {
		t.Fatal("FromRequest() error = nil, want invalid view")
	}
}
