package coverageview

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/writer/cerebro/internal/sourcecoverage"
)

func TestRecordsPageUsesBoundedCursor(t *testing.T) {
	records := []sourcecoverage.Record{{DimensionID: "a"}, {DimensionID: "b"}, {DimensionID: "c"}}
	request := httptest.NewRequest(http.MethodGet, "/connectors/coverage?coverage_view=page&page_size=2", nil)

	first, metadata, err := RecordsPage(request, records)
	if err != nil {
		t.Fatalf("RecordsPage(first) error = %v", err)
	}
	if len(first) != 2 || metadata.Total != 3 || metadata.Returned != 2 || metadata.NextCursor == "" {
		t.Fatalf("first page = %#v metadata=%#v", first, metadata)
	}
	request = httptest.NewRequest(http.MethodGet, "/connectors/coverage?coverage_view=page&page_size=2&cursor="+metadata.NextCursor, nil)
	second, metadata, err := RecordsPage(request, records)
	if err != nil {
		t.Fatalf("RecordsPage(second) error = %v", err)
	}
	if len(second) != 1 || second[0].DimensionID != "c" || metadata.NextCursor != "" {
		t.Fatalf("second page = %#v metadata=%#v", second, metadata)
	}
}
