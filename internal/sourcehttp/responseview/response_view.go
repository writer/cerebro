package responseview

import (
	"errors"
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/grcproductareas"
)

type View string

const (
	Expanded View = "expanded"
	Summary  View = "summary"
)

type CoverageScope string

const (
	CoverageCatalog    CoverageScope = "catalog"
	CoverageConfigured CoverageScope = "configured"
)

var (
	ErrInvalidView          = errors.New("view must be summary when provided")
	ErrInvalidCoverageScope = errors.New("coverage_scope must be catalog or configured")
)

func FromRequest(r *http.Request) (View, error) {
	if r == nil || r.URL == nil {
		return Expanded, nil
	}
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("view"))) {
	case "":
		return Expanded, nil
	case string(Summary):
		return Summary, nil
	default:
		return Expanded, ErrInvalidView
	}
}

func CoverageScopeFromRequest(r *http.Request, view View) (CoverageScope, error) {
	if r == nil || r.URL == nil {
		return CoverageCatalog, nil
	}
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("coverage_scope"))) {
	case "":
		if view == Summary {
			return CoverageConfigured, nil
		}
		return CoverageCatalog, nil
	case string(CoverageCatalog):
		return CoverageCatalog, nil
	case string(CoverageConfigured):
		return CoverageConfigured, nil
	default:
		return CoverageCatalog, ErrInvalidCoverageScope
	}
}

func CompactProductAreas(views []grcproductareas.View) []grcproductareas.View {
	for index := range views {
		views[index].BlindSpots = nil
	}
	return views
}
