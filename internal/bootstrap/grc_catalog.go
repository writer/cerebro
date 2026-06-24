package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/grccatalog"
)

const maxGRCQueryBodyBytes = 16 << 10

// handleGRCReportCatalog returns the bounded, allowlisted report source
// catalog that custom dashboards and the report builder can query.
func (a *App) handleGRCReportCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"sources":      grccatalog.Catalog(),
		"generated_at": time.Now().UTC(),
	})
}

// grcQuerySources maps each catalog source id to the existing GRC read handler
// that serves it. The mapping is verified against the catalog by test so the
// two cannot drift.
func (a *App) grcQuerySources() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"findings":             a.handleGRCFindings,
		"controls":             a.handleGRCControls,
		"evidence":             a.handleGRCEvidence,
		"trends":               a.handleGRCTrends,
		"frameworks":           a.handleGRCFrameworks,
		"control-coverage":     a.handleGRCControlCoverage,
		"inventory-assets":     a.handleGRCInventoryAssets,
		"inventory-categories": a.handleGRCInventoryCategories,
	}
}

// handleGRCQuery resolves one bounded report query: it validates the request
// against the catalog allowlist, then dispatches to the backing GRC handler so
// tenant scoping, row limits, and data access are reused unchanged.
func (a *App) handleGRCQuery(w http.ResponseWriter, r *http.Request) {
	var query grccatalog.WidgetQuery
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxGRCQueryBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&query); err != nil {
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, err))
		return
	}
	if err := grccatalog.ValidateWidgetQuery(query); err != nil {
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, err))
		return
	}
	source, ok := grccatalog.Lookup(query.SourceID)
	if !ok {
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, grccatalog.ErrUnknownSource))
		return
	}
	handler, ok := a.grcQuerySources()[source.ID]
	if !ok {
		writeGRCError(w, errors.Join(errInvalidHTTPRequest, fmt.Errorf("source %q is not queryable", source.ID)))
		return
	}
	writeGRCQueryResponse(w, source, dispatchGRCQuery(handler, r, source, query))
}

// dispatchGRCQuery translates a validated widget query into a GET request to
// the backing source handler and captures its JSON response. The request
// context (and therefore the authenticated tenant) is preserved; only the
// allowlisted parameters and the clamped limit are forwarded.
func dispatchGRCQuery(handler http.HandlerFunc, r *http.Request, source grccatalog.Source, query grccatalog.WidgetQuery) *capturedHTTPResponse {
	values := url.Values{}
	for key, value := range query.Params {
		values.Set(strings.TrimSpace(key), value)
	}
	if query.Limit > 0 {
		values.Set("limit", strconv.FormatUint(uint64(query.Limit), 10))
	}
	proxy := r.Clone(r.Context())
	proxy.Method = http.MethodGet
	proxy.URL = &url.URL{Path: source.Path, RawQuery: values.Encode()}
	proxy.RequestURI = ""
	proxy.Body = http.NoBody
	proxy.ContentLength = 0
	if proxy.Header != nil {
		proxy.Header.Del("Content-Type")
		proxy.Header.Del("Content-Length")
	}
	return captureHTTPResponse(handler, proxy)
}

// writeGRCQueryResponse wraps a successful source response in a query envelope
// and otherwise propagates the backing handler's status and error body so
// validation, tenant, and availability failures surface unchanged.
func writeGRCQueryResponse(w http.ResponseWriter, source grccatalog.Source, captured *capturedHTTPResponse) {
	if captured == nil {
		writeGRCError(w, fmt.Errorf("%w: empty query response", errInvalidHTTPRequest))
		return
	}
	if captured.statusCode != http.StatusOK {
		copyHeaders(w.Header(), captured.header)
		w.WriteHeader(captured.statusCode)
		_, _ = w.Write(captured.body.Bytes()) // #nosec G705 -- GRC errors are plain text via http.Error; forward the captured status, headers, and body verbatim instead of mislabeling them as JSON.
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"source_id":    source.ID,
		"generated_at": time.Now().UTC(),
		"data":         json.RawMessage(captured.body.Bytes()),
	})
}
