package bootstrap

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/writer/cerebro/internal/auditevents"
	"github.com/writer/cerebro/internal/ports"
)

var errAuditEventsUnavailable = errors.New("audit events are not configured")

var auditEventErrorMappings = []bootstrapErrorMapping{
	{match: matchesAnyError(ports.ErrAuditEventInvalid, errInvalidHTTPRequest), httpStatus: http.StatusBadRequest},
	{match: matchesAnyError(errAuditEventsUnavailable), httpStatus: http.StatusServiceUnavailable},
}

func (a *App) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	reader := auditEventReader(a.deps.StateStore)
	if reader == nil {
		writeAuditEventError(w, errAuditEventsUnavailable)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeAuditEventError(w, err)
		return
	}
	if tenantID == "" {
		writeAuditEventError(w, fmt.Errorf("%w: tenant_id is required", errInvalidHTTPRequest))
		return
	}
	query, err := auditevents.ParseHTTPQuery(r.URL.Query(), tenantID, time.Now().UTC())
	if err != nil {
		writeAuditEventError(w, err)
		return
	}
	page, err := reader.ListAuditEvents(r.Context(), query)
	if err != nil {
		if auditevents.IsInvalid(err) {
			writeAuditEventError(w, err)
		} else {
			writeAuditEventError(w, fmt.Errorf("%w: reader failed", errAuditEventsUnavailable))
		}
		return
	}
	response, err := auditevents.NewHTTPPage(query, page)
	if err != nil {
		writeAuditEventError(w, fmt.Errorf("%w: reader result is invalid", errAuditEventsUnavailable))
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, http.StatusOK, response)
}

func auditEventReader(store ports.StateStore) ports.AuditEventReader {
	reader, ok := store.(ports.AuditEventReader)
	if !ok || isNilInterface(reader) {
		return nil
	}
	return reader
}

func writeAuditEventError(w http.ResponseWriter, err error) {
	writeMappedBootstrapError(w, err, auditEventErrorMappings)
}
