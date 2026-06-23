package bootstrap

import (
	"fmt"
	"net/http"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/reports"
)

func (a *App) handleRunReport(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.RunReportRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeReportError(w, err)
		return
	}
	request.ReportId = r.PathValue("reportID")
	if request.Parameters == nil {
		request.Parameters = map[string]string{}
	}
	configReq := r.Clone(r.Context())
	configReq.Header.Del("X-Cerebro-Source-Config")
	config, err := sourceConfigFromRequest(configReq)
	if err != nil {
		writeReportError(w, fmt.Errorf("%w: %w", reports.ErrInvalidRequest, err))
		return
	}
	if err := authorizeSourceConfigTenant(r.Context(), config); err != nil {
		writeReportError(w, err)
		return
	}
	for key, value := range config {
		request.Parameters[key] = value
	}
	if err := authorizeTenantID(r.Context(), request.GetParameters()["tenant_id"]); err != nil {
		writeReportError(w, err)
		return
	}
	response, err := a.reportService().Run(r.Context(), request)
	if err != nil {
		writeReportError(w, err)
		return
	}
	if err := authorizeTenantID(r.Context(), response.GetRun().GetParameters()["tenant_id"]); err != nil {
		writeReportError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleGetReportRun(w http.ResponseWriter, r *http.Request) {
	response, err := a.reportService().Get(r.Context(), &cerebrov1.GetReportRunRequest{
		Id: r.PathValue("runID"),
	})
	if err != nil {
		writeReportError(w, err)
		return
	}
	if err := authorizeReportRunTenant(r.Context(), response.GetRun()); err != nil {
		writeReportError(w, normalizeIDLookupError(err, ports.ErrReportRunNotFound))
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}
