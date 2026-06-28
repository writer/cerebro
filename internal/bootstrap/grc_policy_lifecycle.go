package bootstrap

import (
	"net/http"

	"github.com/writer/cerebro/internal/graphquery"
	"github.com/writer/cerebro/internal/grcpolicylifecycle"
)

func (a *App) handleGRCPolicyLifecycle(w http.ResponseWriter, r *http.Request) {
	scope, err := grcScopeFromRequest(r)
	if err != nil {
		writeGRCError(w, err)
		return
	}
	store := graphQueryStore(a.deps.GraphStore)
	if store == nil {
		writeGRCError(w, graphquery.ErrRuntimeUnavailable)
		return
	}
	response, err := grcpolicylifecycle.Build(r.Context(), store, grcpolicylifecycle.Scope{
		TenantID:  scope.TenantID,
		SourceID:  scope.SourceID,
		RuntimeID: scope.RuntimeID,
		Limit:     scope.Limit,
	})
	if err != nil {
		writeGRCError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}
