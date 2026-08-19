package bootstrap

import (
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/graphprovenance"
)

func (a *App) handleGetGraphProvenance(w http.ResponseWriter, r *http.Request) {
	urn := strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("urn"), r.URL.Query().Get("root_urn")))
	if err := authorizeCerebroURNTenant(r.Context(), urn); err != nil {
		writeGraphQueryError(w, err)
		return
	}
	response, err := graphprovenance.New(a.deps.GraphReads.Catalog).Get(r.Context(), graphprovenance.Request{URN: urn})
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}
