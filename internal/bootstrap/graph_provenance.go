package bootstrap

import (
	"net/http"
	"strings"

	"github.com/writer/cerebro/internal/graphprovenance"
	"github.com/writer/cerebro/internal/ports"
)

func (a *App) handleGetGraphProvenance(w http.ResponseWriter, r *http.Request) {
	urn := strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("urn"), r.URL.Query().Get("root_urn")))
	if err := authorizeCerebroURNTenant(r.Context(), urn); err != nil {
		writeGraphQueryError(w, err)
		return
	}
	graphStore := dependencyGraphQueryStore(a.deps)
	var catalogStore ports.EntityCatalogStore
	if graphStore != nil {
		catalogStore, _ = graphStore.(ports.EntityCatalogStore)
	}
	response, err := graphprovenance.New(catalogStore).Get(r.Context(), graphprovenance.Request{URN: urn})
	if err != nil {
		writeGraphQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}
