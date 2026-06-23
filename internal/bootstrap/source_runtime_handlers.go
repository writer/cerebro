package bootstrap

import (
	"errors"
	"net/http"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourceruntime"
)

func (a *App) handlePutSourceRuntime(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.PutSourceRuntimeRequest{}
	if err := readProtoJSON(r, request); err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	if request.Runtime == nil {
		request.Runtime = &cerebrov1.SourceRuntime{}
	}
	request.Runtime.Id = r.PathValue("runtimeID")
	if err := authorizePutSourceRuntimeTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetRuntime()); err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	response, err := a.runtimeService().Put(r.Context(), request)
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	bumpGRCCacheForRuntime(r.Context(), a.deps, request.GetRuntime().GetId(), grcCacheScopeRuntime, grcCacheScopeGraph, grcCacheScopeInventory)
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleGetSourceRuntime(w http.ResponseWriter, r *http.Request) {
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), r.PathValue("runtimeID")); err != nil {
		writeSourceRuntimeError(w, normalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound))
		return
	}
	response, err := a.runtimeService().Get(r.Context(), &cerebrov1.GetSourceRuntimeRequest{
		Id: r.PathValue("runtimeID"),
	})
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}

func (a *App) handleListSourceRuntimes(w http.ResponseWriter, r *http.Request) {
	limit, err := uint32QueryParam(r, "limit")
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	filter := ports.SourceRuntimeFilter{
		RuntimeID:  strings.TrimSpace(r.URL.Query().Get("runtime_id")),
		RuntimeIDs: csvQueryValues(r.URL.Query().Get("runtime_ids")),
		TenantID:   strings.TrimSpace(r.URL.Query().Get("tenant_id")),
		SourceID:   strings.TrimSpace(r.URL.Query().Get("source_id")),
		Limit:      limit,
	}
	if filter.TenantID == "" {
		if auth, ok := r.Context().Value(authContextKey{}).(authContext); ok && strings.TrimSpace(auth.principal.TenantID) != "" {
			filter.TenantID = strings.TrimSpace(auth.principal.TenantID)
		}
	}
	if filter.TenantID == "" {
		filter.TenantID = strings.TrimSpace(r.Header.Get("X-Cerebro-Tenant"))
	}
	filterRuntimeIDs := append([]string{}, filter.RuntimeIDs...)
	if strings.TrimSpace(filter.RuntimeID) != "" {
		filterRuntimeIDs = append(filterRuntimeIDs, filter.RuntimeID)
	}
	filterRuntimeIDs = csvQueryValues(strings.Join(filterRuntimeIDs, ","))
	if filter.TenantID == "" && len(filterRuntimeIDs) != 0 && requiresTenantFilter(r.Context()) {
		store := sourceRuntimeStore(a.deps.StateStore)
		if store == nil {
			writeSourceRuntimeError(w, sourceruntime.ErrRuntimeUnavailable)
			return
		}
		tenantIDs := map[string]struct{}{}
		for _, runtimeID := range filterRuntimeIDs {
			runtime, err := store.GetSourceRuntime(r.Context(), runtimeID)
			if errors.Is(err, ports.ErrSourceRuntimeNotFound) {
				writeSourceRuntimeListJSON(w, http.StatusOK, nil)
				return
			}
			if err != nil {
				writeSourceRuntimeError(w, err)
				return
			}
			if !tenantAllowedByContext(r.Context(), runtime.GetTenantId()) {
				writeSourceRuntimeListJSON(w, http.StatusOK, nil)
				return
			}
			if tenantID := strings.TrimSpace(runtime.GetTenantId()); tenantID != "" {
				tenantIDs[tenantID] = struct{}{}
			}
		}
		if len(tenantIDs) > 1 {
			writeSourceRuntimeError(w, errTenantForbidden)
			return
		}
		for tenantID := range tenantIDs {
			filter.TenantID = tenantID
		}
	}
	if filter.TenantID == "" && len(filterRuntimeIDs) == 0 && requiresTenantFilter(r.Context()) {
		writeSourceRuntimeError(w, errTenantForbidden)
		return
	}
	if err := authorizeTenantID(r.Context(), filter.TenantID); err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	runtimes, err := a.runtimeService().List(r.Context(), filter)
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	writeSourceRuntimeListJSON(w, http.StatusOK, runtimes)
}

func (a *App) handleSyncSourceRuntime(w http.ResponseWriter, r *http.Request) {
	request := &cerebrov1.SyncSourceRuntimeRequest{}
	if pageLimit := r.URL.Query().Get("page_limit"); pageLimit != "" {
		body := []byte(`{"page_limit":` + pageLimit + `}`)
		if err := unmarshalHTTPProtoJSON(body, request); err != nil {
			writeSourceRuntimeError(w, err)
			return
		}
	}
	request.Id = r.PathValue("runtimeID")
	if err := authorizeSourceRuntimeIDTenant(r.Context(), sourceRuntimeStore(a.deps.StateStore), request.GetId()); err != nil {
		writeSourceRuntimeError(w, normalizeIDLookupError(err, ports.ErrSourceRuntimeNotFound))
		return
	}
	response, err := a.runtimeService().SyncWithLease(r.Context(), request, sourceruntime.SyncWithLeaseOptions{
		LeaseStore: sourceRuntimeLeaseStore(a.deps.StateStore),
	})
	if err != nil {
		writeSourceRuntimeError(w, err)
		return
	}
	writeProtoJSON(w, http.StatusOK, response)
}
