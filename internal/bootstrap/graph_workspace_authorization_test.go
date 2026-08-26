package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/writer/cerebro/internal/applicationworkspace"
	"github.com/writer/cerebro/internal/config"
)

func TestGRCEntityImpactWorkspaceFailuresSkipNeighborhoodAndLegacyFallback(t *testing.T) {
	const rootURN = "urn:cerebro:tenant-a:github_repo:legacy"
	tests := []struct {
		name        string
		tenantID    string
		workspaceID string
		header      string
		grants      []config.ApplicationWorkspaceGrant
		wantStatus  int
		wantCatalog int
	}{
		{name: "orphan workspace", tenantID: "tenant-a", workspaceID: "workspace-orphan", grants: []config.ApplicationWorkspaceGrant{{TenantID: "tenant-a", ApplicationWorkspaceIDs: []string{"workspace-orphan"}}}, wantStatus: http.StatusNotFound, wantCatalog: 1},
		{name: "workspace outside grant", tenantID: "tenant-a", workspaceID: "workspace-b", grants: []config.ApplicationWorkspaceGrant{{TenantID: "tenant-a", ApplicationWorkspaceIDs: []string{"workspace-a"}}}, wantStatus: http.StatusForbidden},
		{name: "tenant selector mismatch", tenantID: "tenant-a", workspaceID: "workspace-a", header: "tenant-b", grants: []config.ApplicationWorkspaceGrant{{TenantID: "tenant-a", ApplicationWorkspaceIDs: []string{"workspace-a"}}}, wantStatus: http.StatusBadRequest},
		{name: "root tenant mismatch", tenantID: "tenant-b", workspaceID: "workspace-a", grants: []config.ApplicationWorkspaceGrant{{TenantID: "tenant-b", ApplicationWorkspaceIDs: []string{"workspace-a"}}}, wantStatus: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := &stubGraphStore{}
			app := New(config.Config{}, Dependencies{GraphStore: graph, GraphReads: NewGraphReadCapabilities(graph)}, nil)
			request := httptest.NewRequest(http.MethodGet, "/grc/entities/impact?tenant_id="+url.QueryEscape(test.tenantID)+"&workspace_id="+url.QueryEscape(test.workspaceID), nil)
			request.SetPathValue("entityID", rootURN)
			request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{principal: authPrincipal{
				TenantID: test.tenantID, ApplicationWorkspaceGrants: test.grants,
			}}))
			if test.header != "" {
				request.Header.Set(applicationworkspace.TenantHeader, test.header)
			}
			response := httptest.NewRecorder()

			app.handleGRCEntityImpact(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			if graph.neighborhoodRootURN != "" {
				t.Fatalf("neighborhood root = %q, want zero unscoped neighborhood reads", graph.neighborhoodRootURN)
			}
			if len(graph.entityRequests) != test.wantCatalog {
				t.Fatalf("entity catalog requests = %d, want %d (legacy fallback must remain disabled)", len(graph.entityRequests), test.wantCatalog)
			}
		})
	}
}
