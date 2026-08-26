package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/writer/cerebro/internal/applicationworkspace"
	"github.com/writer/cerebro/internal/config"
	"github.com/writer/cerebro/internal/ports"
)

func TestGraphNeighborhoodWorkspaceScopeQualifiesRootWithoutNeighborhoodRead(t *testing.T) {
	const (
		tenantID    = "tenant-a"
		workspaceID = "workspace-a"
		rootURN     = "urn:cerebro:tenant-a:asset:root"
	)
	graph := &stubGraphStore{cypherRows: [][]ports.CypherRow{{{Values: map[string]any{
		"urn": rootURN, "tenant_id": tenantID, "application_workspace_id": workspaceID,
		"runtime_id": "runtime-a", "source_id": "source-a", "entity_type": "asset", "label": "Root", "attributes_json": `{}`,
	}}}}}
	app := New(config.Config{}, Dependencies{GraphStore: graph, GraphReads: NewGraphReadCapabilities(graph)}, nil)
	request := graphWorkspaceRequest(t, tenantID, workspaceID, rootURN, []config.ApplicationWorkspaceGrant{{
		TenantID: tenantID, ApplicationWorkspaceIDs: []string{workspaceID},
	}})
	response := httptest.NewRecorder()

	app.handleGetEntityNeighborhood(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("workspace graph status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	if graph.neighborhoodRootURN != "" {
		t.Fatalf("neighborhood root = %q, want no tenant-wide neighborhood read", graph.neighborhoodRootURN)
	}
	if len(graph.entityRequests) != 1 {
		t.Fatalf("entity catalog requests = %d, want 1 scoped qualification", len(graph.entityRequests))
	}
	filter := graph.entityRequests[0].Filter
	if filter.TenantID != tenantID || filter.ApplicationWorkspaceID != workspaceID || filter.ExactAgentKey != rootURN {
		t.Fatalf("workspace qualification filter = %#v", filter)
	}
}

func TestGraphNeighborhoodWorkspaceFailuresSkipNeighborhoodRead(t *testing.T) {
	const rootURN = "urn:cerebro:tenant-a:asset:root"
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
			request := graphWorkspaceRequest(t, test.tenantID, test.workspaceID, rootURN, test.grants)
			if test.header != "" {
				request.Header.Set(applicationworkspace.TenantHeader, test.header)
			}
			response := httptest.NewRecorder()

			app.handleGetEntityNeighborhood(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			if graph.neighborhoodRootURN != "" {
				t.Fatalf("neighborhood root = %q, want zero neighborhood reads", graph.neighborhoodRootURN)
			}
			if len(graph.entityRequests) != test.wantCatalog {
				t.Fatalf("entity catalog requests = %d, want %d", len(graph.entityRequests), test.wantCatalog)
			}
		})
	}
}

func TestGraphNeighborhoodAuthMiddlewarePreservesWorkspaceIsolation(t *testing.T) {
	const (
		tenantID    = "tenant-a"
		workspaceID = "workspace-orphan"
		rootURN     = "urn:cerebro:tenant-a:asset:root"
	)
	graph := &stubGraphStore{}
	app := New(config.Config{Auth: config.AuthConfig{Enabled: true, APICredentials: []config.APICredential{{
		Key: "workspace-token", Principal: "workspace-user", TenantID: tenantID, Scopes: []string{scopeCosmoSecurityRead},
		ApplicationWorkspaceGrants: []config.ApplicationWorkspaceGrant{{TenantID: tenantID, ApplicationWorkspaceIDs: []string{workspaceID}}},
	}}}}, Dependencies{GraphStore: graph, GraphReads: NewGraphReadCapabilities(graph)}, nil)
	server := httptest.NewServer(app.Handler())
	defer server.Close()

	request, err := http.NewRequest(http.MethodGet, server.URL+"/platform/graph/neighborhood?tenant_id="+tenantID+"&workspace_id="+workspaceID+"&root_urn="+url.QueryEscape(rootURN), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer workspace-token")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("workspace graph status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}
	if graph.neighborhoodRootURN != "" {
		t.Fatalf("neighborhood root = %q, want zero unscoped neighborhood reads", graph.neighborhoodRootURN)
	}
	if len(graph.entityRequests) != 1 || graph.entityRequests[0].Filter.ApplicationWorkspaceID != workspaceID {
		t.Fatalf("workspace catalog requests = %#v, want one exact workspace qualification", graph.entityRequests)
	}
}

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

func graphWorkspaceRequest(t *testing.T, tenantID, workspaceID, rootURN string, grants []config.ApplicationWorkspaceGrant) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/platform/graph/neighborhood?tenant_id="+url.QueryEscape(tenantID)+"&workspace_id="+url.QueryEscape(workspaceID)+"&root_urn="+url.QueryEscape(rootURN), nil)
	return request.WithContext(context.WithValue(request.Context(), authContextKey{}, authContext{principal: authPrincipal{
		TenantID: tenantID, ApplicationWorkspaceGrants: grants,
	}}))
}
