package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenAPIPathsUsesOpenAPIParser(t *testing.T) {
	specPath := filepath.Join(t.TempDir(), "openapi.yaml")
	spec := []byte(`openapi: 3.0.3
info:
  title: Test API
  version: 0.0.1
paths:
  "/v1/actions:batch":
    get:
      responses:
        '200':
          description: OK
    post:
      responses:
        '202':
          description: Accepted
    head:
      responses:
        '200':
          description: OK
  /v1/plain:
    delete:
      responses:
        '204':
          description: Deleted
`)
	if err := os.WriteFile(specPath, spec, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	paths, methods, err := openAPIPaths(specPath)
	if err != nil {
		t.Fatalf("openAPIPaths() error = %v", err)
	}
	if !paths["/v1/actions:batch"] {
		t.Fatalf("paths missing quoted colon path: %#v", paths)
	}
	if !paths["/v1/plain"] {
		t.Fatalf("paths missing plain path: %#v", paths)
	}
	for _, want := range []route{
		{Method: "get", Path: "/v1/actions:batch"},
		{Method: "post", Path: "/v1/actions:batch"},
		{Method: "delete", Path: "/v1/plain"},
	} {
		if !methods[want] {
			t.Fatalf("methods missing %#v from %#v", want, methods)
		}
	}
	if methods[route{Method: "head", Path: "/v1/actions:batch"}] {
		t.Fatalf("methods included HEAD route outside parity contract: %#v", methods)
	}
}

func TestOpenAPIPathsRejectsInvalidSpec(t *testing.T) {
	specPath := filepath.Join(t.TempDir(), "openapi.yaml")
	spec := []byte(`openapi: 3.0.3
info:
  title: Test API
  version: 0.0.1
paths:
  /v1/broken:
    get:
      responses:
        '200':
          description: OK
    invalid-method:
      responses:
        '200':
          description: OK
`)
	if err := os.WriteFile(specPath, spec, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, _, err := openAPIPaths(specPath); err == nil {
		t.Fatal("openAPIPaths() error = nil, want invalid spec error")
	}
}

func TestRouteParityIsBidirectional(t *testing.T) {
	routes := []route{
		{Method: "get", Path: "/v1/registered"},
		{Method: "", Path: "/v1/wildcard"},
		{Method: "post", Path: "/v1/missing-doc"},
	}
	paths := map[string]bool{
		"/v1/registered":   true,
		"/v1/wildcard":     true,
		"/v1/ghost":        true,
		"/v1/wrong-method": true,
	}
	methods := map[route]bool{
		{Method: "get", Path: "/v1/registered"}:    true,
		{Method: "get", Path: "/v1/wildcard"}:      true,
		{Method: "delete", Path: "/v1/ghost"}:      true,
		{Method: "post", Path: "/v1/wrong-method"}: true,
	}

	missing := missingOpenAPIRoutes(routes, paths, methods)
	if len(missing) != 1 || missing[0] != (route{Method: "post", Path: "/v1/missing-doc"}) {
		t.Fatalf("missingOpenAPIRoutes() = %#v", missing)
	}

	unregistered := unregisteredOpenAPIRoutes(routes, methods)
	want := []route{
		{Method: "delete", Path: "/v1/ghost"},
		{Method: "post", Path: "/v1/wrong-method"},
	}
	if len(unregistered) != len(want) {
		t.Fatalf("unregisteredOpenAPIRoutes() = %#v, want %#v", unregistered, want)
	}
	for index := range want {
		if unregistered[index] != want[index] {
			t.Fatalf("unregisteredOpenAPIRoutes()[%d] = %#v, want %#v", index, unregistered[index], want[index])
		}
	}
}

func TestRegisteredRustAuthorityRoutesRequiresTheNativeHandler(t *testing.T) {
	sourcePath := filepath.Join(t.TempDir(), "main.rs")
	if err := os.WriteFile(sourcePath, []byte(`
Router::new().route(
    "/platform/graph/neighborhood",
    get(product_neighborhood_route),
).route(
    "/platform/graph/provenance",
    get(graph_provenance_route),
)
`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	routes, err := registeredRustAuthorityRoutes(sourcePath)
	if err != nil {
		t.Fatalf("registeredRustAuthorityRoutes() error = %v", err)
	}
	want := []route{
		{Method: "get", Path: "/platform/graph/neighborhood"},
		{Method: "get", Path: "/platform/graph/provenance"},
	}
	if len(routes) != len(want) {
		t.Fatalf("registeredRustAuthorityRoutes() = %#v, want %#v", routes, want)
	}
	for index := range want {
		if routes[index] != want[index] {
			t.Fatalf("registeredRustAuthorityRoutes()[%d] = %#v, want %#v", index, routes[index], want[index])
		}
	}

	if err := os.WriteFile(sourcePath, []byte(`Router::new()`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := registeredRustAuthorityRoutes(sourcePath); err == nil {
		t.Fatal("registeredRustAuthorityRoutes() error = nil, want missing handler error")
	}
}
