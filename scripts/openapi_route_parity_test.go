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
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "main.rs")
	ledgerPath := filepath.Join(dir, "rust-authority-routes.json")
	if err := os.WriteFile(sourcePath, []byte(`
Router::new().route(
    "/v1/example",
    get(example_route),
)
`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(ledgerPath, []byte(`[
  {"method": "GET", "path": "/v1/example", "marker": "get(example_route)"}
]`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	routes, err := registeredRustAuthorityRoutes(sourcePath, ledgerPath)
	if err != nil {
		t.Fatalf("registeredRustAuthorityRoutes() error = %v", err)
	}
	want := []route{{Method: "get", Path: "/v1/example"}}
	if len(routes) != len(want) || routes[0] != want[0] {
		t.Fatalf("registeredRustAuthorityRoutes() = %#v, want %#v", routes, want)
	}

	if err := os.WriteFile(sourcePath, []byte(`Router::new()`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := registeredRustAuthorityRoutes(sourcePath, ledgerPath); err == nil {
		t.Fatal("registeredRustAuthorityRoutes() error = nil, want missing handler error")
	}

	if err := os.WriteFile(ledgerPath, []byte(`[{"method": "GET", "path": "/v1/example"}]`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := registeredRustAuthorityRoutes(sourcePath, ledgerPath); err == nil {
		t.Fatal("registeredRustAuthorityRoutes() error = nil, want incomplete ledger entry error")
	}
}

func TestRustAuthorityLedgerMatchesCheckedInRouter(t *testing.T) {
	routes, err := registeredRustAuthorityRoutes(
		filepath.Join("..", "crates", "cerebro-platform", "src", "main.rs"),
		filepath.Join("..", rustAuthorityLedgerPath),
	)
	if err != nil {
		t.Fatalf("registeredRustAuthorityRoutes() error = %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("rust authority ledger is empty")
	}
}
