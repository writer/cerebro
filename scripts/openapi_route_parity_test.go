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
