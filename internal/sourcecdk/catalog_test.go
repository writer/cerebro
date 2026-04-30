package sourcecdk

import "testing"

func TestLoadCatalog(t *testing.T) {
	spec, err := LoadCatalog([]byte(`
id: github
name: GitHub
description: GitHub audit source
emitted_kinds:
  - github.audit
  - github.pull_request
`))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	if spec.Id != "github" {
		t.Fatalf("Id = %q, want %q", spec.Id, "github")
	}
	if len(spec.EmittedKinds) != 2 {
		t.Fatalf("len(EmittedKinds) = %d, want 2", len(spec.EmittedKinds))
	}
}

func TestLoadCatalogRejectsMissingID(t *testing.T) {
	if _, err := LoadCatalog([]byte("name: GitHub\n")); err == nil {
		t.Fatal("LoadCatalog() error = nil, want non-nil")
	}
}
