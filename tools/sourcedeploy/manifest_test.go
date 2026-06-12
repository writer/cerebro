package sourcedeploy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseValidManifest(t *testing.T) {
	t.Parallel()
	data := []byte(`
sourceId: example
secretKeys:
  - EXAMPLE_API_TOKEN
  - EXAMPLE_DOMAIN
runtimes:
  - localId: live
    config:
      domain: env:EXAMPLE_DOMAIN
      family: live
      token: env:EXAMPLE_API_TOKEN
`)
	manifest, err := Parse(data, "example.yaml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if manifest.SourceID != "example" {
		t.Fatalf("sourceId mismatch: %q", manifest.SourceID)
	}
	if len(manifest.Runtimes) != 1 {
		t.Fatalf("expected 1 runtime, got %d", len(manifest.Runtimes))
	}
}

func TestValidateRejectsInvalidManifests(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"non-kebab sourceId": `
sourceId: Example
runtimes:
  - localId: a
    config: {family: a}
`,
		"sensitive literal token": `
sourceId: example
runtimes:
  - localId: live
    config:
      family: a
      token: literal-secret
`,
		"sensitive literal apikey": `
sourceId: example
runtimes:
  - localId: live
    config:
      family: a
      apiKey: literal
`,
		"non-screaming secret key": `
sourceId: example
secretKeys:
  - lowercase_secret
runtimes:
  - localId: live
    config: {family: a}
`,
		"non-env-var secret key": `
sourceId: example
secretKeys:
  - BAD-SECRET
runtimes:
  - localId: live
    config: {family: a}
`,
		"unknown top-level field": `
sourceId: example
schedules: []
runtimes:
  - localId: live
    config: {family: a}
`,
		"unknown runtime field": `
sourceId: example
runtimes:
  - localId: live
    family: audit
    config: {family: a}
`,
		"undeclared env ref": `
sourceId: example
secretKeys:
  - EXAMPLE_API_TOKEN
runtimes:
  - localId: live
    config:
      domain: env:EXAMPLE_DOMAIN
      family: a
      token: env:EXAMPLE_API_TOKEN
`,
		"invalid env ref": `
sourceId: example
secretKeys:
  - EXAMPLE_API_TOKEN
runtimes:
  - localId: live
    config:
      family: a
      token: env:example_api_token
`,
		"runtime config empty": `
sourceId: example
runtimes:
  - localId: live
    config: {}
`,
		"duplicate runtime": `
sourceId: example
runtimes:
  - localId: live
    config: {family: a}
  - localId: live
    config: {family: a}
`,
		"non-kebab runtime localId": `
sourceId: example
runtimes:
  - localId: Bad_ID
    config: {family: a}
`,
	}
	for name, body := range cases {
		body := body
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse([]byte(body), name); err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
		})
	}
}

func TestDiscoverWalksSourcesRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	mkSource := func(id, body string) {
		dir := filepath.Join(root, id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte(body), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	mkSource("alpha", "sourceId: alpha\nsecretKeys: [ALPHA_TOKEN]\n")
	mkSource("beta", "sourceId: beta\n")
	if err := os.MkdirAll(filepath.Join(root, "gamma"), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(manifests))
	}
	if manifests[0].SourceID != "alpha" || manifests[1].SourceID != "beta" {
		t.Fatalf("Discover returned unsorted: %#v", manifests)
	}
}

func TestDiscoverAllowsCatalogIDDifferentFromDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "googleworkspace")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte("id: google_workspace\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(catalog): %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte("sourceId: google_workspace\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(deploy): %v", err)
	}
	manifests, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(manifests) != 1 || manifests[0].SourceID != "google_workspace" {
		t.Fatalf("Discover() = %#v, want google_workspace", manifests)
	}
}

func TestDiscoverRejectsMisplacedSource(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "catalog.yaml"), []byte("id: alpha\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(catalog): %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte("sourceId: beta\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := Discover(root)
	if !errors.Is(err, ErrSourceIDMismatch) {
		t.Fatalf("expected ErrSourceIDMismatch, got %v", err)
	}
}

func FuzzParseDeployManifest(f *testing.F) {
	f.Add([]byte(`
sourceId: example
secretKeys: [EXAMPLE_API_TOKEN]
runtimes:
  - localId: live
    config:
      family: live
      token: env:EXAMPLE_API_TOKEN
`))
	f.Add([]byte(`sourceId: Example`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`sourceId: example
runtimes:
  - localId: live
    config: {token: literal-secret}
`))
	f.Add([]byte(`sourceId: example
secretKeys: [TOKEN]
runtimes:
  - localId: live
    config: {token: env:OTHER_TOKEN}
`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		manifest, err := Parse(data, "fuzz.yaml")
		if err != nil {
			return
		}
		if err := manifest.Validate(); err != nil {
			t.Fatalf("Parse returned invalid manifest: %v", err)
		}
		if !sourceIDPattern.MatchString(manifest.SourceID) {
			t.Fatalf("invalid source id accepted: %q", manifest.SourceID)
		}
		seenSecrets := map[string]struct{}{}
		for _, key := range manifest.SecretKeys {
			if !envVarRegex.MatchString(key) {
				t.Fatalf("invalid secret key accepted: %q", key)
			}
			if _, ok := seenSecrets[key]; ok {
				t.Fatalf("duplicate secret key accepted: %q", key)
			}
			seenSecrets[key] = struct{}{}
		}
		seenRuntimes := map[string]struct{}{}
		for _, runtime := range manifest.Runtimes {
			if !idPattern.MatchString(runtime.LocalID) {
				t.Fatalf("invalid runtime id accepted: %q", runtime.LocalID)
			}
			if _, ok := seenRuntimes[runtime.LocalID]; ok {
				t.Fatalf("duplicate runtime accepted: %q", runtime.LocalID)
			}
			seenRuntimes[runtime.LocalID] = struct{}{}
			if len(runtime.Config) == 0 {
				t.Fatalf("empty runtime config accepted for %q", runtime.LocalID)
			}
			for key, value := range runtime.Config {
				if isSensitiveConfigKey(key) && !envRefRegex.MatchString(value) {
					t.Fatalf("sensitive literal accepted for key %q", key)
				}
			}
		}
	})
}
