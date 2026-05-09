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
schedules:
  - localName: live
    runtimeLocalId: live
    scheduleExpression: rate(10 minutes)
    taskCount: 1
    command:
      - orchestrator
      - run
environments:
  sec-dev:
    extraSecretKeys:
      - EXAMPLE_BACKFILL_KEY
    extraRuntimes:
      - localId: backfill
        config:
          domain: env:EXAMPLE_DOMAIN
          family: live
          since: "2026-01-01T00:00:00Z"
          token: env:EXAMPLE_API_TOKEN
    extraSchedules:
      - localName: backfill
        runtimeLocalId: backfill
        scheduleExpression: rate(15 minutes)
    disabledSchedules:
      - live
`)
	manifest, err := Parse(data, "example.yaml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if manifest.SourceID != "example" {
		t.Fatalf("sourceId mismatch: %q", manifest.SourceID)
	}
	if len(manifest.Environments) != 1 {
		t.Fatalf("expected 1 environment override, got %d", len(manifest.Environments))
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
		"schedule unknown runtime": `
sourceId: example
schedules:
  - localName: live
    runtimeLocalId: ghost
    scheduleExpression: rate(1 hour)
`,
		"schedule pre-declares runtime_id": `
sourceId: example
runtimes:
  - localId: live
    config: {family: a}
schedules:
  - localName: live
    runtimeLocalId: live
    scheduleExpression: rate(1 hour)
    command:
      - orchestrator
      - run
      - runtime_id=writer-example-live
`,
		"overlay disables unknown runtime": `
sourceId: example
runtimes:
  - localId: live
    config: {family: a}
environments:
  sec-dev:
    disabledRuntimes:
      - phantom
`,
		"overlay extra collides": `
sourceId: example
runtimes:
  - localId: live
    config: {family: a}
environments:
  sec-dev:
    extraRuntimes:
      - localId: live
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

func TestDiscoverRejectsMisplacedSource(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte("sourceId: beta\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := Discover(root)
	if !errors.Is(err, ErrSourceIDMismatch) {
		t.Fatalf("expected ErrSourceIDMismatch, got %v", err)
	}
}
