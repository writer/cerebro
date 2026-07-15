package providercontractlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestBuildIsDeterministicAndIncludesReferenceClosure(t *testing.T) {
	selection := []Selection{{FamilyID: "users", Method: "GET", Path: "/users", OperationID: "listUsers"}}
	first, err := Build(loadDocument(t, providerFixture), "example", selection)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	second, err := Build(loadDocument(t, strings.ReplaceAll(providerFixture, `"title":"Example"`, `"title": "Example"`)), "example", selection)
	if err != nil {
		t.Fatalf("second Build() error = %v", err)
	}
	if first.DocumentDigest != second.DocumentDigest || first.AuthDigest != second.AuthDigest || first.Operations[0].Digest != second.Operations[0].Digest {
		t.Fatalf("lock changed across input formatting:\nfirst=%#v\nsecond=%#v", first, second)
	}

	changedSchema := strings.Replace(providerFixture, `"email":{"type":"string"}`, `"email":{"type":"string","format":"email"}`, 1)
	changed, err := Build(loadDocument(t, changedSchema), "example", selection)
	if err != nil {
		t.Fatalf("Build(changed schema) error = %v", err)
	}
	if first.Operations[0].Digest == changed.Operations[0].Digest {
		t.Fatal("selected operation digest did not include referenced response schema")
	}
}

func TestCompareClassifiesProviderDrift(t *testing.T) {
	selection := []Selection{{FamilyID: "users", Method: "GET", Path: "/users", OperationID: "listUsers"}}
	baseline, err := Build(loadDocument(t, providerFixture), "example", selection)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if drift := Compare(nil, baseline); drift.Status != DriftNew {
		t.Fatalf("new drift = %#v", drift)
	}
	if drift := Compare(&baseline, baseline); drift.Status != DriftUnchanged {
		t.Fatalf("unchanged drift = %#v", drift)
	}

	additiveDocument := strings.Replace(providerFixture, `"schemas":{`, `"schemas":{"Unused":{"type":"string"},`, 1)
	additive, err := Build(loadDocument(t, additiveDocument), "example", selection)
	if err != nil {
		t.Fatalf("Build(additive) error = %v", err)
	}
	if drift := Compare(&baseline, additive); drift.Status != DriftAdditive {
		t.Fatalf("additive drift = %#v", drift)
	}

	changedSchema := strings.Replace(providerFixture, `"email":{"type":"string"}`, `"email":{"type":"string","format":"email"}`, 1)
	behavioral, err := Build(loadDocument(t, changedSchema), "example", selection)
	if err != nil {
		t.Fatalf("Build(behavioral) error = %v", err)
	}
	if drift := Compare(&baseline, behavioral); drift.Status != DriftBehavioralReview {
		t.Fatalf("behavioral drift = %#v", drift)
	}

	changedAuth := strings.Replace(providerFixture, `"scheme":"bearer"`, `"scheme":"basic"`, 1)
	breaking, err := Build(loadDocument(t, changedAuth), "example", selection)
	if err != nil {
		t.Fatalf("Build(breaking) error = %v", err)
	}
	if drift := Compare(&baseline, breaking); drift.Status != DriftBreaking {
		t.Fatalf("breaking drift = %#v", drift)
	}

	withoutSelection, err := Build(loadDocument(t, providerFixture), "example", nil)
	if err != nil {
		t.Fatalf("Build(without selection) error = %v", err)
	}
	if drift := Compare(&baseline, withoutSelection); drift.Status != DriftBreaking {
		t.Fatalf("removed operation drift = %#v", drift)
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	lock, err := Build(loadDocument(t, providerFixture), "example", []Selection{{FamilyID: "users", Method: "GET", Path: "/users"}})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "locks", "provider.json")
	if err := Write(path, lock); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	loaded, err := Read(path)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if Compare(&lock, loaded).Status != DriftUnchanged {
		t.Fatalf("round-trip lock changed: %#v", loaded)
	}
	before, err := Digest(lock)
	if err != nil {
		t.Fatalf("Digest(lock) error = %v", err)
	}
	after, err := Digest(loaded)
	if err != nil {
		t.Fatalf("Digest(loaded) error = %v", err)
	}
	if before != after {
		t.Fatalf("lock digest changed after round trip: %s != %s", before, after)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat lock: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %o, want 600", info.Mode().Perm())
	}
}

func loadDocument(t *testing.T, payload string) *openapi3.T {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromData([]byte(payload))
	if err != nil {
		t.Fatalf("load OpenAPI document: %v\n%s", err, payload)
	}
	return doc
}

const providerFixture = `{
  "openapi":"3.0.3",
  "info":{"title":"Example","version":"1.0.0"},
  "security":[{"Bearer":[]}],
  "components":{
    "securitySchemes":{"Bearer":{"type":"http","scheme":"bearer"}},
    "schemas":{"User":{"type":"object","properties":{"id":{"type":"string"},"email":{"type":"string"}}}}
  },
  "paths":{
    "/users":{"get":{"operationId":"listUsers","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"array","items":{"$ref":"#/components/schemas/User"}}}}}}}}
  }
}`
