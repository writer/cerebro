package cloudidentitysource

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"

	ci "github.com/writer/cerebro/internal/cloudidentity"
	k8syaml "sigs.k8s.io/yaml"
)

// fakeChartReader is an in-memory ci.ChartReader whose ReadChart always
// errors and records every call it receives, so tests can assert a
// dependency's chart content was never fetched (for example a Helm
// condition/tags-disabled dependency, which must cause neither a fetch nor
// a pin-validation gap).
type fakeChartReader struct {
	calls []ci.ChartReference
}

func (f *fakeChartReader) ReadChart(_ context.Context, ref ci.ChartReference) (ci.Repository, error) {
	f.calls = append(f.calls, ref)
	return ci.Repository{}, fmt.Errorf("fakeChartReader: unexpected fetch of %s/%s@%s", ref.Repository, ref.Name, ref.Version)
}

// fakeRepositoryReader is an in-memory ci.RepositoryReader keyed by
// "repository@revision:root", used to drive Argo CD recursion and renderer
// tests without any real network I/O.
type fakeRepositoryReader struct {
	repos map[string]ci.Repository
	errs  map[string]error
	calls []ci.SourcePin
}

func newFakeRepositoryReader() *fakeRepositoryReader {
	return &fakeRepositoryReader{repos: map[string]ci.Repository{}, errs: map[string]error{}}
}

func fakeRepoKey(pin ci.SourcePin) string {
	return pin.Repository + "@" + pin.Revision + ":" + pin.Root
}

func (f *fakeRepositoryReader) register(pin ci.SourcePin, files map[string]string) {
	f.repos[fakeRepoKey(pin)] = buildFakeRepository(pin, files)
}

func (f *fakeRepositoryReader) ReadRepository(ctx context.Context, pin ci.SourcePin) (ci.Repository, error) {
	f.calls = append(f.calls, pin)
	key := fakeRepoKey(pin)
	if err, ok := f.errs[key]; ok {
		return ci.Repository{}, err
	}
	if repo, ok := f.repos[key]; ok {
		return repo, nil
	}
	return ci.Repository{}, fmt.Errorf("fakeRepositoryReader: no repository registered for %q", key)
}

func buildFakeRepository(pin ci.SourcePin, files map[string]string) ci.Repository {
	out := make([]ci.SourceFile, 0, len(files))
	for p, c := range files {
		out = append(out, ci.SourceFile{Path: p, Content: []byte(c)})
	}
	return ci.Repository{Pin: pin, Files: out}
}

func buildInlineRepository(repository, revision string, files map[string]string) ci.Repository {
	return buildFakeRepository(ci.SourcePin{Repository: repository, Revision: revision, Exact: true}, files)
}

// buildTarGz packages files (relative paths, e.g. "mychart/Chart.yaml") into
// an in-memory gzip-compressed tar archive, mirroring a packaged Helm chart
// or OCI chart content layer for ChartReader/dependency tests.
func buildTarGz(files map[string]string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			panic(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			panic(err)
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func testContext() context.Context { return context.Background() }

// manifestMarshalYAMLForTest renders an arbitrary decoded object back to
// YAML text so it can be registered as repository file content, keeping
// recursive-expansion tests honest about decoding real bytes rather than
// handing Go values directly to the code under test.
func manifestMarshalYAMLForTest(obj map[string]any) (string, error) {
	out, err := k8syaml.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
