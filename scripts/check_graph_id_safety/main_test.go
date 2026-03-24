package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckFilesAcceptsTypedGraphIDConstructors(t *testing.T) {
	t.Parallel()

	path := writeGraphIDSafetyFixture(t, "safe.go", `package sample

import "github.com/writer/cerebro/internal/graph"

func serviceNodeID(name string) string { return "service:" + name }
func serviceEdgeID(source, target string) string { return source + "->" + target }

func build(source, target string) {
	nodeID := serviceNodeID(source)
	_ = &graph.Node{ID: nodeID, Kind: graph.NodeKindService, Name: source}
	_ = &graph.Edge{ID: serviceEdgeID(source, target), Source: source, Target: target, Kind: graph.EdgeKindContains}
}
`)

	diagnostics, err := checkFiles([]string{path})
	if err != nil {
		t.Fatalf("checkFiles() error = %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("checkFiles() diagnostics = %#v, want none", diagnostics)
	}
}

func TestCheckFilesRejectsInlineGraphIDBuilders(t *testing.T) {
	t.Parallel()

	path := writeGraphIDSafetyFixture(t, "unsafe.go", `package sample

import (
	"fmt"

	"github.com/writer/cerebro/internal/graph"
)

func build(source, target string) {
	_ = &graph.Node{ID: fmt.Sprintf("service:%s", source), Kind: graph.NodeKindService, Name: source}
	_ = &graph.Edge{ID: source + "->" + target, Source: source, Target: target, Kind: graph.EdgeKindContains}
}
`)

	diagnostics, err := checkFiles([]string{path})
	if err != nil {
		t.Fatalf("checkFiles() error = %v", err)
	}
	if len(diagnostics) != 2 {
		t.Fatalf("checkFiles() diagnostics = %#v, want 2", diagnostics)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "typed nodeID helper") {
		t.Fatalf("expected diagnostics to mention typed nodeID helper, got %#v", diagnostics)
	}
	if !strings.Contains(strings.Join(diagnostics, "\n"), "typed edgeID helper") {
		t.Fatalf("expected diagnostics to mention typed edgeID helper, got %#v", diagnostics)
	}
}

func TestCheckFilesRejectsPropagatedUnsafeGraphIDValues(t *testing.T) {
	t.Parallel()

	path := writeGraphIDSafetyFixture(t, "propagated.go", `package sample

import (
	"fmt"

	"github.com/writer/cerebro/internal/graph"
)

func build(name string) {
	id := fmt.Sprintf("service:%s", name)
	_ = &graph.Node{ID: id, Kind: graph.NodeKindService, Name: name}
}
`)

	diagnostics, err := checkFiles([]string{path})
	if err != nil {
		t.Fatalf("checkFiles() error = %v", err)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("checkFiles() diagnostics = %#v, want 1", diagnostics)
	}
}

func TestFilteredGoPathsSkipsTestsAndNonGoFiles(t *testing.T) {
	t.Parallel()

	paths := filteredGoPaths([]string{"internal/app/app.go", "internal/app/app_test.go", "README.md"})
	if len(paths) != 1 || paths[0] != filepath.Clean("internal/app/app.go") {
		t.Fatalf("filteredGoPaths() = %#v, want only non-test Go files", paths)
	}
}

func TestCheckFilesAcceptsFirstIdentifierFromMultiReturnTypedConstructor(t *testing.T) {
	t.Parallel()

	path := writeGraphIDSafetyFixture(t, "multi_return.go", `package sample

import "github.com/writer/cerebro/internal/graph"

func serviceNodeID(name string) (string, error) { return "service:" + name, nil }

func build(name string) error {
	nodeID, err := serviceNodeID(name)
	if err != nil {
		return err
	}
	_ = &graph.Node{ID: nodeID, Kind: graph.NodeKindService, Name: name}
	return nil
}
`)

	diagnostics, err := checkFiles([]string{path})
	if err != nil {
		t.Fatalf("checkFiles() error = %v", err)
	}
	if len(diagnostics) != 0 {
		t.Fatalf("checkFiles() diagnostics = %#v, want none", diagnostics)
	}
}

func TestCheckFilesDoesNotLeakSafeInitIdentifiersOutsideIfScope(t *testing.T) {
	t.Parallel()

	path := writeGraphIDSafetyFixture(t, "if_scope.go", `package sample

import (
	"fmt"

	"github.com/writer/cerebro/internal/graph"
)

func serviceNodeID(name string) string { return "service:" + name }

func build(name string, ok bool) {
	nodeID := fmt.Sprintf("unsafe:%s", name)
	if scoped := serviceNodeID(name); ok {
		_ = &graph.Node{ID: scoped, Kind: graph.NodeKindService, Name: name}
	}
	_ = &graph.Node{ID: nodeID, Kind: graph.NodeKindService, Name: name}
}
`)

	diagnostics, err := checkFiles([]string{path})
	if err != nil {
		t.Fatalf("checkFiles() error = %v", err)
	}
	if len(diagnostics) != 1 {
		t.Fatalf("checkFiles() diagnostics = %#v, want 1", diagnostics)
	}
}

func writeGraphIDSafetyFixture(t *testing.T, name string, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
	return path
}
