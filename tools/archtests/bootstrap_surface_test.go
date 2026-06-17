package archtests

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const bootstrapProductionGoLineBudget = 22276

type bootstrapFileLineCount struct {
	path  string
	lines int
}

func TestBootstrapProductionSurfaceDoesNotGrow(t *testing.T) {
	root := repoRoot(t)
	counts := bootstrapProductionLineCounts(t, root, filepath.Join(root, "internal", "bootstrap"))
	total := 0
	for _, count := range counts {
		total += count.lines
	}
	if total <= bootstrapProductionGoLineBudget {
		return
	}
	t.Fatalf(
		"internal/bootstrap production Go grew to %d lines, budget %d (+%d).\n%s\nMove new domain behavior behind a domain package and keep bootstrap focused on routing, auth, request/response mapping, and dependency wiring; update the budget only with an architecture note.",
		total,
		bootstrapProductionGoLineBudget,
		total-bootstrapProductionGoLineBudget,
		topBootstrapFiles(counts, 8),
	)
}

func TestArchitectureDocumentsBootstrapOwnership(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "docs", "ARCHITECTURE.md"))
	if err != nil {
		t.Fatalf("read docs/ARCHITECTURE.md: %v", err)
	}
	for _, marker := range []string{
		"## Bootstrap ownership",
		"outer composition root",
		"routing, auth, request/response mapping, and dependency wiring",
		"New domain behavior should land behind a domain package",
		"Production Go under `internal/bootstrap` is ratcheted by `tools/archtests`",
	} {
		if !bytes.Contains(body, []byte(marker)) {
			t.Fatalf("docs/ARCHITECTURE.md missing bootstrap ownership marker %q", marker)
		}
	}
}

func bootstrapProductionLineCounts(t *testing.T, root string, dir string) []bootstrapFileLineCount {
	t.Helper()
	counts := []bootstrapFileLineCount{}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		counts = append(counts, bootstrapFileLineCount{
			path:  filepath.ToSlash(shortPath(root, path)),
			lines: countLines(t, path),
		})
		return nil
	}); err != nil {
		t.Fatalf("scan internal/bootstrap: %v", err)
	}
	return counts
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()

	lines := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return lines
}

func topBootstrapFiles(counts []bootstrapFileLineCount, limit int) string {
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].lines == counts[j].lines {
			return counts[i].path < counts[j].path
		}
		return counts[i].lines > counts[j].lines
	})
	if limit > len(counts) {
		limit = len(counts)
	}
	lines := make([]string, 0, limit+1)
	lines = append(lines, "largest bootstrap production files:")
	for i := 0; i < limit; i++ {
		lines = append(lines, fmt.Sprintf("- %s: %d", counts[i].path, counts[i].lines))
	}
	return strings.Join(lines, "\n")
}
