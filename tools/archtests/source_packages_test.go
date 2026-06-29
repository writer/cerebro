package archtests

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const newSourcePackageLOCBudget = 300

// Grandfathered budgets are exact current nonblank Go LOC ceilings for legacy
// sources. If a source shrinks, lower its ceiling in the same change; if a
// source grows, move shared behavior into the Source CDK instead of raising it.
var grandfatheredSourcePackageLOCBudgets = map[string]int{
	"aurelius":        619,
	"aws":             19078,
	"azure":           2858,
	"cosmo":           1006,
	"gcp":             2130,
	"github":          2024,
	"googleworkspace": 815,
	"grc":             1195,
	"okta":            2256,
	"panopticon":      763,
	"sentinelone":     2112,
	"vulnview":        1002,
}

func TestSourcePackagesHaveCatalogFixturesAndTests(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "sources"))
	if err != nil {
		t.Fatalf("ReadDir(sources): %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if entry.Name() == "internal" {
			continue
		}
		sourceDir := filepath.Join("..", "..", "sources", entry.Name())
		if _, err := os.Stat(filepath.Join(sourceDir, "catalog.yaml")); err != nil {
			t.Fatalf("%s missing catalog.yaml: %v", entry.Name(), err)
		}
		files, err := os.ReadDir(sourceDir)
		if err != nil {
			t.Fatalf("ReadDir(%s): %v", sourceDir, err)
		}
		hasTest := false
		for _, file := range files {
			if strings.HasSuffix(file.Name(), "_test.go") {
				hasTest = true
				break
			}
		}
		if !hasTest {
			t.Fatalf("%s missing replay/unit test", entry.Name())
		}
		testdata, err := os.ReadDir(filepath.Join(sourceDir, "testdata"))
		if err != nil {
			t.Fatalf("%s missing testdata: %v", entry.Name(), err)
		}
		if len(testdata) == 0 {
			t.Fatalf("%s testdata is empty", entry.Name())
		}
	}
}

func TestSourcePackagesStayWithinLOCBudget(t *testing.T) {
	root := repoRoot(t)
	sourceRoot := filepath.Join(root, "sources")
	entries, err := os.ReadDir(sourceRoot)
	if err != nil {
		t.Fatalf("ReadDir(sources): %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "internal" {
			continue
		}
		limit := newSourcePackageLOCBudget
		if grandfatheredLimit, ok := grandfatheredSourcePackageLOCBudgets[entry.Name()]; ok {
			limit = grandfatheredLimit
		}
		lines, err := sourcePackageGoLines(filepath.Join(sourceRoot, entry.Name()))
		if err != nil {
			t.Fatalf("count source LOC for %s: %v", entry.Name(), err)
		}
		if lines > limit {
			t.Fatalf("sources/%s has %d Go LOC, budget is %d; move shared I/O/pagination logic into the Source CDK instead of raising the ratchet", entry.Name(), lines, limit)
		}
	}
}

func TestGrandfatheredSourceLOCBudgetsRatchetDownToCurrentSize(t *testing.T) {
	root := repoRoot(t)
	sourceRoot := filepath.Join(root, "sources")
	for name, budget := range grandfatheredSourcePackageLOCBudgets {
		lines, err := sourcePackageGoLines(filepath.Join(sourceRoot, name))
		if err != nil {
			t.Fatalf("count source LOC for %s: %v", name, err)
		}
		if lines != budget {
			t.Fatalf("sources/%s has %d Go LOC but grandfathered budget is %d; keep legacy source budgets as exact no-growth ceilings", name, lines, budget)
		}
	}
}

func TestGrandfatheredSourceExtractionPlanIsDocumented(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "docs", "engineering", "source-cdk-extraction.md"))
	if err != nil {
		t.Fatalf("read docs/engineering/source-cdk-extraction.md: %v", err)
	}
	text := string(body)
	for _, marker := range []string{
		"New source packages must stay at or below 300 nonblank Go LOC",
		"exact no-growth ceilings",
		"Move provider client construction, retry policy, and pagination loops",
		"Keep normalization, graph projection, persistence, and finding logic outside",
	} {
		if !strings.Contains(text, marker) {
			t.Fatalf("docs/engineering/source-cdk-extraction.md missing extraction marker %q", marker)
		}
	}
	for name, budget := range grandfatheredSourcePackageLOCBudgets {
		marker := fmt.Sprintf("| `%s` | %d |", name, budget)
		if !strings.Contains(text, marker) {
			t.Fatalf("docs/engineering/source-cdk-extraction.md missing grandfathered source marker %q", marker)
		}
	}
}

func sourcePackageGoLines(dir string) (int, error) {
	total := 0
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "testdata":
				return filepath.SkipDir
			default:
				return nil
			}
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(body), "\n") {
			if strings.TrimSpace(line) != "" {
				total++
			}
		}
		return nil
	})
	return total, err
}
