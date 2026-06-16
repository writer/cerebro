package archtests

import (
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
	"aurelius":        653,
	"aws":             16652,
	"azure":           2582,
	"cosmo":           1112,
	"gcp":             2078,
	"github":          2194,
	"googleworkspace": 827,
	"grc":             1378,
	"okta":            2433,
	"panopticon":      820,
	"sentinelone":     2181,
	"vulnview":        1064,
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
