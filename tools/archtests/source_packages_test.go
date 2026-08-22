package archtests

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/connectorcatalog"
)

const newSourcePackageLOCBudget = 300

// deepTierSourcePackages are promoted to the Deep source tier: they are exempt
// from the flat LOC budget and instead held to the Depth Contract
// (connectorcatalog.RuntimeDepth score of 100). See docs/engineering/non-goals.md
// "Sources are tiered" and docs/engineering/source-cdk-extraction.md "Deep Source
// Tier". Adding a source here without it meeting the Depth Contract fails
// TestDeepTierSourcesMeetDepthContract.
var deepTierSourcePackages = map[string]struct{}{
	"digitalocean": {},
}

// catalogRuntimeOnlySourcePackages have retired their provider-local Go
// runtime. Their portable catalog and Rust catalog-runtime coverage remain the
// production and parity contracts, so source.go and Go-only runtime tests must
// not be restored.
var priorCatalogRuntimeOnlySourcePackages = map[string]struct{}{
	"acunetix":        {},
	"adobe_workfront": {},
	"aircall":         {},
	"airfocus":        {},
	"akeyless":        {},
	"backstage":       {},
	"beezup":          {},
	"bitwarden":       {},
	"box":             {},
	"conjur":          {},
	"datadog":         {},
	"duo":             {},
	"fivetran":        {},
	"increase":        {},
	"jira":            {},
	"langchain":       {},
	"deepseek":        {},
	"openai":          {},
	"slack":           {},
}

//go:embed testdata/catalog_runtime_go_retirement_v1.txt
var catalogRuntimeGoRetirementInventory string

const (
	catalogRuntimeGoRetirementCount  = 758
	catalogRuntimeGoRetirementSHA256 = "8fe6562af550c2c164db03cecd719f80dc5595db2a4d3f4dd34e82c6cec80133"
)

var catalogRuntimeOnlySourcePackages = catalogRuntimeOnlyPackages()

func catalogRuntimeOnlyPackages() map[string]struct{} {
	packages := make(map[string]struct{}, len(priorCatalogRuntimeOnlySourcePackages)+catalogRuntimeGoRetirementCount)
	for name := range priorCatalogRuntimeOnlySourcePackages {
		packages[name] = struct{}{}
	}
	for _, name := range strings.Split(strings.TrimSpace(catalogRuntimeGoRetirementInventory), "\n") {
		packages[name] = struct{}{}
	}
	return packages
}

const deepTierDepthContractScore = 100

func TestCatalogRuntimeGoRetirementInventoryIsDeterministic(t *testing.T) {
	entries := strings.Split(strings.TrimSpace(catalogRuntimeGoRetirementInventory), "\n")
	if len(entries) != catalogRuntimeGoRetirementCount {
		t.Fatalf("catalog-runtime retirement inventory has %d sources, want %d", len(entries), catalogRuntimeGoRetirementCount)
	}
	if !sort.StringsAreSorted(entries) {
		t.Fatal("catalog-runtime retirement inventory is not sorted")
	}
	root := repoRoot(t)
	for index, name := range entries {
		if strings.TrimSpace(name) != name || name == "" {
			t.Fatalf("catalog-runtime retirement inventory entry %d is invalid: %q", index, name)
		}
		if index > 0 && entries[index-1] == name {
			t.Fatalf("catalog-runtime retirement inventory repeats %q", name)
		}
		sourceRoot := filepath.Join(root, "sources", name)
		if _, err := os.Stat(filepath.Join(sourceRoot, "catalog.yaml")); err != nil {
			t.Fatalf("catalog-runtime retirement inventory source %q has no catalog: %v", name, err)
		}
		goFiles, err := filepath.Glob(filepath.Join(sourceRoot, "*.go"))
		if err != nil {
			t.Fatalf("find Go files for catalog-runtime source %q: %v", name, err)
		}
		if len(goFiles) != 0 {
			t.Fatalf("catalog-runtime source %q restored provider-local Go files: %v", name, goFiles)
		}
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(catalogRuntimeGoRetirementInventory)))
	if digest != catalogRuntimeGoRetirementSHA256 {
		t.Fatalf("catalog-runtime retirement inventory digest = %s, want %s", digest, catalogRuntimeGoRetirementSHA256)
	}
	if _, retired := catalogRuntimeOnlySourcePackages["github"]; retired {
		t.Fatal("GitHub remains Go-authoritative and must not enter the catalog-runtime retirement inventory")
	}
	if _, retired := catalogRuntimeOnlySourcePackages["slack"]; !retired {
		t.Fatal("Slack provider-local Go must remain retired")
	}
}

// Grandfathered budgets are exact current nonblank Go LOC ceilings for legacy
// sources. If a source shrinks, lower its ceiling in the same change; if a
// source grows, move shared behavior into the Source CDK instead of raising it.
var grandfatheredSourcePackageLOCBudgets = map[string]int{
	"aurelius":        619,
	"aws":             19046,
	"azure":           2858,
	"cosmo":           1006,
	"gcp":             2130,
	"github":          2009,
	"googleworkspace": 814,
	"grc":             1195,
	"okta":            2239,
	"panopticon":      763,
	"sentinelone":     2096,
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
		_, catalogRuntimeOnly := catalogRuntimeOnlySourcePackages[entry.Name()]
		if _, err := os.Stat(filepath.Join(sourceDir, "catalog.yaml")); err != nil {
			t.Fatalf("%s missing catalog.yaml: %v", entry.Name(), err)
		}
		if catalogRuntimeOnly {
			goFiles, err := filepath.Glob(filepath.Join(sourceDir, "*.go"))
			if err != nil {
				t.Fatalf("find Go files for catalog-runtime source %s: %v", entry.Name(), err)
			}
			if len(goFiles) != 0 {
				t.Fatalf("%s restored retired provider-local Go files: %v", entry.Name(), goFiles)
			}
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
		if !hasTest && !catalogRuntimeOnly {
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
		if _, ok := deepTierSourcePackages[entry.Name()]; ok {
			// Deep-tier sources are bounded by the Depth Contract, not the LOC
			// budget; see TestDeepTierSourcesMeetDepthContract.
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

func TestDeepTierSourcesMeetDepthContract(t *testing.T) {
	if len(deepTierSourcePackages) == 0 {
		t.Skip("no deep-tier sources registered")
	}
	root := repoRoot(t)
	inventory, err := connectorcatalog.DiscoverRuntimeDepth(root)
	if err != nil {
		t.Fatalf("DiscoverRuntimeDepth: %v", err)
	}
	for name := range deepTierSourcePackages {
		depth, ok := inventory[name]
		if !ok {
			t.Fatalf("deep-tier source %q has no runtime depth inventory entry", name)
		}
		if depth.Score != deepTierDepthContractScore {
			t.Fatalf("deep-tier source %q runtime depth score = %d (missing=%v), want %d; a Deep source must meet the Depth Contract in exchange for exceeding the LOC budget", name, depth.Score, depth.Missing, deepTierDepthContractScore)
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
		if isSourcegenGeneratedBody(body) {
			return nil
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
