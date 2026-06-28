package connectorcatalog

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuntimeDepthInventory maps source IDs to repository evidence for a concrete
// Source CDK package. Catalog-only connector definitions will not have an entry.
type RuntimeDepthInventory map[string]RuntimeDepth

// RuntimeDepth captures the repository-level implementation signals expected
// from reference sources such as GitHub: source package, catalog, fixtures,
// deploy manifest, and projector coverage.
type RuntimeDepth struct {
	SourceID                string   `json:"source_id"`
	PackagePath             string   `json:"package_path,omitempty"`
	Score                   int      `json:"score"`
	Missing                 []string `json:"missing,omitempty"`
	HasSourcePackage        bool     `json:"has_source_package,omitempty"`
	HasSourceCatalog        bool     `json:"has_source_catalog,omitempty"`
	HasSourceImplementation bool     `json:"has_source_implementation,omitempty"`
	HasSourceTests          bool     `json:"has_source_tests,omitempty"`
	HasReadFixtures         bool     `json:"has_read_fixtures,omitempty"`
	HasDiscoverFixtures     bool     `json:"has_discover_fixtures,omitempty"`
	HasFixturePair          bool     `json:"has_fixture_pair,omitempty"`
	HasDeployManifest       bool     `json:"has_deploy_manifest,omitempty"`
	HasProjectorTests       bool     `json:"has_projector_tests,omitempty"`
	HasEventContracts       bool     `json:"has_event_contracts,omitempty"`
	HasCoverageContract     bool     `json:"has_coverage_contract,omitempty"`
	RuntimeFamilies         []string `json:"runtime_families,omitempty"`
	ReadFixtureFamilies     []string `json:"read_fixture_families,omitempty"`
	DiscoverFixtureFamilies []string `json:"discover_fixture_families,omitempty"`
}

type runtimeCatalogFields struct {
	ID              string   `yaml:"id"`
	RuntimeFamilies []string `yaml:"runtime_families"`
	EventContracts  []struct {
		Kind string `yaml:"kind"`
	} `yaml:"event_contracts"`
	CoverageContract *struct{} `yaml:"coverage_contract"`
}

// DiscoverRuntimeDepth scans repository source packages and sourceprojection
// tests for reference-runtime evidence. Missing sources/ is treated as an empty
// inventory so callers can use the review tool on partial checkouts.
func DiscoverRuntimeDepth(root string) (RuntimeDepthInventory, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "" || root == "." {
		root = "."
	}
	repoRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("open repository root: %w", err)
	}
	defer func() {
		_ = repoRoot.Close()
	}()
	inventory := RuntimeDepthInventory{}
	projectorTests, err := discoverProjectorTestSources(repoRoot)
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(repoRoot.FS(), "sources")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return inventory, nil
		}
		return nil, fmt.Errorf("read sources directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sourceDir := filepath.Join(root, "sources", entry.Name())
		depth, err := inspectRuntimeDepth(root, repoRoot, sourceDir, projectorTests)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(depth.SourceID) == "" {
			continue
		}
		inventory[depth.SourceID] = depth
	}
	return inventory, nil
}

func inspectRuntimeDepth(root string, repoRoot *os.Root, sourceDir string, projectorTests map[string]struct{}) (RuntimeDepth, error) {
	sourceID := filepath.Base(sourceDir)
	depth := RuntimeDepth{
		SourceID:         sourceID,
		PackagePath:      slashRel(root, sourceDir),
		HasSourcePackage: true,
	}
	if hasRegularFile(filepath.Join(sourceDir, "catalog.yaml")) {
		depth.HasSourceCatalog = true
		catalog, err := readRuntimeCatalogFields(repoRoot, filepath.ToSlash(filepath.Join(depth.PackagePath, "catalog.yaml")))
		if err != nil {
			return RuntimeDepth{}, err
		}
		if strings.TrimSpace(catalog.ID) != "" {
			depth.SourceID = strings.TrimSpace(catalog.ID)
		}
		depth.RuntimeFamilies = normalizedList(catalog.RuntimeFamilies)
		depth.HasEventContracts = len(catalog.EventContracts) > 0
		depth.HasCoverageContract = catalog.CoverageContract != nil
	}
	depth.HasSourceImplementation = hasRegularFile(filepath.Join(sourceDir, "source.go"))
	depth.HasSourceTests = hasSourceTests(sourceDir)
	depth.HasDeployManifest = hasRegularFile(filepath.Join(sourceDir, "deploy.yaml"))
	depth.ReadFixtureFamilies, depth.DiscoverFixtureFamilies = fixtureFamilies(sourceDir)
	depth.HasReadFixtures = len(depth.ReadFixtureFamilies) > 0
	depth.HasDiscoverFixtures = len(depth.DiscoverFixtureFamilies) > 0
	depth.HasFixturePair = hasFixturePair(depth.ReadFixtureFamilies, depth.DiscoverFixtureFamilies)
	_, depth.HasProjectorTests = projectorTests[depth.SourceID]
	depth.Score, depth.Missing = runtimeDepthScore(depth)
	sort.Strings(depth.RuntimeFamilies)
	sort.Strings(depth.ReadFixtureFamilies)
	sort.Strings(depth.DiscoverFixtureFamilies)
	sort.Strings(depth.Missing)
	return depth, nil
}

func readRuntimeCatalogFields(repoRoot *os.Root, path string) (runtimeCatalogFields, error) {
	payload, err := repoRoot.ReadFile(path)
	if err != nil {
		return runtimeCatalogFields{}, fmt.Errorf("read %s: %w", path, err)
	}
	var catalog runtimeCatalogFields
	if err := yaml.Unmarshal(payload, &catalog); err != nil {
		return runtimeCatalogFields{}, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return catalog, nil
}

func runtimeDepthScore(depth RuntimeDepth) (int, []string) {
	score := 0
	var missing []string
	if depth.HasSourcePackage {
		score += 10
	} else {
		missing = append(missing, "runtime:source_package")
	}
	if depth.HasSourceCatalog {
		score += 10
	} else {
		missing = append(missing, "runtime:catalog")
	}
	if depth.HasEventContracts && depth.HasCoverageContract {
		score += 15
	} else {
		missing = append(missing, "runtime:catalog_contracts")
	}
	if depth.HasSourceImplementation {
		score += 15
	} else {
		missing = append(missing, "runtime:source_go")
	}
	if depth.HasSourceTests {
		score += 15
	} else {
		missing = append(missing, "runtime:source_tests")
	}
	if depth.HasFixturePair {
		score += 15
	} else {
		missing = append(missing, "runtime:fixture_pair")
	}
	if depth.HasDeployManifest {
		score += 10
	} else {
		missing = append(missing, "runtime:deploy_manifest")
	}
	if depth.HasProjectorTests {
		score += 10
	} else {
		missing = append(missing, "runtime:projector_tests")
	}
	return score, missing
}

func hasRegularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func hasSourceTests(sourceDir string) bool {
	matches, err := filepath.Glob(filepath.Join(sourceDir, "*_test.go"))
	return err == nil && len(matches) > 0
}

func fixtureFamilies(sourceDir string) ([]string, []string) {
	testdata := filepath.Join(sourceDir, "testdata")
	entries, err := os.ReadDir(testdata)
	if err != nil {
		return nil, nil
	}
	read := map[string]struct{}{}
	discover := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		switch {
		case name == "read":
			read["default"] = struct{}{}
		case strings.HasPrefix(name, "read_"):
			read[strings.TrimPrefix(name, "read_")] = struct{}{}
		case name == "discover":
			discover["default"] = struct{}{}
		case strings.HasPrefix(name, "discover_"):
			discover[strings.TrimPrefix(name, "discover_")] = struct{}{}
		}
	}
	return sortedKeys(read), sortedKeys(discover)
}

func hasFixturePair(read []string, discover []string) bool {
	if len(read) == 0 || len(discover) == 0 {
		return false
	}
	discovered := map[string]struct{}{}
	for _, family := range discover {
		discovered[family] = struct{}{}
	}
	for _, family := range read {
		if _, ok := discovered[family]; ok {
			return true
		}
	}
	return false
}

func discoverProjectorTestSources(repoRoot *os.Root) (map[string]struct{}, error) {
	sources := map[string]struct{}{}
	const dir = "internal/sourceprojection"
	err := fs.WalkDir(repoRoot.FS(), dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		payload, err := repoRoot.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		for _, sourceID := range sourceIDsFromProjectorTest(string(payload)) {
			sources[sourceID] = struct{}{}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return sources, nil
		}
		return nil, err
	}
	return sources, nil
}

func sourceIDsFromProjectorTest(content string) []string {
	file, err := parser.ParseFile(token.NewFileSet(), "sourceprojection_test.go", content, 0)
	if err != nil {
		return nil
	}
	eventSources := map[string]struct{}{}
	kindSources := map[string]struct{}{}
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.ImportSpec:
			return false
		case *ast.KeyValueExpr:
			key, ok := n.Key.(*ast.Ident)
			if !ok {
				return true
			}
			value, ok := stringLiteralValue(n.Value)
			if !ok {
				return true
			}
			switch key.Name {
			case "SourceId":
				if sourceIDLooksStable(value) {
					eventSources[value] = struct{}{}
				}
			case "Kind":
				if sourceID, ok := sourceIDFromEventKindLiteral(value); ok {
					kindSources[sourceID] = struct{}{}
				}
			}
		case *ast.BasicLit:
			value, ok := stringLiteralValue(n)
			if !ok {
				return true
			}
			if sourceID, ok := sourceIDFromEventKindLiteral(value); ok {
				kindSources[sourceID] = struct{}{}
			}
		}
		return true
	})
	covered := map[string]struct{}{}
	for sourceID := range kindSources {
		if _, ok := eventSources[sourceID]; ok {
			covered[sourceID] = struct{}{}
		}
	}
	return sortedKeys(covered)
}

func stringLiteralValue(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(value), true
}

func sourceIDFromEventKindLiteral(value string) (string, bool) {
	if strings.Contains(value, "/") || strings.Contains(value, "@") || strings.Contains(value, "://") {
		return "", false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return "", false
	}
	for _, part := range parts {
		if !sourceIDLooksStable(part) {
			return "", false
		}
	}
	return parts[0], true
}

func sourceIDLooksStable(value string) bool {
	if len(value) < 2 {
		return false
	}
	if value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func normalizedList(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen[value] = struct{}{}
	}
	return sortedKeys(seen)
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func slashRel(root string, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
