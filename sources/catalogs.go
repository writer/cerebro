// Package sourcecatalogs exposes the checked-in portable source catalogs as one
// data index. Standard sources can retain event, coverage, and lifecycle
// contracts without compiling every provider-specific Go package.
package sourcecatalogs

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

var sourceIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

//go:embed */catalog.yaml
var builtinCatalogFS embed.FS

// BuiltinCatalog returns the portable source catalog for one validated source
// identifier.
func BuiltinCatalog(sourceID string) ([]byte, error) {
	sourceID = strings.TrimSpace(sourceID)
	if !sourceIDPattern.MatchString(sourceID) {
		return nil, fmt.Errorf("invalid source id %q", sourceID)
	}
	payload, err := builtinCatalogFS.ReadFile(sourceID + "/catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("read source catalog %q: %w", sourceID, err)
	}
	return payload, nil
}

// BuiltinCatalogKeys returns every embedded catalog path key in deterministic
// order. A few bespoke packages intentionally use a legacy directory name that
// differs from the source ID stored in the catalog.
func BuiltinCatalogKeys() ([]string, error) {
	paths, err := fs.Glob(builtinCatalogFS, "*/catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("list source catalogs: %w", err)
	}
	ids := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		sourceID := strings.TrimSuffix(path, "/catalog.yaml")
		if !sourceIDPattern.MatchString(sourceID) {
			return nil, fmt.Errorf("invalid embedded source id %q", sourceID)
		}
		if _, ok := seen[sourceID]; ok {
			return nil, fmt.Errorf("duplicate embedded source id %q", sourceID)
		}
		seen[sourceID] = struct{}{}
		ids = append(ids, sourceID)
	}
	sort.Strings(ids)
	return ids, nil
}
