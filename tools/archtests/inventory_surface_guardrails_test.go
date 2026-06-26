package archtests

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/graphquery"
)

func TestInventorySurfaceDefaultsRemainCompatible(t *testing.T) {
	if got := graphquery.NormalizeInventorySurface(""); got != graphquery.InventorySurfaceAll {
		t.Fatalf("omitted inventory surface = %q, want %q for API compatibility", got, graphquery.InventorySurfaceAll)
	}
	if got := graphquery.NormalizeInventorySurface("unknown"); got != graphquery.InventorySurfaceAsset {
		t.Fatalf("unknown inventory surface = %q, want conservative %q", got, graphquery.InventorySurfaceAsset)
	}
}

func TestInventorySurfaceClassifierKeepsFutureSignalNamesReviewable(t *testing.T) {
	for _, entityType := range []string{"custom_vendor.alert", "internal.finding", "partner_threat"} {
		if got := graphquery.InventorySurfaceForEntityType(entityType); got != graphquery.InventorySurfaceAsset {
			t.Fatalf("future entity type %q surface = %q, want %q until explicitly allowlisted", entityType, got, graphquery.InventorySurfaceAsset)
		}
	}
	for _, entityType := range []string{"aws.securityhub.finding", "panopticon.alert", "github.secret_scanning_alert"} {
		if got := graphquery.InventorySurfaceForEntityType(entityType); got != graphquery.InventorySurfaceSignal {
			t.Fatalf("known signal entity type %q surface = %q, want %q", entityType, got, graphquery.InventorySurfaceSignal)
		}
	}
}

func TestInventorySurfaceRulesDoNotUseBroadSuffixDemotion(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "internal", "graphquery", "inventory_surface.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse inventory_surface.go: %v", err)
	}
	forbidden := map[string]struct{}{
		".alert": {}, "_alert": {},
		".advisory": {}, "_advisory": {},
		".evidence": {}, "_evidence": {},
		".finding": {}, "_finding": {},
		".threat": {}, "_threat": {},
	}
	ast.Inspect(file, func(node ast.Node) bool {
		value, ok := inventorySurfaceStringLiteralValue(node)
		if !ok {
			return true
		}
		if _, blocked := forbidden[value]; blocked {
			t.Fatalf("inventory surface string literal %q is too broad; add exact or narrow prefix rules instead", value)
		}
		return true
	})
}

func TestInventorySurfaceOpenAPIDocumentsOmittedAllRecords(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read openapi.yaml: %v", err)
	}
	if !strings.Contains(string(body), "description: Inventory record surface. Omit for all records; pass asset for reviewable assets only.") {
		t.Fatal("inventory surface OpenAPI parameter must document omitted surface as all records and asset as the reviewable-asset filter")
	}
}

func inventorySurfaceStringLiteralValue(node ast.Node) (string, bool) {
	basic, ok := node.(*ast.BasicLit)
	if !ok || basic.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(basic.Value)
	if err != nil {
		return "", false
	}
	return value, true
}
