package archtests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeepSecConfigKeepsSecurityCriticalSurfacesInScope(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, ".deepsec", "data", "cerebro", "config.json"))
	if err != nil {
		t.Fatalf("read deepsec project config: %v", err)
	}
	var config struct {
		IgnorePaths []string `json:"ignorePaths"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatalf("decode deepsec project config: %v", err)
	}
	for _, ignored := range config.IgnorePaths {
		normalized := strings.TrimSpace(ignored)
		if normalized == "" {
			continue
		}
		for _, forbidden := range []string{
			".github/",
			"api/",
			"docs/",
			"internal/",
			"policies/",
			"sources/",
			"tools/",
		} {
			if ignorePathCoversDeepSecSurface(normalized, forbidden) {
				t.Fatalf("deepsec ignorePaths excludes security-critical surface %q via %q", forbidden, normalized)
			}
		}
		if strings.Contains(normalized, "_test.go") {
			t.Fatalf("deepsec ignorePaths excludes tests via %q", normalized)
		}
	}

	deepsecConfig, err := os.ReadFile(filepath.Join(root, ".deepsec", "deepsec.config.ts"))
	if err != nil {
		t.Fatalf("read deepsec config: %v", err)
	}
	text := string(deepsecConfig)
	for _, required := range []string{
		`".github/workflows/"`,
		`"api/"`,
		`"internal/bootstrap/"`,
		`"internal/connectorcatalog/"`,
		`"internal/deviceauth/"`,
		`"internal/graphagent/"`,
		`"internal/sourcehttp/"`,
		`"internal/sourceruntime/"`,
		`"policies/"`,
		`"sources/"`,
		`"tools/"`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("deepsec priorityPaths missing %s", required)
		}
	}
}

func ignorePathCoversDeepSecSurface(pattern string, surface string) bool {
	normalized := strings.TrimPrefix(filepath.ToSlash(strings.TrimSpace(pattern)), "./")
	surface = filepath.ToSlash(strings.TrimSpace(surface))
	if normalized == "" || surface == "" {
		return false
	}
	if strings.HasPrefix(normalized, surface) {
		return true
	}
	for strings.HasPrefix(normalized, "**/") {
		normalized = strings.TrimPrefix(normalized, "**/")
		if strings.HasPrefix(normalized, surface) {
			return true
		}
	}
	return strings.Contains(normalized, "/"+surface)
}

func TestIgnorePathCoversDeepSecSurfaceDetectsGlobBypass(t *testing.T) {
	if !ignorePathCoversDeepSecSurface("**/internal/**", "internal/") {
		t.Fatal("glob-prefixed internal ignore path was not detected")
	}
	if !ignorePathCoversDeepSecSurface("foo/tools/**", "tools/") {
		t.Fatal("nested tools ignore path was not detected")
	}
	if ignorePathCoversDeepSecSurface("tmp/internal-not-surface/**", "internal/") {
		t.Fatal("non-surface segment was treated as ignored internal surface")
	}
}
