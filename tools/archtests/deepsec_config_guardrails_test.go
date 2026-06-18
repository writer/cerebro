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
		for _, forbidden := range deepsecSecurityCriticalSurfaces() {
			if deepsecIgnorePathTouchesSurface(normalized, forbidden) {
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

func TestDeepSecIgnorePathSurfaceDetectionCatchesGlobBypasses(t *testing.T) {
	for _, tt := range []struct {
		name      string
		ignored   string
		forbidden string
		want      bool
	}{
		{name: "direct internal", ignored: "internal/**", forbidden: "internal/", want: true},
		{name: "glob-prefixed internal", ignored: "**/internal/**", forbidden: "internal/", want: true},
		{name: "nested api", ignored: "foo/api/**", forbidden: "api/", want: true},
		{name: "root github", ignored: "/.github/workflows/**", forbidden: ".github/", want: true},
		{name: "allowed vendor", ignored: "vendor/**", forbidden: "internal/"},
		{name: "allowed data", ignored: ".deepsec/data/**", forbidden: "docs/"},
		{name: "substring is not segment", ignored: "notinternal/**", forbidden: "internal/"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := deepsecIgnorePathTouchesSurface(tt.ignored, tt.forbidden); got != tt.want {
				t.Fatalf("deepsecIgnorePathTouchesSurface(%q, %q) = %v, want %v", tt.ignored, tt.forbidden, got, tt.want)
			}
		})
	}
}

func deepsecSecurityCriticalSurfaces() []string {
	return []string{
		".github/",
		"api/",
		"docs/",
		"internal/",
		"policies/",
		"sources/",
		"tools/",
	}
}

func deepsecIgnorePathTouchesSurface(ignored string, forbidden string) bool {
	normalized := strings.Trim(strings.ReplaceAll(strings.TrimSpace(ignored), "\\", "/"), "/")
	surface := strings.Trim(strings.TrimSpace(forbidden), "/")
	if normalized == "" || surface == "" {
		return false
	}
	if normalized == surface || strings.HasPrefix(normalized, surface+"/") {
		return true
	}
	return strings.Contains(normalized, "/"+surface+"/") || strings.HasSuffix(normalized, "/"+surface)
}
