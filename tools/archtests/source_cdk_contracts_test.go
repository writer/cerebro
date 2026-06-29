package archtests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var helperDuplicationGrandfatheredSources = map[string]struct{}{}

func TestNewSourcesDoNotDuplicateSourceCDKHelpers(t *testing.T) {
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
		if _, ok := helperDuplicationGrandfatheredSources[entry.Name()]; ok {
			continue
		}
		sourcePath := filepath.Join(sourceRoot, entry.Name(), "source.go")
		body, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatalf("read %s: %v", sourcePath, err)
		}
		text := string(body)
		for _, duplicated := range []string{
			"func renderTemplate(",
			"func requiredConfigValue(",
			"func configValue(",
			"func isUnsafeHost(",
			"func isLoopbackHost(",
			"func parseTimeSelector(",
			"func addQuery(",
		} {
			if strings.Contains(text, duplicated) {
				t.Fatalf("sources/%s duplicates Source CDK helper %s", entry.Name(), duplicated)
			}
		}
	}
}

func TestGeneratedSourceUsesSourceCDKTemplateHelpers(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "internal", "sourcegen", "generator.go"))
	if err != nil {
		t.Fatalf("read generator.go: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"sourcehttp.ResolveClientCredentialsRuntimeConfig",
		"sourcecdk.ConfigValue",
		"kind_lifecycle:",
		"status: active",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("generator.go missing %q", want)
		}
	}
	for _, duplicated := range []string{
		"func renderTemplate(template string, cfg sourcecdk.Config)",
		"func requiredConfigValue(cfg sourcecdk.Config, key string)",
	} {
		if strings.Contains(text, duplicated) {
			t.Fatalf("generator.go still emits duplicated helper %q", duplicated)
		}
	}
}
