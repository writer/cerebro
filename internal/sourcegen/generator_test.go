package sourcegen

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/tools/sourcedeploy"
)

func TestGenerateWritesSourceRuntimeSDKScaffold(t *testing.T) {
	outputDir := t.TempDir()
	result, err := Generate(Request{
		SourceID:             "demo_source",
		SourceType:           SourceTypeJSONAPI,
		AuthModel:            AuthModelBearerToken,
		AssetSchemas:         []string{"host"},
		FindingSchemas:       []string{"vulnerability"},
		FreshnessExpectation: "2h",
		FailureModes:         []string{"auth_error", "rate_limit"},
		OutputDir:            outputDir,
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if result.DryRun {
		t.Fatal("DryRun = true, want false")
	}
	for _, path := range []string{
		"sources/demo_source/catalog.yaml",
		"sources/demo_source/deploy.yaml",
		"sources/demo_source/source.go",
		"sources/demo_source/source_test.go",
		"sources/demo_source/source_health_receipt.json",
		"sources/demo_source/SOURCE_RUNTIME.md",
		"sources/demo_source/PR_BODY.md",
		"internal/sourceprojection/demo_source.go",
		"internal/sourceprojection/demo_source_test.go",
	} {
		if _, err := os.Stat(filepath.Join(outputDir, path)); err != nil {
			t.Fatalf("generated %s: %v", path, err)
		}
	}
	catalog := readGeneratedFile(t, outputDir, "sources/demo_source/catalog.yaml")
	for _, want := range []string{
		"id: demo_source",
		"- demo_source.asset_host",
		"- demo_source.finding_vulnerability",
		"- demo_source.evidence_cas_reference",
		"schema_ref: demo_source/asset_host/v1",
	} {
		if !strings.Contains(catalog, want) {
			t.Fatalf("catalog missing %q:\n%s", want, catalog)
		}
	}
	receipt := map[string]any{}
	if err := json.Unmarshal([]byte(readGeneratedFile(t, outputDir, "sources/demo_source/source_health_receipt.json")), &receipt); err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	if got := receipt["health_endpoint"]; got != "/source-runtimes/health?source_id=demo_source" {
		t.Fatalf("health_endpoint = %#v", got)
	}
	if got := receipt["stale_after_seconds"]; got != float64(7200) {
		t.Fatalf("stale_after_seconds = %#v, want 7200", got)
	}
	deploy, err := sourcedeploy.Parse([]byte(readGeneratedFile(t, outputDir, "sources/demo_source/deploy.yaml")), "generated")
	if err != nil {
		t.Fatalf("parse deploy manifest: %v", err)
	}
	if len(deploy.Runtimes) != 1 {
		t.Fatalf("deploy runtimes = %d, want 1", len(deploy.Runtimes))
	}
	config := deploy.Runtimes[0].Config
	if config["expected_cadence_seconds"] != "7200" || config["stale_after_seconds"] != "7200" {
		t.Fatalf("deploy freshness config = %#v", config)
	}
	sourceTest := readGeneratedFile(t, outputDir, "sources/demo_source/source_test.go")
	authCheck := strings.Index(sourceTest, `r.Header.Get("Authorization")`)
	healthCheck := strings.Index(sourceTest, `r.URL.Path == defaultHealthPath`)
	if authCheck < 0 || healthCheck < 0 || authCheck > healthCheck {
		t.Fatalf("generated source test must assert health auth before health short-circuit:\n%s", sourceTest)
	}
}

func TestGenerateDryRunDoesNotWriteFiles(t *testing.T) {
	outputDir := t.TempDir()
	result, err := Generate(Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host"},
		OutputDir:    outputDir,
		DryRun:       true,
	})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if !result.DryRun {
		t.Fatal("DryRun = false, want true")
	}
	if len(result.Files) == 0 {
		t.Fatal("dry run did not report generated files")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "sources/demo_source/source.go")); !os.IsNotExist(err) {
		t.Fatalf("source.go exists after dry run, err=%v", err)
	}
}

func TestGenerateRejectsMissingSchemas(t *testing.T) {
	_, err := Generate(Request{SourceID: "demo_source"})
	if err == nil {
		t.Fatal("Generate() error = nil, want error")
	}
	if !errors.Is(err, errMissingSchemas) {
		t.Fatalf("Generate() error = %v, want errMissingSchemas", err)
	}
}

func TestGenerateRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		request Request
	}{
		{
			name:    "bad source id",
			request: Request{SourceID: "Demo", AssetSchemas: []string{"host"}},
		},
		{
			name:    "unsupported source type",
			request: Request{SourceID: "demo_source", SourceType: "webhook", AssetSchemas: []string{"host"}},
		},
		{
			name:    "unsupported auth model",
			request: Request{SourceID: "demo_source", AuthModel: "oauth", AssetSchemas: []string{"host"}},
		},
		{
			name:    "bad schema",
			request: Request{SourceID: "demo_source", AssetSchemas: []string{"Host"}},
		},
		{
			name:    "too fresh",
			request: Request{SourceID: "demo_source", AssetSchemas: []string{"host"}, FreshnessExpectation: "30s"},
		},
		{
			name:    "bad health path",
			request: Request{SourceID: "demo_source", AssetSchemas: []string{"host"}, HealthPath: "/readyz bad"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Generate(test.request); err == nil {
				t.Fatal("Generate() error = nil, want error")
			}
		})
	}
}

func TestGenerateRejectsGeneratedIdentifierCollision(t *testing.T) {
	_, err := Generate(Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host-name", "host_name"},
		OutputDir:    t.TempDir(),
	})
	if err == nil {
		t.Fatal("Generate() error = nil, want collision error")
	}
	if !errors.Is(err, errGeneratedNameCollision) {
		t.Fatalf("Generate() error = %v, want errGeneratedNameCollision", err)
	}
}

func TestGenerateQuotesCatalogText(t *testing.T) {
	outputDir := t.TempDir()
	name := "Demo: Source # One"
	description := "line one\nline two: yes"
	if _, err := Generate(Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host"},
		Name:         name,
		Description:  description,
		OutputDir:    outputDir,
	}); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	spec, err := sourcecdk.LoadCatalog([]byte(readGeneratedFile(t, outputDir, "sources/demo_source/catalog.yaml")))
	if err != nil {
		t.Fatalf("LoadCatalog() error = %v", err)
	}
	if spec.GetName() != name || spec.GetDescription() != description {
		t.Fatalf("catalog spec = %#v", spec)
	}
}

func TestGeneratePreflightsExistingFilesBeforeWriting(t *testing.T) {
	outputDir := t.TempDir()
	existing := filepath.Join(outputDir, "sources", "demo_source", "source.go")
	if err := os.MkdirAll(filepath.Dir(existing), 0o750); err != nil {
		t.Fatalf("mkdir existing fixture: %v", err)
	}
	if err := os.WriteFile(existing, []byte("existing"), 0o600); err != nil {
		t.Fatalf("write existing fixture: %v", err)
	}
	if _, err := Generate(Request{
		SourceID:     "demo_source",
		AssetSchemas: []string{"host"},
		OutputDir:    outputDir,
	}); err == nil {
		t.Fatal("Generate() error = nil, want existing file error")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "sources", "demo_source", "catalog.yaml")); !os.IsNotExist(err) {
		t.Fatalf("catalog.yaml was written before preflight completed, err=%v", err)
	}
}

func TestGenerateFindingOnlyScaffold(t *testing.T) {
	outputDir := t.TempDir()
	if _, err := Generate(Request{
		SourceID:       "demo_source",
		FindingSchemas: []string{"vulnerability"},
		OutputDir:      outputDir,
	}); err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	source := readGeneratedFile(t, outputDir, "sources/demo_source/source.go")
	for _, want := range []string{"familyFindingVulnerability", `"/findings/vulnerability"`, `"finding_id": "finding_id|id"`} {
		if !strings.Contains(source, want) {
			t.Fatalf("source.go missing %q:\n%s", want, source)
		}
	}
	projection := readGeneratedFile(t, outputDir, "internal/sourceprojection/demo_source.go")
	for _, want := range []string{"demoSourceFindingVulnerabilityProjections", "demoSourceFindingProjections", "relationAffects", "relationSupports"} {
		if !strings.Contains(projection, want) {
			t.Fatalf("projection missing %q:\n%s", want, projection)
		}
	}
}

func FuzzGenerateDryRun(f *testing.F) {
	f.Add("demo_source", AuthModelBearerToken, "host", "vulnerability", "2h", "/readyz", "auth_error")
	f.Add("demo-source", AuthModelAPIToken, "asset", "", "24h", "/healthz", "rate_limit")
	f.Add("bad source", "oauth", "Host", "Finding", "30s", "/bad path", "schema_drift")

	f.Fuzz(func(t *testing.T, sourceID string, authModel string, assetSchema string, findingSchema string, freshness string, healthPath string, failureMode string) {
		if len(sourceID) > 64 || len(authModel) > 32 || len(assetSchema) > 64 || len(findingSchema) > 64 || len(freshness) > 32 || len(healthPath) > 128 || len(failureMode) > 64 {
			return
		}

		result, err := Generate(Request{
			SourceID:             sourceID,
			SourceType:           SourceTypeJSONAPI,
			AuthModel:            authModel,
			AssetSchemas:         []string{assetSchema},
			FindingSchemas:       []string{findingSchema},
			FreshnessExpectation: freshness,
			FailureModes:         []string{failureMode},
			HealthPath:           healthPath,
			OutputDir:            "out",
			DryRun:               true,
		})
		if err != nil {
			return
		}
		if result == nil {
			t.Fatal("Generate() returned nil result with nil error")
		}
		if !result.DryRun {
			t.Fatal("DryRun = false, want true")
		}
		if result.SourceID == "" || result.SourceType != SourceTypeJSONAPI || result.AuthModel == "" {
			t.Fatalf("incomplete result = %#v", result)
		}
		if len(result.Files) == 0 {
			t.Fatal("successful dry run reported no files")
		}
		for _, path := range result.Files {
			clean := filepath.Clean(path)
			if filepath.IsAbs(clean) || !strings.HasPrefix(clean, "out"+string(os.PathSeparator)) {
				t.Fatalf("generated path escaped output dir: %q", path)
			}
		}
		if !strings.Contains(result.SourceHealthReceipt, result.SourceID) || !strings.Contains(result.PRBody, result.SourceID) {
			t.Fatalf("receipt/PR paths do not include source id: %#v", result)
		}
	})
}

func readGeneratedFile(t *testing.T, root string, path string) string {
	t.Helper()
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("abs root: %v", err)
	}
	fullPath := filepath.Join(cleanRoot, filepath.Clean(path))
	payload, err := os.ReadFile(fullPath) // #nosec G304 -- generated file path is under this test's temporary output directory.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(payload)
}
