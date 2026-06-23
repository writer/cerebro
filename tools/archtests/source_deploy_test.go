package archtests

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/writer/cerebro/tools/sourcedeploy"
	"gopkg.in/yaml.v3"
)

// requireDeployManifest holds sources that must declare a deploy.yaml so the
// sourcedeploy synthesizer can render their Pulumi config. Sources that do
// not own runtimes (e.g. push-only SDK adapters, infrastructure scanners
// driven by the orchestrator default command) are exempt by being absent.
var requireDeployManifest = map[string]struct{}{
	"aws":              {},
	"azure":            {},
	"gcp":              {},
	"github":           {},
	"google_workspace": {},
	"grc":              {},
	"kandji":           {},
	"kolide":           {},
	"kubernetes":       {},
	"okta":             {},
	"sentinelone":      {},
	"trusted_endpoint": {},
	"vulnview":         {},
}

var requireSourceHealthReceipt = map[string]struct{}{
	"aws":         {},
	"github":      {},
	"grc":         {},
	"okta":        {},
	"sentinelone": {},
}

func TestSourceDeployManifestsAreValid(t *testing.T) {
	root := filepath.Join("..", "..", "sources")
	manifests, err := sourcedeploy.Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	have := make(map[string]struct{}, len(manifests))
	for _, manifest := range manifests {
		have[manifest.SourceID] = struct{}{}
	}

	missing := make([]string, 0)
	for id := range requireDeployManifest {
		if _, ok := have[id]; !ok {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("sources missing deploy.yaml: %v", missing)
	}

	for _, manifest := range manifests {
		if err := manifest.Validate(); err != nil {
			t.Fatalf("source %s: %v", manifest.SourceID, err)
		}
	}
}

func TestPrioritySourcesDeclareHealthReceipts(t *testing.T) {
	root := filepath.Join("..", "..", "sources")
	manifests, err := sourcedeploy.Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	contract, err := sourcedeploy.RenderContract(root, manifests, sourcedeploy.ContractOptions{
		Environment: "sec-dev",
		TenantID:    "writer",
	})
	if err != nil {
		t.Fatalf("RenderContract: %v", err)
	}

	receiptsBySource := make(map[string]map[string]any)
	for _, source := range contract.Sources {
		if source.SourceHealthReceipt != nil {
			receiptsBySource[source.SourceID] = source.SourceHealthReceipt
		}
	}

	missing := make([]string, 0)
	for id := range requireSourceHealthReceipt {
		receipt := receiptsBySource[id]
		if len(receipt) == 0 {
			missing = append(missing, id)
			continue
		}
		requireHealthReceiptField(t, id, receipt, "receipt_kind", "source_health.receipt")
		requireHealthReceiptField(t, id, receipt, "source_id", id)
		requireHealthReceiptField(t, id, receipt, "health_endpoint", "/source-runtimes/health?source_id="+id)
		requireNonEmptyHealthReceiptField(t, id, receipt, "source_type")
		requireNonEmptyHealthReceiptField(t, id, receipt, "auth_model")
		requireNonEmptyHealthReceiptField(t, id, receipt, "adapter_health_path")
		requireNonEmptyHealthReceiptField(t, id, receipt, "evidence_cas_reference_kind")
		requirePositiveHealthReceiptSeconds(t, id, receipt, "expected_cadence_seconds")
		requirePositiveHealthReceiptSeconds(t, id, receipt, "stale_after_seconds")
		requireNonEmptyHealthReceiptList(t, id, receipt, "failure_modes")
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("priority sources missing source_health_receipt.json: %v", missing)
	}
}

func TestCloudProviderDeployManifestsCoverRuntimeFamilies(t *testing.T) {
	root := filepath.Join("..", "..", "sources")
	manifests, err := sourcedeploy.Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	manifestBySource := make(map[string]sourcedeploy.Manifest, len(manifests))
	for _, manifest := range manifests {
		manifestBySource[manifest.SourceID] = manifest
	}

	for _, sourceID := range []string{"aws", "azure", "gcp"} {
		t.Run(sourceID, func(t *testing.T) {
			catalog := loadRuntimeFamilyCatalog(t, root, sourceID)
			manifest, ok := manifestBySource[sourceID]
			if !ok {
				t.Fatalf("%s deploy manifest not found", sourceID)
			}

			want := make(map[string]struct{}, len(catalog.RuntimeFamilies))
			for _, family := range catalog.RuntimeFamilies {
				if family = strings.TrimSpace(family); family != "" {
					want[family] = struct{}{}
				}
			}
			have := make(map[string]struct{}, len(manifest.Runtimes))
			for _, runtime := range manifest.Runtimes {
				if family := strings.TrimSpace(runtime.Config["family"]); family != "" {
					have[family] = struct{}{}
				}
			}

			missing := sortedSetDifference(want, have)
			if len(missing) > 0 {
				t.Fatalf("%s deploy manifest missing runtime families: %v", sourceID, missing)
			}
			extra := sortedSetDifference(have, want)
			if len(extra) > 0 {
				t.Fatalf("%s deploy manifest has unknown runtime families: %v", sourceID, extra)
			}
		})
	}
}

func TestSourceDeployManifestsRenderForKnownEnvironments(t *testing.T) {
	root := filepath.Join("..", "..", "sources")
	manifests, err := sourcedeploy.Discover(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Discover: %v", err)
	}
	if len(manifests) == 0 {
		t.Skip("no manifests to render")
	}
	for _, env := range []string{"sec-dev", "go-prod", "gcp-prod"} {
		if _, err := sourcedeploy.Render(manifests, sourcedeploy.RenderOptions{
			Environment: env,
			TenantID:    "writer",
		}); err != nil {
			t.Fatalf("Render(%s): %v", env, err)
		}
	}
}

type runtimeFamilyCatalog struct {
	RuntimeFamilies []string `yaml:"runtime_families"`
}

func loadRuntimeFamilyCatalog(t *testing.T, root string, sourceID string) runtimeFamilyCatalog {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, sourceID, "catalog.yaml"))
	if err != nil {
		t.Fatalf("read %s catalog: %v", sourceID, err)
	}
	var catalog runtimeFamilyCatalog
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		t.Fatalf("decode %s catalog: %v", sourceID, err)
	}
	return catalog
}

func requireHealthReceiptField(t *testing.T, sourceID string, receipt map[string]any, key string, want string) {
	t.Helper()
	if got, ok := receipt[key].(string); !ok || strings.TrimSpace(got) != want {
		t.Fatalf("%s health receipt %s = %#v, want %q", sourceID, key, receipt[key], want)
	}
}

func requireNonEmptyHealthReceiptField(t *testing.T, sourceID string, receipt map[string]any, key string) {
	t.Helper()
	if got, ok := receipt[key].(string); !ok || strings.TrimSpace(got) == "" {
		t.Fatalf("%s health receipt %s = %#v, want non-empty string", sourceID, key, receipt[key])
	}
}

func requirePositiveHealthReceiptSeconds(t *testing.T, sourceID string, receipt map[string]any, key string) {
	t.Helper()
	switch got := receipt[key].(type) {
	case float64:
		if got > 0 {
			return
		}
	case int:
		if got > 0 {
			return
		}
	}
	t.Fatalf("%s health receipt %s = %#v, want positive seconds", sourceID, key, receipt[key])
}

func requireNonEmptyHealthReceiptList(t *testing.T, sourceID string, receipt map[string]any, key string) {
	t.Helper()
	values, ok := receipt[key].([]any)
	if !ok || len(values) == 0 {
		t.Fatalf("%s health receipt %s = %#v, want non-empty list", sourceID, key, receipt[key])
	}
	for _, value := range values {
		if text, ok := value.(string); !ok || strings.TrimSpace(text) == "" {
			t.Fatalf("%s health receipt %s contains %#v, want non-empty strings", sourceID, key, value)
		}
	}
}

func sortedSetDifference(left map[string]struct{}, right map[string]struct{}) []string {
	out := make([]string, 0)
	for value := range left {
		if _, ok := right[value]; !ok {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func TestGitHubDeployManifestIncludesCerebroSelfRuntimes(t *testing.T) {
	root := filepath.Join("..", "..", "sources")
	manifests, err := sourcedeploy.Discover(root)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	var githubManifest *sourcedeploy.Manifest
	for i := range manifests {
		if manifests[i].SourceID == "github" {
			githubManifest = &manifests[i]
			break
		}
	}
	if githubManifest == nil {
		t.Fatal("github deploy manifest not found")
	}

	want := map[string]map[string]string{
		"cerebro-audit": {
			"family":   "audit",
			"include":  "all",
			"order":    "desc",
			"owner":    "writer",
			"per_page": "100",
			"phrase":   "repo:writer/cerebro",
			"token":    "env:GITHUB_TOKEN",
		},
		"cerebro-dependabot-alert": {
			"family":   "dependabot_alert",
			"owner":    "writer",
			"per_page": "100",
			"repo":     "cerebro",
			"state":    "open",
			"token":    "env:GITHUB_TOKEN",
		},
		"cerebro-pull-request": {
			"family":   "pull_request",
			"owner":    "writer",
			"per_page": "100",
			"repo":     "cerebro",
			"state":    "all",
			"token":    "env:GITHUB_TOKEN",
		},
		"cerebro-repository": {
			"family":   "repository",
			"owner":    "writer",
			"per_page": "100",
			"repo":     "cerebro",
			"token":    "env:GITHUB_TOKEN",
		},
	}

	have := map[string]map[string]string{}
	for _, runtime := range githubManifest.Runtimes {
		if _, ok := want[runtime.LocalID]; ok {
			have[runtime.LocalID] = runtime.Config
		}
	}

	missing := make([]string, 0)
	for id := range want {
		if _, ok := have[id]; !ok {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("github deploy manifest missing Cerebro self runtimes: %v", missing)
	}

	for id, wantConfig := range want {
		gotConfig := have[id]
		for key, wantValue := range wantConfig {
			if got := gotConfig[key]; got != wantValue {
				t.Fatalf("%s config %s = %q, want %q", id, key, got, wantValue)
			}
		}
	}
}
