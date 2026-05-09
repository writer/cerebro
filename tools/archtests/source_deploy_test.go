package archtests

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/writer/cerebro/tools/sourcedeploy"
)

// requireDeployManifest holds sources that must declare a deploy.yaml so the
// sourcedeploy synthesizer can render their Pulumi config. Sources that do
// not own runtimes (e.g. push-only SDK adapters, infrastructure scanners
// driven by the orchestrator default command) are exempt by being absent.
var requireDeployManifest = map[string]struct{}{
	"github":      {},
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
