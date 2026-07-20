package archtests

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/writer/cerebro/internal/wasmartifacts"
)

func TestEmbeddedWasmArtifactManifestMatchesRegistriesAndABIs(t *testing.T) {
	root := repoRoot(t)
	if err := wasmartifacts.Check(root); err != nil {
		t.Fatal(err)
	}
	manifest, err := wasmartifacts.Load(filepath.Join(root, filepath.FromSlash(wasmartifacts.ManifestPath)))
	if err != nil {
		t.Fatal(err)
	}
	specs := wasmartifacts.ModuleSpecs()
	if len(manifest.Modules) != len(specs) {
		t.Fatalf("manifest has %d modules, registry has %d", len(manifest.Modules), len(specs))
	}

	pythonRegistry := readArchitectureFile(t, root, "scripts/embedded_wasm.py")
	for index, spec := range specs {
		entry := manifest.Modules[index]
		if entry.Name != spec.Name || entry.Path != spec.ArtifactPath || entry.ABIVersion != spec.ABIVersion {
			t.Fatalf("manifest module %d does not match Go registry: got %+v want %+v", index, entry, spec)
		}
		for _, fragment := range []string{
			fmt.Sprintf(`name="%s"`, spec.Name),
			fmt.Sprintf(`embedded_artifact="%s"`, spec.ArtifactPath),
		} {
			if !strings.Contains(pythonRegistry, fragment) {
				t.Errorf("Python Wasm registry missing %s contract %q", spec.Name, fragment)
			}
		}
		rustSource := readArchitectureFile(t, root, spec.SourcePath)
		abiDeclaration := fmt.Sprintf("pub const ABI_VERSION: u32 = %d;", spec.ABIVersion)
		if !strings.Contains(rustSource, abiDeclaration) {
			t.Errorf("%s must declare %q in %s", spec.Name, abiDeclaration, spec.SourcePath)
		}
	}

	builder := wasmartifacts.CanonicalBuilder()
	toolchain := readArchitectureFile(t, root, "rust-toolchain.toml")
	if !strings.Contains(toolchain, fmt.Sprintf(`channel = "%s"`, builder.RustToolchain)) {
		t.Errorf("rust-toolchain.toml must pin canonical builder toolchain %s", builder.RustToolchain)
	}
	for _, fragment := range []string{
		fmt.Sprintf(`WASM_TARGET = "%s"`, builder.Target),
		fmt.Sprintf(`CANONICAL_PLATFORM = "%s"`, builder.Platform),
	} {
		if !strings.Contains(pythonRegistry, fragment) {
			t.Errorf("Python Wasm registry missing canonical builder input %q", fragment)
		}
	}
}

func readArchitectureFile(t *testing.T, root string, path string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}
