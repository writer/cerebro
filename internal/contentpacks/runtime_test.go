package contentpacks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRuntimeSelectsBothSignedPilotPacks(t *testing.T) {
	root := filepath.Join("..", "..", "contentpacks", "pilot")
	selection := LoadRuntime(RuntimeConfig{
		Root:          root,
		AllowlistPath: filepath.Join(root, "allowlist.json"),
		TenantID:      "content-pack-pilot",
		KernelVersion: "1.0.0",
	})
	if len(selection.State.Rejected) != 0 || len(selection.State.Accepted) != 2 || len(selection.State.FallbackKinds) != 0 {
		t.Fatalf("LoadRuntime() state = %#v", selection.State)
	}
	if len(selection.ConnectorCatalogs["deepseek"]) == 0 {
		t.Fatal("LoadRuntime() missing DeepSeek connector catalog")
	}
	if len(selection.PolicyRules["ai-agent-tool-allowlist-required"]) == 0 {
		t.Fatal("LoadRuntime() missing AI tool policy")
	}
}

func TestLoadRuntimeIsolatesInvalidConnectorAndKeepsPolicy(t *testing.T) {
	repositoryRoot := filepath.Join("..", "..", "contentpacks", "pilot")
	root := t.TempDir()
	copyTestDirectory(t, filepath.Join(repositoryRoot, "connector-deepseek"), filepath.Join(root, "connector-deepseek"))
	copyTestDirectory(t, filepath.Join(repositoryRoot, "policy-ai-controls"), filepath.Join(root, "policy-ai-controls"))
	writeTestFile(t, filepath.Join(root, "connector-deepseek", "manifest.sig"), []byte("invalid"))

	selection := LoadRuntime(RuntimeConfig{
		Root:          root,
		AllowlistPath: filepath.Join(repositoryRoot, "allowlist.json"),
		TenantID:      "content-pack-pilot",
		KernelVersion: "1.0.0",
	})
	if len(selection.State.Rejected) != 1 || len(selection.State.Accepted) != 1 {
		t.Fatalf("LoadRuntime() state = %#v", selection.State)
	}
	if len(selection.ConnectorCatalogs) != 0 || len(selection.PolicyRules) != 1 {
		t.Fatalf("LoadRuntime() connector catalogs = %d, policy rules = %d", len(selection.ConnectorCatalogs), len(selection.PolicyRules))
	}
	if len(selection.State.FallbackKinds) != 1 || selection.State.FallbackKinds[0] != "connector" {
		t.Fatalf("LoadRuntime() fallback kinds = %v", selection.State.FallbackKinds)
	}
}

func TestRuntimeSelectionRejectKindRestoresEmbeddedSurface(t *testing.T) {
	root := filepath.Join("..", "..", "contentpacks", "pilot")
	selection := LoadRuntime(RuntimeConfig{
		Root:          root,
		AllowlistPath: filepath.Join(root, "allowlist.json"),
		TenantID:      "content-pack-pilot",
		KernelVersion: "1.0.0",
	})
	selection.RejectKind("policy-control", "kernel parser rejected policy")
	if len(selection.PolicyRules) != 0 || len(selection.ConnectorCatalogs) != 1 {
		t.Fatalf("RejectKind() connector catalogs = %d, policy rules = %d", len(selection.ConnectorCatalogs), len(selection.PolicyRules))
	}
	if len(selection.State.FallbackKinds) != 1 || selection.State.FallbackKinds[0] != "policy-control" {
		t.Fatalf("RejectKind() fallback kinds = %v", selection.State.FallbackKinds)
	}
}

func copyTestDirectory(t *testing.T, source, destination string) {
	t.Helper()
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatalf("ReadDir(%s) error = %v", source, err)
	}
	if err := os.MkdirAll(destination, 0o750); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", destination, err)
	}
	for _, entry := range entries {
		sourcePath := filepath.Join(source, entry.Name())
		destinationPath := filepath.Join(destination, entry.Name())
		if entry.IsDir() {
			copyTestDirectory(t, sourcePath, destinationPath)
			continue
		}
		payload, err := os.ReadFile(sourcePath) // #nosec G304 -- test copies checked-in content-pack fixtures.
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", sourcePath, err)
		}
		writeTestFile(t, destinationPath, payload)
	}
}
