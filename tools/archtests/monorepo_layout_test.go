package archtests

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type workspaceManifest struct {
	Private         bool              `json:"private"`
	PackageManager  string            `json:"packageManager"`
	Workspaces      []string          `json:"workspaces"`
	Scripts         map[string]string `json:"scripts"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func TestRootWorkspaceOwnsPublicApplicationsAndTypeScriptSDK(t *testing.T) {
	root := repoRoot(t)
	manifest := readWorkspaceManifest(t, filepath.Join(root, "package.json"))
	if !manifest.Private {
		t.Fatal("root package.json must set private=true")
	}
	if !strings.HasPrefix(manifest.PackageManager, "npm@") {
		t.Fatalf("root package manager = %q, want a pinned npm version", manifest.PackageManager)
	}
	for _, workspace := range []string{"apps/*", "sdk/typescript"} {
		if !slices.Contains(manifest.Workspaces, workspace) {
			t.Fatalf("root package.json missing workspace %q", workspace)
		}
	}
	for _, script := range []string{"build:workspaces", "check:workspaces", "test:workspaces", "typecheck:workspaces"} {
		if strings.TrimSpace(manifest.Scripts[script]) == "" {
			t.Fatalf("root package.json missing script %q", script)
		}
	}
	if len(manifest.Dependencies) != 0 || len(manifest.DevDependencies) != 0 {
		t.Fatal("root workspace must not add runtime or development dependencies")
	}
	if _, err := os.Stat(filepath.Join(root, "package-lock.json")); err != nil {
		t.Fatalf("root npm workspace requires package-lock.json: %v", err)
	}
}

func TestPublicApplicationsExcludeOperationalOverlays(t *testing.T) {
	root := repoRoot(t)
	appsRoot := filepath.Join(root, "apps")
	forbidden := map[string]bool{
		".github":    true,
		"deploy":     true,
		"deployment": true,
		"infra":      true,
		"ops":        true,
		"pulumi":     true,
		"terraform":  true,
	}
	err := filepath.WalkDir(appsRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() || path == appsRoot {
			return nil
		}
		name := strings.ToLower(entry.Name())
		if name == "node_modules" || name == ".next" || name == "dist" {
			return filepath.SkipDir
		}
		if forbidden[name] {
			t.Errorf("public application path %s contains an operational overlay directory", filepath.ToSlash(path))
			return filepath.SkipDir
		}
		if filepath.Dir(path) == appsRoot {
			manifestPath := filepath.Join(path, "package.json")
			manifest := readWorkspaceManifest(t, manifestPath)
			if !manifest.Private {
				t.Errorf("%s must set private=true", filepath.ToSlash(manifestPath))
			}
			if _, err := os.Stat(filepath.Join(path, "package-lock.json")); !os.IsNotExist(err) {
				t.Errorf("%s must use the root package-lock.json", filepath.ToSlash(path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk public applications: %v", err)
	}
}

func readWorkspaceManifest(t *testing.T, path string) workspaceManifest {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.ToSlash(path), err)
	}
	var manifest workspaceManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatalf("decode %s: %v", filepath.ToSlash(path), err)
	}
	return manifest
}
