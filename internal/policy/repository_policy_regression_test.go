package policy

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryPoliciesRemainUniqueAndFullyLoadable(t *testing.T) {
	policiesRoot := filepath.Clean("../../policies")

	type repoPolicy struct {
		ID string `json:"id"`
	}

	seenIDs := make(map[string]string)
	expectedLoadablePolicies := 0

	err := filepath.WalkDir(policiesRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if isPolicyMetadataFile(raw) {
			return nil
		}

		var p repoPolicy
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		id := strings.TrimSpace(p.ID)
		if id == "" {
			return fmt.Errorf("policy file missing id: %s", path)
		}

		expectedLoadablePolicies++
		if prevPath, exists := seenIDs[id]; exists {
			return fmt.Errorf("duplicate policy id %q in %s and %s", id, prevPath, path)
		}
		seenIDs[id] = path
		return nil
	})
	if err != nil {
		t.Fatalf("policy corpus validation failed: %v", err)
	}

	engine := NewEngine()
	if err := engine.LoadPolicies(policiesRoot); err != nil {
		t.Fatalf("engine failed loading repository policies: %v", err)
	}

	if got := len(engine.ListPolicies()); got != expectedLoadablePolicies {
		t.Fatalf("loaded policy count mismatch: got %d, expected %d", got, expectedLoadablePolicies)
	}
}
