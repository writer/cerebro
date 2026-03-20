package policy

import (
	"bytes"
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

func TestRepositoryResourceConditionPoliciesUseCELFormat(t *testing.T) {
	policiesRoot := filepath.Clean("../../policies")

	type repoPolicy struct {
		ID              string   `json:"id"`
		Resource        string   `json:"resource"`
		Conditions      []string `json:"conditions"`
		ConditionFormat string   `json:"condition_format"`
	}

	var legacyPaths []string

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

		if strings.TrimSpace(p.Resource) == "" || len(p.Conditions) == 0 {
			return nil
		}
		if normalizeConditionFormat(p.ConditionFormat) != ConditionFormatCEL {
			legacyPaths = append(legacyPaths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("condition-format inventory failed: %v", err)
	}

	if len(legacyPaths) > 0 {
		t.Fatalf("resource condition policies still not migrated to CEL: %v", legacyPaths)
	}
}

func TestRepositoryPolicyInventorySnapshot(t *testing.T) {
	policiesRoot := filepath.Clean("../../policies")

	type repoPolicy struct {
		ID         string          `json:"id"`
		Resource   string          `json:"resource"`
		Conditions []string        `json:"conditions"`
		Query      json.RawMessage `json:"query"`
	}

	totalJSON := 0
	metadataFiles := 0
	loadablePolicies := 0
	resourceConditionPolicies := 0
	queryOnlyPolicies := 0
	mixedShapePolicies := 0
	seenIDs := make(map[string]string)
	duplicateIDs := make(map[string][]string)

	err := filepath.WalkDir(policiesRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}

		totalJSON++

		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if isPolicyMetadataFile(raw) {
			metadataFiles++
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

		loadablePolicies++

		hasQuery := len(bytes.TrimSpace(p.Query)) > 0 && string(bytes.TrimSpace(p.Query)) != "null"
		hasResourceConditions := strings.TrimSpace(p.Resource) != "" && len(p.Conditions) > 0

		switch {
		case hasQuery && !hasResourceConditions:
			queryOnlyPolicies++
		case !hasQuery && hasResourceConditions:
			resourceConditionPolicies++
		default:
			mixedShapePolicies++
		}

		if prevPath, exists := seenIDs[id]; exists {
			duplicateIDs[id] = append(duplicateIDs[id], prevPath, path)
		} else {
			seenIDs[id] = path
		}

		return nil
	})
	if err != nil {
		t.Fatalf("policy inventory snapshot failed: %v", err)
	}

	t.Logf("policy inventory snapshot: total_json=%d metadata=%d loadable=%d resource_condition=%d query_only=%d mixed_shape=%d duplicate_ids=%d",
		totalJSON,
		metadataFiles,
		loadablePolicies,
		resourceConditionPolicies,
		queryOnlyPolicies,
		mixedShapePolicies,
		len(duplicateIDs),
	)

	if len(duplicateIDs) > 0 {
		t.Fatalf("duplicate policy IDs detected in snapshot: %v", duplicateIDs)
	}
}
