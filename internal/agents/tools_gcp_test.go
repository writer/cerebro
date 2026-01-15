package agents

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestGCPInspect(t *testing.T) {
	// Initialize tools
	tools := NewSecurityTools(nil, nil, nil, nil)
	projectID := "writer-devops"

	// Test Case 1: List Storage Buckets
	t.Run("GCP Storage List Buckets", func(t *testing.T) {
		args := map[string]interface{}{
			"service": "storage",
			"action":  "list-buckets",
			"project": projectID,
			"params":  map[string]interface{}{},
		}
		argsBytes, _ := json.Marshal(args)
		
		result, err := tools.gcpInspect(context.Background(), argsBytes)
		if err != nil {
			t.Fatalf("gcpInspect storage:list-buckets failed: %v", err)
		}
		t.Logf("GCP Buckets: %s", result)
		
		if !strings.Contains(result, "[") {
			t.Error("Result should be a JSON array")
		}
	})

	// Test Case 2: List Compute Instances (Aggregated)
	t.Run("GCP Compute List Instances", func(t *testing.T) {
		args := map[string]interface{}{
			"service": "compute",
			"action":  "list-instances",
			"project": projectID,
			"params":  map[string]interface{}{},
		}
		argsBytes, _ := json.Marshal(args)
		
		result, err := tools.gcpInspect(context.Background(), argsBytes)
		if err != nil {
			t.Fatalf("gcpInspect compute:list-instances failed: %v", err)
		}
		t.Logf("GCP Instances: %s", result)
	})
}
