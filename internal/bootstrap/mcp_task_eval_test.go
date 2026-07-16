package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/writer/cerebro/internal/mcpoperations"
)

func TestMCPTaskToolSelectionHillclimbBaseline(t *testing.T) {
	testdata := filepath.Join("..", "mcpoperations", "testdata", "task_tools")
	cases := readMCPTaskEvalJSON[[]mcpoperations.TaskSelectionCase](t, filepath.Join(testdata, "selection_cases.json"))
	baseline := readMCPTaskEvalJSON[mcpoperations.TaskSelectionBaseline](t, filepath.Join(testdata, "baseline.json"))
	descriptors := mcpTaskToolEvalDescriptors()
	report := mcpoperations.ScoreTaskSelection(cases, descriptors)
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal task selection report: %v", err)
	}
	t.Logf("task selection hillclimb report:\n%s", raw)
	if err := mcpoperations.ValidateTaskSelectionBaseline(report, baseline); err != nil {
		t.Fatal(err)
	}
}

func mcpTaskToolEvalDescriptors() []mcpoperations.TaskToolDescriptor {
	tools := mcpToolsForRequest(nil, nil)
	descriptors := make([]mcpoperations.TaskToolDescriptor, 0, len(tools))
	for _, tool := range tools {
		inputs := []string{}
		if properties, ok := tool.InputSchema["properties"].(map[string]any); ok {
			for name := range properties {
				inputs = append(inputs, name)
			}
			sort.Strings(inputs)
		}
		descriptors = append(descriptors, mcpoperations.TaskToolDescriptor{
			Name: tool.Name, Title: tool.Title, Description: tool.Description, InputNames: inputs,
		})
	}
	return descriptors
}

func readMCPTaskEvalJSON[T any](t *testing.T, path string) T {
	t.Helper()
	var value T
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return value
}
