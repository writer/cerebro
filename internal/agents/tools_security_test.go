package agents

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestCloudInspectEnabled(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "default empty", value: "", want: false},
		{name: "false", value: "false", want: false},
		{name: "zero", value: "0", want: false},
		{name: "random", value: "enabled", want: false},
		{name: "true", value: "true", want: true},
		{name: "one", value: "1", want: true},
		{name: "yes", value: "yes", want: true},
		{name: "on uppercase", value: "ON", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("CEREBRO_CLOUD_INSPECT_ENABLED", tt.value)
			if got := cloudInspectEnabled(); got != tt.want {
				t.Fatalf("cloudInspectEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloudInspectTools_DefaultDisabled(t *testing.T) {
	t.Setenv("CEREBRO_CLOUD_INSPECT_ENABLED", "")
	st := &SecurityTools{}

	for _, name := range []string{"aws_inspect", "gcp_inspect", "inspect_cloud_resource"} {
		t.Run(name, func(t *testing.T) {
			tool := findToolByName(st.GetTools(), name)
			if tool == nil {
				t.Fatalf("tool %s not found", name)
			}

			_, err := tool.Handler(context.Background(), json.RawMessage(`{}`))
			if err == nil {
				t.Fatalf("expected disabled error for %s", name)
			}
			if !strings.Contains(err.Error(), "disabled by default") {
				t.Fatalf("expected disabled-by-default message, got %v", err)
			}
		})
	}
}

func findToolByName(tools []Tool, name string) *Tool {
	for i := range tools {
		if tools[i].Name == name {
			return &tools[i]
		}
	}
	return nil
}
