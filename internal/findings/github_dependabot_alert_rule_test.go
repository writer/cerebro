package findings

import (
	"context"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestGitHubDependabotAlertSeverityNormalization(t *testing.T) {
	rule := newGitHubDependabotOpenAlertRule()
	runtime := &cerebrov1.SourceRuntime{Id: "github-runtime", SourceId: "github", TenantId: "writer"}
	for _, tt := range []struct {
		name     string
		severity string
		want     string
	}{
		{name: "critical", severity: "critical", want: "CRITICAL"},
		{name: "high", severity: "high", want: "HIGH"},
		{name: "moderate", severity: "moderate", want: "MEDIUM"},
		{name: "empty", severity: "", want: "MEDIUM"},
		{name: "unknown", severity: "urgent", want: "MEDIUM"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			event := &cerebrov1.EventEnvelope{
				Id:       "dependabot-" + tt.name,
				TenantId: "writer",
				SourceId: "github",
				Kind:     "github.dependabot_alert",
				Attributes: map[string]string{
					"alert_number": "7",
					"repository":   "writer/cerebro",
					"severity":     tt.severity,
					"state":        "open",
				},
			}
			records, err := rule.Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("len(records) = %d, want 1", len(records))
			}
			if got := records[0].Severity; got != tt.want {
				t.Fatalf("Severity = %q, want %q", got, tt.want)
			}
		})
	}
}
