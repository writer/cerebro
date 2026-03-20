package runtime

import "testing"

func TestAdmissionLevelForPressure(t *testing.T) {
	tests := []struct {
		name     string
		pressure AdmissionPressure
		want     AdmissionLevel
	}{
		{name: "green below thresholds", pressure: AdmissionPressure{ConsumerLag: 999, MemoryUtilization: 0.69}, want: AdmissionLevelGreen},
		{name: "yellow at lag threshold", pressure: AdmissionPressure{ConsumerLag: 1000, MemoryUtilization: 0.20}, want: AdmissionLevelYellow},
		{name: "yellow at memory threshold", pressure: AdmissionPressure{ConsumerLag: 0, MemoryUtilization: 0.70}, want: AdmissionLevelYellow},
		{name: "red above lag threshold", pressure: AdmissionPressure{ConsumerLag: 10001, MemoryUtilization: 0.20}, want: AdmissionLevelRed},
		{name: "red above memory threshold", pressure: AdmissionPressure{ConsumerLag: 0, MemoryUtilization: 0.86}, want: AdmissionLevelRed},
		{name: "percentage memory input is normalized", pressure: AdmissionPressure{ConsumerLag: 0, MemoryUtilization: 85}, want: AdmissionLevelYellow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AdmissionLevelForPressure(tt.pressure); got != tt.want {
				t.Fatalf("AdmissionLevelForPressure(%+v) = %q, want %q", tt.pressure, got, tt.want)
			}
		})
	}
}

func TestEventPriorityFromType(t *testing.T) {
	tests := []struct {
		eventType string
		want      EventPriority
	}{
		{eventType: "security_finding", want: EventPriorityCritical},
		{eventType: "alert", want: EventPriorityCritical},
		{eventType: "runtime_alert", want: EventPriorityCritical},
		{eventType: "runtime_observation", want: EventPriorityHigh},
		{eventType: "k8s_audit", want: EventPriorityHigh},
		{eventType: "tap_telemetry", want: EventPriorityNormal},
		{eventType: "metrics", want: EventPriorityLow},
		{eventType: "debug-observation", want: EventPriorityLow},
		{eventType: "custom_signal", want: EventPriorityNormal},
	}

	for _, tt := range tests {
		if got := EventPriorityFromType(tt.eventType); got != tt.want {
			t.Fatalf("EventPriorityFromType(%q) = %q, want %q", tt.eventType, got, tt.want)
		}
	}
}

func TestObservationPriority(t *testing.T) {
	if got := ObservationPriority(&RuntimeObservation{Kind: ObservationKindRuntimeAlert}); got != EventPriorityCritical {
		t.Fatalf("runtime alert priority = %q, want critical", got)
	}
	if got := ObservationPriority(&RuntimeObservation{Kind: ObservationKindNetworkFlow}); got != EventPriorityHigh {
		t.Fatalf("network flow priority = %q, want high", got)
	}
	if got := ObservationPriority(&RuntimeObservation{Kind: ObservationKindUnknown}); got != EventPriorityLow {
		t.Fatalf("unknown priority = %q, want low", got)
	}
}

func TestShouldAdmitPriority(t *testing.T) {
	tests := []struct {
		level    AdmissionLevel
		priority EventPriority
		want     bool
	}{
		{level: AdmissionLevelGreen, priority: EventPriorityLow, want: true},
		{level: AdmissionLevelYellow, priority: EventPriorityLow, want: false},
		{level: AdmissionLevelYellow, priority: EventPriorityNormal, want: true},
		{level: AdmissionLevelRed, priority: EventPriorityHigh, want: false},
		{level: AdmissionLevelRed, priority: EventPriorityCritical, want: true},
	}

	for _, tt := range tests {
		if got := ShouldAdmitPriority(tt.level, tt.priority); got != tt.want {
			t.Fatalf("ShouldAdmitPriority(%q, %q) = %t, want %t", tt.level, tt.priority, got, tt.want)
		}
	}
}

func TestShouldAdmitFindingAlwaysKeepsCriticalFindings(t *testing.T) {
	finding := &RuntimeFinding{ID: "finding-1"}
	if !ShouldAdmitFinding(AdmissionLevelRed, finding) {
		t.Fatal("expected red admission to retain runtime findings")
	}
}
