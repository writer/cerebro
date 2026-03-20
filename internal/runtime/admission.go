package runtime

import "strings"

type AdmissionLevel string

const (
	AdmissionLevelGreen  AdmissionLevel = "green"
	AdmissionLevelYellow AdmissionLevel = "yellow"
	AdmissionLevelRed    AdmissionLevel = "red"
)

type EventPriority string

const (
	EventPriorityCritical EventPriority = "critical"
	EventPriorityHigh     EventPriority = "high"
	EventPriorityNormal   EventPriority = "normal"
	EventPriorityLow      EventPriority = "low"
)

// AdmissionPressure captures the health inputs used for runtime admission control.
type AdmissionPressure struct {
	ConsumerLag       int     `json:"consumer_lag"`
	MemoryUtilization float64 `json:"memory_utilization"`
}

// AdmissionLevelForPressure applies the issue #361 threshold policy.
func AdmissionLevelForPressure(pressure AdmissionPressure) AdmissionLevel {
	memory := normalizeAdmissionMemoryUtilization(pressure.MemoryUtilization)
	switch {
	case pressure.ConsumerLag > 10000 || memory > 0.85:
		return AdmissionLevelRed
	case pressure.ConsumerLag >= 1000 || memory >= 0.70:
		return AdmissionLevelYellow
	default:
		return AdmissionLevelGreen
	}
}

// EventPriorityFromType classifies a generic event type into one admission priority bucket.
func EventPriorityFromType(eventType string) EventPriority {
	switch normalizeAdmissionType(eventType) {
	case "security_finding", "alert", "policy_violation", "runtime_alert", "response_outcome":
		return EventPriorityCritical
	case "runtime_observation", "audit_mutation", "k8s_audit",
		"process_exec", "process_exit", "file_open", "file_write", "network_flow", "dns_query", "trace_link":
		return EventPriorityHigh
	case "tap_telemetry", "heartbeat":
		return EventPriorityNormal
	case "metrics", "debug_observation", "", "unknown":
		return EventPriorityLow
	default:
		return EventPriorityNormal
	}
}

// ObservationPriority classifies one normalized runtime observation for admission control.
func ObservationPriority(observation *RuntimeObservation) EventPriority {
	if observation == nil {
		return EventPriorityLow
	}
	return EventPriorityFromType(string(observation.Kind))
}

// FindingPriority classifies one runtime finding for admission control.
func FindingPriority(finding *RuntimeFinding) EventPriority {
	if finding == nil {
		return EventPriorityLow
	}
	return EventPriorityCritical
}

// ShouldAdmitPriority reports whether work at the given priority should be admitted.
func ShouldAdmitPriority(level AdmissionLevel, priority EventPriority) bool {
	switch level {
	case AdmissionLevelRed:
		return priority == EventPriorityCritical
	case AdmissionLevelYellow:
		return priority != EventPriorityLow
	default:
		return true
	}
}

func ShouldAdmitObservation(level AdmissionLevel, observation *RuntimeObservation) bool {
	return ShouldAdmitPriority(level, ObservationPriority(observation))
}

func ShouldAdmitFinding(level AdmissionLevel, finding *RuntimeFinding) bool {
	return ShouldAdmitPriority(level, FindingPriority(finding))
}

func normalizeAdmissionType(eventType string) string {
	eventType = strings.ToLower(strings.TrimSpace(eventType))
	eventType = strings.ReplaceAll(eventType, "-", "_")
	eventType = strings.ReplaceAll(eventType, " ", "_")
	return eventType
}

func normalizeAdmissionMemoryUtilization(value float64) float64 {
	switch {
	case value < 0:
		return 0
	case value > 1 && value <= 100:
		return value / 100
	default:
		return value
	}
}
