package projectionmeta

import "strings"

const (
	AttributeProjectionClass  = "projection_class"
	AttributeProjectionReason = "projection_reason"

	ClassDurableState   = "durable_state"
	ClassEvidence       = "evidence"
	ClassLifecycleState = "lifecycle_state"
	ClassEphemeralEvent = "ephemeral_event"
)

type Classification struct {
	Class  string
	Reason string
}

func ClassifyEntity(entityType string, attributes map[string]string) Classification {
	entityType = strings.ToLower(strings.TrimSpace(entityType))
	switch entityType {
	case "sentinelone.activity":
		return Classification{Class: ClassEphemeralEvent, Reason: "source_activity_event"}
	case "runtime.evidence", "evidence":
		return Classification{Class: ClassEvidence, Reason: "evidence_reference"}
	case "finding", "ticket", "external_ref", "decision", "action", "outcome", "annotation":
		return Classification{Class: ClassLifecycleState, Reason: "workflow_lifecycle_state"}
	}
	if entityType == "github.runner" && strings.HasPrefix(strings.TrimSpace(attributes["action"]), "workflows.") {
		return Classification{Class: ClassEphemeralEvent, Reason: "hosted_workflow_job_runner_event"}
	}
	if strings.Contains(entityType, "evidence") || strings.HasSuffix(entityType, ".scan") || strings.HasSuffix(entityType, ".verdict") {
		return Classification{Class: ClassEvidence, Reason: "evidence_shaped_entity"}
	}
	return Classification{Class: ClassDurableState, Reason: "projected_current_state"}
}

func ApplyEntityMetadata(entityType string, attributes map[string]string) map[string]string {
	classification := ClassifyEntity(entityType, attributes)
	next := make(map[string]string, len(attributes)+2)
	for key, value := range attributes {
		next[key] = value
	}
	if strings.TrimSpace(next[AttributeProjectionClass]) == "" {
		next[AttributeProjectionClass] = classification.Class
	}
	if strings.TrimSpace(next[AttributeProjectionReason]) == "" {
		next[AttributeProjectionReason] = classification.Reason
	}
	return next
}
