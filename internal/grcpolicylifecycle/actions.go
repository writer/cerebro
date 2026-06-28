package grcpolicylifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	policyLifecycleDefaultSourceID = "grc"
	policyLifecycleProvider        = "policyops"
	policyLifecycleSchemaRef       = "grc/policy/v1"
)

var (
	ErrInvalidRequest     = errors.New("invalid policy lifecycle request")
	ErrRuntimeUnavailable = errors.New("policy lifecycle runtime is unavailable")
)

type ActionRequest struct {
	Action string `json:"action"`
	ActionRequestScope
	ActionRequestTarget
	ActionRequestState
	ActionRequestAssignments
}

type ActionRequestScope struct {
	TenantID       string `json:"tenant_id,omitempty"`
	SourceID       string `json:"source_id,omitempty"`
	RuntimeID      string `json:"runtime_id,omitempty"`
	ActorUserID    string `json:"actor_user_id,omitempty"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type ActionRequestTarget struct {
	PolicyID        string   `json:"policy_id,omitempty"`
	PolicyVersionID string   `json:"policy_version_id,omitempty"`
	TemplateID      string   `json:"template_id,omitempty"`
	GapID           string   `json:"gap_id,omitempty"`
	GapIDs          []string `json:"gap_ids,omitempty"`
	RecordID        string   `json:"record_id,omitempty"`
	RecordURN       string   `json:"record_urn,omitempty"`
}

type ActionRequestState struct {
	Title       string `json:"title,omitempty"`
	Version     string `json:"version,omitempty"`
	Status      string `json:"status,omitempty"`
	GapState    string `json:"gap_state,omitempty"`
	Reason      string `json:"reason,omitempty"`
	DueAt       string `json:"due_at,omitempty"`
	EffectiveAt string `json:"effective_at,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

type ActionRequestAssignments struct {
	Assignees    []string          `json:"assignees,omitempty"`
	Approvers    []string          `json:"approvers,omitempty"`
	Reviewers    []string          `json:"reviewers,omitempty"`
	ControlIDs   []string          `json:"control_ids,omitempty"`
	EvidenceURNs []string          `json:"evidence_urns,omitempty"`
	Attributes   map[string]string `json:"attributes,omitempty"`
}

type ActionResponse struct {
	Action      string            `json:"action"`
	Status      string            `json:"status"`
	EventID     string            `json:"event_id"`
	EventKind   string            `json:"event_kind"`
	SchemaRef   string            `json:"schema_ref"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	GeneratedAt time.Time         `json:"generated_at"`
}

type ActionDefinition struct {
	ID                string `json:"id"`
	Label             string `json:"label"`
	EventKind         string `json:"event_kind"`
	RecordType        string `json:"record_type"`
	Status            string `json:"status"`
	RequiresPolicyID  bool   `json:"requires_policy_id,omitempty"`
	RequiresVersionID bool   `json:"requires_version_id,omitempty"`
	RequiresRecordID  bool   `json:"requires_record_id,omitempty"`
	RequiresGapID     bool   `json:"requires_gap_id,omitempty"`
	DateField         string `json:"date_field,omitempty"`
	ValueField        string `json:"value_field,omitempty"`
	ValueLabel        string `json:"value_label,omitempty"`
}

type policyLifecycleActionDefinition struct {
	ActionDefinition
	idAttribute string
}

var policyLifecycleActionDefinitions = []policyLifecycleActionDefinition{
	{ActionDefinition: ActionDefinition{ID: "template.create", Label: "Create template", EventKind: "grc.policy_template", RecordType: "policy.template", Status: "draft"}, idAttribute: "template_id"},
	{ActionDefinition: ActionDefinition{ID: "template.clone", Label: "Clone template", EventKind: "grc.policy_version", RecordType: "policy.version", Status: "draft", RequiresPolicyID: true}, idAttribute: "policy_version_id"},
	{ActionDefinition: ActionDefinition{ID: "draft.create", Label: "Create draft", EventKind: "grc.policy_version", RecordType: "policy.version", Status: "draft", RequiresPolicyID: true}, idAttribute: "policy_version_id"},
	{ActionDefinition: ActionDefinition{ID: "draft.update", Label: "Save draft", EventKind: "grc.policy_version", RecordType: "policy.version", Status: "draft", RequiresPolicyID: true, RequiresVersionID: true}, idAttribute: "policy_version_id"},
	{ActionDefinition: ActionDefinition{ID: "draft.submit", Label: "Submit draft", EventKind: "grc.policy_approval", RecordType: "policy.approval", Status: "requested", RequiresPolicyID: true, RequiresVersionID: true}, idAttribute: "approval_id"},
	{ActionDefinition: ActionDefinition{ID: "approval.request", Label: "Request approval", EventKind: "grc.policy_approval", RecordType: "policy.approval", Status: "requested", RequiresPolicyID: true, RequiresVersionID: true}, idAttribute: "approval_id"},
	{ActionDefinition: ActionDefinition{ID: "approval.approve", Label: "Approve version", EventKind: "grc.policy_approval", RecordType: "policy.approval", Status: "approved", RequiresPolicyID: true, RequiresVersionID: true}, idAttribute: "approval_id"},
	{ActionDefinition: ActionDefinition{ID: "approval.reject", Label: "Reject version", EventKind: "grc.policy_approval", RecordType: "policy.approval", Status: "rejected", RequiresPolicyID: true, RequiresVersionID: true}, idAttribute: "approval_id"},
	{ActionDefinition: ActionDefinition{ID: "version.publish", Label: "Publish version", EventKind: "grc.policy_version", RecordType: "policy.version", Status: "approved", RequiresPolicyID: true, RequiresVersionID: true}, idAttribute: "policy_version_id"},
	{ActionDefinition: ActionDefinition{ID: "attestation.campaign_create", Label: "Create campaign", EventKind: "grc.policy_acceptance", RecordType: "policy.acceptance", Status: "requested", RequiresPolicyID: true, RequiresVersionID: true}, idAttribute: "acceptance_id"},
	{ActionDefinition: ActionDefinition{ID: "attestation.assign", Label: "Assign attestation", EventKind: "grc.policy_acceptance", RecordType: "policy.acceptance", Status: "pending", RequiresPolicyID: true, RequiresVersionID: true}, idAttribute: "acceptance_id"},
	{ActionDefinition: ActionDefinition{ID: "attestation.accept", Label: "Record attestation", EventKind: "grc.policy_acceptance", RecordType: "policy.acceptance", Status: "accepted", RequiresPolicyID: true, RequiresVersionID: true}, idAttribute: "acceptance_id"},
	{ActionDefinition: ActionDefinition{ID: "review.complete", Label: "Complete review", EventKind: "grc.policy_review", RecordType: "policy.review", Status: "completed", RequiresPolicyID: true}, idAttribute: "review_id"},
	{ActionDefinition: ActionDefinition{ID: "exception.request", Label: "Request exception", EventKind: "grc.policy_exception", RecordType: "policy.exception", Status: "requested", RequiresPolicyID: true}, idAttribute: "exception_id"},
	{ActionDefinition: ActionDefinition{ID: "exception.approve", Label: "Approve exception", EventKind: "grc.policy_exception", RecordType: "policy.exception", Status: "active", RequiresPolicyID: true}, idAttribute: "exception_id"},
	{ActionDefinition: ActionDefinition{ID: "exception.renew", Label: "Renew exception", EventKind: "grc.policy_exception", RecordType: "policy.exception", Status: "active", RequiresPolicyID: true}, idAttribute: "exception_id"},
	{ActionDefinition: ActionDefinition{ID: "exception.close", Label: "Close exception", EventKind: "grc.policy_exception", RecordType: "policy.exception", Status: "closed", RequiresPolicyID: true}, idAttribute: "exception_id"},
	{ActionDefinition: ActionDefinition{ID: "reminder.send", Label: "Send reminder", EventKind: "grc.policy_reminder", RecordType: "policy.reminder", Status: "sent", RequiresPolicyID: true}, idAttribute: "reminder_id"},
	{ActionDefinition: ActionDefinition{ID: "reminder.escalate", Label: "Escalate reminder", EventKind: "grc.policy_reminder", RecordType: "policy.reminder", Status: "escalated", RequiresPolicyID: true}, idAttribute: "reminder_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.assign_owner", Label: "Assign owner", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "in_progress", RequiresRecordID: true, RequiresGapID: true, ValueField: "assigned_user_ids", ValueLabel: "Owner"}, idAttribute: "gap_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.set_review_date", Label: "Set review date", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "in_progress", RequiresRecordID: true, RequiresGapID: true, DateField: "due_at"}, idAttribute: "gap_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.link_policy", Label: "Link policy", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "in_progress", RequiresRecordID: true, RequiresGapID: true, ValueField: "target_policy_id", ValueLabel: "Policy ID"}, idAttribute: "gap_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.map_controls", Label: "Map controls", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "in_progress", RequiresRecordID: true, RequiresGapID: true, ValueField: "control_ids", ValueLabel: "Control IDs"}, idAttribute: "gap_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.add_treatment", Label: "Add treatment", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "in_progress", RequiresRecordID: true, RequiresGapID: true, ValueField: "treatment", ValueLabel: "Treatment"}, idAttribute: "gap_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.set_treatment_date", Label: "Set treatment date", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "in_progress", RequiresRecordID: true, RequiresGapID: true, DateField: "due_at"}, idAttribute: "gap_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.link_source_document", Label: "Link source document", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "in_progress", RequiresRecordID: true, RequiresGapID: true, ValueField: "source_document_id", ValueLabel: "Source document ID"}, idAttribute: "gap_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.attach_evidence", Label: "Attach evidence", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "in_progress", RequiresRecordID: true, RequiresGapID: true, ValueField: "evidence_urns", ValueLabel: "Evidence URNs"}, idAttribute: "gap_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.acknowledge", Label: "Acknowledge gap", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "acknowledged", RequiresRecordID: true, RequiresGapID: true}, idAttribute: "gap_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.snooze", Label: "Snooze gap", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "snoozed", RequiresRecordID: true, RequiresGapID: true, DateField: "due_at"}, idAttribute: "gap_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.accept", Label: "Accept gap", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "accepted", RequiresRecordID: true, RequiresGapID: true}, idAttribute: "gap_id"},
	{ActionDefinition: ActionDefinition{ID: "governance_gap.resolve", Label: "Resolve gap", EventKind: "grc.policy_lifecycle_event", RecordType: "governance.gap", Status: "resolved", RequiresRecordID: true, RequiresGapID: true}, idAttribute: "gap_id"},
}

func ActionDefinitions() []ActionDefinition {
	out := make([]ActionDefinition, 0, len(policyLifecycleActionDefinitions))
	for _, definition := range policyLifecycleActionDefinitions {
		out = append(out, definition.ActionDefinition)
	}
	return out
}

func BuildActionEvent(request ActionRequest, now time.Time) (*cerebrov1.EventEnvelope, ActionResponse, error) {
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	request = normalizeActionRequest(request)
	definition, ok := policyLifecycleActionDefinitionFor(request.Action)
	if !ok {
		return nil, ActionResponse{}, fmt.Errorf("%w: unsupported action %q", ErrInvalidRequest, request.Action)
	}
	if request.TenantID == "" {
		return nil, ActionResponse{}, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	if definition.RequiresPolicyID && request.PolicyID == "" {
		return nil, ActionResponse{}, fmt.Errorf("%w: policy_id is required for %s", ErrInvalidRequest, definition.ID)
	}
	if definition.RequiresVersionID && request.PolicyVersionID == "" {
		return nil, ActionResponse{}, fmt.Errorf("%w: policy_version_id is required for %s", ErrInvalidRequest, definition.ID)
	}
	if definition.RequiresGapID && request.GapID == "" && request.RecordID == "" && request.RecordURN == "" && len(request.GapIDs) == 0 {
		return nil, ActionResponse{}, fmt.Errorf("%w: gap_id is required for %s", ErrInvalidRequest, definition.ID)
	}
	if definition.RequiresGapID && request.GapID != "" && len(request.GapIDs) > 0 {
		return nil, ActionResponse{}, fmt.Errorf("%w: gap_id and gap_ids cannot both be set for %s", ErrInvalidRequest, definition.ID)
	}
	if definition.ID == "governance_gap.link_policy" && policyLifecycleActionAttribute(request, "target_policy_id") == "" {
		return nil, ActionResponse{}, fmt.Errorf("%w: target_policy_id is required for %s", ErrInvalidRequest, definition.ID)
	}

	recordID := policyLifecycleRecordID(request, definition, now)
	attrs := policyLifecycleActionAttributes(request, definition, recordID, now)
	eventID := policyLifecycleEventID(request, definition, recordID, now)
	payload := map[string]any{
		"action":            definition.ID,
		"policy_id":         attrs["policy_id"],
		"policy_version_id": attrs["policy_version_id"],
		"record_id":         recordID,
		"record_type":       definition.RecordType,
		"record_urn":        attrs["record_urn"],
		"status":            attrs["status"],
		"actor_user_id":     attrs["actor_user_id"],
		"reason":            attrs["reason"],
		"occurred_at":       now.Format(time.RFC3339Nano),
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, ActionResponse{}, fmt.Errorf("%w: encode action payload: %w", ErrInvalidRequest, err)
	}
	event := &cerebrov1.EventEnvelope{
		Id:         eventID,
		TenantId:   request.TenantID,
		SourceId:   firstNonEmpty(request.SourceID, policyLifecycleDefaultSourceID),
		Kind:       definition.EventKind,
		OccurredAt: timestamppb.New(now),
		SchemaRef:  policyLifecycleSchemaRef,
		Payload:    rawPayload,
		Attributes: attrs,
	}
	if err := sourcecdk.ValidateEventEnvelope(event); err != nil {
		return nil, ActionResponse{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return event, ActionResponse{
		Action:      definition.ID,
		Status:      attrs["status"],
		EventID:     eventID,
		EventKind:   definition.EventKind,
		SchemaRef:   policyLifecycleSchemaRef,
		Attributes:  attrs,
		GeneratedAt: now,
	}, nil
}

func policyLifecycleActionDefinitionFor(action string) (policyLifecycleActionDefinition, bool) {
	action = strings.ToLower(strings.TrimSpace(action))
	for _, definition := range policyLifecycleActionDefinitions {
		if definition.ID == action {
			return definition, true
		}
	}
	return policyLifecycleActionDefinition{}, false
}

func policyLifecycleActionAttribute(request ActionRequest, key string) string {
	for attrKey, value := range request.Attributes {
		if strings.EqualFold(strings.TrimSpace(attrKey), key) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func normalizeActionRequest(request ActionRequest) ActionRequest {
	request.Action = strings.ToLower(strings.TrimSpace(request.Action))
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.SourceID = strings.TrimSpace(request.SourceID)
	request.RuntimeID = strings.TrimSpace(request.RuntimeID)
	request.PolicyID = strings.TrimSpace(request.PolicyID)
	request.PolicyVersionID = strings.TrimSpace(request.PolicyVersionID)
	request.TemplateID = strings.TrimSpace(request.TemplateID)
	request.GapID = strings.TrimSpace(request.GapID)
	request.GapState = strings.TrimSpace(request.GapState)
	request.RecordID = strings.TrimSpace(request.RecordID)
	request.RecordURN = strings.TrimSpace(request.RecordURN)
	request.Title = strings.TrimSpace(request.Title)
	request.Version = strings.TrimSpace(request.Version)
	request.Status = strings.TrimSpace(request.Status)
	request.ActorUserID = strings.TrimSpace(request.ActorUserID)
	request.Reason = strings.TrimSpace(request.Reason)
	request.DueAt = strings.TrimSpace(request.DueAt)
	request.EffectiveAt = strings.TrimSpace(request.EffectiveAt)
	request.ExpiresAt = strings.TrimSpace(request.ExpiresAt)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	request.Assignees = uniqueStrings(request.Assignees)
	request.Approvers = uniqueStrings(request.Approvers)
	request.Reviewers = uniqueStrings(request.Reviewers)
	request.ControlIDs = uniqueStrings(request.ControlIDs)
	request.EvidenceURNs = uniqueStrings(request.EvidenceURNs)
	request.GapIDs = uniqueStrings(request.GapIDs)
	return request
}

func policyLifecycleRecordID(request ActionRequest, definition policyLifecycleActionDefinition, now time.Time) string {
	if request.RecordID != "" {
		return request.RecordID
	}
	switch definition.idAttribute {
	case "gap_id":
		if len(request.GapIDs) > 0 {
			return policyLifecycleSlug(strings.Join(request.GapIDs, "-"))
		}
		return firstNonEmpty(request.GapID, request.RecordID, request.RecordURN)
	case "template_id":
		if request.TemplateID != "" {
			return request.TemplateID
		}
	case "policy_version_id":
		if request.PolicyVersionID != "" {
			return request.PolicyVersionID
		}
	case "approval_id":
		if request.RecordURN != "" {
			return policyLifecycleSuffixID(request.RecordURN)
		}
	case "acceptance_id":
		if request.RecordURN != "" {
			return policyLifecycleSuffixID(request.RecordURN)
		}
	case "review_id":
		if request.RecordURN != "" {
			return policyLifecycleSuffixID(request.RecordURN)
		}
	case "exception_id":
		if request.RecordURN != "" {
			return policyLifecycleSuffixID(request.RecordURN)
		}
	case "reminder_id":
		if request.RecordURN != "" {
			return policyLifecycleSuffixID(request.RecordURN)
		}
	}
	seed := strings.Join([]string{
		request.PolicyID,
		request.PolicyVersionID,
		request.TemplateID,
		request.Title,
		definition.ID,
		firstNonEmpty(request.IdempotencyKey, now.Format("20060102T150405.000000000Z")),
	}, "-")
	return policyLifecycleSlug(seed)
}

func policyLifecycleSuffixID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ":")
	return strings.TrimSpace(parts[len(parts)-1])
}

func policyLifecycleActionAttributes(request ActionRequest, definition policyLifecycleActionDefinition, recordID string, now time.Time) map[string]string {
	attrs := map[string]string{}
	for key, value := range request.Attributes {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			attrs[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	attrs["provider"] = firstNonEmpty(attrs["provider"], policyLifecycleProvider)
	attrs["source_system"] = firstNonEmpty(attrs["source_system"], attrs["provider"])
	attrs["lifecycle_action"] = definition.ID
	attrs["action"] = definition.ID
	attrs["record_type"] = definition.RecordType
	attrs["status"] = firstNonEmpty(request.Status, definition.Status)
	bulkGapAction := definition.idAttribute == "gap_id" && len(request.GapIDs) > 0
	if bulkGapAction {
		attrs["record_id"] = firstNonEmpty(attrs["record_id"], recordID)
		delete(attrs, "gap_id")
	} else {
		attrs[definition.idAttribute] = firstNonEmpty(recordID, attrs[definition.idAttribute])
	}
	if request.PolicyID != "" {
		attrs["policy_id"] = request.PolicyID
	}
	if request.PolicyVersionID != "" {
		attrs["policy_version_id"] = request.PolicyVersionID
	}
	if request.TemplateID != "" {
		attrs["template_id"] = request.TemplateID
	}
	if request.GapID != "" {
		attrs["gap_id"] = request.GapID
	}
	if len(request.GapIDs) > 0 {
		attrs["gap_ids"] = strings.Join(request.GapIDs, ",")
	}
	if request.GapState != "" {
		attrs["gap_state"] = request.GapState
	}
	if request.RecordID != "" {
		attrs["record_id"] = request.RecordID
	}
	if request.RecordURN != "" {
		attrs["record_urn"] = request.RecordURN
	}
	if request.Title != "" {
		attrs["title"] = request.Title
	}
	if request.Version != "" {
		attrs["version"] = request.Version
	}
	if request.RuntimeID != "" {
		attrs[ports.EventAttributeSourceRuntimeID] = request.RuntimeID
	}
	if request.ActorUserID != "" {
		attrs["actor_user_id"] = request.ActorUserID
		attrs["created_by_user_id"] = request.ActorUserID
	}
	if request.Reason != "" {
		attrs["reason"] = request.Reason
	}
	if request.DueAt != "" {
		attrs["due_at"] = request.DueAt
	}
	if request.EffectiveAt != "" {
		attrs["effective_at"] = request.EffectiveAt
	}
	if request.ExpiresAt != "" {
		attrs["expires_at"] = request.ExpiresAt
	}
	if len(request.Assignees) > 0 {
		attrs["assigned_user_ids"] = strings.Join(request.Assignees, ",")
		attrs["employee_user_ids"] = strings.Join(request.Assignees, ",")
	}
	if len(request.Approvers) > 0 {
		attrs["approver_user_ids"] = strings.Join(request.Approvers, ",")
	}
	if len(request.Reviewers) > 0 {
		attrs["reviewer_user_ids"] = strings.Join(request.Reviewers, ",")
	}
	if len(request.ControlIDs) > 0 {
		attrs["control_ids"] = strings.Join(request.ControlIDs, ",")
	}
	if len(request.EvidenceURNs) > 0 {
		attrs["evidence_cas_uri"] = strings.Join(request.EvidenceURNs, ",")
	}
	policyLifecycleActionSpecificAttributes(attrs, request, definition, now)
	if attrs["source_event_id"] == "" {
		attrs["source_event_id"] = policyLifecycleEventID(request, definition, recordID, now)
	}
	return attrs
}

func policyLifecycleActionSpecificAttributes(attrs map[string]string, request ActionRequest, definition policyLifecycleActionDefinition, now time.Time) {
	switch definition.ID {
	case "governance_gap.assign_owner", "governance_gap.set_review_date", "governance_gap.link_policy", "governance_gap.map_controls", "governance_gap.add_treatment", "governance_gap.set_treatment_date", "governance_gap.link_source_document", "governance_gap.attach_evidence", "governance_gap.acknowledge", "governance_gap.snooze", "governance_gap.accept", "governance_gap.resolve":
		attrs["gap_state"] = firstNonEmpty(attrs["gap_state"], definition.Status)
		attrs["state_updated_at"] = firstNonEmpty(attrs["state_updated_at"], now.Format(time.RFC3339))
		if len(request.GapIDs) == 0 {
			attrs["record_urn"] = firstNonEmpty(attrs["record_urn"], attrs["gap_id"])
			attrs["record_id"] = firstNonEmpty(attrs["record_id"], attrs["gap_id"])
		}
		if definition.ID == "governance_gap.set_review_date" {
			attrs["review_due_at"] = firstNonEmpty(attrs["review_due_at"], request.DueAt)
		}
		if definition.ID == "governance_gap.set_treatment_date" {
			attrs["treatment_due_at"] = firstNonEmpty(attrs["treatment_due_at"], request.DueAt)
		}
	case "draft.submit", "approval.request":
		attrs["requested_at"] = firstNonEmpty(attrs["requested_at"], now.Format(time.RFC3339))
		attrs["requested_by_user_id"] = firstNonEmpty(attrs["requested_by_user_id"], request.ActorUserID)
		attrs["approval_step"] = firstNonEmpty(attrs["approval_step"], "approval")
	case "approval.approve", "approval.reject":
		attrs["approved_at"] = firstNonEmpty(attrs["approved_at"], now.Format(time.RFC3339))
		attrs["approver_user_id"] = firstNonEmpty(attrs["approver_user_id"], request.ActorUserID)
		attrs["approval_step"] = firstNonEmpty(attrs["approval_step"], "approval")
	case "version.publish":
		attrs["approved_at"] = firstNonEmpty(attrs["approved_at"], now.Format(time.RFC3339))
		attrs["effective_at"] = firstNonEmpty(attrs["effective_at"], request.EffectiveAt, now.Format("2006-01-02"))
		attrs["author_user_id"] = firstNonEmpty(attrs["author_user_id"], request.ActorUserID)
	case "attestation.accept":
		attrs["accepted_at"] = firstNonEmpty(attrs["accepted_at"], now.Format(time.RFC3339))
		attrs["person_id"] = firstNonEmpty(attrs["person_id"], request.ActorUserID)
		attrs["user_id"] = firstNonEmpty(attrs["user_id"], request.ActorUserID)
	case "review.complete":
		attrs["reviewed_at"] = firstNonEmpty(attrs["reviewed_at"], now.Format(time.RFC3339))
		attrs["reviewer_user_id"] = firstNonEmpty(attrs["reviewer_user_id"], request.ActorUserID)
	case "exception.approve", "exception.renew":
		attrs["approved_at"] = firstNonEmpty(attrs["approved_at"], now.Format(time.RFC3339))
		attrs["approver_user_id"] = firstNonEmpty(attrs["approver_user_id"], request.ActorUserID)
	case "reminder.send":
		attrs["sent_at"] = firstNonEmpty(attrs["sent_at"], now.Format(time.RFC3339))
		attrs["sent_by_user_id"] = firstNonEmpty(attrs["sent_by_user_id"], request.ActorUserID)
	case "reminder.escalate":
		attrs["sent_at"] = firstNonEmpty(attrs["sent_at"], now.Format(time.RFC3339))
		attrs["sent_by_user_id"] = firstNonEmpty(attrs["sent_by_user_id"], request.ActorUserID)
		attrs["escalated_to_user_ids"] = firstNonEmpty(attrs["escalated_to_user_ids"], strings.Join(request.Approvers, ","))
	}
}

func policyLifecycleEventID(request ActionRequest, definition policyLifecycleActionDefinition, recordID string, now time.Time) string {
	idempotency := request.IdempotencyKey
	if idempotency == "" {
		idempotency = now.Format(time.RFC3339Nano)
	}
	seed := strings.Join([]string{
		request.TenantID,
		firstNonEmpty(request.SourceID, policyLifecycleDefaultSourceID),
		request.RuntimeID,
		definition.ID,
		recordID,
		idempotency,
	}, "\x00")
	sum := sha256.Sum256([]byte(seed))
	return "grc-policy-lifecycle-" + hex.EncodeToString(sum[:])[:16]
}

func policyLifecycleSlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	mapped := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, value)
	mapped = strings.Trim(mapped, "-")
	for strings.Contains(mapped, "--") {
		mapped = strings.ReplaceAll(mapped, "--", "-")
	}
	if mapped == "" {
		return "record"
	}
	return mapped
}

type ExportWindow struct {
	Start *time.Time
	End   *time.Time
}

func ParseExportWindowTime(raw string, endOfDay bool) (*time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		utc := parsed.UTC()
		return &utc, nil
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return nil, fmt.Errorf("invalid time")
	}
	utc := parsed.UTC()
	if endOfDay {
		utc = utc.AddDate(0, 0, 1).Add(-time.Nanosecond)
	}
	return &utc, nil
}

func AuditExportHeader() []string {
	return []string{
		"record_type", "record_id", "policy_id", "policy_title", "version_id",
		"status", "owner", "reviewer", "action", "actor",
		"occurred_at", "due_at", "effective_at", "expires_at",
		"controls", "evidence", "record_urn", "gap_subject_title", "gap_missing_fields", "gap_rule_id",
	}
}

func AuditExportRows(response Response, window ExportWindow) [][]string {
	rows := [][]string{}
	policyTitles := exportPolicyTitles(response.Policies)
	for _, policy := range response.Policies {
		if exportWindowIncludesAny(window, policy.NextReviewDueAt) {
			rows = append(rows, []string{"policy", policy.ID, policy.ID, policy.Title, policy.LatestVersion, policy.Status, policy.Owner, policy.Reviewer, "", "", "", policy.NextReviewDueAt, "", "", exportControls(policy.Controls), exportEvidence(policy.Evidence), policy.URN, "", "", ""})
		}
		for _, version := range policy.Versions {
			if !exportWindowIncludesAny(window, version.CreatedAt, version.ApprovedAt, version.EffectiveAt) {
				continue
			}
			rows = append(rows, []string{"policy.version", version.ID, policy.ID, policy.Title, version.Version, version.Status, firstNonEmpty(version.Owner, policy.Owner), "", "", version.Author, firstNonEmpty(version.CreatedAt, version.ApprovedAt), "", version.EffectiveAt, "", exportControls(version.Controls), exportEvidence(version.Evidence), version.URN, "", "", ""})
		}
		for _, approval := range policy.Approvals {
			if !exportWindowIncludesAny(window, approval.RequestedAt, approval.ApprovedAt, approval.DueAt) {
				continue
			}
			rows = append(rows, []string{"policy.approval", approval.ID, policy.ID, policy.Title, approval.VersionID, approval.Status, firstNonEmpty(approval.RequestedBy, firstNonEmpty(approval.Approvers...)), "", "approval", firstNonEmpty(approval.Approvers...), firstNonEmpty(approval.ApprovedAt, approval.RequestedAt), approval.DueAt, "", "", "", "", approval.URN, "", "", ""})
		}
		for _, attestation := range policy.Attestations {
			if !exportWindowIncludesAny(window, attestation.AcceptedAt, attestation.DueAt) {
				continue
			}
			rows = append(rows, []string{"policy.acceptance", attestation.ID, policy.ID, policy.Title, attestation.VersionID, attestation.Status, firstNonEmpty(attestation.Person, firstNonEmpty(attestation.Assignees...)), "", "attestation", attestation.Person, attestation.AcceptedAt, attestation.DueAt, "", "", "", "", attestation.URN, "", "", ""})
		}
		for _, review := range policy.Reviews {
			if !exportWindowIncludesAny(window, review.ReviewedAt, review.ReviewDueAt) {
				continue
			}
			rows = append(rows, []string{"policy.review", review.ID, policy.ID, policy.Title, review.VersionID, review.Status, firstNonEmpty(review.Owner, policy.Owner), firstNonEmpty(review.Reviewers...), "review", firstNonEmpty(review.Reviewers...), review.ReviewedAt, review.ReviewDueAt, "", "", "", "", review.URN, "", "", ""})
		}
		for _, exception := range policy.Exceptions {
			if !exportWindowIncludesAny(window, exception.ApprovedAt, exception.ExpiresAt) {
				continue
			}
			rows = append(rows, []string{"policy.exception", exception.ID, policy.ID, policy.Title, exception.VersionID, exception.Status, firstNonEmpty(exception.Owner, policy.Owner), firstNonEmpty(exception.Approvers...), "exception", firstNonEmpty(exception.Approvers...), exception.ApprovedAt, "", "", exception.ExpiresAt, exportControls(exception.Controls), "", exception.URN, "", "", ""})
		}
		for _, event := range policy.Events {
			if !exportWindowIncludesAny(window, event.OccurredAt) {
				continue
			}
			rows = append(rows, []string{"policy.lifecycle.event", event.ID, policy.ID, policy.Title, event.VersionID, event.Status, "", "", event.Action, event.Actor, event.OccurredAt, "", "", "", "", "", event.URN, "", "", ""})
		}
	}
	for _, mapping := range response.Mappings {
		rows = append(rows, []string{"policy.mapping", "", mapping.PolicyID, mapping.PolicyTitle, "", "", "", "", "mapping", "", "", "", "", "", exportControls(mapping.Controls), exportEvidence(mapping.Evidence), mapping.SourceURN, "", "", ""})
	}
	for _, gap := range response.GovernanceGaps {
		if !exportWindowIncludesGovernanceGap(window, gap) {
			continue
		}
		rows = append(rows, []string{"governance.gap", gap.SubjectID, gap.PolicyID, policyTitles[gap.PolicyID], "", gap.GapState, gap.Owner, "", gap.Action, gap.LastActor, gap.StateUpdatedAt, gap.DueAt, "", "", "", "", gap.ID, gap.Title, strings.Join(gap.MissingFields, "; "), gap.RuleID})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i][0] == rows[j][0] {
			return strings.Join(rows[i], "\x00") < strings.Join(rows[j], "\x00")
		}
		return rows[i][0] < rows[j][0]
	})
	return rows
}

func exportPolicyTitles(policies []grcPolicyLifecyclePolicy) map[string]string {
	titles := map[string]string{}
	for _, policy := range policies {
		if strings.TrimSpace(policy.ID) != "" && strings.TrimSpace(policy.Title) != "" {
			titles[policy.ID] = policy.Title
		}
	}
	return titles
}

func exportWindowIncludesGovernanceGap(window ExportWindow, gap grcPolicyGovernanceGap) bool {
	if exportWindowIncludesAny(window, gap.DueAt, gap.StateUpdatedAt) {
		return true
	}
	return (window.Start != nil || window.End != nil) && strings.TrimSpace(gap.DueAt) == "" && strings.TrimSpace(gap.StateUpdatedAt) == ""
}

func exportControls(items []grcPolicyControlRef) string {
	values := make([]string, 0, len(items))
	for _, item := range items {
		values = append(values, strings.TrimSpace(strings.Join([]string{item.Framework, item.ControlID, item.Title}, " ")))
	}
	return strings.Join(uniqueStrings(values), "; ")
}

func exportEvidence(items []grcPolicyEvidenceRef) string {
	values := make([]string, 0, len(items))
	for _, item := range items {
		values = append(values, firstNonEmpty(item.Title, item.DocumentID, item.URN))
	}
	return strings.Join(uniqueStrings(values), "; ")
}

func exportWindowIncludesAny(window ExportWindow, values ...string) bool {
	if window.Start == nil && window.End == nil {
		return true
	}
	for _, value := range values {
		if parsed, ok := grcPolicyTime(value); ok && exportWindowIncludes(window, parsed) {
			return true
		}
	}
	return false
}

func exportWindowIncludes(window ExportWindow, value time.Time) bool {
	value = value.UTC()
	if window.Start != nil && value.Before(window.Start.UTC()) {
		return false
	}
	if window.End != nil && value.After(window.End.UTC()) {
		return false
	}
	return true
}
