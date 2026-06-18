package endpointtelemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const sourceID = "trusted_endpoint"

// Principal identifies the authenticated device that submitted telemetry.
type Principal struct {
	TenantID     string
	DeviceID     string
	HardwareUUID string
	Hostname     string
}

// Normalize converts the Trusted Endpoint telemetry ingest envelope into
// bounded source events that downstream projections can persist or replay. It
// emits the supported trusted_endpoint.* telemetry families (host posture,
// security findings, trust-gate decisions, GRC evidence, and action outcomes)
// and rejects malformed records that cannot satisfy the per-kind emission
// contract.
func Normalize(body []byte, principal Principal, observedAt time.Time) ([]*cerebrov1.EventEnvelope, error) {
	tenantID := strings.TrimSpace(principal.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant_id is required")
	}
	agentID := firstNonEmpty(principal.DeviceID, principal.HardwareUUID, principal.Hostname)
	if agentID == "" {
		return nil, fmt.Errorf("device identity is required")
	}
	var payload struct {
		Events  []map[string]any `json:"events"`
		Posture map[string]any   `json:"posture"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode endpoint telemetry: %w", err)
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	var envelopes []*cerebrov1.EventEnvelope
	if payload.Posture != nil {
		eventPayload := map[string]any{
			"agent_id":          agentID,
			"device_id":         principal.DeviceID,
			"hardware_uuid":     principal.HardwareUUID,
			"hostname":          principal.Hostname,
			"observation_table": observationTable(payload.Posture),
			"summary":           payload.Posture,
		}
		envelope, err := eventEnvelope(tenantID, agentID, "trusted_endpoint.host_posture", "trusted_endpoint/host_posture/v1", eventPayload, map[string]string{
			"agent_id":          agentID,
			"device_id":         principal.DeviceID,
			"hardware_key":      firstNonEmpty(principal.HardwareUUID, principal.DeviceID, principal.Hostname),
			"hostname":          principal.Hostname,
			"observation_table": observationTable(payload.Posture),
		}, observedAt, len(envelopes))
		if err != nil {
			return nil, err
		}
		envelopes = append(envelopes, envelope)
	}
	for _, raw := range payload.Events {
		kind, schemaRef, eventPayload, attrs := normalizeEvent(raw, principal, agentID)
		envelope, err := eventEnvelope(tenantID, agentID, kind, schemaRef, eventPayload, attrs, observedAt, len(envelopes))
		if err != nil {
			return nil, err
		}
		envelopes = append(envelopes, envelope)
	}
	for _, envelope := range envelopes {
		if err := sourcecdk.ValidateEventEnvelope(envelope); err != nil {
			return nil, err
		}
		if err := validateEmittedAttributes(envelope); err != nil {
			return nil, err
		}
	}
	return envelopes, nil
}

func normalizeEvent(raw map[string]any, principal Principal, agentID string) (string, string, map[string]any, map[string]string) {
	eventType := firstString(raw, "type", "event", "action", "status")
	if findingID := firstString(raw, "finding_id", "findingId"); findingID != "" {
		severity := normalizeSeverity(firstString(raw, "severity"))
		payload := map[string]any{
			"agent_id":   agentID,
			"device_id":  principal.DeviceID,
			"finding_id": findingID,
			"severity":   severity,
			"source":     "endpoint_telemetry",
			"raw":        raw,
		}
		return "trusted_endpoint.security_finding", "trusted_endpoint/security_finding/v1", payload, map[string]string{
			"agent_id":   agentID,
			"device_id":  principal.DeviceID,
			"finding_id": findingID,
			"severity":   severity,
		}
	}
	if controlID := firstString(raw, "control_id", "controlId"); controlID != "" {
		status := normalizeStatus(firstString(raw, "status", "result", "state"))
		payload := map[string]any{
			"agent_id":   agentID,
			"device_id":  principal.DeviceID,
			"control_id": controlID,
			"status":     status,
			"framework":  firstString(raw, "framework", "control_framework"),
			"source":     "endpoint_telemetry",
			"raw":        raw,
		}
		return "trusted_endpoint.grc_evidence", "trusted_endpoint/grc_evidence/v1", payload, map[string]string{
			"agent_id":   agentID,
			"device_id":  principal.DeviceID,
			"control_id": controlID,
			"status":     status,
		}
	}
	if isTrustGateEvent(raw, eventType) {
		action := trustGateAction(raw, eventType)
		decision := normalizeDecision(firstNonEmpty(firstString(raw, "decision", "verdict", "result"), decisionFromEventType(eventType)))
		severity := normalizeSeverity(firstString(raw, "severity"))
		lifecycle := normalizeAgentLifecycle(raw)
		payload := map[string]any{
			"agent_id": agentID,
			"action":   action,
			"decision": decision,
			"reason":   firstString(raw, "reason", "decision_reason", "rationale"),
			"source":   "endpoint_telemetry",
			"raw":      raw,
		}
		attrs := map[string]string{
			"agent_id":     agentID,
			"action":       action,
			"decision":     decision,
			"reason":       firstString(raw, "reason", "decision_reason", "rationale"),
			"severity":     severity,
			"agent_status": lifecycle,
		}
		if managed, ok := normalizeManagedFlag(raw); ok {
			attrs["managed"] = strconv.FormatBool(managed)
		}
		return "trusted_endpoint.trust_gate_decision", "trusted_endpoint/trust_gate_decision/v1", payload, attrs
	}
	action := actionFromEventType(eventType)
	outcome := outcomeFromEvent(raw, eventType)
	payload := map[string]any{
		"agent_id":  agentID,
		"device_id": principal.DeviceID,
		"action":    action,
		"outcome":   outcome,
		"raw":       raw,
	}
	return "trusted_endpoint.action_outcome", "trusted_endpoint/action_outcome/v1", payload, map[string]string{
		"agent_id":       agentID,
		"device_id":      principal.DeviceID,
		"action":         action,
		"outcome_result": outcome,
	}
}

// validateEmittedAttributes rejects telemetry that cannot satisfy the per-kind
// emission contract, so malformed trust-gate or GRC evidence records do not
// enter the append log with missing posture-critical fields.
func validateEmittedAttributes(envelope *cerebrov1.EventEnvelope) error {
	attrs := envelope.GetAttributes()
	requireAttrs := func(keys ...string) error {
		for _, key := range keys {
			if strings.TrimSpace(attrs[key]) == "" {
				return fmt.Errorf("%s telemetry missing required attribute %q", envelope.GetKind(), key)
			}
		}
		return nil
	}
	switch envelope.GetKind() {
	case "trusted_endpoint.trust_gate_decision":
		return requireAttrs("agent_id", "action", "decision")
	case "trusted_endpoint.grc_evidence":
		return requireAttrs("agent_id", "control_id", "status")
	case "trusted_endpoint.security_finding":
		return requireAttrs("agent_id", "finding_id", "severity")
	default:
		return nil
	}
}

func eventEnvelope(tenantID, agentID, kind, schemaRef string, payload map[string]any, attrs map[string]string, observedAt time.Time, index int) (*cerebrov1.EventEnvelope, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal endpoint telemetry event: %w", err)
	}
	attrs = trimAttrs(attrs)
	id := eventID(tenantID, agentID, kind, data, index)
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   tenantID,
		SourceId:   sourceID,
		Kind:       kind,
		SchemaRef:  schemaRef,
		OccurredAt: timestamppb.New(observedAt.UTC()),
		Payload:    data,
		Attributes: attrs,
	}, nil
}

func eventID(tenantID, agentID, kind string, payload []byte, index int) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", tenantID, agentID, kind, index, payload)))
	return "trusted_endpoint_" + hex.EncodeToString(hash[:12])
}

func observationTable(posture map[string]any) string {
	return firstNonEmpty(firstString(posture, "observation_table", "type", "kind"), "secheck.posture")
}

func isTrustGateEvent(raw map[string]any, eventType string) bool {
	if firstString(raw, "decision", "verdict") != "" {
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(eventType), "trust_gate")
}

func trustGateAction(raw map[string]any, eventType string) string {
	if action := firstString(raw, "action", "gated_action", "operation"); action != "" {
		return action
	}
	if _, after, ok := strings.Cut(strings.TrimSpace(eventType), "."); ok && strings.TrimSpace(after) != "" {
		return after
	}
	return "trust_gate"
}

func decisionFromEventType(eventType string) string {
	if _, after, ok := strings.Cut(strings.TrimSpace(eventType), "."); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

func normalizeDecision(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "deny", "denied", "block", "blocked", "fail", "failed", "reject", "rejected":
		return "deny"
	case "allow", "allowed", "pass", "passed", "ok", "permit", "permitted", "approved":
		return "allow"
	case "error", "errored":
		return "error"
	case "":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "fail", "failed", "failing", "non_compliant", "noncompliant", "violation":
		return "failing"
	case "pass", "passed", "passing", "compliant", "ok", "success":
		return "passing"
	case "":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

// normalizeAgentLifecycle derives a deterministic agent lifecycle state from the
// endpoint control-plane fields so downstream trust-gate findings can resolve for
// deprovisioned/offboarded agents instead of reading inconsistent raw values.
func normalizeAgentLifecycle(raw map[string]any) string {
	return normalizeAgentStatus(firstString(raw, "agent_status", "device_status", "agent_state", "lifecycle", "lifecycle_state", "enrollment_status"))
}

func normalizeAgentStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return ""
	case "deprovisioned", "deleted", "removed", "offboarded", "off-boarded", "off boarded", "unenrolled", "un-enrolled", "deactivated", "inactive", "retired", "decommissioned", "disabled", "terminated", "revoked":
		return "deprovisioned"
	case "active", "enrolled", "managed", "enabled", "provisioned", "online":
		return "active"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func normalizeManagedFlag(raw map[string]any) (bool, bool) {
	value, ok := raw["managed"]
	if !ok {
		return false, false
	}
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "t", "true", "yes", "y", "enabled", "on", "active", "managed":
			return true, true
		case "0", "f", "false", "no", "n", "disabled", "off", "inactive", "unmanaged":
			return false, true
		}
	}
	return false, false
}

func normalizeSeverity(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return "unknown"
	}
	return trimmed
}

func actionFromEventType(eventType string) string {
	eventType = strings.TrimSpace(eventType)
	if eventType == "" {
		return "endpoint.telemetry"
	}
	if before, _, ok := strings.Cut(eventType, "."); ok && strings.TrimSpace(before) != "" {
		return before
	}
	return eventType
}

func outcomeFromEvent(raw map[string]any, eventType string) string {
	if outcome := firstString(raw, "outcome", "result", "status"); outcome != "" {
		return outcome
	}
	if _, after, ok := strings.Cut(strings.TrimSpace(eventType), "."); ok && strings.TrimSpace(after) != "" {
		return after
	}
	return "observed"
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := values[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if trimmed := strings.TrimSpace(typed); trimmed != "" {
				return trimmed
			}
		case fmt.Stringer:
			if trimmed := strings.TrimSpace(typed.String()); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func trimAttrs(attrs map[string]string) map[string]string {
	out := make(map[string]string, len(attrs))
	for key, value := range attrs {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			out[key] = value
		}
	}
	return out
}
