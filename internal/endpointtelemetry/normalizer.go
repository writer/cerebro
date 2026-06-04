package endpointtelemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const sourceID = "trusted_endpoint"
const runtimeID = "trusted-endpoint"

// Principal identifies the authenticated device that submitted telemetry.
type Principal struct {
	TenantID     string
	DeviceID     string
	HardwareUUID string
	SerialNumber string
	Hostname     string
}

// Normalize converts the endpoint telemetry ingest envelope into bounded
// source events that downstream projections can persist or replay.
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
			"serial_number":     principal.SerialNumber,
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
			"serial_number":     principal.SerialNumber,
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
	}
	return envelopes, nil
}

func normalizeEvent(raw map[string]any, principal Principal, agentID string) (string, string, map[string]any, map[string]string) {
	eventType := firstString(raw, "type", "event", "action", "status")
	action := actionFromEventType(eventType)
	outcome := outcomeFromEvent(raw, eventType)
	if firstString(raw, "finding_id", "findingId") != "" {
		findingID := firstString(raw, "finding_id", "findingId")
		severity := firstNonEmpty(firstString(raw, "severity"), "unknown")
		payload := map[string]any{
			"agent_id":      agentID,
			"device_id":     principal.DeviceID,
			"serial_number": principal.SerialNumber,
			"finding_id":    findingID,
			"severity":      severity,
			"source":        "endpoint_telemetry",
			"raw":           raw,
		}
		return "trusted_endpoint.security_finding", "trusted_endpoint/security_finding/v1", payload, map[string]string{
			"agent_id":      agentID,
			"device_id":     principal.DeviceID,
			"serial_number": principal.SerialNumber,
			"finding_id":    findingID,
			"severity":      severity,
		}
	}
	payload := map[string]any{
		"agent_id":      agentID,
		"device_id":     principal.DeviceID,
		"serial_number": principal.SerialNumber,
		"action":        action,
		"outcome":       outcome,
		"raw":           raw,
	}
	return "trusted_endpoint.action_outcome", "trusted_endpoint/action_outcome/v1", payload, map[string]string{
		"agent_id":       agentID,
		"device_id":      principal.DeviceID,
		"serial_number":  principal.SerialNumber,
		"action":         action,
		"outcome_result": outcome,
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
	out["source_runtime_id"] = runtimeID
	for key, value := range attrs {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			out[key] = value
		}
	}
	return out
}
