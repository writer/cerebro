// Package secheck implements a telemetry adapter for the SeCheck endpoint
// vulnerability agent. It normalizes endpoint verification, remediation,
// and heartbeat events into Cerebro runtime observations.
package secheck

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/runtime"
	"github.com/writer/cerebro/internal/runtime/adapters"
)

const SourceName = "secheck"

type Adapter struct{}

var _ adapters.Adapter = Adapter{}

func (Adapter) Source() string { return SourceName }

type endpointPayload struct {
	DeviceID     string         `json:"device_id"`
	Hostname     string         `json:"hostname"`
	OSType       string         `json:"os_type"`
	AgentVersion string         `json:"agent_version"`
	OrgID        string         `json:"org_id"`
	EventType    string         `json:"event_type"`
	Timestamp    string         `json:"timestamp"`
	Events       []agentEvent   `json:"events"`
	Posture      *postureReport `json:"posture,omitempty"`
}

type agentEvent struct {
	Type      string         `json:"type"`
	FindingID string         `json:"finding_id"`
	CVEID     string         `json:"cve_id"`
	Package   string         `json:"package"`
	Severity  string         `json:"severity"`
	Manager   string         `json:"manager"`
	Ecosystem string         `json:"ecosystem"`
	Status    string         `json:"status"`
	Data      map[string]any `json:"data,omitempty"`
}

type postureReport struct {
	FindingsConfirmed  int    `json:"findings_confirmed"`
	FindingsDisputed   int    `json:"findings_disputed"`
	FindingsRemediated int    `json:"findings_remediated"`
	FindingsSnoozed    int    `json:"findings_snoozed"`
	NetworkType        string `json:"network_type"`
}

func (Adapter) Normalize(_ context.Context, raw []byte) ([]*runtime.RuntimeObservation, error) {
	var payload endpointPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode secheck payload: %w", err)
	}

	if strings.TrimSpace(payload.DeviceID) == "" {
		return nil, fmt.Errorf("decode secheck payload: device_id is required")
	}

	observations := make([]*runtime.RuntimeObservation, 0, len(payload.Events)+1)

	for idx, event := range payload.Events {
		observation := observationFromEvent(payload, event, idx)
		normalized, err := runtime.NormalizeObservation(observation)
		if err != nil {
			continue
		}
		observations = append(observations, normalized)
	}

	if payload.Posture != nil {
		observation := observationFromPosture(payload)
		normalized, err := runtime.NormalizeObservation(observation)
		if err == nil {
			observations = append(observations, normalized)
		}
	}

	return observations, nil
}

func observationFromEvent(payload endpointPayload, event agentEvent, idx int) *runtime.RuntimeObservation {
	observedAt := parseTime(payload.Timestamp)
	kind := observationKind(event.Type)

	metadata := map[string]any{
		"device_id":     payload.DeviceID,
		"hostname":      payload.Hostname,
		"os_type":       payload.OSType,
		"agent_version": payload.AgentVersion,
		"org_id":        payload.OrgID,
		"event_type":    event.Type,
		"finding_id":    event.FindingID,
		"cve_id":        event.CVEID,
		"package":       event.Package,
		"severity":      event.Severity,
		"manager":       event.Manager,
		"ecosystem":     event.Ecosystem,
		"status":        event.Status,
	}
	for k, v := range event.Data {
		metadata[k] = v
	}

	resourceID := fmt.Sprintf("endpoint:%s", payload.DeviceID)
	if event.Package != "" {
		resourceID = fmt.Sprintf("endpoint:%s/pkg:%s", payload.DeviceID, event.Package)
	}

	return &runtime.RuntimeObservation{
		ID:           fmt.Sprintf("secheck-%s-%d-%d", payload.DeviceID, observedAt.Unix(), idx),
		Kind:         kind,
		Source:       SourceName,
		ObservedAt:   observedAt,
		ResourceID:   resourceID,
		ResourceType: "endpoint_device",
		NodeName:     payload.Hostname,
		PrincipalID:  payload.DeviceID,
		Tags:         eventTags(event),
		Metadata:     metadata,
	}
}

func observationFromPosture(payload endpointPayload) *runtime.RuntimeObservation {
	observedAt := parseTime(payload.Timestamp)
	metadata := map[string]any{
		"device_id":           payload.DeviceID,
		"hostname":            payload.Hostname,
		"os_type":             payload.OSType,
		"agent_version":       payload.AgentVersion,
		"org_id":              payload.OrgID,
		"findings_confirmed":  payload.Posture.FindingsConfirmed,
		"findings_disputed":   payload.Posture.FindingsDisputed,
		"findings_remediated": payload.Posture.FindingsRemediated,
		"findings_snoozed":    payload.Posture.FindingsSnoozed,
		"network_type":        payload.Posture.NetworkType,
	}

	return &runtime.RuntimeObservation{
		ID:           fmt.Sprintf("secheck-%s-heartbeat-%d", payload.DeviceID, observedAt.Unix()),
		Kind:         runtime.ObservationKindRuntimeAlert,
		Source:       SourceName,
		ObservedAt:   observedAt,
		ResourceID:   fmt.Sprintf("endpoint:%s", payload.DeviceID),
		ResourceType: "endpoint_device",
		NodeName:     payload.Hostname,
		PrincipalID:  payload.DeviceID,
		Tags:         []string{"secheck", "heartbeat", "posture"},
		Metadata:     metadata,
	}
}

func observationKind(eventType string) runtime.RuntimeObservationKind {
	switch eventType {
	case "verification.confirmed", "verification.disputed", "verification.pending":
		return runtime.ObservationKindRuntimeAlert
	case "remediation.completed", "remediation.failed", "remediation.snoozed":
		return runtime.ObservationKindResponseOutcome
	default:
		return runtime.ObservationKindRuntimeAlert
	}
}

func eventTags(event agentEvent) []string {
	tags := []string{"secheck"}
	if event.Type != "" {
		tags = append(tags, "secheck:"+event.Type)
	}
	if event.Severity != "" {
		tags = append(tags, "severity:"+event.Severity)
	}
	if event.CVEID != "" {
		tags = append(tags, "cve:"+event.CVEID)
	}
	if event.Ecosystem != "" {
		tags = append(tags, "ecosystem:"+event.Ecosystem)
	}
	return tags
}

func parseTime(ts string) time.Time {
	if ts == "" {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Now().UTC()
	}
	return t.UTC()
}
