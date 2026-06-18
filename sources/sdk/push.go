package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/sourcecdk"
)

const (
	integrationPostureKind      = "sdk.integration_posture"
	integrationPostureSchemaRef = "sdk/integration_posture/v1"

	postureStatusAtRisk = "at_risk"
	postureStatusSecure = "secure"
)

var errPostureStatusRequired = errors.New("sdk telemetry posture status is required")

// PushedTelemetry is one raw SDK push-surface integration posture payload
// submitted by an SDK-onboarded application about a resource it owns.
type PushedTelemetry struct {
	TenantID      string
	RuntimeID     string
	Integration   string
	ResourceURN   string
	ResourceType  string
	ResourceLabel string
	Control       string
	PostureStatus string
	RiskReason    string
	OccurredAt    time.Time
	Attributes    map[string]string
}

// NormalizePushedTelemetry validates and normalizes one pushed SDK integration
// posture payload into a deterministic sdk.integration_posture event. It rejects
// payloads that omit required tenant/source/identity fields, that carry a
// malformed or cross-tenant resource urn, that embed unsafe control characters,
// or that report an unrecognized posture status.
func NormalizePushedTelemetry(payload PushedTelemetry) (*cerebrov1.EventEnvelope, error) {
	tenantID, err := safeRequiredToken("tenant id", payload.TenantID)
	if err != nil {
		return nil, err
	}
	integration, err := safeRequiredToken("integration", payload.Integration)
	if err != nil {
		return nil, err
	}
	control, err := safeRequiredToken("control", payload.Control)
	if err != nil {
		return nil, err
	}
	resourceURN := strings.TrimSpace(payload.ResourceURN)
	if resourceURN == "" {
		return nil, fmt.Errorf("%w: sdk telemetry resource urn is required", sourcecdk.ErrInvalidConfig)
	}
	if _, err := sourcecdk.ParseURN(resourceURN); err != nil {
		return nil, fmt.Errorf("%w: sdk telemetry resource urn is malformed: %w", sourcecdk.ErrInvalidConfig, err)
	}
	if !strings.HasPrefix(resourceURN, "urn:cerebro:"+tenantID+":") {
		return nil, fmt.Errorf("%w: sdk telemetry resource urn must belong to tenant %q", sourcecdk.ErrInvalidConfig, tenantID)
	}
	if hasUnsafeCharacters(resourceURN) {
		return nil, fmt.Errorf("%w: sdk telemetry resource urn contains unsafe characters", sourcecdk.ErrInvalidConfig)
	}
	rawPostureStatus := strings.TrimSpace(payload.PostureStatus)
	if rawPostureStatus == "" {
		return nil, fmt.Errorf("%w: %w", sourcecdk.ErrInvalidConfig, errPostureStatusRequired)
	}
	postureStatus := normalizePostureStatus(rawPostureStatus)
	if postureStatus == "" {
		return nil, fmt.Errorf("%w: sdk telemetry posture status %q is not recognized", sourcecdk.ErrInvalidConfig, payload.PostureStatus)
	}

	attributes := map[string]string{}
	for key, value := range payload.Attributes {
		normalizedKey := strings.TrimSpace(key)
		normalizedValue := strings.TrimSpace(value)
		if normalizedKey == "" || normalizedValue == "" {
			continue
		}
		if hasUnsafeCharacters(normalizedKey) || hasUnsafeCharacters(normalizedValue) {
			return nil, fmt.Errorf("%w: sdk telemetry attribute %q contains unsafe characters", sourcecdk.ErrInvalidConfig, normalizedKey)
		}
		attributes[normalizedKey] = normalizedValue
	}
	resourceLabel := strings.TrimSpace(payload.ResourceLabel)
	riskReason := strings.TrimSpace(payload.RiskReason)
	resourceType := strings.TrimSpace(payload.ResourceType)
	for label, value := range map[string]string{"resource_label": resourceLabel, "risk_reason": riskReason, "resource_type": resourceType} {
		if hasUnsafeCharacters(value) {
			return nil, fmt.Errorf("%w: sdk telemetry %s contains unsafe characters", sourcecdk.ErrInvalidConfig, label)
		}
	}

	runtimeID := strings.TrimSpace(payload.RuntimeID)
	if hasUnsafeCharacters(runtimeID) {
		return nil, fmt.Errorf("%w: sdk telemetry runtime id contains unsafe characters", sourcecdk.ErrInvalidConfig)
	}
	setAttribute(attributes, "integration", integration)
	setAttribute(attributes, "resource_urn", resourceURN)
	setAttribute(attributes, "resource_type", resourceType)
	setAttribute(attributes, "resource_label", resourceLabel)
	setAttribute(attributes, "control", control)
	setAttribute(attributes, "posture_status", postureStatus)
	setAttribute(attributes, "risk_reason", riskReason)
	setAttribute(attributes, "source_runtime_id", runtimeID)

	event := &cerebrov1.EventEnvelope{
		Id:         integrationPostureEventID(tenantID, integration, control, resourceURN, postureStatus),
		TenantId:   tenantID,
		SourceId:   "sdk",
		Kind:       integrationPostureKind,
		SchemaRef:  integrationPostureSchemaRef,
		Attributes: attributes,
	}
	if !payload.OccurredAt.IsZero() {
		event.OccurredAt = timestamppb.New(payload.OccurredAt.UTC())
	}
	return event, nil
}

func safeRequiredToken(field string, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("%w: sdk telemetry %s is required", sourcecdk.ErrInvalidConfig, field)
	}
	if hasUnsafeCharacters(trimmed) {
		return "", fmt.Errorf("%w: sdk telemetry %s contains unsafe characters", sourcecdk.ErrInvalidConfig, field)
	}
	if strings.Contains(trimmed, ":") {
		return "", fmt.Errorf("%w: sdk telemetry %s contains reserved ':' character", sourcecdk.ErrInvalidConfig, field)
	}
	return trimmed, nil
}

func hasUnsafeCharacters(value string) bool {
	for _, r := range value {
		if r == '\n' || r == '\r' || r == '\t' || r == 0x00 {
			return true
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func setAttribute(attributes map[string]string, key string, value string) {
	if strings.TrimSpace(value) == "" {
		delete(attributes, key)
		return
	}
	attributes[key] = value
}

func normalizePostureStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case postureStatusAtRisk, "atrisk", "risk", "at-risk", "insecure", "failing", "fail", "failed", "noncompliant", "non_compliant", "non-compliant", "violation", "open", "high_risk", "high-risk":
		return postureStatusAtRisk
	case postureStatusSecure, "ok", "pass", "passing", "passed", "compliant", "resolved", "healthy", "remediated", "closed":
		return postureStatusSecure
	default:
		return ""
	}
}

// integrationPostureEventID derives a deterministic append-log identity for one
// posture report. The posture status is part of the identity so a posture
// transition (for example at_risk to secure) yields a distinct event id and is
// not dropped by the append-log Msg-Id dedupe, while idempotent re-reports of
// the same posture keep a stable id and stay deduplicated.
func integrationPostureEventID(tenantID string, integration string, control string, resourceURN string, postureStatus string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{tenantID, integration, control, resourceURN, postureStatus}, "\x00")))
	return "sdk-integration-posture-" + hex.EncodeToString(sum[:12])
}
