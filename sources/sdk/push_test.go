package sdk

import (
	"errors"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/sourcecdk"
)

func validPushedTelemetry() PushedTelemetry {
	return PushedTelemetry{
		TenantID:      "writer",
		RuntimeID:     "writer-sdk-jira-posture",
		Integration:   "jira",
		ResourceURN:   "urn:cerebro:writer:runtime:writer-sdk-jira-posture:workspace:writer",
		ResourceType:  "workspace",
		ResourceLabel: "Writer Jira",
		Control:       "sso_enforced",
		PostureStatus: "at_risk",
		RiskReason:    "workspace allows password-only sign-in",
		OccurredAt:    time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
		Attributes:    map[string]string{"owner": "Security"},
	}
}

func TestNormalizePushedTelemetryAcceptsValidPosture(t *testing.T) {
	event, err := NormalizePushedTelemetry(validPushedTelemetry())
	if err != nil {
		t.Fatalf("NormalizePushedTelemetry() error = %v", err)
	}
	if event.GetKind() != "sdk.integration_posture" {
		t.Fatalf("Kind = %q, want sdk.integration_posture", event.GetKind())
	}
	if event.GetTenantId() != "writer" || event.GetSourceId() != "sdk" {
		t.Fatalf("tenant/source = %q/%q, want writer/sdk", event.GetTenantId(), event.GetSourceId())
	}
	attrs := event.GetAttributes()
	if attrs["integration"] != "jira" {
		t.Fatalf("integration = %q, want jira", attrs["integration"])
	}
	if attrs["resource_urn"] != "urn:cerebro:writer:runtime:writer-sdk-jira-posture:workspace:writer" {
		t.Fatalf("resource_urn = %q", attrs["resource_urn"])
	}
	if attrs["control"] != "sso_enforced" || attrs["posture_status"] != "at_risk" {
		t.Fatalf("control/posture = %q/%q", attrs["control"], attrs["posture_status"])
	}
	if attrs["source_runtime_id"] != "writer-sdk-jira-posture" {
		t.Fatalf("source_runtime_id = %q", attrs["source_runtime_id"])
	}
	if attrs["owner"] != "Security" {
		t.Fatalf("owner passthrough = %q, want Security", attrs["owner"])
	}
	if event.GetId() == "" {
		t.Fatal("event id is empty, want deterministic id")
	}
}

func TestNormalizePushedTelemetryIsDeterministic(t *testing.T) {
	first, err := NormalizePushedTelemetry(validPushedTelemetry())
	if err != nil {
		t.Fatalf("NormalizePushedTelemetry() error = %v", err)
	}
	second, err := NormalizePushedTelemetry(validPushedTelemetry())
	if err != nil {
		t.Fatalf("NormalizePushedTelemetry() error = %v", err)
	}
	if first.GetId() != second.GetId() {
		t.Fatalf("event ids %q and %q differ, want deterministic identity", first.GetId(), second.GetId())
	}
}

func TestNormalizePushedTelemetryPostureTransitionProducesDistinctEventIDs(t *testing.T) {
	atRisk := validPushedTelemetry()
	atRisk.PostureStatus = "at_risk"
	secure := validPushedTelemetry()
	secure.PostureStatus = "secure"

	atRiskEvent, err := NormalizePushedTelemetry(atRisk)
	if err != nil {
		t.Fatalf("NormalizePushedTelemetry(at_risk) error = %v", err)
	}
	secureEvent, err := NormalizePushedTelemetry(secure)
	if err != nil {
		t.Fatalf("NormalizePushedTelemetry(secure) error = %v", err)
	}
	if atRiskEvent.GetId() == secureEvent.GetId() {
		t.Fatalf("at_risk and secure transition share event id %q; the secure transition would be dropped by append-log Msg-Id dedupe and the finding would never resolve", atRiskEvent.GetId())
	}
}

func TestNormalizePushedTelemetryIdenticalPostureRetriesShareEventID(t *testing.T) {
	first := validPushedTelemetry()
	first.PostureStatus = "at_risk"
	first.OccurredAt = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	second := validPushedTelemetry()
	second.PostureStatus = "at_risk"
	second.OccurredAt = time.Date(2026, 5, 1, 18, 0, 0, 0, time.UTC)

	firstEvent, err := NormalizePushedTelemetry(first)
	if err != nil {
		t.Fatalf("NormalizePushedTelemetry(first) error = %v", err)
	}
	secondEvent, err := NormalizePushedTelemetry(second)
	if err != nil {
		t.Fatalf("NormalizePushedTelemetry(second) error = %v", err)
	}
	if firstEvent.GetId() != secondEvent.GetId() {
		t.Fatalf("identical posture retries produced event ids %q and %q; idempotent re-reports of the same posture must stay deduplicated", firstEvent.GetId(), secondEvent.GetId())
	}
}

func TestNormalizePushedTelemetryRejectsMissingIdentity(t *testing.T) {
	cases := map[string]func(p *PushedTelemetry){
		"tenant":       func(p *PushedTelemetry) { p.TenantID = "  " },
		"integration":  func(p *PushedTelemetry) { p.Integration = "" },
		"control":      func(p *PushedTelemetry) { p.Control = "" },
		"resource_urn": func(p *PushedTelemetry) { p.ResourceURN = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			payload := validPushedTelemetry()
			mutate(&payload)
			_, err := NormalizePushedTelemetry(payload)
			if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
				t.Fatalf("NormalizePushedTelemetry() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNormalizePushedTelemetryRejectsMalformedResourceURN(t *testing.T) {
	payload := validPushedTelemetry()
	payload.ResourceURN = "not-a-urn"
	_, err := NormalizePushedTelemetry(payload)
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("NormalizePushedTelemetry() error = %v, want ErrInvalidConfig", err)
	}
}

func TestNormalizePushedTelemetryRejectsCrossTenantResourceURN(t *testing.T) {
	payload := validPushedTelemetry()
	payload.ResourceURN = "urn:cerebro:acme:workspace:acme"
	_, err := NormalizePushedTelemetry(payload)
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("NormalizePushedTelemetry() cross-tenant error = %v, want ErrInvalidConfig", err)
	}
}

func TestNormalizePushedTelemetryRejectsUnsafeControlCharacters(t *testing.T) {
	cases := map[string]func(p *PushedTelemetry){
		"integration":     func(p *PushedTelemetry) { p.Integration = "jira\nrm -rf" },
		"control":         func(p *PushedTelemetry) { p.Control = "sso\tenforced" },
		"runtime_id":      func(p *PushedTelemetry) { p.RuntimeID = "writer-sdk\njira" },
		"resource_urn":    func(p *PushedTelemetry) { p.ResourceURN = "urn:cerebro:writer:workspace:name\x01" },
		"attribute_value": func(p *PushedTelemetry) { p.Attributes = map[string]string{"owner": "sec\x00urity"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			payload := validPushedTelemetry()
			mutate(&payload)
			_, err := NormalizePushedTelemetry(payload)
			if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
				t.Fatalf("NormalizePushedTelemetry() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNormalizePushedTelemetryRejectsReservedTokenDelimiter(t *testing.T) {
	cases := map[string]func(p *PushedTelemetry){
		"integration": func(p *PushedTelemetry) { p.Integration = "jira:prod" },
		"control":     func(p *PushedTelemetry) { p.Control = "sso:enforced" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			payload := validPushedTelemetry()
			mutate(&payload)
			_, err := NormalizePushedTelemetry(payload)
			if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
				t.Fatalf("NormalizePushedTelemetry() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNormalizePushedTelemetryRejectsUnknownPostureStatus(t *testing.T) {
	payload := validPushedTelemetry()
	payload.PostureStatus = "purple"
	_, err := NormalizePushedTelemetry(payload)
	if !errors.Is(err, sourcecdk.ErrInvalidConfig) {
		t.Fatalf("NormalizePushedTelemetry() error = %v, want ErrInvalidConfig", err)
	}
}

func TestNormalizePushedTelemetryNormalizesPostureSynonyms(t *testing.T) {
	cases := map[string]string{
		"failing":   "at_risk",
		"violation": "at_risk",
		"compliant": "secure",
		"resolved":  "secure",
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			payload := validPushedTelemetry()
			payload.PostureStatus = input
			event, err := NormalizePushedTelemetry(payload)
			if err != nil {
				t.Fatalf("NormalizePushedTelemetry() error = %v", err)
			}
			if got := event.GetAttributes()["posture_status"]; got != want {
				t.Fatalf("posture_status = %q, want %q", got, want)
			}
		})
	}
}
