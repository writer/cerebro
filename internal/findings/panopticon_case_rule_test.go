package findings

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPanopticonCuratedCaseFindingRule(t *testing.T) {
	rule := newPanopticonCuratedCaseRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("panopticon-curated-case does not expose RuleMetadata")
	}
	definition := metadataRule.RuleMetadata()
	if err := definition.Validate(); err != nil {
		t.Fatalf("RuleDefinition.Validate() error = %v", err)
	}
	if definition.Lifecycle.Kind != LifecycleDurableState {
		t.Fatalf("Lifecycle.Kind = %q, want %q", definition.Lifecycle.Kind, LifecycleDurableState)
	}
	if definition.Lifecycle.Anchor != AnchorSourceState {
		t.Fatalf("Lifecycle.Anchor = %q, want %q", definition.Lifecycle.Anchor, AnchorSourceState)
	}
	if !cloudStringSlicesEqual(definition.FingerprintFields, []string{"tenant_id", "case_id"}) {
		t.Fatalf("FingerprintFields = %v, want [tenant_id case_id]", definition.FingerprintFields)
	}
	if !rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "panopticon"}) {
		t.Fatal("default Panopticon runtime must support the case rule")
	}
	if rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "panopticon", Config: map[string]string{"family": "alert"}}) {
		t.Fatal("explicit Panopticon alert runtime must not produce case findings")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("panopticon-curated-case does not implement CounterEventRule")
	}
	runtime := &cerebrov1.SourceRuntime{Id: "writer-panopticon-case", SourceId: "panopticon", TenantId: "writer", Config: map[string]string{"family": "case"}}
	open := panopticonCaseEventAt("panopticon-case-1", "case-123", "investigating", "Risky Chrome extension", "high", identityTrajectoryBaseTime)
	findings, err := rule.Evaluate(context.Background(), runtime, open)
	if err != nil {
		t.Fatalf("Evaluate(open) error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Evaluate(open) returned %d findings, want 1", len(findings))
	}
	finding := findings[0]
	if finding.RuleID != panopticonCuratedCaseRuleID {
		t.Fatalf("RuleID = %q, want %q", finding.RuleID, panopticonCuratedCaseRuleID)
	}
	if finding.Severity != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH", finding.Severity)
	}
	if finding.PolicyID != "case-123" {
		t.Fatalf("PolicyID = %q, want case-123", finding.PolicyID)
	}
	if !strings.Contains(finding.Summary, "Risky Chrome extension") || !strings.Contains(finding.Summary, "SIEM preprocessing") {
		t.Fatalf("Summary = %q, want case title and preprocessing boundary", finding.Summary)
	}
	if got := len(finding.ExternalRefs); got != 1 {
		t.Fatalf("ExternalRefs = %d, want 1", got)
	}
	externalRef := finding.ExternalRefs[0]
	if externalRef.System != "panopticon" || externalRef.Kind != "case" || externalRef.ExternalID != "case-123" {
		t.Fatalf("ExternalRef = %+v, want panopticon case case-123", externalRef)
	}
	if externalRef.LifecycleOwner != "external_owned" {
		t.Fatalf("ExternalRef.LifecycleOwner = %q, want external_owned", externalRef.LifecycleOwner)
	}
	if got := finding.Attributes["upstream_signal_boundary"]; got != "panopticon_case" {
		t.Fatalf("upstream_signal_boundary = %q, want panopticon_case", got)
	}
	for key, want := range map[string]string{
		"lookup_table":            "chrome_extensions_risk",
		"preprocessing_decision":  "escalated",
		"preprocessing_reason":    "extension matched risky lookup table",
		"upstream_alert_count":    "1",
		"upstream_alert_ids":      "alert-case-123",
		"upstream_detection_id":   "panther_chrome_extension_installed",
		"upstream_detection_name": "Chrome extension installed",
		"upstream_siem":           "Panther",
	} {
		if got := finding.Attributes[key]; got != want {
			t.Fatalf("Attributes[%q] = %q, want %q", key, got, want)
		}
		if got := finding.GraphEvidenceRows[0].GetAttributes()[key]; got != want {
			t.Fatalf("GraphEvidenceRows[0].Attributes[%q] = %q, want %q", key, got, want)
		}
	}
	if !containsTrimmed(finding.ResourceURNs, "urn:cerebro:writer:panopticon_case:case-123") {
		t.Fatalf("ResourceURNs = %#v, want Panopticon case URN", finding.ResourceURNs)
	}

	openAnchor := counterRule.OpenAnchor(finding.Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty", finding.Attributes)
	}
	closed := panopticonCaseEventAt("panopticon-case-closed", "case-123", "closed", "Risky Chrome extension", "high", identityTrajectoryBaseTime.Add(time.Minute))
	findings, err = rule.Evaluate(context.Background(), runtime, closed)
	if err != nil {
		t.Fatalf("Evaluate(closed) error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Evaluate(closed) returned %d findings, want 0 once Panopticon closes case", len(findings))
	}
	closeAnchor, closes := counterRule.CloseOnEvent(closed)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(closed) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}
	assertIdentityRuleRemediationTrajectory(t, rule, open, closed, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestPanopticonCuratedCaseRuleIgnoresAlerts(t *testing.T) {
	rule := newPanopticonCuratedCaseRule()
	records, err := rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "writer-panopticon-alert", SourceId: "panopticon", TenantId: "writer", Config: map[string]string{"family": "alert"}}, &cerebrov1.EventEnvelope{
		Id:         "panopticon-alert-1",
		TenantId:   "writer",
		SourceId:   "panopticon",
		Kind:       "panopticon.alert",
		OccurredAt: timestamppb.New(identityTrajectoryBaseTime),
		Attributes: map[string]string{
			"alert_id": "alert-1",
			"severity": "high",
			"status":   "open",
			"title":    "Raw Panther alert",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate(alert) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(alert) returned %d findings, want 0", len(records))
	}
}

func panopticonCaseEventAt(id string, caseID string, status string, title string, severity string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	payload, _ := json.Marshal(map[string]interface{}{
		"case_id":                caseID,
		"status":                 status,
		"title":                  title,
		"severity":               severity,
		"case_url":               "https://panopticon.example.test/cases/" + caseID,
		"lookup_table":           "chrome_extensions_risk",
		"preprocessing_decision": "escalated",
		"preprocessing_reason":   "extension matched risky lookup table",
		"alerts": []map[string]interface{}{
			{
				"alert_id":  "alert-" + caseID,
				"rule_id":   "panther_chrome_extension_installed",
				"rule_name": "Chrome extension installed",
				"severity":  severity,
				"source":    "Panther",
				"status":    status,
				"title":     title,
			},
		},
	})
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "panopticon",
		Kind:       "panopticon.case",
		SchemaRef:  "panopticon/case/v1",
		OccurredAt: timestamppb.New(occurredAt),
		Payload:    payload,
		Attributes: map[string]string{
			"case_id":    caseID,
			"status":     status,
			"title":      title,
			"severity":   severity,
			"case_url":   "https://panopticon.example.test/cases/" + caseID,
			"runtime_id": "writer-panopticon-case",
		},
	}
}
