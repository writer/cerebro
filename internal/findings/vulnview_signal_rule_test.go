package findings

import (
	"context"
	"strings"
	"testing"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestVulnviewActionableExternalFinding(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("vulnview-actionable-external-finding does not expose RuleMetadata")
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
	if !cloudStringSlicesEqual(definition.FingerprintFields, []string{"asset_urn", "template_id"}) {
		t.Fatalf("FingerprintFields = %v, want [asset_urn template_id]", definition.FingerprintFields)
	}
	for _, field := range definition.FingerprintFields {
		if strings.EqualFold(field, "matched_at") {
			t.Fatalf("FingerprintFields = %v, must not include matched_at", definition.FingerprintFields)
		}
	}
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("vulnview-actionable-external-finding does not implement CounterEventRule")
	}
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-vulnerability", SourceId: "vulnview", TenantId: "writer"}
	event := vulnViewActionableExternalFindingEventAt("vulnview-vuln-1", "https://admin.writer.com/login", "open", "high", identityTrajectoryBaseTime)
	findings, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(Evaluate()) = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.RuleID != vulnViewActionableExternalFindingRuleID {
		t.Fatalf("RuleID = %q, want %q", finding.RuleID, vulnViewActionableExternalFindingRuleID)
	}
	if finding.Severity != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH", finding.Severity)
	}
	if finding.PolicyID != "exposed-panel" {
		t.Fatalf("PolicyID = %q, want exposed-panel", finding.PolicyID)
	}
	if finding.Attributes["target"] != "admin.writer.com" {
		t.Fatalf("target = %q, want admin.writer.com", finding.Attributes["target"])
	}
	wantAssetURN := "urn:cerebro:writer:external_asset:admin.writer.com"
	if finding.Attributes["primary_resource_urn"] != wantAssetURN {
		t.Fatalf("primary_resource_urn = %q, want %q", finding.Attributes["primary_resource_urn"], wantAssetURN)
	}
	if finding.Attributes["asset_urn"] != wantAssetURN {
		t.Fatalf("asset_urn = %q, want %q", finding.Attributes["asset_urn"], wantAssetURN)
	}
	wantFingerprint := hashFindingFingerprint(vulnViewActionableExternalFindingRuleID, wantAssetURN, "exposed-panel")
	if finding.Fingerprint != wantFingerprint {
		t.Fatalf("Fingerprint = %q, want asset/template fingerprint %q", finding.Fingerprint, wantFingerprint)
	}
	openAnchor := counterRule.OpenAnchor(finding.Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty, want asset/template anchor", finding.Attributes)
	}

	rescan := vulnViewActionableExternalFindingEventAt("vulnview-vuln-2", "https://admin.writer.com/admin", "open", "high", identityTrajectoryBaseTime.Add(time.Minute))
	findings, err = rule.Evaluate(context.Background(), runtime, rescan)
	if err != nil {
		t.Fatalf("Evaluate(rescan) error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Evaluate(rescan) returned %d findings, want 1", len(findings))
	}
	if got := findings[0].Fingerprint; got != finding.Fingerprint {
		t.Fatalf("rescan fingerprint = %q, want stable %q when only matched_at changes", got, finding.Fingerprint)
	}

	closed := vulnViewActionableExternalFindingEventAt("vulnview-vuln-closed", "https://admin.writer.com/admin", "closed", "high", identityTrajectoryBaseTime.Add(2*time.Minute))
	findings, err = rule.Evaluate(context.Background(), runtime, closed)
	if err != nil {
		t.Fatalf("Evaluate(closed) error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Evaluate(closed) returned %d findings, want 0 once VulnView reports closed", len(findings))
	}
	closeAnchor, closes := counterRule.CloseOnEvent(closed)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(closed) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}

	noLongerActionable := vulnViewActionableExternalFindingEventAt("vulnview-vuln-low", "https://admin.writer.com/settings", "open", "low", identityTrajectoryBaseTime.Add(3*time.Minute))
	findings, err = rule.Evaluate(context.Background(), runtime, noLongerActionable)
	if err != nil {
		t.Fatalf("Evaluate(no longer actionable) error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Evaluate(no longer actionable) returned %d findings, want 0 after rescan no longer matches", len(findings))
	}
	closeAnchor, closes = counterRule.CloseOnEvent(noLongerActionable)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(no longer actionable) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}

	assertIdentityRuleRemediationTrajectory(t, rule, event, closed, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
	olderClosed := vulnViewActionableExternalFindingEventAt("vulnview-vuln-closed-before-open", "https://admin.writer.com/admin", "closed", "high", identityTrajectoryBaseTime.Add(-time.Minute))
	assertIdentityRuleOlderCloseDoesNotResolveLaterOpen(t, rule, olderClosed, event)
}

func TestVulnViewActionableExternalFindingRuleIgnoresInfo(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	findings, err := rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "writer-vulnview", SourceId: "vulnview", TenantId: "writer"}, &cerebrov1.EventEnvelope{
		Id:       "vulnview-info-1",
		TenantId: "writer",
		SourceId: "vulnview",
		Kind:     "vulnview.vulnerability",
		Attributes: map[string]string{
			"name":     "Technology Detection",
			"severity": "info",
		},
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("len(Evaluate()) = %d, want 0", len(findings))
	}
}

func TestVulnViewActionableExternalFindingRuleDeduplicatesMatchedLocations(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-vulnerability", SourceId: "vulnview", TenantId: "writer"}
	base := &cerebrov1.EventEnvelope{
		Id:       "vulnview-vuln-1",
		TenantId: "writer",
		SourceId: "vulnview",
		Kind:     "vulnview.vulnerability",
		Attributes: map[string]string{
			"host":        "app.writer.com",
			"matched_at":  "https://app.writer.com/login",
			"name":        "Test CVE",
			"severity":    "high",
			"target_id":   "app.writer.com",
			"template_id": "cve-2026-1234",
		},
	}
	first, err := rule.Evaluate(context.Background(), runtime, base)
	if err != nil {
		t.Fatalf("Evaluate(first) error = %v", err)
	}
	base.Id = "vulnview-vuln-2"
	base.Attributes["matched_at"] = "https://app.writer.com/admin"
	second, err := rule.Evaluate(context.Background(), runtime, base)
	if err != nil {
		t.Fatalf("Evaluate(second) error = %v", err)
	}
	if first[0].ID != second[0].ID {
		t.Fatalf("finding IDs split for distinct matched_at values: first=%q second=%q", first[0].ID, second[0].ID)
	}
}

func vulnViewActionableExternalFindingEventAt(id string, matchedAt string, status string, severity string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "vulnview",
		Kind:       "vulnview.vulnerability",
		OccurredAt: timestamppb.New(occurredAt),
		Attributes: map[string]string{
			"external_id": "scan-1:exposed-panel:admin.writer.com",
			"host":        "admin.writer.com",
			"matched_at":  matchedAt,
			"name":        "Exposed Admin Panel",
			"severity":    severity,
			"status":      status,
			"target_id":   "admin.writer.com",
			"template_id": "exposed-panel",
		},
	}
}
