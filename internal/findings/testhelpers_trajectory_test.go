package findings

import (
	"context"
	"sort"
	"strings"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/securityevents"
	"github.com/writer/cerebro/internal/workflowevents"
	"google.golang.org/protobuf/proto"
)

type FindingStatus = cerebrov1.FindingStatus

func assertGitHubRuleTrajectory(t *testing.T, rule Rule, events []Event, expectedFinalStatus FindingStatus) {
	t.Helper()
	if rule == nil {
		t.Fatal("rule is required")
	}
	spec := rule.Spec()
	if spec == nil || strings.TrimSpace(spec.GetId()) == "" {
		t.Fatal("rule must expose a non-empty RuleSpec.Id")
	}
	if len(events) == 0 {
		t.Fatal("events are required")
	}
	if isRetiredGitHubAuditRule(rule) {
		assertGitHubAuditRuleRetired(t, rule)
		return
	}
	ruleID := strings.TrimSpace(spec.GetId())
	expectedStatus := githubTrajectoryFindingStatusString(t, expectedFinalStatus)
	runtimeID := githubTrajectoryRuntimeID(events)
	tenantID := githubTrajectoryTenantID(events)
	family := githubTrajectoryFamily(events)

	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry(%q) error = %v", ruleID, err)
	}
	store := &stubFindingStore{}
	replayer := &stubReplayer{events: events}
	appendLog := &recordingAppendLog{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{
			runtimeID: {
				Id:       runtimeID,
				SourceId: "github",
				TenantId: tenantID,
				Config:   map[string]string{"family": family},
			},
		}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	).WithGraphStore(&stubGraphStore{}).WithAppendLog(appendLog)

	result, err := service.EvaluateSourceRuntimeRules(context.Background(), EvaluateRulesRequest{
		RuntimeID: runtimeID,
		RuleIDs:   []string{ruleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeRules(%q) error = %v", ruleID, err)
	}
	if replayer.calls != 1 {
		t.Fatalf("Replay calls = %d, want 1", replayer.calls)
	}
	if got := strings.TrimSpace(replayer.request.RuntimeID); got != runtimeID {
		t.Fatalf("Replay RuntimeID = %q, want %q", got, runtimeID)
	}
	if result == nil {
		t.Fatal("EvaluateSourceRuntimeRules returned nil result")
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", got)
	}
	evaluation := result.Evaluations[0]
	if evaluation == nil {
		t.Fatal("evaluation result is nil")
	}
	if got := strings.TrimSpace(evaluation.Rule.GetId()); got != ruleID {
		t.Fatalf("evaluation rule id = %q, want %q", got, ruleID)
	}
	if len(evaluation.Findings) == 0 {
		t.Fatalf("rule %q emitted no findings; trajectory helper needs one opening finding", ruleID)
	}

	finalFindings := githubTrajectoryPersistedFindings(store, ruleID, runtimeID)
	if got := len(finalFindings); got != 1 {
		t.Fatalf("persisted findings for rule %q = %d, want 1", ruleID, got)
	}
	finalFinding := finalFindings[0]
	if got := strings.TrimSpace(finalFinding.Status); got != expectedStatus {
		t.Fatalf("final finding status = %q, want %q", got, expectedStatus)
	}

	baseline := evaluation.Findings[0]
	if baseline == nil {
		t.Fatal("first emitted finding is nil")
	}
	baselineFingerprint := strings.TrimSpace(baseline.Fingerprint)
	if baselineFingerprint == "" {
		t.Fatalf("first emitted finding %q has empty fingerprint", baseline.ID)
	}
	for i, emitted := range evaluation.Findings {
		if emitted == nil {
			t.Fatalf("emitted finding %d is nil", i)
		}
		if got := strings.TrimSpace(emitted.Fingerprint); got != baselineFingerprint {
			t.Fatalf("emitted finding %d fingerprint = %q, want stable %q", i, got, baselineFingerprint)
		}
	}
	if got := strings.TrimSpace(finalFinding.Fingerprint); got != baselineFingerprint {
		t.Fatalf("final finding fingerprint = %q, want stable %q", got, baselineFingerprint)
	}
	assertGitHubTrajectoryAnchorAttributesPreserved(t, rule, baseline, finalFinding)
	assertGitHubTrajectoryWorkflowEvents(t, appendLog.events, finalFinding, baselineFingerprint, expectedStatus)
}

func githubTrajectoryFindingStatusString(t *testing.T, status FindingStatus) string {
	t.Helper()
	switch status {
	case cerebrov1.FindingStatus_FINDING_STATUS_OPEN:
		return findingStatusOpen
	case cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED:
		return findingStatusResolved
	case cerebrov1.FindingStatus_FINDING_STATUS_SUPPRESSED:
		return findingStatusSuppressed
	default:
		t.Fatalf("unsupported expected final finding status: %s", status.String())
		return ""
	}
}

func githubTrajectoryRuntimeID(events []Event) string {
	for _, event := range events {
		if event == nil {
			continue
		}
		if runtimeID := strings.TrimSpace(event.GetAttributes()[ports.EventAttributeSourceRuntimeID]); runtimeID != "" {
			return runtimeID
		}
	}
	return "example-github-audit"
}

func githubTrajectoryTenantID(events []Event) string {
	for _, event := range events {
		if event == nil {
			continue
		}
		if tenantID := strings.TrimSpace(event.GetTenantId()); tenantID != "" {
			return tenantID
		}
	}
	return "writer"
}

func githubTrajectoryFamily(events []Event) string {
	for _, event := range events {
		if event == nil {
			continue
		}
		if family := strings.TrimSpace(event.GetAttributes()["family"]); family != "" {
			return family
		}
		kind := strings.TrimSpace(event.GetKind())
		if strings.HasPrefix(kind, "github.") {
			return strings.TrimPrefix(kind, "github.")
		}
	}
	return "audit"
}

func githubTrajectoryPersistedFindings(store *stubFindingStore, ruleID string, runtimeID string) []*ports.FindingRecord {
	if store == nil {
		return nil
	}
	findings := make([]*ports.FindingRecord, 0, len(store.findings))
	for _, finding := range store.findings {
		if finding == nil {
			continue
		}
		if strings.TrimSpace(finding.RuleID) != strings.TrimSpace(ruleID) {
			continue
		}
		if strings.TrimSpace(finding.RuntimeID) != strings.TrimSpace(runtimeID) {
			continue
		}
		if finding.Tombstoned {
			continue
		}
		findings = append(findings, cloneFinding(finding))
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})
	return findings
}

func assertGitHubTrajectoryAnchorAttributesPreserved(t *testing.T, rule Rule, baseline *ports.FindingRecord, finalFinding *ports.FindingRecord) {
	t.Helper()
	if baseline == nil || finalFinding == nil {
		t.Fatal("baseline and final finding are required")
	}
	if len(baseline.ResourceURNs) != 0 && !cloudStringSlicesEqual(finalFinding.ResourceURNs, baseline.ResourceURNs) {
		t.Fatalf("final ResourceURNs = %#v, want preserved %#v", finalFinding.ResourceURNs, baseline.ResourceURNs)
	}
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
	}
	for _, field := range metadataRule.RuleMetadata().FingerprintFields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		expected := strings.TrimSpace(baseline.Attributes[field])
		if expected == "" {
			continue
		}
		if got := strings.TrimSpace(finalFinding.Attributes[field]); got != expected {
			t.Fatalf("final anchor attribute %q = %q, want preserved %q", field, got, expected)
		}
	}
}

func assertGitHubTrajectoryWorkflowEvents(t *testing.T, events []*cerebrov1.EventEnvelope, finalFinding *ports.FindingRecord, fingerprint string, expectedStatus string) {
	t.Helper()
	findingID := strings.TrimSpace(finalFinding.ID)
	recorded := false
	statusChanged := false
	for _, event := range events {
		if event == nil {
			continue
		}
		switch event.GetKind() {
		case workflowevents.EventKindFindingRecorded, securityevents.FindingRecorded:
			payload, err := decodeCanonicalFindingRecorded(event)
			if err != nil {
				t.Fatalf("DecodeFindingRecorded(%q): %v", event.GetId(), err)
			}
			if strings.TrimSpace(payload.Finding.FindingID) != findingID {
				continue
			}
			recorded = true
			if got := strings.TrimSpace(payload.Finding.Fingerprint); got != fingerprint {
				t.Fatalf("workflow recorded fingerprint = %q, want %q", got, fingerprint)
			}
			if expectedStatus == findingStatusOpen {
				if got := strings.TrimSpace(payload.Finding.Status); got != expectedStatus {
					t.Fatalf("workflow recorded status = %q, want %q", got, expectedStatus)
				}
			}
		case workflowevents.EventKindFindingStatusChanged, securityevents.FindingStatusChanged:
			payload, err := decodeCanonicalFindingStatusChanged(event)
			if err != nil {
				t.Fatalf("DecodeFindingStatusChanged(%q): %v", event.GetId(), err)
			}
			if strings.TrimSpace(payload.Finding.FindingID) != findingID {
				continue
			}
			statusChanged = true
			if got := strings.TrimSpace(payload.Finding.Fingerprint); got != fingerprint {
				t.Fatalf("workflow status-changed fingerprint = %q, want %q", got, fingerprint)
			}
			if got := strings.TrimSpace(payload.Status); got != expectedStatus {
				t.Fatalf("workflow status-changed status = %q, want %q", got, expectedStatus)
			}
			if got := strings.TrimSpace(payload.Finding.Status); got != expectedStatus {
				t.Fatalf("workflow status-changed finding status = %q, want %q", got, expectedStatus)
			}
		}
	}
	if !recorded {
		t.Fatalf("workflow finding.recorded event for finding %q not found in %d appended events", findingID, len(events))
	}
	if expectedStatus != findingStatusOpen && !statusChanged {
		t.Fatalf("workflow finding.status_changed event for final status %q and finding %q not found in %d appended events", expectedStatus, findingID, len(events))
	}
}

func decodeCanonicalFindingRecorded(event *cerebrov1.EventEnvelope) (*workflowevents.FindingRecorded, error) {
	if event.GetKind() != securityevents.FindingRecorded {
		return workflowevents.DecodeFindingRecorded(event)
	}
	clone := protoCloneEvent(event, workflowevents.EventKindFindingRecorded)
	return workflowevents.DecodeFindingRecorded(clone)
}

func decodeCanonicalFindingStatusChanged(event *cerebrov1.EventEnvelope) (*workflowevents.FindingStatusChanged, error) {
	if event.GetKind() != securityevents.FindingStatusChanged {
		return workflowevents.DecodeFindingStatusChanged(event)
	}
	clone := protoCloneEvent(event, workflowevents.EventKindFindingStatusChanged)
	return workflowevents.DecodeFindingStatusChanged(clone)
}

func protoCloneEvent(event *cerebrov1.EventEnvelope, kind string) *cerebrov1.EventEnvelope {
	clone := proto.Clone(event).(*cerebrov1.EventEnvelope)
	clone.Kind = kind
	clone.Attributes = map[string]string{}
	for key, value := range event.GetAttributes() {
		clone.Attributes[key] = value
	}
	return clone
}
