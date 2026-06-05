package findings

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
	"github.com/writer/cerebro/internal/sourcecdk"
	"github.com/writer/cerebro/internal/workflowevents"
	vulnviewsource "github.com/writer/cerebro/sources/vulnview"
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

func TestVulnViewActionableExternalFindingSourceAdapterStateTrajectory(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	for _, tc := range []struct {
		name   string
		family string
	}{
		{name: "vulnerability", family: "vulnerability"},
		{name: "dns alert", family: "dns_alert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			open, closed := vulnViewSourceAdapterStateEvents(t, tc.family)
			counterRule, ok := rule.(CounterEventRule)
			if !ok {
				t.Fatal("vulnview-actionable-external-finding does not implement CounterEventRule")
			}
			runtime := &cerebrov1.SourceRuntime{Id: "example-vulnview-" + tc.family, SourceId: "vulnview", TenantId: "writer", Config: map[string]string{"family": tc.family}}
			records, err := rule.Evaluate(context.Background(), runtime, open)
			if err != nil {
				t.Fatalf("Evaluate(open) error = %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("Evaluate(open) returned %d findings, want 1", len(records))
			}
			openAnchor := counterRule.OpenAnchor(records[0].Attributes)
			if openAnchor == "" {
				t.Fatalf("OpenAnchor(%v) = empty, want asset/template anchor", records[0].Attributes)
			}
			if _, ok := open.GetAttributes()["status"]; ok {
				t.Fatalf("source adapter emitted legacy status attribute %q; rule must consume namespaced VulnView state", open.GetAttributes()["status"])
			}
			if _, ok := open.GetAttributes()["state"]; ok {
				t.Fatalf("source adapter emitted legacy state attribute %q; rule must consume namespaced VulnView state", open.GetAttributes()["state"])
			}

			records, err = rule.Evaluate(context.Background(), runtime, closed)
			if err != nil {
				t.Fatalf("Evaluate(closed) error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate(closed) returned %d findings, want 0 once VulnView reports closed", len(records))
			}
			closeAnchor, closes := counterRule.CloseOnEvent(closed)
			if !closes || closeAnchor != openAnchor {
				t.Fatalf("CloseOnEvent(closed) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
			}
			assertIdentityRuleRemediationTrajectory(t, rule, open, closed, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
		})
	}
}

func TestVulnViewActionableExternalFindingIgnoresLegacySyntheticStateOnly(t *testing.T) {
	rule := newVulnViewActionableExternalFindingRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-vulnerability", SourceId: "vulnview", TenantId: "writer"}
	for _, legacyKey := range []string{"status", "state"} {
		t.Run(legacyKey, func(t *testing.T) {
			event := &cerebrov1.EventEnvelope{
				Id:         "vulnview-legacy-synthetic-" + legacyKey,
				TenantId:   "writer",
				SourceId:   "vulnview",
				Kind:       "vulnview.vulnerability",
				OccurredAt: timestamppb.New(identityTrajectoryBaseTime),
				Attributes: map[string]string{
					"external_id": "scan-1:exposed-panel:admin.writer.com",
					"host":        "admin.writer.com",
					"matched_at":  "https://admin.writer.com/login",
					"name":        "Exposed Admin Panel",
					"severity":    "high",
					legacyKey:     "open",
					"target_id":   "admin.writer.com",
					"template_id": "exposed-panel",
				},
			}
			findings, err := rule.Evaluate(context.Background(), runtime, event)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("Evaluate() returned %d findings from legacy synthetic %s-only event, want 0", len(findings), legacyKey)
			}
		})
	}
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
			"host":                   "app.writer.com",
			"matched_at":             "https://app.writer.com/login",
			"name":                   "Test CVE",
			"severity":               "high",
			"target_id":              "app.writer.com",
			"template_id":            "cve-2026-1234",
			"vulnview_finding_state": "open",
			"vulnview_status":        "open",
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

func TestVulnViewActionableExternalFindingServicePreservesCollapsedEvidence(t *testing.T) {
	store := &stubFindingStore{}
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-vulnerability", SourceId: "vulnview", TenantId: "writer"}
	service := New(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtime.GetId(): runtime}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{
			vulnViewActionableExternalFindingEventAt("vulnview-vuln-1", "https://admin.writer.com/login", "open", "high", identityTrajectoryBaseTime),
			vulnViewActionableExternalFindingEventAt("vulnview-vuln-2", "https://admin.writer.com/admin", "open", "high", identityTrajectoryBaseTime.Add(time.Minute)),
		}},
		store,
		store,
		store,
		store,
	)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: runtime.GetId(),
		RuleID:    vulnViewActionableExternalFindingRuleID,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if result.EventsEvaluated != 2 {
		t.Fatalf("EventsEvaluated = %d, want 2", result.EventsEvaluated)
	}
	if len(store.findings) != 1 {
		t.Fatalf("len(store.findings) = %d, want 1", len(store.findings))
	}
	var stored *ports.FindingRecord
	for _, finding := range store.findings {
		stored = finding
	}
	if stored == nil {
		t.Fatal("stored finding = nil")
	}
	for _, eventID := range []string{"vulnview-vuln-1", "vulnview-vuln-2"} {
		if !containsString(stored.EventIDs, eventID) {
			t.Fatalf("stored.EventIDs = %#v, want %q", stored.EventIDs, eventID)
		}
	}
	wantLocations := "https://admin.writer.com/login,https://admin.writer.com/admin"
	if got := stored.Attributes["matched_locations"]; got != wantLocations {
		t.Fatalf("matched_locations = %q, want %q", got, wantLocations)
	}
	if !containsString(stored.RiskReasons, "multiple_events") {
		t.Fatalf("RiskReasons = %#v, want multiple_events", stored.RiskReasons)
	}
}

func TestVulnViewActionableExternalFindingRecordsPanopticonThreatHuntAction(t *testing.T) {
	appendLog := &recordingAppendLog{}
	graph := &stubGraphStore{}
	store := &stubFindingStore{}
	runtime := &cerebrov1.SourceRuntime{Id: "writer-vulnview-vulnerability", SourceId: "vulnview", TenantId: "writer"}
	event := vulnViewActionableExternalFindingEventAt("vulnview-cve-1", "https://app.example.com/login", "open", "critical", identityTrajectoryBaseTime)
	event.Attributes["external_id"] = "scan-1:cve-2026-1234:app.example.com"
	event.Attributes["host"] = "app.example.com"
	event.Attributes["name"] = "CVE-2026-1234 test exposure"
	event.Attributes["target_id"] = "app.example.com"
	event.Attributes["template_id"] = "cve-2026-1234"
	service := New(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtime.GetId(): runtime}},
		&stubReplayer{events: []*cerebrov1.EventEnvelope{event}},
		store,
		store,
		store,
		store,
	).WithGraphStore(graph).WithAppendLog(appendLog)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID: runtime.GetId(),
		RuleID:    vulnViewActionableExternalFindingRuleID,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("Findings = %#v, want one VulnView finding", result.Findings)
	}
	var actionEvent *cerebrov1.EventEnvelope
	for _, event := range appendLog.events {
		if event.GetKind() == workflowevents.EventKindKnowledgeActionRecorded {
			actionEvent = event
			break
		}
	}
	if actionEvent == nil {
		t.Fatalf("appendLog events = %#v, want Panopticon action event", eventKindsForTest(appendLog.events))
	}
	action, err := workflowevents.DecodeActionRecorded(actionEvent)
	if err != nil {
		t.Fatalf("DecodeActionRecorded() error = %v", err)
	}
	if action.ActionType != panopticonThreatHuntActionType {
		t.Fatalf("ActionType = %q, want %q", action.ActionType, panopticonThreatHuntActionType)
	}
	if action.Status != "requested" {
		t.Fatalf("Status = %q, want requested", action.Status)
	}
	if action.Metadata["cve_id"] != "CVE-2026-1234" {
		t.Fatalf("metadata cve_id = %#v, want CVE-2026-1234", action.Metadata["cve_id"])
	}
	if action.Metadata["handoff_target"] != "panopticon" || action.Metadata["panopticon_orchestrator"] != "soc-planner" {
		t.Fatalf("metadata = %#v, want Panopticon soc-planner handoff", action.Metadata)
	}
	if action.Metadata["ioc_lookup_required"] != true {
		t.Fatalf("metadata ioc_lookup_required = %#v, want true", action.Metadata["ioc_lookup_required"])
	}
	findingURN := findingGraphFindingURN("writer", result.Findings[0])
	if len(action.TargetIDs) != 1 || action.TargetIDs[0] != findingURN {
		t.Fatalf("TargetIDs = %#v, want finding target %q", action.TargetIDs, findingURN)
	}
	linkKey := action.ActionID + "|targets|" + findingURN
	if _, ok := graph.links[linkKey]; !ok {
		t.Fatalf("graph action target link %q missing; links=%#v", linkKey, graph.links)
	}
}

func TestVulnViewActionableExternalFindingSkipsPanopticonThreatHuntWithoutCVE(t *testing.T) {
	finding := &ports.FindingRecord{
		ID:        "finding-1",
		TenantID:  "writer",
		RuntimeID: "writer-vulnview-vulnerability",
		RuleID:    vulnViewActionableExternalFindingRuleID,
		Status:    findingStatusOpen,
		Severity:  "HIGH",
		Attributes: map[string]string{
			"event_kind":  "vulnview.vulnerability",
			"template_id": "exposed-panel",
		},
	}
	event, err := panopticonThreatHuntActionEvent(finding)
	if err != nil {
		t.Fatalf("panopticonThreatHuntActionEvent() error = %v", err)
	}
	if event != nil {
		t.Fatalf("panopticonThreatHuntActionEvent() = %#v, want nil for non-CVE template", event)
	}
}

func eventKindsForTest(events []*cerebrov1.EventEnvelope) []string {
	kinds := make([]string, 0, len(events))
	for _, event := range events {
		kinds = append(kinds, event.GetKind())
	}
	return kinds
}

func vulnViewActionableExternalFindingEventAt(id string, matchedAt string, status string, severity string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "vulnview",
		Kind:       "vulnview.vulnerability",
		OccurredAt: timestamppb.New(occurredAt),
		Attributes: map[string]string{
			"external_id":            "scan-1:exposed-panel:admin.writer.com",
			"host":                   "admin.writer.com",
			"matched_at":             matchedAt,
			"name":                   "Exposed Admin Panel",
			"severity":               severity,
			"target_id":              "admin.writer.com",
			"template_id":            "exposed-panel",
			"vulnview_finding_state": status,
			"vulnview_status":        status,
		},
	}
}

func vulnViewSourceAdapterStateEvents(t *testing.T, family string) (*cerebrov1.EventEnvelope, *cerebrov1.EventEnvelope) {
	t.Helper()
	state := "open"
	observedAt := identityTrajectoryBaseTime
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600})
		case "/vulnerabilities":
			if family != "vulnerability" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"type":       "vulnerability",
				"templateId": "exposed-panel",
				"name":       "Exposed Admin Panel",
				"severity":   "high",
				"host":       "admin.writer.com",
				"matchedAt":  "https://admin.writer.com/login",
				"scanId":     "scan-1",
				"status":     state,
				"timestamp":  observedAt.Format(time.RFC3339),
			}}})
		case "/assets":
			if family != "dns_alert" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{
				"asset": "admin.writer.com",
				"dnsAlerts": []map[string]any{{
					"alert":     "dangling-cname",
					"severity":  "high",
					"state":     state,
					"timestamp": observedAt.Format(time.RFC3339),
				}},
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	source, err := vulnviewsource.New()
	if err != nil {
		t.Fatalf("vulnview.New() error = %v", err)
	}
	enableVulnViewLoopbackForTest(t, source)
	cfg := sourcecdk.NewConfig(map[string]string{
		"tenant_id":     "writer",
		"base_url":      server.URL,
		"token_url":     server.URL + "/token",
		"client_id":     "client",
		"client_secret": "secret",
		"family":        family,
	})
	readEvent := func(nextState string, ts time.Time) *cerebrov1.EventEnvelope {
		t.Helper()
		state = nextState
		observedAt = ts
		pull, err := source.Read(context.Background(), cfg, nil)
		if err != nil {
			t.Fatalf("Read(%s, %s) error = %v", family, nextState, err)
		}
		if len(pull.Events) != 1 {
			t.Fatalf("Read(%s, %s) emitted %d events, want 1", family, nextState, len(pull.Events))
		}
		return pull.Events[0]
	}
	return readEvent("open", identityTrajectoryBaseTime), readEvent("resolved", identityTrajectoryBaseTime.Add(2*time.Minute))
}

func enableVulnViewLoopbackForTest(t *testing.T, source *vulnviewsource.Source) {
	t.Helper()
	field := reflect.ValueOf(source).Elem().FieldByName("allowLoopbackBaseURL")
	if !field.IsValid() {
		t.Fatal("vulnview.Source.allowLoopbackBaseURL field not found")
	}
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().SetBool(true)
}
