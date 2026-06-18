package findings

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func evidenceCASObjectEvent(id string, attrs map[string]string, occurredAt time.Time) *cerebrov1.EventEnvelope {
	base := map[string]string{
		"family":            "object",
		"evidence_id":       "evidence-1",
		"evidence_type":     "evidence_cas.artifact",
		"source_system":     "iris",
		"source_runtime_id": "writer-evidence-cas",
	}
	for key, value := range attrs {
		if value == "" {
			delete(base, key)
			continue
		}
		base[key] = value
	}
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "evidence_cas",
		Kind:       "evidence_cas.object",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "evidence_cas/object/v1",
		Attributes: base,
	}
}

func TestEvidenceCASUnresolvedLinkageFixture(t *testing.T) {
	assertRuleFixture(t, newEvidenceCASUnresolvedLinkageRule(), "testdata/rules/evidence-cas-unresolved-linkage.json")
}

func TestEvidenceCASUnresolvedLinkageOpensOnUnresolvedContext(t *testing.T) {
	rule := newEvidenceCASUnresolvedLinkageRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-evidence-cas", SourceId: "evidence_cas", TenantId: "writer"}

	unresolved := evidenceCASObjectEvent("evidence-unresolved", map[string]string{
		"evidence_id":             "evidence-unresolved",
		"case_id":                 "case-1",
		"case_link_status":        "missing",
		"unresolved_case_context": "true",
		"resource_urn":            "urn:cerebro:writer:case:case-1",
		"resource_link_status":    "missing",
	}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	records, err := rule.Evaluate(context.Background(), runtime, unresolved)
	if err != nil {
		t.Fatalf("Evaluate(unresolved) error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("Evaluate(unresolved) emitted %d findings, want 1", len(records))
	}
	finding := records[0]
	if got := strings.TrimSpace(finding.Status); got != findingStatusOpen {
		t.Fatalf("status = %q, want open", got)
	}
	if got := finding.Severity; got != "MEDIUM" {
		t.Fatalf("severity = %q, want MEDIUM", got)
	}
	assertFindingResourceURN(t, finding.ResourceURNs, "urn:cerebro:writer:runtime_evidence:evidence-unresolved")
	if got := finding.Attributes["unresolved_linkage"]; got != "resource_and_case" {
		t.Fatalf("unresolved_linkage = %q, want resource_and_case", got)
	}
}

func TestEvidenceCASUnresolvedLinkageIgnoresResolvedAndBareEvidence(t *testing.T) {
	rule := newEvidenceCASUnresolvedLinkageRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-evidence-cas", SourceId: "evidence_cas", TenantId: "writer"}

	resolved := evidenceCASObjectEvent("evidence-linked", map[string]string{
		"case_id":              "case-1",
		"case_link_status":     "linked",
		"resource_urn":         "urn:cerebro:writer:case:case-1",
		"resource_link_status": "linked",
	}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	records, err := rule.Evaluate(context.Background(), runtime, resolved)
	if err != nil {
		t.Fatalf("Evaluate(resolved) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(resolved) emitted %d findings, want 0", len(records))
	}

	// Evidence that declares no case or resource context is not a linkage risk
	// and must not surface as a finding even though no context resolved.
	bare := evidenceCASObjectEvent("evidence-bare", map[string]string{
		"case_id":              "",
		"resource_urn":         "",
		"resource_link_status": "missing",
	}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	records, err = rule.Evaluate(context.Background(), runtime, bare)
	if err != nil {
		t.Fatalf("Evaluate(bare) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(bare) emitted %d findings, want 0", len(records))
	}
}

func TestEvidenceCASUnresolvedLinkageOpensOnSuppliedContextWithBlankLinkStatus(t *testing.T) {
	rule := newEvidenceCASUnresolvedLinkageRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-evidence-cas", SourceId: "evidence_cas", TenantId: "writer"}
	occurredAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name  string
		attrs map[string]string
		scope string
	}{
		{
			name: "case",
			attrs: map[string]string{
				"case_id":          "case-blank-status",
				"case_link_status": "",
			},
			scope: "case",
		},
		{
			name: "resource",
			attrs: map[string]string{
				"resource_id":          "resource-blank-status",
				"resource_link_status": "",
			},
			scope: "resource",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, err := rule.Evaluate(context.Background(), runtime, evidenceCASObjectEvent("evidence-"+tc.name+"-blank-status", tc.attrs, occurredAt))
			if err != nil {
				t.Fatalf("Evaluate(%s) error = %v", tc.name, err)
			}
			if len(records) != 1 {
				t.Fatalf("Evaluate(%s) emitted %d findings, want 1", tc.name, len(records))
			}
			if got := records[0].Attributes["unresolved_linkage"]; got != tc.scope {
				t.Fatalf("unresolved_linkage = %q, want %q", got, tc.scope)
			}
		})
	}
}

func TestEvidenceCASUnresolvedLinkageOpensOnExplicitUnresolvedContextWithoutIdentifiers(t *testing.T) {
	rule := newEvidenceCASUnresolvedLinkageRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-evidence-cas", SourceId: "evidence_cas", TenantId: "writer"}
	occurredAt := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name  string
		attrs map[string]string
		scope string
	}{
		{
			name: "case marker",
			attrs: map[string]string{
				"case_id":                 "",
				"case_link_status":        "",
				"unresolved_case_context": "true",
			},
			scope: "case",
		},
		{
			name: "resource marker",
			attrs: map[string]string{
				"resource_id":                 "",
				"resource_urn":                "",
				"resource_link_status":        "",
				"unresolved_resource_context": "true",
			},
			scope: "resource",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, err := rule.Evaluate(context.Background(), runtime, evidenceCASObjectEvent("evidence-"+strings.ReplaceAll(tc.name, " ", "-"), tc.attrs, occurredAt))
			if err != nil {
				t.Fatalf("Evaluate(%s) error = %v", tc.name, err)
			}
			if len(records) != 1 {
				t.Fatalf("Evaluate(%s) emitted %d findings, want 1", tc.name, len(records))
			}
			if got := records[0].Attributes["unresolved_linkage"]; got != tc.scope {
				t.Fatalf("unresolved_linkage = %q, want %q", got, tc.scope)
			}
		})
	}
}

func TestEvidenceCASUnresolvedLinkageContextlessFollowupKeepsFindingOpen(t *testing.T) {
	rule := newEvidenceCASUnresolvedLinkageRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-evidence-cas", SourceId: "evidence_cas", TenantId: "writer"}

	opened, err := rule.Evaluate(context.Background(), runtime, evidenceCASObjectEvent("evidence-open-1", map[string]string{
		"case_id":                 "case-1",
		"case_link_status":        "missing",
		"unresolved_case_context": "true",
	}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatalf("Evaluate(open) error = %v", err)
	}
	if len(opened) != 1 || strings.TrimSpace(opened[0].Status) != findingStatusOpen {
		t.Fatalf("Evaluate(open) = %d findings, want 1 open", len(opened))
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}

	// A later event sharing the same evidence_id that supplies no case or
	// resource context at all must not close the finding: the absence of
	// unresolved markers is not evidence that the linkage was repaired.
	contextless := evidenceCASObjectEvent("evidence-followup", map[string]string{
		"case_id":                 "",
		"case_urn":                "",
		"case_link_status":        "",
		"unresolved_case_context": "",
		"resource_urn":            "",
		"resource_id":             "",
		"resource_link_status":    "",
	}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	if anchor, closes := counterRule.CloseOnEvent(contextless); closes || anchor != "" {
		t.Fatalf("CloseOnEvent(contextless) = (%q, %v), want no close", anchor, closes)
	}

	records, err := rule.Evaluate(context.Background(), runtime, contextless)
	if err != nil {
		t.Fatalf("Evaluate(contextless) error = %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("Evaluate(contextless) emitted %d findings, want 0", len(records))
	}
}

func TestEvidenceCASUnresolvedLinkageRemediationResolves(t *testing.T) {
	open := evidenceCASObjectEvent("evidence-open", map[string]string{
		"case_id":                 "case-1",
		"case_link_status":        "missing",
		"unresolved_case_context": "true",
	}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	resolved := evidenceCASObjectEvent("evidence-resolved", map[string]string{
		"case_id":          "case-1",
		"case_urn":         "urn:cerebro:writer:case:case-1",
		"case_link_status": "linked",
	}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	assertIdentityRuleRemediationTrajectory(t, newEvidenceCASUnresolvedLinkageRule(), open, resolved, cerebrov1.FindingStatus_FINDING_STATUS_RESOLVED)
}

func TestEvidenceCASUnresolvedLinkageReopensOnRecurrence(t *testing.T) {
	rule := newEvidenceCASUnresolvedLinkageRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-evidence-cas", SourceId: "evidence_cas", TenantId: "writer"}

	emitOpen := func(event *cerebrov1.EventEnvelope) *ports.FindingRecord {
		t.Helper()
		records, err := rule.Evaluate(context.Background(), runtime, event)
		if err != nil {
			t.Fatalf("Evaluate(%q) error = %v", event.GetId(), err)
		}
		if len(records) != 1 {
			t.Fatalf("Evaluate(%q) emitted %d findings, want 1", event.GetId(), len(records))
		}
		if got := strings.TrimSpace(records[0].Status); got != findingStatusOpen {
			t.Fatalf("Evaluate(%q) status = %q, want open", event.GetId(), got)
		}
		return records[0]
	}

	opened := emitOpen(evidenceCASObjectEvent("evidence-open-1", map[string]string{
		"case_id":                 "case-1",
		"case_link_status":        "missing",
		"unresolved_case_context": "true",
	}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)))
	openFingerprint := strings.TrimSpace(opened.Fingerprint)
	if openFingerprint == "" {
		t.Fatal("opened finding has empty fingerprint")
	}

	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("rule does not implement CounterEventRule")
	}
	resolvedEvent := evidenceCASObjectEvent("evidence-resolved", map[string]string{
		"case_id":          "case-1",
		"case_urn":         "urn:cerebro:writer:case:case-1",
		"case_link_status": "linked",
	}, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC))
	closeAnchor, closes := counterRule.CloseOnEvent(resolvedEvent)
	if !closes || closeAnchor == "" {
		t.Fatalf("CloseOnEvent(resolved) = (%q, %v), want a non-empty closing anchor", closeAnchor, closes)
	}
	if openAnchor := counterRule.OpenAnchor(opened.Attributes); openAnchor != closeAnchor {
		t.Fatalf("OpenAnchor(open finding) = %q, want match close anchor %q", openAnchor, closeAnchor)
	}

	reopened := emitOpen(evidenceCASObjectEvent("evidence-open-2", map[string]string{
		"case_id":                 "case-1",
		"case_link_status":        "missing",
		"unresolved_case_context": "true",
	}, time.Date(2026, 5, 1, 14, 0, 0, 0, time.UTC)))
	if got := strings.TrimSpace(reopened.Fingerprint); got != openFingerprint {
		t.Fatalf("recurrence fingerprint = %q, want stable %q", got, openFingerprint)
	}
	if got := strings.TrimSpace(reopened.ID); got != strings.TrimSpace(opened.ID) {
		t.Fatalf("recurrence finding id = %q, want stable %q", got, strings.TrimSpace(opened.ID))
	}
}

func TestEvidenceCASUnresolvedLinkageLifecycleMetadata(t *testing.T) {
	rule := newEvidenceCASUnresolvedLinkageRule()
	metadataRule, ok := rule.(MetadataRule)
	if !ok {
		t.Fatal("rule does not expose RuleMetadata")
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
}
