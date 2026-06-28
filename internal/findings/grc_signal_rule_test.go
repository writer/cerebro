package findings

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestGRCControlTestNeedsAttentionRule(t *testing.T) {
	rule := newGRCControlTestNeedsAttentionRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc", SourceId: "grc"}
	event := &cerebrov1.EventEnvelope{
		Id:         "grc-vrm-control_test-ai-training",
		TenantId:   "writer",
		SourceId:   "grc",
		Kind:       "grc.control_test",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"provider": "vrm",
			"test_id":  "ai-risk-security-training-records",
			"name":     "AI risk security awareness training selected",
			"status":   "NEEDS_ATTENTION",
		},
	}

	findings, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if got := findings[0].RuleID; got != grcControlTestNeedsAttentionRuleID {
		t.Fatalf("RuleID = %q, want %q", got, grcControlTestNeedsAttentionRuleID)
	}
	if got := findings[0].PolicyID; got != "ai-risk-security-training-records" {
		t.Fatalf("PolicyID = %q, want test id", got)
	}
	if len(findings[0].ControlRefs) == 0 {
		t.Fatal("ControlRefs = 0, want rule control refs copied onto finding")
	}
}

func TestGRCControlTestNeedsAttentionRuleFingerprintSeparatesTenants(t *testing.T) {
	rule := newGRCControlTestNeedsAttentionRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc", SourceId: "grc"}
	eventForTenant := func(tenantID string) *cerebrov1.EventEnvelope {
		return &cerebrov1.EventEnvelope{
			Id:       "grc-vrm-control_test-ai-training",
			TenantId: tenantID,
			SourceId: "grc",
			Kind:     "grc.control_test",
			Attributes: map[string]string{
				"provider": "vrm",
				"test_id":  "ai-risk-security-training-records",
				"name":     "AI risk security awareness training selected",
				"status":   "NEEDS_ATTENTION",
			},
		}
	}

	first, err := rule.Evaluate(context.Background(), runtime, eventForTenant("writer"))
	if err != nil {
		t.Fatalf("Evaluate(first) error = %v", err)
	}
	second, err := rule.Evaluate(context.Background(), runtime, eventForTenant("acme"))
	if err != nil {
		t.Fatalf("Evaluate(second) error = %v", err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("len(first), len(second) = %d, %d; want 1, 1", len(first), len(second))
	}
	if first[0].Fingerprint == second[0].Fingerprint {
		t.Fatalf("fingerprint collapsed same GRC test across tenants: %q", first[0].Fingerprint)
	}
}

func TestGRCControlTestNeedsAttentionRuleFingerprintSeparatesRuntimes(t *testing.T) {
	rule := newGRCControlTestNeedsAttentionRule()
	event := &cerebrov1.EventEnvelope{
		Id:       "grc-vrm-control_test-ai-training",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.control_test",
		Attributes: map[string]string{
			"provider": "vrm",
			"test_id":  "ai-risk-security-training-records",
			"name":     "AI risk security awareness training selected",
			"status":   "NEEDS_ATTENTION",
		},
	}

	first, err := rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "writer-grc-us", SourceId: "grc"}, event)
	if err != nil {
		t.Fatalf("Evaluate(first) error = %v", err)
	}
	second, err := rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "writer-grc-eu", SourceId: "grc"}, event)
	if err != nil {
		t.Fatalf("Evaluate(second) error = %v", err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("len(first), len(second) = %d, %d; want 1, 1", len(first), len(second))
	}
	if first[0].Fingerprint == second[0].Fingerprint {
		t.Fatalf("fingerprint collapsed same GRC test across runtimes: %q", first[0].Fingerprint)
	}
}

func TestGRCVulnerabilitySLAOverdueRule(t *testing.T) {
	rule := newGRCVulnerabilitySLAOverdueRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc", SourceId: "grc"}
	event := &cerebrov1.EventEnvelope{
		Id:         "grc-vrm-vulnerability-vuln-1",
		TenantId:   "writer",
		SourceId:   "grc",
		Kind:       "grc.vulnerability",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"provider":          "vrm",
			"vulnerability_id":  "vuln-1",
			"name":              "CVE-2026-4242",
			"package":           "pkg:golang/example/module@1.2.3",
			"severity":          "HIGH",
			"is_fixable":        "true",
			"remediate_by_date": "2020-01-01T00:00:00Z",
		},
	}

	findings, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if got := findings[0].Severity; got != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH", got)
	}
	if got := findings[0].Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:vulnerability:cve-2026-4242" {
		t.Fatalf("primary_resource_urn = %q, want canonical vulnerability", got)
	}
}

func TestGRCVulnerabilitySLAOverdueRuleFingerprintSeparatesPackageAndTarget(t *testing.T) {
	rule := newGRCVulnerabilitySLAOverdueRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc", SourceId: "grc"}
	eventFor := func(id, packageName, targetID string) *cerebrov1.EventEnvelope {
		return &cerebrov1.EventEnvelope{
			Id:       id,
			TenantId: "writer",
			SourceId: "grc",
			Kind:     "grc.vulnerability",
			Attributes: map[string]string{
				"provider":          "vrm",
				"vulnerability_id":  id,
				"name":              "CVE-2026-4242",
				"package":           packageName,
				"target_id":         targetID,
				"severity":          "HIGH",
				"is_fixable":        "true",
				"remediate_by_date": "2020-01-01T00:00:00Z",
			},
		}
	}
	first, err := rule.Evaluate(context.Background(), runtime, eventFor("vuln-1", "pkg:golang/example/module@1.2.3", "asset-1"))
	if err != nil {
		t.Fatalf("Evaluate(first) error = %v", err)
	}
	second, err := rule.Evaluate(context.Background(), runtime, eventFor("vuln-2", "pkg:golang/example/other@9.9.9", "asset-2"))
	if err != nil {
		t.Fatalf("Evaluate(second) error = %v", err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("len(first), len(second) = %d, %d; want 1, 1", len(first), len(second))
	}
	if first[0].Fingerprint == second[0].Fingerprint {
		t.Fatalf("fingerprint collapsed distinct package/target vulnerabilities: %q", first[0].Fingerprint)
	}
}

func TestGRCVendorReviewOverdueRule(t *testing.T) {
	rule := newGRCVendorReviewOverdueRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc", SourceId: "grc"}
	event := &cerebrov1.EventEnvelope{
		Id:         "grc-vrm-vendor-vendor-1",
		TenantId:   "writer",
		SourceId:   "grc",
		Kind:       "grc.vendor",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"provider":                      "vrm",
			"vendor_id":                     "vendor-1",
			"name":                          "Acme SaaS",
			"security_owner_user_id":        "user-1",
			"next_security_review_due_date": "2020-01-01T00:00:00Z",
		},
	}

	findings, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if got := findings[0].RuleID; got != grcVendorReviewOverdueRuleID {
		t.Fatalf("RuleID = %q, want %q", got, grcVendorReviewOverdueRuleID)
	}
	if got := findings[0].Attributes["primary_resource_urn"]; got != "urn:cerebro:writer:vendor:vrm:vendor-1" {
		t.Fatalf("primary_resource_urn = %q, want vendor", got)
	}
}

func TestGRCVendorReviewRuleIgnoresCurrentVendor(t *testing.T) {
	rule := newGRCVendorReviewOverdueRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc", SourceId: "grc"}
	event := &cerebrov1.EventEnvelope{
		Id:       "grc-vrm-vendor-vendor-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":                      "vrm",
			"vendor_id":                     "vendor-1",
			"name":                          "Acme SaaS",
			"security_owner_user_id":        "user-1",
			"next_security_review_due_date": "2999-01-01T00:00:00Z",
		},
	}

	findings, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestGRCVendorReviewRuleClosesOnRestoredPosture(t *testing.T) {
	rule := newGRCVendorReviewOverdueRule()
	counterRule, ok := rule.(CounterEventRule)
	if !ok {
		t.Fatal("grc-vendor-review-overdue does not implement CounterEventRule")
	}
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc", SourceId: "grc"}
	openEvent := &cerebrov1.EventEnvelope{
		Id:       "grc-vrm-vendor-vendor-1-open",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":  "vrm",
			"vendor_id": "vendor-1",
			"name":      "Acme SaaS",
		},
	}
	findings, err := rule.Evaluate(context.Background(), runtime, openEvent)
	if err != nil {
		t.Fatalf("Evaluate(open) error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(open findings) = %d, want 1", len(findings))
	}
	openAnchor := counterRule.OpenAnchor(findings[0].Attributes)
	if openAnchor == "" {
		t.Fatalf("OpenAnchor(%v) = empty, want vendor anchor", findings[0].Attributes)
	}

	restored := &cerebrov1.EventEnvelope{
		Id:       "grc-vrm-vendor-vendor-1-restored",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":                      "vrm",
			"vendor_id":                     "vendor-1",
			"name":                          "Acme SaaS",
			"business_owner_user_id":        "user-1",
			"next_security_review_due_date": "2999-01-01T00:00:00Z",
		},
	}
	closeAnchor, closes := counterRule.CloseOnEvent(restored)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(restored) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}

	missingDueDate := &cerebrov1.EventEnvelope{
		Id:       "grc-vrm-vendor-vendor-1-missing-due-date",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":               "vrm",
			"vendor_id":              "vendor-1",
			"name":                   "Acme SaaS",
			"business_owner_user_id": "user-1",
		},
	}
	closeAnchor, closes = counterRule.CloseOnEvent(missingDueDate)
	if closes || closeAnchor != "" {
		t.Fatalf("CloseOnEvent(missingDueDate) = (%q, %v), want no close", closeAnchor, closes)
	}

	unrelated := &cerebrov1.EventEnvelope{
		Id:       "grc-vrm-vendor-vendor-2-restored",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":                      "vrm",
			"vendor_id":                     "vendor-2",
			"name":                          "Other SaaS",
			"business_owner_user_id":        "user-2",
			"next_security_review_due_date": "2999-01-01T00:00:00Z",
		},
	}
	closeAnchor, closes = counterRule.CloseOnEvent(unrelated)
	if !closes || closeAnchor == openAnchor {
		t.Fatalf("CloseOnEvent(unrelated) = (%q, %v), want different close anchor", closeAnchor, closes)
	}

	wrongKind := &cerebrov1.EventEnvelope{
		Id:       "grc-vrm-asset-vendor-1-restored",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.asset",
		Attributes: map[string]string{
			"provider":                      "vrm",
			"vendor_id":                     "vendor-1",
			"name":                          "Acme SaaS",
			"business_owner_user_id":        "user-1",
			"next_security_review_due_date": "2999-01-01T00:00:00Z",
		},
	}
	closeAnchor, closes = counterRule.CloseOnEvent(wrongKind)
	if closes || closeAnchor != "" {
		t.Fatalf("CloseOnEvent(wrongKind) = (%q, %v), want no close", closeAnchor, closes)
	}

	contextless := &cerebrov1.EventEnvelope{
		Id:       "grc-vrm-vendor-missing-id-restored",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":                      "vrm",
			"name":                          "No ID SaaS",
			"business_owner_user_id":        "user-3",
			"next_security_review_due_date": "2999-01-01T00:00:00Z",
		},
	}
	closeAnchor, closes = counterRule.CloseOnEvent(contextless)
	if closes || closeAnchor != "" {
		t.Fatalf("CloseOnEvent(contextless) = (%q, %v), want no close", closeAnchor, closes)
	}

	completed := &cerebrov1.EventEnvelope{
		Id:       "grc-vrm-vendor-vendor-1-completed",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":                             "vrm",
			"vendor_id":                            "vendor-1",
			"name":                                 "Acme SaaS",
			"business_owner_user_id":               "user-1",
			"last_security_review_completion_date": "2026-01-01T00:00:00Z",
		},
	}
	closeAnchor, closes = counterRule.CloseOnEvent(completed)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(completed) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}

	inactive := &cerebrov1.EventEnvelope{
		Id:       "grc-vrm-vendor-vendor-1-retired",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":  "vrm",
			"vendor_id": "vendor-1",
			"name":      "Acme SaaS",
			"status":    "retired",
		},
	}
	closeAnchor, closes = counterRule.CloseOnEvent(inactive)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(inactive) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}

	inactiveSynonym := &cerebrov1.EventEnvelope{
		Id:       "grc-vrm-vendor-vendor-1-decommissioning",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":  "vrm",
			"vendor_id": "vendor-1",
			"name":      "Acme SaaS",
			"status":    "decommissioning",
		},
	}
	closeAnchor, closes = counterRule.CloseOnEvent(inactiveSynonym)
	if !closes || closeAnchor != openAnchor {
		t.Fatalf("CloseOnEvent(inactiveSynonym) = (%q, %v), want (%q, true)", closeAnchor, closes, openAnchor)
	}
}
