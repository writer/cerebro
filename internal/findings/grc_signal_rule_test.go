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
		Id:         "grc-vanta-control_test-ai-training",
		TenantId:   "writer",
		SourceId:   "grc",
		Kind:       "grc.control_test",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"provider": "vanta",
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
}

func TestGRCVulnerabilitySLAOverdueRule(t *testing.T) {
	rule := newGRCVulnerabilitySLAOverdueRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc", SourceId: "grc"}
	event := &cerebrov1.EventEnvelope{
		Id:         "grc-vanta-vulnerability-vuln-1",
		TenantId:   "writer",
		SourceId:   "grc",
		Kind:       "grc.vulnerability",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"provider":          "vanta",
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
}

func TestGRCVendorReviewOverdueRule(t *testing.T) {
	rule := newGRCVendorReviewOverdueRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc", SourceId: "grc"}
	event := &cerebrov1.EventEnvelope{
		Id:         "grc-vanta-vendor-vendor-1",
		TenantId:   "writer",
		SourceId:   "grc",
		Kind:       "grc.vendor",
		OccurredAt: timestamppb.New(time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC)),
		Attributes: map[string]string{
			"provider":                      "vanta",
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
}

func TestGRCVendorReviewRuleIgnoresCurrentVendor(t *testing.T) {
	rule := newGRCVendorReviewOverdueRule()
	runtime := &cerebrov1.SourceRuntime{Id: "writer-grc", SourceId: "grc"}
	event := &cerebrov1.EventEnvelope{
		Id:       "grc-vanta-vendor-vendor-1",
		TenantId: "writer",
		SourceId: "grc",
		Kind:     "grc.vendor",
		Attributes: map[string]string{
			"provider":                      "vanta",
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
