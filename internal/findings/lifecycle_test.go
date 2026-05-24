package findings

import (
	"strings"
	"testing"
	"time"
)

func TestLifecycleKindConstants(t *testing.T) {
	cases := []struct {
		name     string
		got      LifecycleKind
		expected string
	}{
		{"LifecycleDurableState", LifecycleDurableState, "durable_state"},
		{"LifecycleAuditEvidence", LifecycleAuditEvidence, "audit_evidence"},
		{"LifecycleTTLEvidence", LifecycleTTLEvidence, "ttl_evidence"},
		{"LifecycleRetired", LifecycleRetired, "retired"},
	}
	for _, c := range cases {
		if string(c.got) != c.expected {
			t.Errorf("%s = %q, want %q", c.name, string(c.got), c.expected)
		}
	}
}

func TestLifecycleAnchorConstants(t *testing.T) {
	cases := []struct {
		name     string
		got      LifecycleAnchor
		expected string
	}{
		{"AnchorGraphAnchored", AnchorGraphAnchored, "graph_anchored"},
		{"AnchorSourceState", AnchorSourceState, "source_state"},
		{"AnchorNone", AnchorNone, "none"},
	}
	for _, c := range cases {
		if string(c.got) != c.expected {
			t.Errorf("%s = %q, want %q", c.name, string(c.got), c.expected)
		}
	}
}

func validLifecycleBase() RuleDefinition {
	return RuleDefinition{
		ID:         "rule-under-test",
		Name:       "Rule Under Test",
		SourceID:   "github",
		OutputKind: "finding.under_test",
	}
}

func TestRuleDefinitionRequiresLifecycle(t *testing.T) {
	d := validLifecycleBase()
	err := d.Validate()
	if err == nil {
		t.Fatal("Validate() with empty Lifecycle.Kind returned nil, want non-nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "lifecycle") {
		t.Fatalf("Validate() error = %q, want it to mention 'lifecycle'", err.Error())
	}
}

func TestRuleDefinition_TTLEvidence_RequiresTTL(t *testing.T) {
	d := validLifecycleBase()
	d.Lifecycle = Lifecycle{Kind: LifecycleTTLEvidence, TTL: 0}
	if err := d.Validate(); err == nil {
		t.Fatal("Validate() ttl_evidence with TTL=0 returned nil, want non-nil")
	}

	d.Lifecycle = Lifecycle{Kind: LifecycleTTLEvidence, TTL: -time.Minute}
	if err := d.Validate(); err == nil {
		t.Fatal("Validate() ttl_evidence with negative TTL returned nil, want non-nil")
	}

	d.Lifecycle = Lifecycle{Kind: LifecycleTTLEvidence, TTL: 24 * time.Hour}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate() ttl_evidence with TTL=24h error = %v, want nil", err)
	}
}

func TestRuleDefinition_Retired_RequiresNoneAnchor(t *testing.T) {
	d := validLifecycleBase()
	d.Lifecycle = Lifecycle{Kind: LifecycleRetired, Anchor: AnchorGraphAnchored}
	if err := d.Validate(); err == nil {
		t.Fatal("Validate() retired with Anchor=graph_anchored returned nil, want non-nil")
	}

	d.Lifecycle = Lifecycle{Kind: LifecycleRetired, Anchor: AnchorSourceState}
	if err := d.Validate(); err == nil {
		t.Fatal("Validate() retired with Anchor=source_state returned nil, want non-nil")
	}

	d.Lifecycle = Lifecycle{Kind: LifecycleRetired, Anchor: AnchorNone}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate() retired with Anchor=none error = %v, want nil", err)
	}
}

func TestRuleDefinition_DurableState_RequiresAnchor(t *testing.T) {
	d := validLifecycleBase()
	d.Lifecycle = Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorNone}
	if err := d.Validate(); err == nil {
		t.Fatal("Validate() durable_state with Anchor=none returned nil, want non-nil")
	}

	d.Lifecycle = Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorGraphAnchored}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate() durable_state with Anchor=graph_anchored error = %v, want nil", err)
	}

	d.Lifecycle = Lifecycle{Kind: LifecycleDurableState, Anchor: AnchorSourceState}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate() durable_state with Anchor=source_state error = %v, want nil", err)
	}
}
