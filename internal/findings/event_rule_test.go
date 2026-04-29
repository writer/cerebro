package findings

import (
	"context"
	"errors"
	"testing"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

func TestEventRuleScaffoldClonesSpecAndMatchesRuntimeSource(t *testing.T) {
	rule := newEventRule(eventRuleConfig{
		spec:     &cerebrov1.RuleSpec{Id: "github-rule", Name: "GitHub Rule"},
		sourceID: "github",
		match:    func(*cerebrov1.EventEnvelope) bool { return false },
		build: func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return nil, nil
		},
	})

	spec := rule.Spec()
	spec.Id = "mutated"
	if got := rule.Spec().GetId(); got != "github-rule" {
		t.Fatalf("Spec().Id = %q, want github-rule", got)
	}
	if !rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: " GitHub "}) {
		t.Fatal("SupportsRuntime() = false, want true for case-insensitive source id")
	}
	if rule.SupportsRuntime(&cerebrov1.SourceRuntime{SourceId: "okta"}) {
		t.Fatal("SupportsRuntime(okta) = true, want false")
	}
}

func TestRuleDefinitionBuildsSpecAndAttributes(t *testing.T) {
	definition := RuleDefinition{
		ID:                 "github-rule",
		Name:               "GitHub Rule",
		Description:        "Detects a GitHub event.",
		SourceID:           "github",
		EventKinds:         []string{"github.audit"},
		OutputKind:         "finding.github_rule",
		Severity:           "HIGH",
		Status:             "open",
		Maturity:           "test",
		Tags:               []string{"github", "attack.t1562"},
		References:         []string{"https://example.com/rule"},
		FalsePositives:     []string{"approved admin activity"},
		Runbook:            "Review actor and repository.",
		RequiredAttributes: []string{"action", "repository"},
		FingerprintFields:  []string{"repository", "action"},
		ControlRefs:        []ports.FindingControlRef{{FrameworkName: "SOC 2", ControlID: "CC7.1"}},
	}
	if err := definition.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	spec := definition.RuleSpec()
	if got := spec.GetId(); got != "github-rule" {
		t.Fatalf("RuleSpec().Id = %q, want github-rule", got)
	}
	if got := spec.GetOutputKinds()[0]; got != "finding.github_rule" {
		t.Fatalf("RuleSpec().OutputKinds[0] = %q, want finding.github_rule", got)
	}
	attributes := definition.AttributeMap()
	if got := attributes["tags"]; got != "github,attack.t1562" {
		t.Fatalf("AttributeMap()[tags] = %q, want github,attack.t1562", got)
	}
	if got := attributes["required_attributes"]; got != "action,repository" {
		t.Fatalf("AttributeMap()[required_attributes] = %q, want action,repository", got)
	}
}

func TestEventRuleScaffoldEvaluatesMatcherAndBuilder(t *testing.T) {
	buildCalls := 0
	rule := newEventRule(eventRuleConfig{
		spec:     &cerebrov1.RuleSpec{Id: "github-rule"},
		sourceID: "github",
		match: func(event *cerebrov1.EventEnvelope) bool {
			return event.GetAttributes()["emit"] == "true"
		},
		build: func(_ context.Context, runtime *cerebrov1.SourceRuntime, event *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			buildCalls++
			return &ports.FindingRecord{
				ID:        "finding-" + event.GetId(),
				RuntimeID: runtime.GetId(),
				RuleID:    "github-rule",
			}, nil
		},
	})

	skipped, err := rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "writer-github", SourceId: "github"}, &cerebrov1.EventEnvelope{Id: "skip"})
	if err != nil {
		t.Fatalf("Evaluate(skip) error = %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("len(Evaluate(skip)) = %d, want 0", len(skipped))
	}
	if buildCalls != 0 {
		t.Fatalf("buildCalls = %d, want 0 after skipped event", buildCalls)
	}

	findings, err := rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "writer-github", SourceId: "github"}, &cerebrov1.EventEnvelope{
		Id:         "emit",
		Attributes: map[string]string{"emit": "true"},
	})
	if err != nil {
		t.Fatalf("Evaluate(emit) error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(Evaluate(emit)) = %d, want 1", len(findings))
	}
	if got := findings[0].RuntimeID; got != "writer-github" {
		t.Fatalf("Finding.RuntimeID = %q, want writer-github", got)
	}
}

func TestEventRuleScaffoldRequiresRuntimeAndConfiguration(t *testing.T) {
	rule := newEventRule(eventRuleConfig{
		spec:     &cerebrov1.RuleSpec{Id: "github-rule"},
		sourceID: "github",
		match:    func(*cerebrov1.EventEnvelope) bool { return true },
		build: func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return nil, nil
		},
	})
	if _, err := rule.Evaluate(context.Background(), nil, &cerebrov1.EventEnvelope{}); err == nil {
		t.Fatal("Evaluate(nil runtime) error = nil, want non-nil")
	}

	unconfigured := newEventRule(eventRuleConfig{spec: &cerebrov1.RuleSpec{Id: "bad-rule"}})
	if _, err := unconfigured.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "runtime"}, &cerebrov1.EventEnvelope{}); err == nil {
		t.Fatal("Evaluate(unconfigured) error = nil, want non-nil")
	}

	invalidDefinition := newEventRule(eventRuleConfig{
		definition: RuleDefinition{ID: "bad-rule"},
		match:      func(*cerebrov1.EventEnvelope) bool { return true },
		build: func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return nil, nil
		},
	})
	if _, err := invalidDefinition.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "runtime"}, &cerebrov1.EventEnvelope{}); err == nil {
		t.Fatal("Evaluate(invalid definition) error = nil, want non-nil")
	}
}

func TestEventRuleScaffoldPropagatesBuildErrors(t *testing.T) {
	wantErr := errors.New("build failed")
	rule := newEventRule(eventRuleConfig{
		spec:     &cerebrov1.RuleSpec{Id: "github-rule"},
		sourceID: "github",
		match:    func(*cerebrov1.EventEnvelope) bool { return true },
		build: func(context.Context, *cerebrov1.SourceRuntime, *cerebrov1.EventEnvelope) (*ports.FindingRecord, error) {
			return nil, wantErr
		},
	})
	if _, err := rule.Evaluate(context.Background(), &cerebrov1.SourceRuntime{Id: "runtime"}, &cerebrov1.EventEnvelope{}); !errors.Is(err, wantErr) {
		t.Fatalf("Evaluate() error = %v, want %v", err, wantErr)
	}
}
