package complianceimpact

import (
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/compliance"
	"github.com/writer/cerebro/internal/complianceintegration"
)

func TestBuildAssessmentDirectiveTargetsCompleteImpact(t *testing.T) {
	result := directiveImpactResult(true)
	directive, err := BuildAssessmentDirective(result, time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if directive.Mode != AssessmentModeTargeted || len(directive.ObjectiveRevisions) != 1 || directive.Digest == "" || directive.IdempotencyKey == "" {
		t.Fatalf("directive = %#v", directive)
	}
}

func TestBuildAssessmentDirectiveFallsBackToFullReconciliation(t *testing.T) {
	result := directiveImpactResult(false)
	result.Issues = []Issue{{Code: ReasonDepthBudgetExceeded}}
	directive, err := BuildAssessmentDirective(result, time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if directive.Mode != AssessmentModeFullReconciliation || len(directive.ObjectiveRevisions) != 0 || len(directive.Issues) != 1 {
		t.Fatalf("directive = %#v", directive)
	}
}

func TestBuildAssessmentDirectiveTreatsRecordedIssueAsIncomplete(t *testing.T) {
	result := directiveImpactResult(true)
	result.Issues = []Issue{{Code: ReasonDepthBudgetExceeded}}
	directive, err := BuildAssessmentDirective(result, time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if directive.Mode != AssessmentModeFullReconciliation || directive.ImpactComplete || len(directive.ObjectiveRevisions) != 0 {
		t.Fatalf("directive = %#v", directive)
	}
}

func TestBuildAssessmentDirectiveIsDeterministic(t *testing.T) {
	result := directiveImpactResult(true)
	at := time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)
	left, err := BuildAssessmentDirective(result, at)
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildAssessmentDirective(result, at)
	if err != nil {
		t.Fatal(err)
	}
	if left.Digest != right.Digest || left.IdempotencyKey != right.IdempotencyKey {
		t.Fatalf("directives differ: %#v != %#v", left, right)
	}
}

func TestBuildAssessmentDirectiveSeparatesRetryIdentityFromRequestReceipt(t *testing.T) {
	result := directiveImpactResult(true)
	left, err := BuildAssessmentDirective(result, time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	right, err := BuildAssessmentDirective(result, time.Date(2026, 7, 14, 0, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if left.IdempotencyKey != right.IdempotencyKey {
		t.Fatalf("idempotency keys differ: %s != %s", left.IdempotencyKey, right.IdempotencyKey)
	}
	if left.Digest == right.Digest {
		t.Fatalf("receipt digests unexpectedly match: %s", left.Digest)
	}
}

func directiveImpactResult(complete bool) Result {
	at := time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)
	root := mustImpactRevision("source", complianceintegration.FactClaim, "evidence", "rev-1", 1, "sha256:"+strings.Repeat("a", 64), at)
	objective := mustImpactRevision("compliance", complianceintegration.FactObjective, "objective", "objective-rev", 2, "sha256:"+strings.Repeat("b", 64), at)
	signal, err := complianceintegration.NewChangeSignal(complianceintegration.ChangeDeleted, root, nil, at)
	if err != nil {
		panic(err)
	}
	return Result{
		TenantID: "tenant", Signal: signal, Complete: complete,
		Objectives: []AffectedFact{{Revision: objective, Reasons: []ReasonCode{ReasonDependencyChanged}, Distance: 1}},
	}
}

func mustImpactRevision(domain string, kind complianceintegration.FactKind, id string, revisionID string, version uint64, digest string, at time.Time) complianceintegration.RevisionRef {
	value, err := complianceintegration.AdaptRevisionRef("tenant", domain, kind, compliance.RevisionRef{ID: id, RevisionID: revisionID, Version: version, ContentDigest: compliance.ContentDigest(digest), LastModified: at})
	if err != nil {
		panic(err)
	}
	return value
}
