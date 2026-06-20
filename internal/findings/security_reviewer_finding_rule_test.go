package findings

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

func TestSecurityReviewerFindingRuleMapsReviewerFindingDeterministically(t *testing.T) {
	rule := newSecurityReviewerFindingRule()
	runtime := securityReviewerRuntime()
	event := securityReviewerEvent("reviewer-finding-1", map[string]string{
		"base_sha":         "base-1",
		"branch":           "codex/sec-1058-security-reviewer-findings-20260616",
		"file":             "internal/bootstrap/app.go",
		"head_sha":         "head-1",
		"line":             "42",
		"message":          "handler accepts reviewer-controlled redirect target",
		"pull_request":     "1058",
		"repository":       "writer/cerebro",
		"review_subject":   "https://github.com/writer/cerebro/pull/1058",
		"reviewer":         "security-reviewer",
		"reviewer_source":  "droid-review",
		"rule":             "open-redirect",
		"severity":         "high",
		"pull_request_url": "https://github.com/writer/cerebro/pull/1058",
	})

	records, err := rule.Evaluate(context.Background(), runtime, event)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if got := len(records); got != 1 {
		t.Fatalf("Evaluate() returned %d records, want 1", got)
	}
	finding := records[0]
	wantFingerprint := hashFindingFingerprint(
		securityReviewerFindingRuleID,
		event.GetTenantId(),
		"https://github.com/writer/cerebro/pull/1058",
		"open-redirect",
		"internal/bootstrap/app.go",
		"42",
		"handler accepts reviewer-controlled redirect target",
	)
	if finding.ID != wantFingerprint || finding.Fingerprint != wantFingerprint {
		t.Fatalf("finding ID/fingerprint = %q/%q, want %q", finding.ID, finding.Fingerprint, wantFingerprint)
	}
	if finding.RuleID != securityReviewerFindingRuleID {
		t.Fatalf("RuleID = %q, want %q", finding.RuleID, securityReviewerFindingRuleID)
	}
	if finding.Severity != "HIGH" {
		t.Fatalf("Severity = %q, want HIGH", finding.Severity)
	}
	if finding.Status != findingStatusOpen {
		t.Fatalf("Status = %q, want %q", finding.Status, findingStatusOpen)
	}
	if finding.PolicyID != "open-redirect" || finding.CheckID != "open-redirect" {
		t.Fatalf("PolicyID/CheckID = %q/%q, want reviewer rule", finding.PolicyID, finding.CheckID)
	}
	if got := strings.Join(finding.EventIDs, ","); got != "reviewer-finding-1" {
		t.Fatalf("EventIDs = %q, want reviewer-finding-1", got)
	}
	if got := finding.Attributes["reviewer"]; got != "security-reviewer" {
		t.Fatalf("Attributes[reviewer] = %q, want security-reviewer", got)
	}
	if got := finding.Attributes["review_subject"]; got != "https://github.com/writer/cerebro/pull/1058" {
		t.Fatalf("Attributes[review_subject] = %q", got)
	}
	if got := finding.Attributes["source_runtime_id"]; got != runtime.GetId() {
		t.Fatalf("Attributes[source_runtime_id] = %q, want %q", got, runtime.GetId())
	}
	if got := len(finding.GraphEvidenceRows); got != 1 {
		t.Fatalf("GraphEvidenceRows = %d, want 1", got)
	}
	if got := finding.GraphEvidenceRows[0].GetAttributes()["reviewer_rule"]; got != "open-redirect" {
		t.Fatalf("GraphEvidenceRows[0].Attributes[reviewer_rule] = %q, want open-redirect", got)
	}
}

func TestSecurityReviewerFindingRuleFingerprintIgnoresEventIDAndObservedAt(t *testing.T) {
	rule := newSecurityReviewerFindingRule()
	runtime := securityReviewerRuntime()
	attrs := map[string]string{
		"file":           "internal/findings/candidates.go",
		"line":           "101",
		"message":        "candidate transition is not compare-and-swap protected",
		"repository":     "writer/cerebro",
		"review_subject": "https://github.com/writer/cerebro/pull/1058",
		"rule":           "candidate-lifecycle-atomicity",
		"severity":       "P1",
	}
	first := securityReviewerEvent("reviewer-finding-a", attrs)
	second := securityReviewerEvent("reviewer-finding-b", attrs)
	second.OccurredAt = timestamppb.New(first.GetOccurredAt().AsTime().Add(2 * time.Hour))

	firstRecords, err := rule.Evaluate(context.Background(), runtime, first)
	if err != nil {
		t.Fatalf("Evaluate(first) error = %v", err)
	}
	secondRecords, err := rule.Evaluate(context.Background(), runtime, second)
	if err != nil {
		t.Fatalf("Evaluate(second) error = %v", err)
	}
	if firstRecords[0].Fingerprint != secondRecords[0].Fingerprint {
		t.Fatalf("fingerprint changed across equivalent reviewer findings: %q vs %q", firstRecords[0].Fingerprint, secondRecords[0].Fingerprint)
	}
	if firstRecords[0].EventIDs[0] == secondRecords[0].EventIDs[0] {
		t.Fatalf("event IDs unexpectedly equal: %v", firstRecords[0].EventIDs)
	}
}

func TestSecurityReviewerFindingRuleRequiresMessageAndStableAnchor(t *testing.T) {
	rule := newSecurityReviewerFindingRule()
	runtime := securityReviewerRuntime()
	for _, tc := range []struct {
		name  string
		attrs map[string]string
	}{
		{
			name: "missing message",
			attrs: map[string]string{
				"file":           "internal/findings/candidates.go",
				"review_subject": "https://github.com/writer/cerebro/pull/1058",
				"rule":           "candidate-lifecycle-atomicity",
			},
		},
		{
			name: "missing anchor",
			attrs: map[string]string{
				"message": "reviewer finding without stable subject",
				"rule":    "missing-anchor",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, err := rule.Evaluate(context.Background(), runtime, securityReviewerEvent("reviewer-no-match", tc.attrs))
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if len(records) != 0 {
				t.Fatalf("Evaluate() returned %d records, want no match", len(records))
			}
		})
	}
}

func TestSecurityReviewerFindingRuleEntersCandidateEvaluationPipeline(t *testing.T) {
	rule := newSecurityReviewerFindingRule()
	registry, err := NewRegistry(rule)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	runtime := securityReviewerRuntime()
	replayer := &stubReplayer{events: []*cerebrov1.EventEnvelope{
		securityReviewerEvent("reviewer-finding-1", map[string]string{
			"file":           "internal/bootstrap/app.go",
			"line":           "42",
			"message":        "handler accepts reviewer-controlled redirect target",
			"repository":     "writer/cerebro",
			"review_subject": "https://github.com/writer/cerebro/pull/1058",
			"reviewer":       "security-reviewer",
			"rule":           "open-redirect",
			"severity":       "high",
		}),
	}}
	store := &stubFindingStore{}
	service := NewWithRegistry(
		&stubRuntimeStore{runtimes: map[string]*cerebrov1.SourceRuntime{runtime.GetId(): runtime}},
		replayer,
		store,
		store,
		store,
		store,
		registry,
	).WithFindingCandidateStore(store)

	result, err := service.EvaluateSourceRuntimeCandidateRules(context.Background(), EvaluateCandidateRulesRequest{
		RuntimeID: runtime.GetId(),
		RuleIDs:   []string{securityReviewerFindingRuleID},
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntimeCandidateRules() error = %v", err)
	}
	if !replayer.request.ExactKindFilters {
		t.Fatal("Replay().ExactKindFilters = false, want true")
	}
	if got, want := replayer.request.KindPrefixes, []string{"security_reviewer.finding"}; !slices.Equal(got, want) {
		t.Fatalf("Replay().KindPrefixes = %#v, want %#v", got, want)
	}
	if got := store.candidateState.upsertCount; got != 1 {
		t.Fatalf("candidate upserts = %d, want 1", got)
	}
	if got := len(result.Evaluations); got != 1 {
		t.Fatalf("evaluations = %d, want 1", got)
	}
	candidates := result.Evaluations[0].Candidates
	if got := len(candidates); got != 1 {
		t.Fatalf("candidates = %d, want 1", got)
	}
	candidate := candidates[0]
	if candidate.Status != findingCandidateStatusCandidate {
		t.Fatalf("candidate status = %q, want %q", candidate.Status, findingCandidateStatusCandidate)
	}
	if candidate.Finding == nil || candidate.Finding.RuleID != securityReviewerFindingRuleID {
		t.Fatalf("candidate finding = %#v, want security reviewer rule", candidate.Finding)
	}
	if got := len(candidate.Evidence); got != 1 {
		t.Fatalf("candidate evidence = %d, want 1", got)
	}
	if got := len(candidate.Evidence[0].GetGraphRows()); got != 1 {
		t.Fatalf("candidate evidence graph rows = %d, want reviewer graph evidence", got)
	}
}

func securityReviewerRuntime() *cerebrov1.SourceRuntime {
	return &cerebrov1.SourceRuntime{
		Id:       "security-reviewer-runtime",
		SourceId: securityReviewerFindingSource,
		TenantId: "writer",
	}
}

func securityReviewerEvent(id string, attrs map[string]string) *cerebrov1.EventEnvelope {
	copied := make(map[string]string, len(attrs))
	for key, value := range attrs {
		copied[key] = value
	}
	occurredAt := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   securityReviewerFindingSource,
		Kind:       "security_reviewer.finding",
		OccurredAt: timestamppb.New(occurredAt),
		SchemaRef:  "security-reviewer/finding/v1",
		Attributes: copied,
	}
}
