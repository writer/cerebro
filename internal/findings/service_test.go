package findings

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/ports"
)

type stubRuntimeStore struct {
	runtimes map[string]*cerebrov1.SourceRuntime
}

func (s *stubRuntimeStore) Ping(context.Context) error { return nil }

func (s *stubRuntimeStore) PutSourceRuntime(context.Context, *cerebrov1.SourceRuntime) error {
	return nil
}

func (s *stubRuntimeStore) GetSourceRuntime(_ context.Context, id string) (*cerebrov1.SourceRuntime, error) {
	runtime, ok := s.runtimes[id]
	if !ok {
		return nil, ports.ErrSourceRuntimeNotFound
	}
	return proto.Clone(runtime).(*cerebrov1.SourceRuntime), nil
}

type stubReplayer struct {
	request ports.ReplayRequest
	events  []*cerebrov1.EventEnvelope
}

func (s *stubReplayer) Replay(_ context.Context, request ports.ReplayRequest) ([]*cerebrov1.EventEnvelope, error) {
	s.request = request
	events := make([]*cerebrov1.EventEnvelope, 0, len(s.events))
	for _, event := range s.events {
		events = append(events, proto.Clone(event).(*cerebrov1.EventEnvelope))
	}
	return events, nil
}

type stubFindingStore struct {
	findings map[string]*ports.FindingRecord
	request  ports.ListFindingsRequest
}

func (s *stubFindingStore) Ping(context.Context) error { return nil }

func (s *stubFindingStore) UpsertFinding(_ context.Context, finding *ports.FindingRecord) (*ports.FindingRecord, error) {
	if finding == nil {
		return nil, errors.New("finding is required")
	}
	if s.findings == nil {
		s.findings = make(map[string]*ports.FindingRecord)
	}
	cloned := cloneFinding(finding)
	s.findings[cloned.ID] = cloned
	return cloneFinding(cloned), nil
}

func (s *stubFindingStore) ListFindings(_ context.Context, request ports.ListFindingsRequest) ([]*ports.FindingRecord, error) {
	s.request = request
	findings := []*ports.FindingRecord{}
	for _, finding := range s.findings {
		if !findingMatches(request, finding) {
			continue
		}
		findings = append(findings, cloneFinding(finding))
	}
	sort.Slice(findings, func(i, j int) bool {
		left := findings[i]
		right := findings[j]
		switch {
		case left.LastObservedAt.Equal(right.LastObservedAt):
			return left.ID < right.ID
		case left.LastObservedAt.IsZero():
			return false
		case right.LastObservedAt.IsZero():
			return true
		default:
			return left.LastObservedAt.After(right.LastObservedAt)
		}
	})
	if request.Limit != 0 && len(findings) > int(request.Limit) {
		findings = findings[:int(request.Limit)]
	}
	return findings, nil
}

func TestEvaluateSourceRuntimeFindingsReplaysOktaPolicyRuleLifecycleTampering(t *testing.T) {
	replayer := &stubReplayer{
		events: []*cerebrov1.EventEnvelope{
			newAuditEvent("okta-audit-1", "user.session.start", "SUCCESS"),
			newAuditEvent("okta-audit-2", "policy.rule.update", "SUCCESS"),
		},
	}
	store := &stubFindingStore{}
	service := New(&stubRuntimeStore{
		runtimes: map[string]*cerebrov1.SourceRuntime{
			"writer-okta-audit": {
				Id:       "writer-okta-audit",
				SourceId: "okta",
				TenantId: "writer",
			},
		},
	}, replayer, store)

	result, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{
		RuntimeID:  "writer-okta-audit",
		EventLimit: 25,
	})
	if err != nil {
		t.Fatalf("EvaluateSourceRuntime() error = %v", err)
	}
	if result.Runtime.GetId() != "writer-okta-audit" {
		t.Fatalf("Runtime.ID = %q, want writer-okta-audit", result.Runtime.GetId())
	}
	if result.Rule.GetId() != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("Rule.ID = %q, want %q", result.Rule.GetId(), oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if result.EventsEvaluated != 2 {
		t.Fatalf("EventsEvaluated = %d, want 2", result.EventsEvaluated)
	}
	if got := replayer.request.RuntimeID; got != "writer-okta-audit" {
		t.Fatalf("Replay().RuntimeID = %q, want writer-okta-audit", got)
	}
	if got := replayer.request.Limit; got != 25 {
		t.Fatalf("Replay().Limit = %d, want 25", got)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.RuleID != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("Finding.RuleID = %q, want %q", finding.RuleID, oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if finding.Severity != "HIGH" {
		t.Fatalf("Finding.Severity = %q, want HIGH", finding.Severity)
	}
	if finding.Status != "open" {
		t.Fatalf("Finding.Status = %q, want open", finding.Status)
	}
	if finding.Summary != "admin@writer.com performed policy.rule.update on pol-1" {
		t.Fatalf("Finding.Summary = %q, want admin@writer.com performed policy.rule.update on pol-1", finding.Summary)
	}
	if len(finding.ResourceURNs) != 2 {
		t.Fatalf("len(Finding.ResourceURNs) = %d, want 2", len(finding.ResourceURNs))
	}
	if finding.ResourceURNs[0] != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("Finding.ResourceURNs[0] = %q, want policy rule urn", finding.ResourceURNs[0])
	}
	if finding.ResourceURNs[1] != "urn:cerebro:writer:okta_user:00u2" {
		t.Fatalf("Finding.ResourceURNs[1] = %q, want actor urn", finding.ResourceURNs[1])
	}
	if finding.Attributes["primary_actor_urn"] != "urn:cerebro:writer:okta_user:00u2" {
		t.Fatalf("Finding.Attributes[primary_actor_urn] = %q, want actor urn", finding.Attributes["primary_actor_urn"])
	}
	if finding.Attributes["primary_resource_urn"] != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("Finding.Attributes[primary_resource_urn] = %q, want resource urn", finding.Attributes["primary_resource_urn"])
	}
	if len(store.findings) != 1 {
		t.Fatalf("len(store.findings) = %d, want 1", len(store.findings))
	}
}

func TestEvaluateSourceRuntimeFindingsRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil)
	if _, err := service.EvaluateSourceRuntime(context.Background(), EvaluateRequest{RuntimeID: "writer-okta-audit"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("EvaluateSourceRuntime() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func TestListFindingsReturnsFilteredPersistedFindings(t *testing.T) {
	store := &stubFindingStore{
		findings: map[string]*ports.FindingRecord{
			"finding-1": {
				ID:             "finding-1",
				RuntimeID:      "writer-okta-audit",
				RuleID:         oktaPolicyRuleLifecycleTamperingRuleID,
				Severity:       "HIGH",
				Status:         "open",
				ResourceURNs:   []string{"urn:cerebro:writer:okta_resource:policyrule:pol-1"},
				EventIDs:       []string{"okta-audit-2"},
				LastObservedAt: time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
			},
			"finding-2": {
				ID:             "finding-2",
				RuntimeID:      "writer-okta-audit",
				RuleID:         oktaPolicyRuleLifecycleTamperingRuleID,
				Severity:       "MEDIUM",
				Status:         "resolved",
				ResourceURNs:   []string{"urn:cerebro:writer:okta_resource:policyrule:pol-2"},
				EventIDs:       []string{"okta-audit-3"},
				LastObservedAt: time.Date(2026, 4, 23, 11, 0, 0, 0, time.UTC),
			},
		},
	}
	service := New(
		&stubRuntimeStore{
			runtimes: map[string]*cerebrov1.SourceRuntime{
				"writer-okta-audit": {
					Id:       "writer-okta-audit",
					SourceId: "okta",
					TenantId: "writer",
				},
			},
		},
		&stubReplayer{},
		store,
	)

	result, err := service.ListFindings(context.Background(), ListRequest{
		RuntimeID:   "writer-okta-audit",
		RuleID:      oktaPolicyRuleLifecycleTamperingRuleID,
		Severity:    "HIGH",
		Status:      "open",
		ResourceURN: "urn:cerebro:writer:okta_resource:policyrule:pol-1",
		EventID:     "okta-audit-2",
		Limit:       1,
	})
	if err != nil {
		t.Fatalf("ListFindings() error = %v", err)
	}
	if got := len(result.Findings); got != 1 {
		t.Fatalf("len(ListFindings().Findings) = %d, want 1", got)
	}
	if got := result.Findings[0].ID; got != "finding-1" {
		t.Fatalf("ListFindings().Findings[0].ID = %q, want finding-1", got)
	}
	if got := store.request.RuntimeID; got != "writer-okta-audit" {
		t.Fatalf("ListFindings().RuntimeID = %q, want writer-okta-audit", got)
	}
	if got := store.request.RuleID; got != oktaPolicyRuleLifecycleTamperingRuleID {
		t.Fatalf("ListFindings().RuleID = %q, want %q", got, oktaPolicyRuleLifecycleTamperingRuleID)
	}
	if got := store.request.Severity; got != "HIGH" {
		t.Fatalf("ListFindings().Severity = %q, want HIGH", got)
	}
	if got := store.request.Status; got != "open" {
		t.Fatalf("ListFindings().Status = %q, want open", got)
	}
	if got := store.request.ResourceURN; got != "urn:cerebro:writer:okta_resource:policyrule:pol-1" {
		t.Fatalf("ListFindings().ResourceURN = %q, want policy rule urn", got)
	}
	if got := store.request.EventID; got != "okta-audit-2" {
		t.Fatalf("ListFindings().EventID = %q, want okta-audit-2", got)
	}
	if got := store.request.Limit; got != 1 {
		t.Fatalf("ListFindings().Limit = %d, want 1", got)
	}
}

func TestListFindingsRequiresAvailableDependencies(t *testing.T) {
	service := New(nil, nil, nil)
	if _, err := service.ListFindings(context.Background(), ListRequest{RuntimeID: "writer-okta-audit"}); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("ListFindings() error = %v, want %v", err, ErrRuntimeUnavailable)
	}
}

func newAuditEvent(id string, eventType string, outcome string) *cerebrov1.EventEnvelope {
	return &cerebrov1.EventEnvelope{
		Id:         id,
		TenantId:   "writer",
		SourceId:   "okta",
		Kind:       "okta.audit",
		OccurredAt: timestamppb.New(time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)),
		SchemaRef:  "okta/audit/v1",
		Attributes: map[string]string{
			"domain":                            "writer.okta.com",
			"event_type":                        eventType,
			"resource_id":                       "pol-1",
			"resource_type":                     "PolicyRule",
			"actor_id":                          "00u2",
			"actor_type":                        "User",
			"actor_alternate_id":                "admin@writer.com",
			"actor_display_name":                "Admin Example",
			"outcome_result":                    outcome,
			ports.EventAttributeSourceRuntimeID: "writer-okta-audit",
		},
	}
}

func cloneFinding(finding *ports.FindingRecord) *ports.FindingRecord {
	if finding == nil {
		return nil
	}
	resourceURNs := make([]string, len(finding.ResourceURNs))
	copy(resourceURNs, finding.ResourceURNs)
	eventIDs := make([]string, len(finding.EventIDs))
	copy(eventIDs, finding.EventIDs)
	attributes := make(map[string]string, len(finding.Attributes))
	for key, value := range finding.Attributes {
		attributes[key] = value
	}
	return &ports.FindingRecord{
		ID:              finding.ID,
		Fingerprint:     finding.Fingerprint,
		TenantID:        finding.TenantID,
		RuntimeID:       finding.RuntimeID,
		RuleID:          finding.RuleID,
		Title:           finding.Title,
		Severity:        finding.Severity,
		Status:          finding.Status,
		Summary:         finding.Summary,
		ResourceURNs:    resourceURNs,
		EventIDs:        eventIDs,
		Attributes:      attributes,
		FirstObservedAt: finding.FirstObservedAt,
		LastObservedAt:  finding.LastObservedAt,
	}
}

func findingMatches(request ports.ListFindingsRequest, finding *ports.FindingRecord) bool {
	if finding == nil {
		return false
	}
	if strings.TrimSpace(finding.RuntimeID) != strings.TrimSpace(request.RuntimeID) {
		return false
	}
	if request.FindingID != "" && strings.TrimSpace(finding.ID) != strings.TrimSpace(request.FindingID) {
		return false
	}
	if request.RuleID != "" && strings.TrimSpace(finding.RuleID) != strings.TrimSpace(request.RuleID) {
		return false
	}
	if request.Severity != "" && strings.TrimSpace(finding.Severity) != strings.TrimSpace(request.Severity) {
		return false
	}
	if request.Status != "" && strings.TrimSpace(finding.Status) != strings.TrimSpace(request.Status) {
		return false
	}
	if request.ResourceURN != "" && !containsTrimmed(finding.ResourceURNs, request.ResourceURN) {
		return false
	}
	if request.EventID != "" && !containsTrimmed(finding.EventIDs, request.EventID) {
		return false
	}
	return true
}

func containsTrimmed(values []string, expected string) bool {
	trimmedExpected := strings.TrimSpace(expected)
	for _, value := range values {
		if strings.TrimSpace(value) == trimmedExpected {
			return true
		}
	}
	return false
}
