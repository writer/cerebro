package policycandidate

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/writer/cerebro/internal/findingdsl"
)

type memoryEvaluationDatasetStore struct {
	datasets  map[string]*PolicyEvaluationDataset
	revisions map[string]*PolicyEvaluationDatasetRevision
	cases     map[string][]*PolicyEvaluationDatasetCase
}

func newMemoryEvaluationDatasetStore() *memoryEvaluationDatasetStore {
	return &memoryEvaluationDatasetStore{datasets: map[string]*PolicyEvaluationDataset{}, revisions: map[string]*PolicyEvaluationDatasetRevision{}, cases: map[string][]*PolicyEvaluationDatasetCase{}}
}

func (s *memoryEvaluationDatasetStore) CreatePolicyEvaluationDataset(_ context.Context, record CreatePolicyEvaluationDatasetRecord) (*PolicyEvaluationDataset, *PolicyEvaluationDatasetRevision, error) {
	if existing := s.datasets[record.Dataset.ID]; existing != nil {
		if existing.CreateRequestHash != record.Dataset.CreateRequestHash {
			return nil, nil, ErrConflict
		}
		return cloneEvaluationDataset(existing), cloneEvaluationDatasetRevision(s.revisions[record.Revision.ID]), nil
	}
	s.datasets[record.Dataset.ID] = cloneEvaluationDataset(record.Dataset)
	s.revisions[record.Revision.ID] = cloneEvaluationDatasetRevision(record.Revision)
	s.cases[record.Revision.ID] = cloneEvaluationDatasetCases(record.Cases)
	return cloneEvaluationDataset(record.Dataset), cloneEvaluationDatasetRevision(record.Revision), nil
}

func (s *memoryEvaluationDatasetStore) GetPolicyEvaluationDataset(_ context.Context, tenantID, datasetID string) (*PolicyEvaluationDataset, error) {
	dataset := s.datasets[datasetID]
	if dataset == nil || dataset.TenantID != tenantID {
		return nil, ErrNotFound
	}
	return cloneEvaluationDataset(dataset), nil
}

func (s *memoryEvaluationDatasetStore) ListPolicyEvaluationDatasets(_ context.Context, request ListPolicyEvaluationDatasetsRequest) ([]*PolicyEvaluationDataset, error) {
	var out []*PolicyEvaluationDataset
	for _, dataset := range s.datasets {
		if dataset.TenantID == request.TenantID && (request.CandidateID == "" || dataset.CandidateID == request.CandidateID) {
			out = append(out, cloneEvaluationDataset(dataset))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > request.Limit {
		out = out[:request.Limit]
	}
	return out, nil
}

func (s *memoryEvaluationDatasetStore) AppendPolicyEvaluationDatasetRevision(_ context.Context, record AppendPolicyEvaluationDatasetRevisionRecord) (*PolicyEvaluationDataset, *PolicyEvaluationDatasetRevision, error) {
	if existing := s.revisions[record.Revision.ID]; existing != nil {
		if existing.RequestHash != record.Revision.RequestHash {
			return nil, nil, ErrConflict
		}
		return cloneEvaluationDataset(s.datasets[record.Dataset.ID]), cloneEvaluationDatasetRevision(existing), nil
	}
	current := s.datasets[record.Dataset.ID]
	if current == nil || current.AggregateVersion != record.ExpectedVersion {
		return nil, nil, ErrConflict
	}
	s.datasets[record.Dataset.ID] = cloneEvaluationDataset(record.Dataset)
	s.revisions[record.Revision.ID] = cloneEvaluationDatasetRevision(record.Revision)
	s.cases[record.Revision.ID] = cloneEvaluationDatasetCases(record.Cases)
	return cloneEvaluationDataset(record.Dataset), cloneEvaluationDatasetRevision(record.Revision), nil
}

func (s *memoryEvaluationDatasetStore) GetPolicyEvaluationDatasetRevision(_ context.Context, request GetPolicyEvaluationDatasetRevisionRequest) (*PolicyEvaluationDatasetRevision, error) {
	revision := s.revisions[request.RevisionID]
	if revision == nil || revision.TenantID != request.TenantID || revision.DatasetID != request.DatasetID {
		return nil, ErrNotFound
	}
	return cloneEvaluationDatasetRevision(revision), nil
}

func (s *memoryEvaluationDatasetStore) GetPolicyEvaluationDatasetRevisionSnapshot(_ context.Context, request GetPolicyEvaluationDatasetRevisionRequest) (*PolicyEvaluationDatasetRevisionSnapshot, error) {
	revision, err := s.GetPolicyEvaluationDatasetRevision(context.Background(), request)
	if err != nil {
		return nil, err
	}
	return &PolicyEvaluationDatasetRevisionSnapshot{Revision: revision, Cases: cloneEvaluationDatasetCases(s.cases[request.RevisionID])}, nil
}

func (s *memoryEvaluationDatasetStore) ListPolicyEvaluationDatasetRevisions(_ context.Context, request ListPolicyEvaluationDatasetRevisionsRequest) ([]*PolicyEvaluationDatasetRevision, error) {
	var out []*PolicyEvaluationDatasetRevision
	for _, revision := range s.revisions {
		if revision.TenantID == request.TenantID && revision.DatasetID == request.DatasetID {
			out = append(out, cloneEvaluationDatasetRevision(revision))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	if len(out) > request.Limit {
		out = out[:request.Limit]
	}
	return out, nil
}

func (s *memoryEvaluationDatasetStore) ListPolicyEvaluationDatasetCases(_ context.Context, request ListPolicyEvaluationDatasetCasesRequest) ([]*PolicyEvaluationDatasetCase, error) {
	revision := s.revisions[request.RevisionID]
	if revision == nil || revision.TenantID != request.TenantID || revision.DatasetID != request.DatasetID {
		return nil, ErrNotFound
	}
	return cloneEvaluationDatasetCases(s.cases[request.RevisionID]), nil
}

func TestPolicyEvaluationDatasetCreateAppendReplayAndCAS(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	candidate := evaluationDatasetCandidate()
	candidateStore := &memoryStore{records: map[string]*Candidate{candidate.ID: candidate}}
	datasetStore := newMemoryEvaluationDatasetStore()
	service := Service{Store: candidateStore, Datasets: datasetStore, Now: func() time.Time { return now }}
	createRequest := CreatePolicyEvaluationDatasetRequest{
		TenantID: candidate.TenantID, CandidateID: candidate.ID, Name: "Multi-hop access path", ChangeSummary: "Import the authored proof suite.",
		ActorID: "slack-agent", IdempotencyKey: "dataset-create-1",
	}
	created, err := service.CreatePolicyEvaluationDataset(context.Background(), createRequest)
	if err != nil {
		t.Fatalf("CreatePolicyEvaluationDataset() error = %v", err)
	}
	if created.Dataset.AggregateVersion != 1 || created.Revision.Version != 1 || created.Revision.CaseCount != 2 {
		t.Fatalf("created result = %#v", created)
	}
	initialCases := datasetStore.cases[created.Revision.ID]
	if len(initialCases) != 2 || !strings.HasPrefix(initialCases[0].ID, "case_") || initialCases[0].ContentDigest == "" {
		t.Fatalf("initial cases = %#v", initialCases)
	}
	replayed, err := service.CreatePolicyEvaluationDataset(context.Background(), createRequest)
	if err != nil || replayed.Dataset.ID != created.Dataset.ID || replayed.Revision.ID != created.Revision.ID {
		t.Fatalf("create replay = %#v, %v", replayed, err)
	}
	conflictingCreate := createRequest
	conflictingCreate.Name = "Different logical request"
	if _, err := service.CreatePolicyEvaluationDataset(context.Background(), conflictingCreate); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting create error = %v, want conflict", err)
	}

	appendRequest := AppendPolicyEvaluationDatasetRevisionRequest{
		TenantID: candidate.TenantID, DatasetID: created.Dataset.ID, ExpectedVersion: 1,
		ChangeSummary: "Add a second passing mutation.", ActorID: "slack-agent", IdempotencyKey: "dataset-append-1",
		Cases: []PolicyEvaluationDatasetCaseInput{
			{ID: initialCases[0].ID, Test: initialCases[0].Test},
			{ID: initialCases[1].ID, Test: initialCases[1].Test},
			{ID: "case_second_passing_path", Test: secondPassingEvaluationCase()},
		},
	}
	appended, err := service.AppendPolicyEvaluationDatasetRevision(context.Background(), appendRequest)
	if err != nil {
		t.Fatalf("AppendPolicyEvaluationDatasetRevision() error = %v", err)
	}
	if appended.Dataset.AggregateVersion != 2 || appended.Revision.PredecessorID != created.Revision.ID || appended.Revision.CaseCount != 3 {
		t.Fatalf("appended result = %#v", appended)
	}
	if len(datasetStore.cases[created.Revision.ID]) != 2 {
		t.Fatal("append mutated the predecessor snapshot")
	}
	gotDataset, err := service.GetPolicyEvaluationDataset(context.Background(), candidate.TenantID, created.Dataset.ID)
	if err != nil || gotDataset.CurrentRevisionID != appended.Revision.ID {
		t.Fatalf("GetPolicyEvaluationDataset() = %#v, %v", gotDataset, err)
	}
	datasets, err := service.ListPolicyEvaluationDatasets(context.Background(), ListPolicyEvaluationDatasetsRequest{TenantID: candidate.TenantID, CandidateID: candidate.ID})
	if err != nil || len(datasets) != 1 {
		t.Fatalf("ListPolicyEvaluationDatasets() = %#v, %v", datasets, err)
	}
	revisions, err := service.ListPolicyEvaluationDatasetRevisions(context.Background(), ListPolicyEvaluationDatasetRevisionsRequest{TenantID: candidate.TenantID, DatasetID: created.Dataset.ID})
	if err != nil || len(revisions) != 2 || revisions[0].ID != created.Revision.ID || revisions[1].ID != appended.Revision.ID {
		t.Fatalf("ListPolicyEvaluationDatasetRevisions() = %#v, %v", revisions, err)
	}
	revisionCases, err := service.ListPolicyEvaluationDatasetCases(context.Background(), ListPolicyEvaluationDatasetCasesRequest{TenantID: candidate.TenantID, DatasetID: created.Dataset.ID, RevisionID: appended.Revision.ID})
	if err != nil || len(revisionCases) != 3 {
		t.Fatalf("ListPolicyEvaluationDatasetCases() = %#v, %v", revisionCases, err)
	}
	appendReplay, err := service.AppendPolicyEvaluationDatasetRevision(context.Background(), appendRequest)
	if err != nil || appendReplay.Revision.ID != appended.Revision.ID || appendReplay.Dataset.AggregateVersion != 2 {
		t.Fatalf("append replay = %#v, %v", appendReplay, err)
	}
	thirdRequest := AppendPolicyEvaluationDatasetRevisionRequest{
		TenantID: candidate.TenantID, DatasetID: created.Dataset.ID, ExpectedVersion: 2,
		ChangeSummary: "Refine the second passing mutation.", ActorID: "slack-agent", IdempotencyKey: "dataset-append-2",
		Cases: []PolicyEvaluationDatasetCaseInput{
			{ID: datasetStore.cases[appended.Revision.ID][0].ID, Test: datasetStore.cases[appended.Revision.ID][0].Test},
			{ID: datasetStore.cases[appended.Revision.ID][1].ID, Test: datasetStore.cases[appended.Revision.ID][1].Test},
			{ID: datasetStore.cases[appended.Revision.ID][2].ID, Test: datasetStore.cases[appended.Revision.ID][2].Test},
		},
	}
	thirdRequest.Cases[2].Test.Name = "passes after the same edge remains absent"
	third, err := service.AppendPolicyEvaluationDatasetRevision(context.Background(), thirdRequest)
	if err != nil || third.Dataset.AggregateVersion != 3 {
		t.Fatalf("third revision = %#v, %v", third, err)
	}
	appendReplay, err = service.AppendPolicyEvaluationDatasetRevision(context.Background(), appendRequest)
	if err != nil || appendReplay.Revision.ID != appended.Revision.ID || appendReplay.Dataset.AggregateVersion != 3 || appendReplay.Dataset.CurrentRevisionID != third.Revision.ID {
		t.Fatalf("old append replay after advance = %#v, %v", appendReplay, err)
	}
	stale := appendRequest
	stale.IdempotencyKey = "dataset-append-stale"
	if _, err := service.AppendPolicyEvaluationDatasetRevision(context.Background(), stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale append error = %v, want conflict", err)
	}
}

func TestPolicyEvaluationDatasetRejectsCrossTenantCreateAndTamperedSnapshot(t *testing.T) {
	candidate := evaluationDatasetCandidate()
	candidateStore := &memoryStore{records: map[string]*Candidate{candidate.ID: candidate}}
	datasetStore := newMemoryEvaluationDatasetStore()
	service := Service{Store: candidateStore, Datasets: datasetStore}
	request := CreatePolicyEvaluationDatasetRequest{
		TenantID: "tenant-b", CandidateID: candidate.ID, Name: "Multi-hop access path",
		ChangeSummary: "Import the authored proof suite.", ActorID: "agent", IdempotencyKey: "cross-tenant-create",
	}
	if _, err := service.CreatePolicyEvaluationDataset(context.Background(), request); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant create error = %v, want not found", err)
	}
	if len(datasetStore.datasets) != 0 {
		t.Fatal("cross-tenant create wrote a dataset")
	}
	request.TenantID = candidate.TenantID
	created, err := service.CreatePolicyEvaluationDataset(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	datasetStore.cases[created.Revision.ID][0].Test.Name = "tampered case"
	_, err = service.ListPolicyEvaluationDatasetCases(context.Background(), ListPolicyEvaluationDatasetCasesRequest{
		TenantID: candidate.TenantID, DatasetID: created.Dataset.ID, RevisionID: created.Revision.ID,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("tampered snapshot error = %v, want conflict", err)
	}
}

func TestPolicyEvaluationDatasetRejectsUnsafeCasePayloads(t *testing.T) {
	valid := evaluationDatasetSuite().Cases[0]
	tests := map[string]func(*findingdsl.PolicyRuleTestCase){
		"resource rows": func(testCase *findingdsl.PolicyRuleTestCase) { testCase.Resource = map[string]any{"id": "live"} },
		"query rows":    func(testCase *findingdsl.PolicyRuleTestCase) { testCase.QueryRows = []map[string]any{{"id": "live"}} },
		"live urn": func(testCase *findingdsl.PolicyRuleTestCase) {
			testCase.GraphFixture.Nodes[0].URN = "arn:aws:iam::123456789012:role/live"
		},
		"secret value": func(testCase *findingdsl.PolicyRuleTestCase) {
			testCase.GraphFixture.Nodes[0].Attributes = map[string]string{"access_token": "value"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			testCase := cloneEvaluationDatasetTestCase(valid)
			mutate(&testCase)
			if _, err := DigestPolicyEvaluationDatasetCase(testCase); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("unsafe case error = %v, want invalid request", err)
			}
		})
	}
}

func TestPolicyEvaluationDatasetDigestNormalizesGraphOrdering(t *testing.T) {
	left := evaluationDatasetSuite().Cases[0]
	right := left
	right.GraphFixture = &findingdsl.PolicyGraphFixture{
		TenantID: left.GraphFixture.TenantID,
		Nodes:    append([]findingdsl.PolicyGraphFixtureNode(nil), left.GraphFixture.Nodes...),
		Edges:    append([]findingdsl.PolicyGraphFixtureEdge(nil), left.GraphFixture.Edges...),
	}
	right.GraphFixture.Nodes[0], right.GraphFixture.Nodes[2] = right.GraphFixture.Nodes[2], right.GraphFixture.Nodes[0]
	right.GraphFixture.Edges[0], right.GraphFixture.Edges[1] = right.GraphFixture.Edges[1], right.GraphFixture.Edges[0]
	leftDigest, err := DigestPolicyEvaluationDatasetCase(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := DigestPolicyEvaluationDatasetCase(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("equivalent graph fixture digests differ: %s != %s", leftDigest, rightDigest)
	}
	right.WantFinding = false
	changedDigest, err := DigestPolicyEvaluationDatasetCase(right)
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == leftDigest {
		t.Fatal("material case change did not change digest")
	}
}

func evaluationDatasetCandidate() *Candidate {
	return &Candidate{
		ID: "pc_dataset", TenantID: "tenant-a", Status: StatusProved, Revision: 2,
		Artifacts: &Artifacts{
			Rule: graphRule(), Suite: evaluationDatasetSuite(),
			PolicyDigest: strings.Repeat("a", 64), TestDigest: strings.Repeat("b", 64),
		},
	}
}

func evaluationDatasetSuite() findingdsl.PolicyRuleTestSuite {
	nodes := []findingdsl.PolicyGraphFixtureNode{
		{URN: "urn:test:actor", SourceID: "aws", EntityType: "aws.session"},
		{URN: "urn:test:task", SourceID: "aws", EntityType: "aws.task"},
		{URN: "urn:test:definition", SourceID: "aws", EntityType: "aws.task_definition"},
	}
	edges := []findingdsl.PolicyGraphFixtureEdge{
		{FromURN: "urn:test:actor", ToURN: "urn:test:task", SourceID: "aws", Relation: "acted_on"},
		{FromURN: "urn:test:task", ToURN: "urn:test:definition", SourceID: "aws", Relation: "depends_on"},
	}
	passingEdges := append([]findingdsl.PolicyGraphFixtureEdge(nil), edges[:1]...)
	return findingdsl.PolicyRuleTestSuite{APIVersion: findingdsl.APIVersion, Kind: findingdsl.KindPolicyFindingRuleTest, Cases: []findingdsl.PolicyRuleTestCase{
		{Name: "finds the complete two-hop path", GraphFixture: &findingdsl.PolicyGraphFixture{TenantID: "fixture", Nodes: nodes, Edges: edges}, WantEvidenceURNs: []string{"urn:test:actor", "urn:test:definition"}, WantFinding: true},
		{Name: "passes when the critical edge is absent", GraphFixture: &findingdsl.PolicyGraphFixture{TenantID: "fixture", Nodes: nodes, Edges: passingEdges}, WantFinding: false},
	}}
}

func secondPassingEvaluationCase() findingdsl.PolicyRuleTestCase {
	testCase := evaluationDatasetSuite().Cases[1]
	testCase.Name = "passes when the same critical edge remains absent"
	return testCase
}

func cloneEvaluationDataset(dataset *PolicyEvaluationDataset) *PolicyEvaluationDataset {
	if dataset == nil {
		return nil
	}
	cloned := *dataset
	return &cloned
}

func cloneEvaluationDatasetRevision(revision *PolicyEvaluationDatasetRevision) *PolicyEvaluationDatasetRevision {
	if revision == nil {
		return nil
	}
	cloned := *revision
	return &cloned
}

func cloneEvaluationDatasetCases(cases []*PolicyEvaluationDatasetCase) []*PolicyEvaluationDatasetCase {
	payload, _ := json.Marshal(cases)
	var cloned []*PolicyEvaluationDatasetCase
	_ = json.Unmarshal(payload, &cloned)
	return cloned
}

func cloneEvaluationDatasetTestCase(testCase findingdsl.PolicyRuleTestCase) findingdsl.PolicyRuleTestCase {
	payload, _ := json.Marshal(testCase)
	var cloned findingdsl.PolicyRuleTestCase
	_ = json.Unmarshal(payload, &cloned)
	return cloned
}
