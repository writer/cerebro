package policycandidate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/findingdsl"
)

const (
	maxEvaluationDatasetNameBytes          = 200
	maxEvaluationDatasetChangeSummaryBytes = 1000
	maxEvaluationDatasetActorBytes         = 256
	maxEvaluationDatasetCaseBytes          = 64 << 10
	maxEvaluationDatasetFixtureNodes       = 64
	maxEvaluationDatasetFixtureEdges       = 128
	maxEvaluationDatasetFixtureAttributes  = 32
	maxEvaluationDatasetFixtureValueBytes  = 256
	maxEvaluationDatasetEvidenceURNs       = 32
)

var evaluationDatasetCaseIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
var syntheticEvaluationDatasetURNPattern = regexp.MustCompile(`^urn:(?:test|fixture):[a-z0-9][a-z0-9:._/-]{0,239}$`)
var evaluationDatasetFixtureTokenPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)
var evaluationDatasetFixtureLabelPattern = regexp.MustCompile(`^fixture-(?:(?:node|edge|ref|value)-[a-z0-9][a-z0-9-]{0,63}|candidate-marker)$`)
var evaluationDatasetAttributeKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var evaluationDatasetEnumValuePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z_]{0,63}$`)
var evaluationDatasetCountValuePattern = regexp.MustCompile(`^[0-9]{1,6}$`)
var evaluationDatasetResourceIDPattern = regexp.MustCompile(`(?i)\b(?:ami|acl|eni|igw|i|nat|rtb|sg|snap|subnet|vol|vpc|vpce)-[0-9a-f]{8,17}\b`)
var evaluationDatasetUUIDPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
var evaluationDatasetIPv4Pattern = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

func (s Service) CreatePolicyEvaluationDataset(ctx context.Context, request CreatePolicyEvaluationDatasetRequest) (*PolicyEvaluationDatasetResult, error) {
	if s.Datasets == nil {
		return nil, ErrStoreUnavailable
	}
	request = normalizeCreatePolicyEvaluationDatasetRequest(request)
	if err := validateCreatePolicyEvaluationDatasetRequest(request); err != nil {
		return nil, err
	}
	candidate, err := s.Get(ctx, request.CandidateID)
	if err != nil {
		return nil, err
	}
	if candidate.TenantID != request.TenantID {
		return nil, ErrNotFound
	}
	requestHash, err := canonicalDigest(struct {
		Schema, TenantID, CandidateID, Name, ChangeSummary, ActorID, IdempotencyKey string
	}{"policy-evaluation-dataset-create/v1", request.TenantID, request.CandidateID, request.Name, request.ChangeSummary, request.ActorID, request.IdempotencyKey})
	if err != nil {
		return nil, fmt.Errorf("digest policy evaluation dataset request: %w", err)
	}
	datasetID := deterministicEvaluationDatasetID(candidate.TenantID, candidate.ID, request.IdempotencyKey)
	revisionID := deterministicEvaluationDatasetRevisionID(candidate.TenantID, datasetID, request.IdempotencyKey)
	if existing, getErr := s.Datasets.GetPolicyEvaluationDataset(ctx, candidate.TenantID, datasetID); getErr == nil {
		if existing.CreateRequestHash != requestHash {
			return nil, fmt.Errorf("%w: idempotency key was already used for a different dataset request", ErrConflict)
		}
		revision, _, revisionErr := s.verifiedEvaluationDatasetSnapshot(ctx, GetPolicyEvaluationDatasetRevisionRequest{
			TenantID: candidate.TenantID, DatasetID: datasetID, RevisionID: revisionID,
		})
		if revisionErr != nil {
			return nil, revisionErr
		}
		return &PolicyEvaluationDatasetResult{Dataset: existing, Revision: revision}, nil
	} else if !errors.Is(getErr, ErrNotFound) {
		return nil, getErr
	}
	if err := validateEvaluationDatasetCandidate(candidate); err != nil {
		return nil, err
	}
	inputs := make([]PolicyEvaluationDatasetCaseInput, len(candidate.Artifacts.Suite.Cases))
	for index, testCase := range candidate.Artifacts.Suite.Cases {
		caseID := stableEvaluationDatasetCaseID(testCase.Name)
		normalized, normalizeErr := normalizeAuthoredEvaluationDatasetTestCase(testCase, caseID)
		if normalizeErr != nil {
			return nil, normalizeErr
		}
		inputs[index] = PolicyEvaluationDatasetCaseInput{ID: caseID, Test: normalized}
	}
	cases, err := buildEvaluationDatasetCases(datasetID, revisionID, inputs, false)
	if err != nil {
		return nil, err
	}
	contentDigest, err := DigestPolicyEvaluationDatasetRevision(candidate.ID, candidate.Artifacts.PolicyDigest, candidate.Artifacts.TestDigest, cases)
	if err != nil {
		return nil, err
	}
	now := s.now()
	dataset := &PolicyEvaluationDataset{
		ID: datasetID, TenantID: candidate.TenantID, CandidateID: candidate.ID, Name: request.Name,
		CurrentRevisionID: revisionID, AggregateVersion: 1, CreatedAt: now, UpdatedAt: now, CreateRequestHash: requestHash,
	}
	revision := &PolicyEvaluationDatasetRevision{
		ID: revisionID, TenantID: candidate.TenantID, DatasetID: datasetID, Version: 1,
		PolicyDigest: candidate.Artifacts.PolicyDigest, SourceTestDigest: candidate.Artifacts.TestDigest,
		ContentDigest: contentDigest, CaseCount: len(cases), ChangeSummary: request.ChangeSummary,
		CreatedBy: request.ActorID, CreatedAt: now, RequestHash: requestHash,
	}
	storedDataset, storedRevision, err := s.Datasets.CreatePolicyEvaluationDataset(ctx, CreatePolicyEvaluationDatasetRecord{
		Dataset: dataset, Revision: revision, Cases: cases, IdempotencyKey: request.IdempotencyKey,
	})
	if err != nil {
		return nil, err
	}
	return &PolicyEvaluationDatasetResult{Dataset: storedDataset, Revision: storedRevision}, nil
}

func (s Service) AppendPolicyEvaluationDatasetRevision(ctx context.Context, request AppendPolicyEvaluationDatasetRevisionRequest) (*PolicyEvaluationDatasetResult, error) {
	if s.Datasets == nil {
		return nil, ErrStoreUnavailable
	}
	request = normalizeAppendPolicyEvaluationDatasetRevisionRequest(request)
	if err := validateAppendPolicyEvaluationDatasetRevisionRequest(request); err != nil {
		return nil, err
	}
	dataset, err := s.Datasets.GetPolicyEvaluationDataset(ctx, request.TenantID, request.DatasetID)
	if err != nil {
		return nil, err
	}
	normalizedInputs, err := normalizeEvaluationDatasetCaseInputs(request.Cases)
	if err != nil {
		return nil, err
	}
	requestHash, err := canonicalDigest(struct {
		Schema, TenantID, DatasetID, ChangeSummary, ActorID, IdempotencyKey string
		ExpectedVersion                                                     uint64
		Cases                                                               []PolicyEvaluationDatasetCaseInput
	}{"policy-evaluation-dataset-append/v1", request.TenantID, request.DatasetID, request.ChangeSummary, request.ActorID, request.IdempotencyKey, request.ExpectedVersion, normalizedInputs})
	if err != nil {
		return nil, fmt.Errorf("digest policy evaluation dataset append request: %w", err)
	}
	revisionID := deterministicEvaluationDatasetRevisionID(dataset.TenantID, dataset.ID, request.IdempotencyKey)
	if existing, _, getErr := s.verifiedEvaluationDatasetSnapshot(ctx, GetPolicyEvaluationDatasetRevisionRequest{
		TenantID: dataset.TenantID, DatasetID: dataset.ID, RevisionID: revisionID,
	}); getErr == nil {
		if existing.RequestHash != requestHash {
			return nil, fmt.Errorf("%w: idempotency key was already used for a different revision request", ErrConflict)
		}
		return &PolicyEvaluationDatasetResult{Dataset: dataset, Revision: existing}, nil
	} else if !errors.Is(getErr, ErrNotFound) {
		return nil, getErr
	}
	if dataset.AggregateVersion != request.ExpectedVersion {
		return nil, fmt.Errorf("%w: dataset version is %d, expected %d", ErrConflict, dataset.AggregateVersion, request.ExpectedVersion)
	}
	candidate, err := s.Get(ctx, dataset.CandidateID)
	if err != nil {
		return nil, err
	}
	if candidate.TenantID != dataset.TenantID {
		return nil, fmt.Errorf("%w: dataset candidate tenant changed", ErrConflict)
	}
	if err := validateEvaluationDatasetCandidate(candidate); err != nil {
		return nil, err
	}
	suite := findingdsl.PolicyRuleTestSuite{APIVersion: findingdsl.APIVersion, Kind: findingdsl.KindPolicyFindingRuleTest, Cases: make([]findingdsl.PolicyRuleTestCase, len(normalizedInputs))}
	for index := range normalizedInputs {
		suite.Cases[index] = normalizedInputs[index].Test
	}
	if issues := findingdsl.ValidatePolicyRuleTestSuiteAgainstRule(candidate.Artifacts.Rule, suite); len(issues) != 0 {
		return nil, evaluationDatasetIssuesError(issues)
	}
	cases, err := buildEvaluationDatasetCases(dataset.ID, revisionID, normalizedInputs, true)
	if err != nil {
		return nil, err
	}
	contentDigest, err := DigestPolicyEvaluationDatasetRevision(candidate.ID, candidate.Artifacts.PolicyDigest, candidate.Artifacts.TestDigest, cases)
	if err != nil {
		return nil, err
	}
	predecessor, _, err := s.verifiedEvaluationDatasetSnapshot(ctx, GetPolicyEvaluationDatasetRevisionRequest{
		TenantID: dataset.TenantID, DatasetID: dataset.ID, RevisionID: dataset.CurrentRevisionID,
	})
	if err != nil {
		return nil, err
	}
	if predecessor.ContentDigest == contentDigest {
		return nil, fmt.Errorf("%w: revision does not change the dataset", ErrConflict)
	}
	now := s.now()
	revision := &PolicyEvaluationDatasetRevision{
		ID: revisionID, TenantID: dataset.TenantID, DatasetID: dataset.ID, Version: dataset.AggregateVersion + 1,
		PredecessorID: predecessor.ID, PolicyDigest: candidate.Artifacts.PolicyDigest, SourceTestDigest: candidate.Artifacts.TestDigest,
		ContentDigest: contentDigest, CaseCount: len(cases), ChangeSummary: request.ChangeSummary,
		CreatedBy: request.ActorID, CreatedAt: now, RequestHash: requestHash,
	}
	updated := *dataset
	updated.CurrentRevisionID = revision.ID
	updated.AggregateVersion = revision.Version
	updated.UpdatedAt = now
	storedDataset, storedRevision, err := s.Datasets.AppendPolicyEvaluationDatasetRevision(ctx, AppendPolicyEvaluationDatasetRevisionRecord{
		Dataset: &updated, Revision: revision, Cases: cases, ExpectedVersion: request.ExpectedVersion, IdempotencyKey: request.IdempotencyKey,
	})
	if err != nil {
		return nil, err
	}
	return &PolicyEvaluationDatasetResult{Dataset: storedDataset, Revision: storedRevision}, nil
}

func (s Service) GetPolicyEvaluationDataset(ctx context.Context, tenantID, datasetID string) (*PolicyEvaluationDataset, error) {
	if s.Datasets == nil {
		return nil, ErrStoreUnavailable
	}
	tenantID, datasetID = strings.TrimSpace(tenantID), strings.TrimSpace(datasetID)
	if tenantID == "" || datasetID == "" {
		return nil, fmt.Errorf("%w: tenant id and dataset id are required", ErrInvalidRequest)
	}
	dataset, err := s.Datasets.GetPolicyEvaluationDataset(ctx, tenantID, datasetID)
	if err != nil {
		return nil, err
	}
	if dataset.TenantID != tenantID || dataset.ID != datasetID || dataset.CurrentRevisionID == "" {
		return nil, fmt.Errorf("%w: dataset identity or current revision is invalid", ErrConflict)
	}
	if _, _, err := s.verifiedEvaluationDatasetSnapshot(ctx, GetPolicyEvaluationDatasetRevisionRequest{
		TenantID: tenantID, DatasetID: datasetID, RevisionID: dataset.CurrentRevisionID,
	}); err != nil {
		return nil, err
	}
	return dataset, nil
}

func (s Service) ListPolicyEvaluationDatasets(ctx context.Context, request ListPolicyEvaluationDatasetsRequest) ([]*PolicyEvaluationDataset, error) {
	if s.Datasets == nil {
		return nil, ErrStoreUnavailable
	}
	request.TenantID, request.CandidateID = strings.TrimSpace(request.TenantID), strings.TrimSpace(request.CandidateID)
	if request.TenantID == "" {
		return nil, fmt.Errorf("%w: tenant id is required", ErrInvalidRequest)
	}
	if request.Limit == 0 {
		request.Limit = DefaultEvaluationDatasetListLimit
	}
	if request.Limit < 1 || request.Limit > MaxEvaluationDatasetListLimit {
		return nil, fmt.Errorf("%w: dataset limit must be between 1 and %d", ErrInvalidRequest, MaxEvaluationDatasetListLimit)
	}
	datasets, err := s.Datasets.ListPolicyEvaluationDatasets(ctx, request)
	if err != nil {
		return nil, err
	}
	for _, dataset := range datasets {
		if dataset == nil || dataset.TenantID != request.TenantID || (request.CandidateID != "" && dataset.CandidateID != request.CandidateID) || dataset.CurrentRevisionID == "" {
			return nil, fmt.Errorf("%w: dataset list identity changed", ErrConflict)
		}
		if _, _, err := s.verifiedEvaluationDatasetSnapshot(ctx, GetPolicyEvaluationDatasetRevisionRequest{
			TenantID: request.TenantID, DatasetID: dataset.ID, RevisionID: dataset.CurrentRevisionID,
		}); err != nil {
			return nil, err
		}
	}
	return datasets, nil
}

func (s Service) GetPolicyEvaluationDatasetRevision(ctx context.Context, request GetPolicyEvaluationDatasetRevisionRequest) (*PolicyEvaluationDatasetRevision, error) {
	if s.Datasets == nil {
		return nil, ErrStoreUnavailable
	}
	request.TenantID, request.DatasetID, request.RevisionID = strings.TrimSpace(request.TenantID), strings.TrimSpace(request.DatasetID), strings.TrimSpace(request.RevisionID)
	if request.TenantID == "" || request.DatasetID == "" || request.RevisionID == "" {
		return nil, fmt.Errorf("%w: tenant id, dataset id, and revision id are required", ErrInvalidRequest)
	}
	revision, _, err := s.verifiedEvaluationDatasetSnapshot(ctx, request)
	return revision, err
}

func (s Service) ListPolicyEvaluationDatasetRevisions(ctx context.Context, request ListPolicyEvaluationDatasetRevisionsRequest) ([]*PolicyEvaluationDatasetRevision, error) {
	if s.Datasets == nil {
		return nil, ErrStoreUnavailable
	}
	request.TenantID, request.DatasetID = strings.TrimSpace(request.TenantID), strings.TrimSpace(request.DatasetID)
	if request.TenantID == "" || request.DatasetID == "" {
		return nil, fmt.Errorf("%w: tenant id and dataset id are required", ErrInvalidRequest)
	}
	if request.Limit == 0 {
		request.Limit = DefaultEvaluationDatasetRevisionListLimit
	}
	if request.Limit < 1 || request.Limit > MaxEvaluationDatasetRevisionListLimit {
		return nil, fmt.Errorf("%w: revision limit must be between 1 and %d", ErrInvalidRequest, MaxEvaluationDatasetRevisionListLimit)
	}
	revisions, err := s.Datasets.ListPolicyEvaluationDatasetRevisions(ctx, request)
	if err != nil {
		return nil, err
	}
	verified := make([]*PolicyEvaluationDatasetRevision, 0, len(revisions))
	for _, revision := range revisions {
		if revision == nil {
			return nil, fmt.Errorf("%w: dataset revision is missing", ErrConflict)
		}
		loaded, _, loadErr := s.verifiedEvaluationDatasetSnapshot(ctx, GetPolicyEvaluationDatasetRevisionRequest{
			TenantID: request.TenantID, DatasetID: request.DatasetID, RevisionID: revision.ID,
		})
		if loadErr != nil {
			return nil, loadErr
		}
		verified = append(verified, loaded)
	}
	return verified, nil
}

func (s Service) ListPolicyEvaluationDatasetCases(ctx context.Context, request ListPolicyEvaluationDatasetCasesRequest) ([]*PolicyEvaluationDatasetCase, error) {
	if s.Datasets == nil {
		return nil, ErrStoreUnavailable
	}
	request.TenantID, request.DatasetID, request.RevisionID = strings.TrimSpace(request.TenantID), strings.TrimSpace(request.DatasetID), strings.TrimSpace(request.RevisionID)
	if request.TenantID == "" || request.DatasetID == "" || request.RevisionID == "" {
		return nil, fmt.Errorf("%w: tenant id, dataset id, and revision id are required", ErrInvalidRequest)
	}
	_, cases, err := s.verifiedEvaluationDatasetSnapshot(ctx, GetPolicyEvaluationDatasetRevisionRequest(request))
	return cases, err
}

func (s Service) verifiedEvaluationDatasetSnapshot(ctx context.Context, request GetPolicyEvaluationDatasetRevisionRequest) (*PolicyEvaluationDatasetRevision, []*PolicyEvaluationDatasetCase, error) {
	snapshot, err := s.Datasets.GetPolicyEvaluationDatasetRevisionSnapshot(ctx, request)
	if err != nil {
		return nil, nil, err
	}
	if snapshot == nil || snapshot.Revision == nil {
		return nil, nil, fmt.Errorf("%w: dataset revision snapshot is missing", ErrConflict)
	}
	revision := snapshot.Revision
	if revision.TenantID != request.TenantID || revision.DatasetID != request.DatasetID || revision.ID != request.RevisionID {
		return nil, nil, fmt.Errorf("%w: dataset revision snapshot identity changed", ErrConflict)
	}
	dataset, err := s.Datasets.GetPolicyEvaluationDataset(ctx, request.TenantID, request.DatasetID)
	if err != nil {
		return nil, nil, err
	}
	if dataset.TenantID != request.TenantID || dataset.ID != request.DatasetID || strings.TrimSpace(dataset.CandidateID) == "" {
		return nil, nil, fmt.Errorf("%w: dataset identity changed", ErrConflict)
	}
	if revision.CaseCount != len(snapshot.Cases) {
		return nil, nil, fmt.Errorf("%w: dataset revision case count changed", ErrConflict)
	}
	seen := make(map[string]struct{}, len(snapshot.Cases))
	for index, testCase := range snapshot.Cases {
		if testCase == nil || testCase.DatasetID != revision.DatasetID || testCase.RevisionID != revision.ID || testCase.Ordinal != index || !evaluationDatasetCaseIDPattern.MatchString(testCase.ID) {
			return nil, nil, fmt.Errorf("%w: dataset revision case identity changed", ErrConflict)
		}
		if _, exists := seen[testCase.ID]; exists {
			return nil, nil, fmt.Errorf("%w: dataset revision contains duplicate cases", ErrConflict)
		}
		seen[testCase.ID] = struct{}{}
		digest, digestErr := DigestPolicyEvaluationDatasetCase(testCase.Test)
		if digestErr != nil || digest != testCase.ContentDigest {
			return nil, nil, fmt.Errorf("%w: dataset revision case digest changed", ErrConflict)
		}
	}
	digest, err := DigestPolicyEvaluationDatasetRevision(dataset.CandidateID, revision.PolicyDigest, revision.SourceTestDigest, snapshot.Cases)
	if err != nil || digest != revision.ContentDigest {
		return nil, nil, fmt.Errorf("%w: dataset revision content digest changed", ErrConflict)
	}
	return revision, snapshot.Cases, nil
}

func DigestPolicyEvaluationDatasetCase(testCase findingdsl.PolicyRuleTestCase) (string, error) {
	normalized, err := normalizeEvaluationDatasetTestCase(testCase)
	if err != nil {
		return "", err
	}
	return canonicalDigest(struct {
		Schema string
		Test   findingdsl.PolicyRuleTestCase
	}{"policy-evaluation-case/v1", normalized})
}

func DigestPolicyEvaluationDatasetRevision(candidateID, policyDigest, sourceTestDigest string, cases []*PolicyEvaluationDatasetCase) (string, error) {
	type casePin struct {
		ID            string
		Ordinal       int
		ContentDigest string
	}
	pins := make([]casePin, len(cases))
	for index, testCase := range cases {
		if testCase == nil {
			return "", fmt.Errorf("%w: dataset case %d is required", ErrInvalidRequest, index)
		}
		pins[index] = casePin{ID: testCase.ID, Ordinal: testCase.Ordinal, ContentDigest: testCase.ContentDigest}
	}
	return canonicalDigest(struct {
		Schema, CandidateID, PolicyDigest, SourceTestDigest string
		Cases                                               []casePin
	}{"policy-evaluation-dataset/v1", strings.TrimSpace(candidateID), strings.TrimSpace(policyDigest), strings.TrimSpace(sourceTestDigest), pins})
}

func buildEvaluationDatasetCases(datasetID, revisionID string, inputs []PolicyEvaluationDatasetCaseInput, requireIDs bool) ([]*PolicyEvaluationDatasetCase, error) {
	if len(inputs) < 1 || len(inputs) > MaxEvaluationDatasetCases {
		return nil, fmt.Errorf("%w: datasets require between 1 and %d cases", ErrInvalidRequest, MaxEvaluationDatasetCases)
	}
	seenIDs := make(map[string]struct{}, len(inputs))
	seenNames := make(map[string]struct{}, len(inputs))
	out := make([]*PolicyEvaluationDatasetCase, len(inputs))
	for index, input := range inputs {
		input.ID = strings.TrimSpace(input.ID)
		if input.ID == "" && !requireIDs {
			input.ID = stableEvaluationDatasetCaseID(input.Test.Name)
		}
		if !evaluationDatasetCaseIDPattern.MatchString(input.ID) {
			return nil, fmt.Errorf("%w: cases[%d].id must be a stable lowercase identifier", ErrInvalidRequest, index)
		}
		if _, exists := seenIDs[input.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate dataset case id %q", ErrInvalidRequest, input.ID)
		}
		seenIDs[input.ID] = struct{}{}
		nameKey := strings.ToLower(strings.TrimSpace(input.Test.Name))
		if _, exists := seenNames[nameKey]; exists {
			return nil, fmt.Errorf("%w: duplicate dataset case name %q", ErrInvalidRequest, input.Test.Name)
		}
		seenNames[nameKey] = struct{}{}
		caseDigest, err := DigestPolicyEvaluationDatasetCase(input.Test)
		if err != nil {
			return nil, err
		}
		out[index] = &PolicyEvaluationDatasetCase{
			ID: input.ID, DatasetID: datasetID, RevisionID: revisionID, Ordinal: index,
			ContentDigest: caseDigest, Test: input.Test,
		}
	}
	return out, nil
}

func normalizeEvaluationDatasetCaseInputs(inputs []PolicyEvaluationDatasetCaseInput) ([]PolicyEvaluationDatasetCaseInput, error) {
	out := make([]PolicyEvaluationDatasetCaseInput, len(inputs))
	for index, input := range inputs {
		input.ID = strings.TrimSpace(input.ID)
		if strings.TrimSpace(input.Test.Name) != input.ID {
			return nil, fmt.Errorf("%w: cases[%d].test.name must equal its synthetic case id", ErrInvalidRequest, index)
		}
		input.Test.Name = input.ID
		normalized, err := normalizeEvaluationDatasetTestCase(input.Test)
		if err != nil {
			return nil, err
		}
		out[index] = PolicyEvaluationDatasetCaseInput{ID: input.ID, Test: normalized}
	}
	return out, nil
}

func normalizeAuthoredEvaluationDatasetTestCase(testCase findingdsl.PolicyRuleTestCase, caseID string) (findingdsl.PolicyRuleTestCase, error) {
	payload, err := json.Marshal(testCase)
	if err != nil {
		return findingdsl.PolicyRuleTestCase{}, fmt.Errorf("%w: encode authored dataset test case: %w", ErrInvalidRequest, err)
	}
	var normalized findingdsl.PolicyRuleTestCase
	if err := json.Unmarshal(payload, &normalized); err != nil {
		return findingdsl.PolicyRuleTestCase{}, fmt.Errorf("%w: decode authored dataset test case: %w", ErrInvalidRequest, err)
	}
	normalized.Name = caseID
	fixture := normalized.GraphFixture
	if fixture == nil {
		return normalizeEvaluationDatasetTestCase(normalized)
	}
	fixture.TenantID = "test"
	urns := make(map[string]string, len(fixture.Nodes))
	for index := range fixture.Nodes {
		node := &fixture.Nodes[index]
		oldURN := strings.TrimSpace(node.URN)
		newURN := fmt.Sprintf("urn:test:node-%d", index+1)
		if oldURN == "" {
			return findingdsl.PolicyRuleTestCase{}, fmt.Errorf("%w: authored dataset fixture node %d has no URN", ErrInvalidRequest, index)
		}
		if _, duplicate := urns[oldURN]; duplicate {
			return findingdsl.PolicyRuleTestCase{}, fmt.Errorf("%w: authored dataset fixture node URNs must be unique", ErrInvalidRequest)
		}
		urns[oldURN] = newURN
		node.URN = newURN
		if strings.TrimSpace(node.RuntimeID) != "" {
			node.RuntimeID = fmt.Sprintf("runtime:test:node-%d", index+1)
		}
		node.Label = fmt.Sprintf("fixture-node-%d", index+1)
		node.Attributes = normalizeAuthoredEvaluationDatasetAttributes(node.Attributes, fmt.Sprintf("node-%d", index+1))
	}
	for index := range fixture.Edges {
		edge := &fixture.Edges[index]
		fromURN, fromOK := urns[strings.TrimSpace(edge.FromURN)]
		toURN, toOK := urns[strings.TrimSpace(edge.ToURN)]
		if !fromOK || !toOK {
			return findingdsl.PolicyRuleTestCase{}, fmt.Errorf("%w: authored dataset fixture edge %d references an unknown node", ErrInvalidRequest, index)
		}
		edge.FromURN, edge.ToURN = fromURN, toURN
		if strings.TrimSpace(edge.RuntimeID) != "" {
			edge.RuntimeID = fmt.Sprintf("runtime:test:edge-%d", index+1)
		}
		edge.Attributes = normalizeAuthoredEvaluationDatasetAttributes(edge.Attributes, fmt.Sprintf("edge-%d", index+1))
	}
	for index, urn := range normalized.WantEvidenceURNs {
		mapped, ok := urns[strings.TrimSpace(urn)]
		if !ok {
			return findingdsl.PolicyRuleTestCase{}, fmt.Errorf("%w: authored dataset evidence URN %d references an unknown node", ErrInvalidRequest, index)
		}
		normalized.WantEvidenceURNs[index] = mapped
	}
	return normalizeEvaluationDatasetTestCase(normalized)
}

func normalizeAuthoredEvaluationDatasetAttributes(attributes map[string]string, token string) map[string]string {
	if len(attributes) == 0 {
		return nil
	}
	out := make(map[string]string, len(attributes))
	for rawKey, rawValue := range attributes {
		key, value := strings.TrimSpace(rawKey), strings.TrimSpace(rawValue)
		if evaluationDatasetAttributeValueAllowed(key, value) {
			out[key] = value
			continue
		}
		out[key] = "fixture-ref-" + token
	}
	return out
}

func normalizeEvaluationDatasetTestCase(testCase findingdsl.PolicyRuleTestCase) (findingdsl.PolicyRuleTestCase, error) {
	payload, err := json.Marshal(testCase)
	if err != nil {
		return findingdsl.PolicyRuleTestCase{}, fmt.Errorf("%w: encode dataset test case: %w", ErrInvalidRequest, err)
	}
	var normalized findingdsl.PolicyRuleTestCase
	if err := json.Unmarshal(payload, &normalized); err != nil {
		return findingdsl.PolicyRuleTestCase{}, fmt.Errorf("%w: decode dataset test case: %w", ErrInvalidRequest, err)
	}
	normalized.Name = strings.TrimSpace(normalized.Name)
	sort.Strings(normalized.WantEvidenceURNs)
	if fixture := normalized.GraphFixture; fixture != nil {
		fixture.TenantID = strings.TrimSpace(fixture.TenantID)
		for index := range fixture.Nodes {
			node := &fixture.Nodes[index]
			node.URN, node.SourceID, node.RuntimeID = strings.TrimSpace(node.URN), strings.TrimSpace(node.SourceID), strings.TrimSpace(node.RuntimeID)
			node.EntityType, node.Label = strings.TrimSpace(node.EntityType), strings.TrimSpace(node.Label)
		}
		for index := range fixture.Edges {
			edge := &fixture.Edges[index]
			edge.FromURN, edge.ToURN, edge.SourceID = strings.TrimSpace(edge.FromURN), strings.TrimSpace(edge.ToURN), strings.TrimSpace(edge.SourceID)
			edge.RuntimeID, edge.Relation = strings.TrimSpace(edge.RuntimeID), strings.TrimSpace(edge.Relation)
		}
		sort.Slice(fixture.Nodes, func(i, j int) bool { return fixture.Nodes[i].URN < fixture.Nodes[j].URN })
		sort.Slice(fixture.Edges, func(i, j int) bool {
			left, right := fixture.Edges[i], fixture.Edges[j]
			return left.FromURN+"\x00"+left.Relation+"\x00"+left.ToURN < right.FromURN+"\x00"+right.Relation+"\x00"+right.ToURN
		})
	}
	if err := validateEvaluationDatasetTestCaseBoundary(normalized, len(payload)); err != nil {
		return findingdsl.PolicyRuleTestCase{}, err
	}
	return normalized, nil
}

func validateEvaluationDatasetTestCaseBoundary(testCase findingdsl.PolicyRuleTestCase, encodedBytes int) error {
	if encodedBytes > maxEvaluationDatasetCaseBytes {
		return fmt.Errorf("%w: dataset case exceeds %d bytes", ErrInvalidRequest, maxEvaluationDatasetCaseBytes)
	}
	if len(testCase.Resource) != 0 || len(testCase.QueryRows) != 0 {
		return fmt.Errorf("%w: durable evaluation cases require a synthetic graph fixture; resource and query rows are not accepted", ErrInvalidRequest)
	}
	if testCase.GraphFixture == nil {
		return fmt.Errorf("%w: durable evaluation cases require a synthetic graph fixture", ErrInvalidRequest)
	}
	if len(testCase.Name) > maxEvaluationDatasetNameBytes || !evaluationDatasetCaseIDPattern.MatchString(testCase.Name) {
		return fmt.Errorf("%w: dataset case name must equal a synthetic case identifier", ErrInvalidRequest)
	}
	fixture := testCase.GraphFixture
	if fixture.TenantID != "fixture" && fixture.TenantID != "test" {
		return fmt.Errorf("%w: dataset graph fixture tenant must be synthetic", ErrInvalidRequest)
	}
	if len(fixture.Nodes) < 1 || len(fixture.Nodes) > maxEvaluationDatasetFixtureNodes || len(fixture.Edges) > maxEvaluationDatasetFixtureEdges {
		return fmt.Errorf("%w: dataset graph fixture exceeds its topology limit", ErrInvalidRequest)
	}
	if len(testCase.WantEvidenceURNs) > maxEvaluationDatasetEvidenceURNs {
		return fmt.Errorf("%w: dataset case has too many evidence URNs", ErrInvalidRequest)
	}
	for _, urn := range testCase.WantEvidenceURNs {
		if !syntheticEvaluationDatasetURNPattern.MatchString(urn) {
			return fmt.Errorf("%w: dataset evidence URNs must use the urn:test or urn:fixture namespace", ErrInvalidRequest)
		}
	}
	for index, node := range fixture.Nodes {
		if !syntheticEvaluationDatasetURNPattern.MatchString(node.URN) {
			return fmt.Errorf("%w: dataset fixture node %d must use a synthetic URN", ErrInvalidRequest, index)
		}
		if err := validateEvaluationDatasetFixtureToken(node.SourceID, "node source"); err != nil {
			return err
		}
		if err := validateEvaluationDatasetFixtureToken(node.EntityType, "node entity type"); err != nil {
			return err
		}
		if err := validateEvaluationDatasetRuntimeID(node.RuntimeID); err != nil {
			return err
		}
		if node.Label != "" && !evaluationDatasetFixtureLabelPattern.MatchString(node.Label) {
			return fmt.Errorf("%w: dataset fixture node labels must use a fixture token", ErrInvalidRequest)
		}
		if err := validateEvaluationDatasetAttributes(node.Attributes); err != nil {
			return err
		}
	}
	for index, edge := range fixture.Edges {
		if !syntheticEvaluationDatasetURNPattern.MatchString(edge.FromURN) || !syntheticEvaluationDatasetURNPattern.MatchString(edge.ToURN) {
			return fmt.Errorf("%w: dataset fixture edge %d must use synthetic URNs", ErrInvalidRequest, index)
		}
		if err := validateEvaluationDatasetFixtureToken(edge.SourceID, "edge source"); err != nil {
			return err
		}
		if err := validateEvaluationDatasetFixtureToken(edge.Relation, "edge relation"); err != nil {
			return err
		}
		if err := validateEvaluationDatasetRuntimeID(edge.RuntimeID); err != nil {
			return err
		}
		if err := validateEvaluationDatasetAttributes(edge.Attributes); err != nil {
			return err
		}
	}
	return nil
}

func validateEvaluationDatasetFixtureToken(value, label string) error {
	value = strings.TrimSpace(value)
	if value == "" || !evaluationDatasetFixtureTokenPattern.MatchString(value) || containsDisallowedEvaluationDatasetScalar(value) {
		return fmt.Errorf("%w: dataset fixture %s must be an identifier-safe topology token", ErrInvalidRequest, label)
	}
	return nil
}

func validateEvaluationDatasetRuntimeID(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if len(value) > 128 || (!strings.HasPrefix(value, "runtime:test:") && !strings.HasPrefix(value, "runtime:fixture:")) {
		return fmt.Errorf("%w: dataset fixture runtime ids must be synthetic", ErrInvalidRequest)
	}
	return nil
}

func validateEvaluationDatasetAttributes(attributes map[string]string) error {
	if len(attributes) > maxEvaluationDatasetFixtureAttributes {
		return fmt.Errorf("%w: dataset fixture has too many attributes", ErrInvalidRequest)
	}
	for key, value := range attributes {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !evaluationDatasetAttributeKeyPattern.MatchString(key) || len(value) > maxEvaluationDatasetFixtureValueBytes || !evaluationDatasetAttributeValueAllowed(key, value) {
			return fmt.Errorf("%w: dataset fixture attributes must use typed synthetic values", ErrInvalidRequest)
		}
	}
	return nil
}

func evaluationDatasetAttributeValueAllowed(key, value string) bool {
	if containsDisallowedEvaluationDatasetScalar(key) || containsDisallowedEvaluationDatasetScalar(value) {
		return false
	}
	if evaluationDatasetFixtureLabelPattern.MatchString(value) {
		return true
	}
	if strings.HasPrefix(key, "has_") {
		return value == "true" || value == "false"
	}
	if strings.HasSuffix(key, "_count") {
		return evaluationDatasetCountValuePattern.MatchString(value)
	}
	switch key {
	case "event_type", "last_status", "observed_last_status", "role_usage", "state", "status":
		return evaluationDatasetEnumValuePattern.MatchString(value) && !looksOpaqueEvaluationDatasetScalar(value)
	default:
		return false
	}
}

func containsDisallowedEvaluationDatasetScalar(value string) bool {
	return containsLiveIdentifier(value) || containsSensitiveEvaluationDatasetValue(value) ||
		evaluationDatasetResourceIDPattern.MatchString(value) || evaluationDatasetUUIDPattern.MatchString(value) || evaluationDatasetIPv4Pattern.MatchString(value) ||
		looksOpaqueEvaluationDatasetScalar(value)
}

func looksOpaqueEvaluationDatasetScalar(value string) bool {
	if len(value) < 20 {
		return false
	}
	var lower, upper, digit bool
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
			lower = true
		case character >= 'A' && character <= 'Z':
			upper = true
		case character >= '0' && character <= '9':
			digit = true
		}
	}
	return lower && upper && digit
}

func containsSensitiveEvaluationDatasetValue(value string) bool {
	normalized := strings.ToLower(value)
	for _, marker := range []string{"password", "secret", "token", "credential", "private_key", "access_key", "-----begin", "akia", "asia", "ghp_", "github_pat_", "xoxb-", "xoxp-", "bearer "} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func validateEvaluationDatasetCandidate(candidate *Candidate) error {
	if candidate == nil {
		return fmt.Errorf("%w: candidate is required", ErrInvalidRequest)
	}
	if candidate.Status != StatusProved && candidate.Status != StatusReadyForReview {
		return fmt.Errorf("%w: candidate status %q cannot author evaluation datasets", ErrConflict, candidate.Status)
	}
	if candidate.Artifacts == nil {
		return fmt.Errorf("%w: candidate has no proved artifacts", ErrConflict)
	}
	if !experimentDigestPattern.MatchString(strings.TrimSpace(candidate.Artifacts.PolicyDigest)) || !experimentDigestPattern.MatchString(strings.TrimSpace(candidate.Artifacts.TestDigest)) {
		return fmt.Errorf("%w: candidate artifact digests are invalid", ErrConflict)
	}
	if issues := findingdsl.ValidatePolicyRuleTestSuiteAgainstRule(candidate.Artifacts.Rule, candidate.Artifacts.Suite); len(issues) != 0 {
		return evaluationDatasetIssuesError(issues)
	}
	return nil
}

func evaluationDatasetIssuesError(issues []findingdsl.Issue) error {
	if len(issues) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s: %s", ErrInvalidRequest, issues[0].Path, issues[0].Message)
}

func normalizeCreatePolicyEvaluationDatasetRequest(request CreatePolicyEvaluationDatasetRequest) CreatePolicyEvaluationDatasetRequest {
	request.TenantID, request.CandidateID = strings.TrimSpace(request.TenantID), strings.TrimSpace(request.CandidateID)
	request.Name = strings.TrimSpace(request.Name)
	request.ChangeSummary, request.ActorID = strings.TrimSpace(request.ChangeSummary), strings.TrimSpace(request.ActorID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	return request
}

func validateCreatePolicyEvaluationDatasetRequest(request CreatePolicyEvaluationDatasetRequest) error {
	if request.TenantID == "" || request.CandidateID == "" || request.Name == "" || request.ChangeSummary == "" || request.ActorID == "" {
		return fmt.Errorf("%w: tenant id, candidate id, name, change summary, and actor id are required", ErrInvalidRequest)
	}
	if len(request.Name) > maxEvaluationDatasetNameBytes || len(request.ChangeSummary) > maxEvaluationDatasetChangeSummaryBytes || len(request.ActorID) > maxEvaluationDatasetActorBytes {
		return fmt.Errorf("%w: dataset labels exceed their size limit", ErrInvalidRequest)
	}
	if containsLiveIdentifier(request.Name) || containsLiveIdentifier(request.ChangeSummary) || containsSensitiveEvaluationDatasetValue(request.Name) || containsSensitiveEvaluationDatasetValue(request.ChangeSummary) {
		return fmt.Errorf("%w: dataset labels must be redacted", ErrInvalidRequest)
	}
	if len(request.IdempotencyKey) > MaxExperimentLabelBytes || !experimentIdempotencyKeyPattern.MatchString(request.IdempotencyKey) {
		return fmt.Errorf("%w: idempotency key is required", ErrInvalidRequest)
	}
	return nil
}

func normalizeAppendPolicyEvaluationDatasetRevisionRequest(request AppendPolicyEvaluationDatasetRevisionRequest) AppendPolicyEvaluationDatasetRevisionRequest {
	request.TenantID, request.DatasetID = strings.TrimSpace(request.TenantID), strings.TrimSpace(request.DatasetID)
	request.ChangeSummary, request.ActorID = strings.TrimSpace(request.ChangeSummary), strings.TrimSpace(request.ActorID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	return request
}

func validateAppendPolicyEvaluationDatasetRevisionRequest(request AppendPolicyEvaluationDatasetRevisionRequest) error {
	if request.TenantID == "" || request.DatasetID == "" || request.ExpectedVersion == 0 || request.ChangeSummary == "" || request.ActorID == "" {
		return fmt.Errorf("%w: tenant id, dataset id, expected version, change summary, and actor id are required", ErrInvalidRequest)
	}
	if len(request.ChangeSummary) > maxEvaluationDatasetChangeSummaryBytes || len(request.ActorID) > maxEvaluationDatasetActorBytes {
		return fmt.Errorf("%w: revision labels exceed their size limit", ErrInvalidRequest)
	}
	if containsLiveIdentifier(request.ChangeSummary) || containsSensitiveEvaluationDatasetValue(request.ChangeSummary) {
		return fmt.Errorf("%w: revision labels must be redacted", ErrInvalidRequest)
	}
	if len(request.IdempotencyKey) > MaxExperimentLabelBytes || !experimentIdempotencyKeyPattern.MatchString(request.IdempotencyKey) {
		return fmt.Errorf("%w: idempotency key is required", ErrInvalidRequest)
	}
	if len(request.Cases) < 1 || len(request.Cases) > MaxEvaluationDatasetCases {
		return fmt.Errorf("%w: datasets require between 1 and %d cases", ErrInvalidRequest, MaxEvaluationDatasetCases)
	}
	return nil
}

func stableEvaluationDatasetCaseID(name string) string {
	hash := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(name))))
	return "case_" + hex.EncodeToString(hash[:12])
}

func deterministicEvaluationDatasetID(tenantID, candidateID, idempotencyKey string) string {
	return deterministicEvaluationDatasetResourceID("ped_", tenantID, candidateID, idempotencyKey)
}

func deterministicEvaluationDatasetRevisionID(tenantID, datasetID, idempotencyKey string) string {
	return deterministicEvaluationDatasetResourceID("pedr_", tenantID, datasetID, idempotencyKey)
}

func deterministicEvaluationDatasetResourceID(prefix string, parts ...string) string {
	hash := sha256.New()
	hash.Write([]byte(strings.Join(parts, "\x00")))
	return prefix + hex.EncodeToString(hash.Sum(nil)[:16])
}

func canonicalDigest(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(payload)
	return hex.EncodeToString(hash[:]), nil
}
