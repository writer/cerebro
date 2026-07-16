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
)

var evaluationDatasetCaseIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)

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
	requestHash, err := canonicalDigest(struct {
		Schema, CandidateID, Name, ChangeSummary, ActorID, IdempotencyKey string
	}{"policy-evaluation-dataset-create/v1", request.CandidateID, request.Name, request.ChangeSummary, request.ActorID, request.IdempotencyKey})
	if err != nil {
		return nil, fmt.Errorf("digest policy evaluation dataset request: %w", err)
	}
	datasetID := deterministicEvaluationDatasetID(candidate.TenantID, candidate.ID, request.IdempotencyKey)
	revisionID := deterministicEvaluationDatasetRevisionID(candidate.TenantID, datasetID, request.IdempotencyKey)
	if existing, getErr := s.Datasets.GetPolicyEvaluationDataset(ctx, candidate.TenantID, datasetID); getErr == nil {
		if existing.CreateRequestHash != requestHash {
			return nil, fmt.Errorf("%w: idempotency key was already used for a different dataset request", ErrConflict)
		}
		revision, revisionErr := s.Datasets.GetPolicyEvaluationDatasetRevision(ctx, GetPolicyEvaluationDatasetRevisionRequest{
			TenantID: candidate.TenantID, DatasetID: datasetID, RevisionID: revisionID,
		})
		if revisionErr != nil {
			return nil, revisionErr
		}
		return &PolicyEvaluationDatasetResult{Dataset: datasetAtRevision(existing, revision), Revision: revision}, nil
	} else if !errors.Is(getErr, ErrNotFound) {
		return nil, getErr
	}
	if err := validateEvaluationDatasetCandidate(candidate); err != nil {
		return nil, err
	}
	inputs := make([]PolicyEvaluationDatasetCaseInput, len(candidate.Artifacts.Suite.Cases))
	for index, testCase := range candidate.Artifacts.Suite.Cases {
		normalized, normalizeErr := normalizeEvaluationDatasetTestCase(testCase)
		if normalizeErr != nil {
			return nil, normalizeErr
		}
		inputs[index] = PolicyEvaluationDatasetCaseInput{ID: stableEvaluationDatasetCaseID(normalized.Name), Test: normalized}
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
	if existing, getErr := s.Datasets.GetPolicyEvaluationDatasetRevision(ctx, GetPolicyEvaluationDatasetRevisionRequest{
		TenantID: dataset.TenantID, DatasetID: dataset.ID, RevisionID: revisionID,
	}); getErr == nil {
		if existing.RequestHash != requestHash {
			return nil, fmt.Errorf("%w: idempotency key was already used for a different revision request", ErrConflict)
		}
		return &PolicyEvaluationDatasetResult{Dataset: datasetAtRevision(dataset, existing), Revision: existing}, nil
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
	predecessor, err := s.Datasets.GetPolicyEvaluationDatasetRevision(ctx, GetPolicyEvaluationDatasetRevisionRequest{
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
	return s.Datasets.GetPolicyEvaluationDataset(ctx, tenantID, datasetID)
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
	return s.Datasets.ListPolicyEvaluationDatasets(ctx, request)
}

func (s Service) GetPolicyEvaluationDatasetRevision(ctx context.Context, request GetPolicyEvaluationDatasetRevisionRequest) (*PolicyEvaluationDatasetRevision, error) {
	if s.Datasets == nil {
		return nil, ErrStoreUnavailable
	}
	request.TenantID, request.DatasetID, request.RevisionID = strings.TrimSpace(request.TenantID), strings.TrimSpace(request.DatasetID), strings.TrimSpace(request.RevisionID)
	if request.TenantID == "" || request.DatasetID == "" || request.RevisionID == "" {
		return nil, fmt.Errorf("%w: tenant id, dataset id, and revision id are required", ErrInvalidRequest)
	}
	return s.Datasets.GetPolicyEvaluationDatasetRevision(ctx, request)
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
	return s.Datasets.ListPolicyEvaluationDatasetRevisions(ctx, request)
}

func (s Service) ListPolicyEvaluationDatasetCases(ctx context.Context, request ListPolicyEvaluationDatasetCasesRequest) ([]*PolicyEvaluationDatasetCase, error) {
	if s.Datasets == nil {
		return nil, ErrStoreUnavailable
	}
	request.TenantID, request.DatasetID, request.RevisionID = strings.TrimSpace(request.TenantID), strings.TrimSpace(request.DatasetID), strings.TrimSpace(request.RevisionID)
	if request.TenantID == "" || request.DatasetID == "" || request.RevisionID == "" {
		return nil, fmt.Errorf("%w: tenant id, dataset id, and revision id are required", ErrInvalidRequest)
	}
	return s.Datasets.ListPolicyEvaluationDatasetCases(ctx, request)
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
		normalized, err := normalizeEvaluationDatasetTestCase(input.Test)
		if err != nil {
			return nil, err
		}
		out[index] = PolicyEvaluationDatasetCaseInput{ID: strings.TrimSpace(input.ID), Test: normalized}
	}
	return out, nil
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
	return normalized, nil
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
	request.CandidateID, request.Name = strings.TrimSpace(request.CandidateID), strings.TrimSpace(request.Name)
	request.ChangeSummary, request.ActorID = strings.TrimSpace(request.ChangeSummary), strings.TrimSpace(request.ActorID)
	request.IdempotencyKey = strings.TrimSpace(request.IdempotencyKey)
	return request
}

func validateCreatePolicyEvaluationDatasetRequest(request CreatePolicyEvaluationDatasetRequest) error {
	if request.CandidateID == "" || request.Name == "" || request.ChangeSummary == "" || request.ActorID == "" {
		return fmt.Errorf("%w: candidate id, name, change summary, and actor id are required", ErrInvalidRequest)
	}
	if len(request.Name) > maxEvaluationDatasetNameBytes || len(request.ChangeSummary) > maxEvaluationDatasetChangeSummaryBytes || len(request.ActorID) > maxEvaluationDatasetActorBytes {
		return fmt.Errorf("%w: dataset labels exceed their size limit", ErrInvalidRequest)
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

func datasetAtRevision(dataset *PolicyEvaluationDataset, revision *PolicyEvaluationDatasetRevision) *PolicyEvaluationDataset {
	if dataset == nil || revision == nil {
		return dataset
	}
	cloned := *dataset
	cloned.CurrentRevisionID = revision.ID
	cloned.AggregateVersion = revision.Version
	cloned.UpdatedAt = revision.CreatedAt
	return &cloned
}
