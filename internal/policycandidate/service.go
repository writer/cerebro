package policycandidate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/agentauthoring"
	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/graphagent"
	"github.com/writer/cerebro/internal/ports"
	policyauthor "github.com/writer/cerebro/internal/testauthor/policy"
)

var domainPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var accountIDPattern = regexp.MustCompile(`(^|[^0-9])[0-9]{12}([^0-9]|$)`)

type Service struct {
	Store       Store
	Experiments ExperimentStore
	Author      *agentauthoring.Service
	Graph       ports.GraphQueryStore
	Catalog     CoverageCatalog
	Now         func() time.Time
}

func (s Service) Create(ctx context.Context, request CreateRequest) (*Candidate, error) {
	if s.Store == nil {
		return nil, ErrStoreUnavailable
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.Hypothesis = strings.TrimSpace(request.Hypothesis)
	request.Domain = strings.TrimSpace(request.Domain)
	request.Origin.Kind = strings.TrimSpace(request.Origin.Kind)
	request.Origin.ExternalRef = strings.TrimSpace(request.Origin.ExternalRef)
	if request.TenantID == "" || request.Hypothesis == "" || !domainPattern.MatchString(request.Domain) {
		return nil, fmt.Errorf("%w: tenant_id, hypothesis, and lowercase dash-separated domain are required", ErrInvalidRequest)
	}
	if request.Origin.Kind == "" || request.Origin.ExternalRef == "" {
		return nil, fmt.Errorf("%w: origin.kind and origin.external_ref are required", ErrInvalidRequest)
	}
	if request.GraphEvidence == nil {
		return nil, fmt.Errorf("%w: graph_evidence is required for a grounded policy candidate", ErrInvalidRequest)
	}
	if _, err := policyauthor.GraphEvidenceModelContext(*request.GraphEvidence); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	if len(request.Hypothesis) > 4000 {
		return nil, fmt.Errorf("%w: hypothesis exceeds 4000 bytes", ErrInvalidRequest)
	}
	if containsLiveIdentifier(request.Hypothesis) {
		return nil, fmt.Errorf("%w: hypothesis must be redacted before authoring", ErrInvalidRequest)
	}
	grounding, err := groundGraphEvidence(ctx, s.Graph, request.TenantID, *request.GraphEvidence, request.Grounding, s.now)
	if err != nil {
		return nil, err
	}
	coverageGap, err := verifyCoverageGap(ctx, s.Catalog, request.TenantID, *request.GraphEvidence, s.now)
	if err != nil {
		return nil, err
	}
	now := s.now()
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("create policy candidate id: %w", err)
	}
	candidate := &Candidate{
		ID: id, TenantID: request.TenantID, Status: StatusGrounded, Revision: 1,
		Hypothesis: request.Hypothesis, Domain: request.Domain, Origin: request.Origin,
		GraphEvidence: request.GraphEvidence,
		Grounding:     grounding,
		CoverageGap:   coverageGap,
		CreatedAt:     now, UpdatedAt: now,
	}
	if err := s.Store.CreatePolicyCandidate(ctx, candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}

func (s Service) Get(ctx context.Context, id string) (*Candidate, error) {
	if s.Store == nil {
		return nil, ErrStoreUnavailable
	}
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("%w: candidate id is required", ErrInvalidRequest)
	}
	return s.Store.GetPolicyCandidate(ctx, strings.TrimSpace(id))
}

func (s Service) List(ctx context.Context, request ListRequest) ([]*Candidate, error) {
	if s.Store == nil {
		return nil, ErrStoreUnavailable
	}
	request.TenantID = strings.TrimSpace(request.TenantID)
	request.Status = strings.TrimSpace(request.Status)
	if request.TenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	if request.Status != "" && !validStatus(request.Status) {
		return nil, fmt.Errorf("%w: unknown status %q", ErrInvalidRequest, request.Status)
	}
	if request.Limit == 0 {
		request.Limit = DefaultListLimit
	}
	if request.Limit < 1 || request.Limit > MaxListLimit {
		return nil, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidRequest, MaxListLimit)
	}
	return s.Store.ListPolicyCandidates(ctx, request)
}

func (s Service) Prove(ctx context.Context, id string) (*Candidate, error) {
	candidate, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if candidate.Status != StatusGrounded && candidate.Status != StatusBlocked {
		return nil, fmt.Errorf("%w: candidate status %q cannot be proved", ErrConflict, candidate.Status)
	}
	if s.Author == nil {
		return nil, ErrAuthorUnavailable
	}
	if candidate.Grounding == nil || candidate.Grounding.Execution != "graph_store" || candidate.Grounding.NodeCount == 0 || candidate.Grounding.EdgeCount == 0 {
		return nil, fmt.Errorf("%w: candidate has no current graph grounding receipt", ErrConflict)
	}
	if candidate.GraphEvidence == nil {
		return nil, fmt.Errorf("%w: candidate has no grounded evidence", ErrConflict)
	}
	coverageGap, err := verifyCoverageGap(ctx, s.Catalog, candidate.TenantID, *candidate.GraphEvidence, s.now)
	if err != nil {
		return nil, err
	}
	if coverageGap == nil || coverageGap.Execution != "finding_rule_catalog" {
		return nil, fmt.Errorf("%w: candidate has no current coverage-gap receipt", ErrConflict)
	}
	candidate.CoverageGap = coverageGap
	result, err := s.Author.DraftPolicyBundle(ctx, agentauthoring.PolicyBundleDraftRequest{
		Prompt: candidate.Hypothesis, TenantID: candidate.TenantID, Domain: candidate.Domain, GraphEvidence: candidate.GraphEvidence,
	})
	if err != nil {
		return nil, err
	}
	policyDigest := digest(result.PolicyYAML)
	testDigest := digest(result.TestYAML)
	candidate.Artifacts = &Artifacts{
		Rule: result.Rule, PolicyPath: result.PolicyPath, PolicyYAML: string(result.PolicyYAML), PolicyDigest: policyDigest,
		Suite: result.Suite, TestPath: result.TestPath, TestYAML: string(result.TestYAML), TestDigest: testDigest,
	}
	candidate.Proof = &result.Proof
	candidate.Status = StatusProved
	candidate.PRReady = false
	return s.save(ctx, candidate)
}

func (s Service) Shadow(ctx context.Context, id string) (*Candidate, error) {
	candidate, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if candidate.Status != StatusProved && candidate.Status != StatusReadyForReview {
		return nil, fmt.Errorf("%w: candidate status %q cannot shadow", ErrConflict, candidate.Status)
	}
	if s.Graph == nil {
		return nil, ErrGraphUnavailable
	}
	if candidate.Artifacts == nil || candidate.Proof == nil {
		return nil, fmt.Errorf("%w: candidate has no proved artifacts", ErrConflict)
	}
	if candidate.GraphEvidence == nil {
		return nil, fmt.Errorf("%w: candidate has no grounded evidence", ErrConflict)
	}
	coverageGap, err := verifyCoverageGap(ctx, s.Catalog, candidate.TenantID, *candidate.GraphEvidence, s.now)
	if err != nil {
		return nil, err
	}
	if coverageGap == nil || coverageGap.Execution != "finding_rule_catalog" {
		return nil, fmt.Errorf("%w: candidate has no current coverage-gap receipt", ErrConflict)
	}
	candidate.CoverageGap = coverageGap
	rule := candidate.Artifacts.Rule
	if issues := findingdsl.ValidatePolicyRule(rule); len(issues) != 0 {
		return nil, fmt.Errorf("%w: stored rule is invalid", ErrConflict)
	}
	params := cloneMap(rule.Spec.Graph.Params)
	if params == nil {
		params = map[string]any{}
	}
	params["tenant_id"] = candidate.TenantID
	evaluationLimit := rule.Spec.Graph.RowLimit
	if evaluationLimit <= 0 || evaluationLimit > MaxShadowRows {
		evaluationLimit = MaxShadowRows
	}
	fetchLimit := evaluationLimit + 1
	params["row_limit"] = fetchLimit
	validation, _, err := graphagent.ValidateRuntimeBoundReadCypher(ctx, rule.Spec.Graph.Query, fetchLimit)
	if err != nil {
		return nil, fmt.Errorf("%w: validate stored graph query: %w", ErrConflict, err)
	}
	if !validation.OK {
		return nil, fmt.Errorf("%w: stored graph query refused (%s): %s", ErrConflict, validation.Code, validation.Reason)
	}
	rows, err := s.Graph.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: rule.Spec.Graph.Query, Params: params, RowLimit: fetchLimit})
	if err != nil {
		return nil, err
	}
	receiptID, err := newID()
	if err != nil {
		return nil, fmt.Errorf("create shadow receipt id: %w", err)
	}
	matchCount := len(rows)
	if matchCount > evaluationLimit {
		matchCount = evaluationLimit
	}
	candidate.Shadow = &ShadowReceipt{
		Execution: "graph_store", MatchCount: matchCount, Truncated: len(rows) > evaluationLimit,
		ReceiptID: "shadow_" + strings.TrimPrefix(receiptID, "pc_"), ObservedAt: s.now(),
	}
	if candidate.Shadow.MatchCount == 0 || candidate.Shadow.Truncated {
		candidate.Status = StatusProved
		candidate.PRReady = false
		return s.save(ctx, candidate)
	}
	candidate.Status = StatusReadyForReview
	candidate.PRReady = true
	return s.save(ctx, candidate)
}

func (s Service) save(ctx context.Context, candidate *Candidate) (*Candidate, error) {
	expected := candidate.Revision
	candidate.Revision++
	candidate.UpdatedAt = s.now()
	if err := s.Store.SavePolicyCandidate(ctx, candidate, expected); err != nil {
		candidate.Revision = expected
		return nil, err
	}
	return candidate, nil
}

func (s Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func validStatus(status string) bool {
	switch status {
	case StatusGrounded, StatusProved, StatusReadyForReview, StatusBlocked:
		return true
	default:
		return false
	}
}

func newID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "pc_" + hex.EncodeToString(value[:]), nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func containsLiveIdentifier(value string) bool {
	normalized := strings.ToLower(value)
	return strings.Contains(normalized, "arn:aws") || strings.Contains(normalized, "https://") ||
		strings.Contains(normalized, "http://") || strings.Contains(normalized, "@") || accountIDPattern.MatchString(normalized)
}
