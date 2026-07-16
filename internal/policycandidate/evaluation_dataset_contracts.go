package policycandidate

import (
	"context"
	"time"

	"github.com/writer/cerebro/internal/findingdsl"
)

const (
	DefaultEvaluationDatasetListLimit         = 25
	MaxEvaluationDatasetListLimit             = 100
	DefaultEvaluationDatasetRevisionListLimit = 25
	MaxEvaluationDatasetRevisionListLimit     = 100
	MaxEvaluationDatasetCases                 = 100
)

// PolicyEvaluationDataset is the mutable identity and current-revision pointer
// for an immutable sequence of policy evaluation snapshots.
type PolicyEvaluationDataset struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	CandidateID       string    `json:"candidate_id"`
	Name              string    `json:"name"`
	CurrentRevisionID string    `json:"current_revision_id"`
	AggregateVersion  uint64    `json:"aggregate_version"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	CreateRequestHash string    `json:"-"`
}

// PolicyEvaluationDatasetRevision is one immutable, reproducible snapshot.
// PolicyDigest and SourceTestDigest pin the candidate artifacts used to
// validate the snapshot; ContentDigest covers the ordered case contents.
type PolicyEvaluationDatasetRevision struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	DatasetID        string    `json:"dataset_id"`
	Version          uint64    `json:"version"`
	PredecessorID    string    `json:"predecessor_id,omitempty"`
	PolicyDigest     string    `json:"policy_digest"`
	SourceTestDigest string    `json:"source_test_digest"`
	ContentDigest    string    `json:"content_digest"`
	CaseCount        int       `json:"case_count"`
	ChangeSummary    string    `json:"change_summary"`
	CreatedBy        string    `json:"created_by"`
	CreatedAt        time.Time `json:"created_at"`
	RequestHash      string    `json:"-"`
}

// PolicyEvaluationDatasetCase belongs to exactly one immutable revision.
// ID is stable across revisions when the logical case is retained.
type PolicyEvaluationDatasetCase struct {
	ID            string                        `json:"id"`
	DatasetID     string                        `json:"dataset_id"`
	RevisionID    string                        `json:"revision_id"`
	Ordinal       int                           `json:"ordinal"`
	ContentDigest string                        `json:"content_digest"`
	Test          findingdsl.PolicyRuleTestCase `json:"test"`
}

type PolicyEvaluationDatasetCaseInput struct {
	ID   string                        `json:"id"`
	Test findingdsl.PolicyRuleTestCase `json:"test"`
}

type CreatePolicyEvaluationDatasetRequest struct {
	CandidateID    string `json:"candidate_id"`
	Name           string `json:"name"`
	ChangeSummary  string `json:"change_summary"`
	ActorID        string `json:"actor_id"`
	IdempotencyKey string `json:"idempotency_key"`
}

type AppendPolicyEvaluationDatasetRevisionRequest struct {
	TenantID        string                             `json:"tenant_id"`
	DatasetID       string                             `json:"dataset_id"`
	ExpectedVersion uint64                             `json:"expected_version"`
	ChangeSummary   string                             `json:"change_summary"`
	ActorID         string                             `json:"actor_id"`
	IdempotencyKey  string                             `json:"idempotency_key"`
	Cases           []PolicyEvaluationDatasetCaseInput `json:"cases"`
}

type PolicyEvaluationDatasetResult struct {
	Dataset  *PolicyEvaluationDataset         `json:"dataset"`
	Revision *PolicyEvaluationDatasetRevision `json:"revision"`
}

type ListPolicyEvaluationDatasetsRequest struct {
	TenantID    string
	CandidateID string
	Limit       int
}

type GetPolicyEvaluationDatasetRevisionRequest struct {
	TenantID   string
	DatasetID  string
	RevisionID string
}

type ListPolicyEvaluationDatasetRevisionsRequest struct {
	TenantID  string
	DatasetID string
	Limit     int
}

type ListPolicyEvaluationDatasetCasesRequest struct {
	TenantID   string
	DatasetID  string
	RevisionID string
}

// CreatePolicyEvaluationDatasetRecord and
// AppendPolicyEvaluationDatasetRevisionRecord are atomic store commands.
// Implementations must enforce the request hashes and append CAS transactionally.
type CreatePolicyEvaluationDatasetRecord struct {
	Dataset        *PolicyEvaluationDataset
	Revision       *PolicyEvaluationDatasetRevision
	Cases          []*PolicyEvaluationDatasetCase
	IdempotencyKey string
}

type AppendPolicyEvaluationDatasetRevisionRecord struct {
	Dataset         *PolicyEvaluationDataset
	Revision        *PolicyEvaluationDatasetRevision
	Cases           []*PolicyEvaluationDatasetCase
	ExpectedVersion uint64
	IdempotencyKey  string
}

type PolicyEvaluationDatasetStore interface {
	CreatePolicyEvaluationDataset(context.Context, CreatePolicyEvaluationDatasetRecord) (*PolicyEvaluationDataset, *PolicyEvaluationDatasetRevision, error)
	GetPolicyEvaluationDataset(context.Context, string, string) (*PolicyEvaluationDataset, error)
	ListPolicyEvaluationDatasets(context.Context, ListPolicyEvaluationDatasetsRequest) ([]*PolicyEvaluationDataset, error)
	AppendPolicyEvaluationDatasetRevision(context.Context, AppendPolicyEvaluationDatasetRevisionRecord) (*PolicyEvaluationDataset, *PolicyEvaluationDatasetRevision, error)
	GetPolicyEvaluationDatasetRevision(context.Context, GetPolicyEvaluationDatasetRevisionRequest) (*PolicyEvaluationDatasetRevision, error)
	ListPolicyEvaluationDatasetRevisions(context.Context, ListPolicyEvaluationDatasetRevisionsRequest) ([]*PolicyEvaluationDatasetRevision, error)
	ListPolicyEvaluationDatasetCases(context.Context, ListPolicyEvaluationDatasetCasesRequest) ([]*PolicyEvaluationDatasetCase, error)
}
