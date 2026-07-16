package policyevaluationdatasets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/findingdsl"
	"github.com/writer/cerebro/internal/policycandidate"
)

const maxBodyBytes = 1 << 20

type TenantResolver func(context.Context, string) (string, error)
type TenantAuthorizer func(context.Context, string) error
type ActorResolver func(context.Context) string
type ErrorWriter func(http.ResponseWriter, error)

type Handler struct {
	service   policycandidate.Service
	resolve   TenantResolver
	authorize TenantAuthorizer
	actor     ActorResolver
	writeErr  ErrorWriter
}

func NewHandler(service policycandidate.Service, resolve TenantResolver, authorize TenantAuthorizer, actor ActorResolver, writeErr ErrorWriter) *Handler {
	return &Handler{service: service, resolve: resolve, authorize: authorize, actor: actor, writeErr: writeErr}
}

type createRequest struct {
	Name          string `json:"name"`
	ChangeSummary string `json:"change_summary"`
}

type appendRevisionRequest struct {
	ExpectedVersion uint64                                             `json:"expected_version"`
	ChangeSummary   string                                             `json:"change_summary"`
	Cases           []policycandidate.PolicyEvaluationDatasetCaseInput `json:"cases"`
}

type DatasetView struct {
	ID                string    `json:"id"`
	CandidateID       string    `json:"candidate_id"`
	Name              string    `json:"name"`
	CurrentRevisionID string    `json:"current_revision_id"`
	AggregateVersion  uint64    `json:"aggregate_version"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type RevisionView struct {
	ID               string    `json:"id"`
	DatasetID        string    `json:"dataset_id"`
	Version          uint64    `json:"version"`
	PredecessorID    string    `json:"predecessor_id,omitempty"`
	PolicyDigest     string    `json:"policy_digest"`
	SourceTestDigest string    `json:"source_test_digest"`
	ContentDigest    string    `json:"content_digest"`
	CaseCount        int       `json:"case_count"`
	ChangeSummary    string    `json:"change_summary"`
	CreatedAt        time.Time `json:"created_at"`
}

type CaseView struct {
	ID            string                        `json:"id"`
	DatasetID     string                        `json:"dataset_id"`
	RevisionID    string                        `json:"revision_id"`
	Ordinal       int                           `json:"ordinal"`
	ContentDigest string                        `json:"content_digest"`
	Test          findingdsl.PolicyRuleTestCase `json:"test"`
}

type ResultView struct {
	Dataset  DatasetView  `json:"dataset"`
	Revision RevisionView `json:"revision"`
}

type DatasetResponse struct {
	Dataset DatasetView `json:"dataset"`
}

type DatasetListResponse struct {
	Datasets []DatasetView `json:"datasets"`
}

type RevisionResponse struct {
	Revision RevisionView `json:"revision"`
}

type RevisionListResponse struct {
	Revisions []RevisionView `json:"revisions"`
}

type CaseListResponse struct {
	Cases []CaseView `json:"cases"`
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	candidate, err := h.authorizedCandidate(r, r.PathValue("candidateID"))
	if err != nil {
		h.error(w, err)
		return
	}
	var request createRequest
	if err := decodeRequest(w, r, &request); err != nil {
		h.error(w, err)
		return
	}
	result, err := h.service.CreatePolicyEvaluationDataset(r.Context(), policycandidate.CreatePolicyEvaluationDatasetRequest{
		TenantID: candidate.TenantID, CandidateID: candidate.ID, Name: request.Name, ChangeSummary: request.ChangeSummary,
		ActorID: h.actor(r.Context()), IdempotencyKey: r.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		h.error(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, newResultView(result))
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	candidate, err := h.authorizedCandidate(r, r.PathValue("candidateID"))
	if err != nil {
		h.error(w, err)
		return
	}
	limit, err := listLimit(r)
	if err != nil {
		h.error(w, err)
		return
	}
	datasets, err := h.service.ListPolicyEvaluationDatasets(r.Context(), policycandidate.ListPolicyEvaluationDatasetsRequest{
		TenantID: candidate.TenantID, CandidateID: candidate.ID, Limit: limit,
	})
	if err != nil {
		h.error(w, err)
		return
	}
	views := make([]DatasetView, 0, len(datasets))
	for _, dataset := range datasets {
		views = append(views, newDatasetView(dataset))
	}
	writeJSON(w, http.StatusOK, DatasetListResponse{Datasets: views})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	dataset, err := h.datasetFromRequest(r)
	if err != nil {
		h.error(w, err)
		return
	}
	writeJSON(w, http.StatusOK, DatasetResponse{Dataset: newDatasetView(dataset)})
}

func (h *Handler) AppendRevision(w http.ResponseWriter, r *http.Request) {
	dataset, err := h.datasetFromRequest(r)
	if err != nil {
		h.error(w, err)
		return
	}
	var request appendRevisionRequest
	if err := decodeRequest(w, r, &request); err != nil {
		h.error(w, err)
		return
	}
	result, err := h.service.AppendPolicyEvaluationDatasetRevision(r.Context(), policycandidate.AppendPolicyEvaluationDatasetRevisionRequest{
		TenantID: dataset.TenantID, DatasetID: dataset.ID, ExpectedVersion: request.ExpectedVersion,
		ChangeSummary: request.ChangeSummary, ActorID: h.actor(r.Context()),
		IdempotencyKey: r.Header.Get("Idempotency-Key"), Cases: request.Cases,
	})
	if err != nil {
		h.error(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, newResultView(result))
}

func (h *Handler) ListRevisions(w http.ResponseWriter, r *http.Request) {
	dataset, err := h.datasetFromRequest(r)
	if err != nil {
		h.error(w, err)
		return
	}
	limit, err := listLimit(r)
	if err != nil {
		h.error(w, err)
		return
	}
	revisions, err := h.service.ListPolicyEvaluationDatasetRevisions(r.Context(), policycandidate.ListPolicyEvaluationDatasetRevisionsRequest{
		TenantID: dataset.TenantID, DatasetID: dataset.ID, Limit: limit,
	})
	if err != nil {
		h.error(w, err)
		return
	}
	views := make([]RevisionView, 0, len(revisions))
	for _, revision := range revisions {
		views = append(views, newRevisionView(revision))
	}
	writeJSON(w, http.StatusOK, RevisionListResponse{Revisions: views})
}

func (h *Handler) GetRevision(w http.ResponseWriter, r *http.Request) {
	dataset, err := h.datasetFromRequest(r)
	if err != nil {
		h.error(w, err)
		return
	}
	revision, err := h.service.GetPolicyEvaluationDatasetRevision(r.Context(), policycandidate.GetPolicyEvaluationDatasetRevisionRequest{
		TenantID: dataset.TenantID, DatasetID: dataset.ID, RevisionID: r.PathValue("revisionID"),
	})
	if err != nil {
		h.error(w, err)
		return
	}
	writeJSON(w, http.StatusOK, RevisionResponse{Revision: newRevisionView(revision)})
}

func (h *Handler) ListCases(w http.ResponseWriter, r *http.Request) {
	dataset, err := h.datasetFromRequest(r)
	if err != nil {
		h.error(w, err)
		return
	}
	cases, err := h.service.ListPolicyEvaluationDatasetCases(r.Context(), policycandidate.ListPolicyEvaluationDatasetCasesRequest{
		TenantID: dataset.TenantID, DatasetID: dataset.ID, RevisionID: r.PathValue("revisionID"),
	})
	if err != nil {
		h.error(w, err)
		return
	}
	views := make([]CaseView, 0, len(cases))
	for _, testCase := range cases {
		views = append(views, newCaseView(testCase))
	}
	writeJSON(w, http.StatusOK, CaseListResponse{Cases: views})
}

func (h *Handler) authorizedCandidate(r *http.Request, candidateID string) (*policycandidate.Candidate, error) {
	candidate, err := h.service.Get(r.Context(), strings.TrimSpace(candidateID))
	if err != nil {
		return nil, err
	}
	if err := h.authorize(r.Context(), candidate.TenantID); err != nil {
		return nil, err
	}
	return candidate, nil
}

func (h *Handler) datasetFromRequest(r *http.Request) (*policycandidate.PolicyEvaluationDataset, error) {
	tenantID, err := h.resolve(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		return nil, err
	}
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", policycandidate.ErrInvalidRequest)
	}
	return h.service.GetPolicyEvaluationDataset(r.Context(), tenantID, r.PathValue("datasetID"))
}

func (h *Handler) error(w http.ResponseWriter, err error) {
	if h.writeErr != nil {
		h.writeErr(w, err)
		return
	}
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func decodeRequest(w http.ResponseWriter, r *http.Request, destination any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: decode request: %w", policycandidate.ErrInvalidRequest, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: request body must contain one JSON value", policycandidate.ErrInvalidRequest)
	}
	return nil
}

func listLimit(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("limit"))
	if raw == "" {
		return 0, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: limit must be an integer", policycandidate.ErrInvalidRequest)
	}
	return limit, nil
}

func newResultView(result *policycandidate.PolicyEvaluationDatasetResult) ResultView {
	if result == nil {
		return ResultView{}
	}
	return ResultView{Dataset: newDatasetView(result.Dataset), Revision: newRevisionView(result.Revision)}
}

func newDatasetView(dataset *policycandidate.PolicyEvaluationDataset) DatasetView {
	if dataset == nil {
		return DatasetView{}
	}
	return DatasetView{
		ID: dataset.ID, CandidateID: dataset.CandidateID, Name: dataset.Name,
		CurrentRevisionID: dataset.CurrentRevisionID, AggregateVersion: dataset.AggregateVersion,
		CreatedAt: dataset.CreatedAt, UpdatedAt: dataset.UpdatedAt,
	}
}

func newRevisionView(revision *policycandidate.PolicyEvaluationDatasetRevision) RevisionView {
	if revision == nil {
		return RevisionView{}
	}
	return RevisionView{
		ID: revision.ID, DatasetID: revision.DatasetID, Version: revision.Version, PredecessorID: revision.PredecessorID,
		PolicyDigest: revision.PolicyDigest, SourceTestDigest: revision.SourceTestDigest, ContentDigest: revision.ContentDigest,
		CaseCount: revision.CaseCount, ChangeSummary: revision.ChangeSummary, CreatedAt: revision.CreatedAt,
	}
}

func newCaseView(testCase *policycandidate.PolicyEvaluationDatasetCase) CaseView {
	if testCase == nil {
		return CaseView{}
	}
	return CaseView{
		ID: testCase.ID, DatasetID: testCase.DatasetID, RevisionID: testCase.RevisionID, Ordinal: testCase.Ordinal,
		ContentDigest: testCase.ContentDigest, Test: testCase.Test,
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
