package complianceread

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
)

const (
	maxCursorBytes = 2048
	maxIdentityLen = 512
)

type TenantResolver func(context.Context, string) (string, error)

type Handler struct {
	repository Repository
	tenant     TenantResolver
}

func NewHandler(repository Repository, tenant TenantResolver) *Handler {
	return &Handler{repository: repository, tenant: tenant}
}

func (h *Handler) ListCompliancePrograms(ctx context.Context, request *connect.Request[cerebrov1.ListComplianceProgramsRequest]) (*connect.Response[cerebrov1.ListComplianceProgramsResponse], error) {
	tenantID, page, err := h.listContext(ctx, request.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	result, err := h.repository.ListCompliancePrograms(ctx, tenantID, request.Msg, page)
	if err != nil {
		return nil, readError(err)
	}
	values := tenantValues(tenantID, result.Records, func(value *cerebrov1.ComplianceProgram) bool { return value != nil })
	pageResponse, err := pageResponse(result.Next)
	if err != nil {
		return nil, readError(err)
	}
	return connect.NewResponse(&cerebrov1.ListComplianceProgramsResponse{Programs: values, Page: pageResponse}), nil
}

func (h *Handler) GetComplianceProgram(ctx context.Context, request *connect.Request[cerebrov1.GetComplianceProgramRequest]) (*connect.Response[cerebrov1.GetComplianceProgramResponse], error) {
	tenantID, id, revisionID, err := h.getContext(ctx, request.Msg.GetId(), request.Msg.GetRevisionId())
	if err != nil {
		return nil, err
	}
	record, err := h.repository.GetComplianceProgram(ctx, tenantID, id, revisionID)
	if err != nil || record.TenantID != tenantID || record.Value == nil {
		return nil, getError(err)
	}
	response := connect.NewResponse(&cerebrov1.GetComplianceProgramResponse{Program: record.Value})
	if err := setRevisionETag(response.Header(), record.Value.GetRevision()); err != nil {
		return nil, readError(err)
	}
	return response, nil
}

func (h *Handler) ListControlImplementations(ctx context.Context, request *connect.Request[cerebrov1.ListControlImplementationsRequest]) (*connect.Response[cerebrov1.ListControlImplementationsResponse], error) {
	tenantID, page, err := h.listContext(ctx, request.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	result, err := h.repository.ListControlImplementations(ctx, tenantID, request.Msg, page)
	if err != nil {
		return nil, readError(err)
	}
	values := tenantValues(tenantID, result.Records, func(value *cerebrov1.ControlImplementation) bool { return value != nil })
	pageResponse, err := pageResponse(result.Next)
	if err != nil {
		return nil, readError(err)
	}
	return connect.NewResponse(&cerebrov1.ListControlImplementationsResponse{Implementations: values, Page: pageResponse}), nil
}

func (h *Handler) GetControlImplementation(ctx context.Context, request *connect.Request[cerebrov1.GetControlImplementationRequest]) (*connect.Response[cerebrov1.GetControlImplementationResponse], error) {
	tenantID, id, revisionID, err := h.getContext(ctx, request.Msg.GetId(), request.Msg.GetRevisionId())
	if err != nil {
		return nil, err
	}
	record, err := h.repository.GetControlImplementation(ctx, tenantID, id, revisionID)
	if err != nil || record.TenantID != tenantID || record.Value == nil {
		return nil, getError(err)
	}
	response := connect.NewResponse(&cerebrov1.GetControlImplementationResponse{Implementation: record.Value})
	if err := setRevisionETag(response.Header(), record.Value.GetRevision()); err != nil {
		return nil, readError(err)
	}
	return response, nil
}

func (h *Handler) ListEvidenceArtifactMetadata(ctx context.Context, request *connect.Request[cerebrov1.ListEvidenceArtifactMetadataRequest]) (*connect.Response[cerebrov1.ListEvidenceArtifactMetadataResponse], error) {
	tenantID, page, err := h.listContext(ctx, request.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	result, err := h.repository.ListEvidenceArtifactMetadata(ctx, tenantID, request.Msg, page)
	if err != nil {
		return nil, readError(err)
	}
	values := tenantValues(tenantID, result.Records, func(value *cerebrov1.EvidenceArtifactMetadata) bool { return value != nil })
	pageResponse, err := pageResponse(result.Next)
	if err != nil {
		return nil, readError(err)
	}
	return connect.NewResponse(&cerebrov1.ListEvidenceArtifactMetadataResponse{Artifacts: values, Page: pageResponse}), nil
}

func (h *Handler) GetEvidenceArtifactMetadata(ctx context.Context, request *connect.Request[cerebrov1.GetEvidenceArtifactMetadataRequest]) (*connect.Response[cerebrov1.GetEvidenceArtifactMetadataResponse], error) {
	tenantID, id, revisionID, err := h.getContext(ctx, request.Msg.GetId(), request.Msg.GetRevisionId())
	if err != nil {
		return nil, err
	}
	record, err := h.repository.GetEvidenceArtifactMetadata(ctx, tenantID, id, revisionID)
	if err != nil || record.TenantID != tenantID || record.Value == nil {
		return nil, getError(err)
	}
	response := connect.NewResponse(&cerebrov1.GetEvidenceArtifactMetadataResponse{Artifact: record.Value})
	if err := setRevisionETag(response.Header(), record.Value.GetRevision()); err != nil {
		return nil, readError(err)
	}
	return response, nil
}

func (h *Handler) ListAssessmentPlans(ctx context.Context, request *connect.Request[cerebrov1.ListAssessmentPlansRequest]) (*connect.Response[cerebrov1.ListAssessmentPlansResponse], error) {
	tenantID, page, err := h.listContext(ctx, request.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	result, err := h.repository.ListAssessmentPlans(ctx, tenantID, request.Msg, page)
	if err != nil {
		return nil, readError(err)
	}
	values := tenantValues(tenantID, result.Records, func(value *cerebrov1.AssessmentPlan) bool { return value != nil })
	pageResponse, err := pageResponse(result.Next)
	if err != nil {
		return nil, readError(err)
	}
	return connect.NewResponse(&cerebrov1.ListAssessmentPlansResponse{Plans: values, Page: pageResponse}), nil
}

func (h *Handler) GetAssessmentPlan(ctx context.Context, request *connect.Request[cerebrov1.GetAssessmentPlanRequest]) (*connect.Response[cerebrov1.GetAssessmentPlanResponse], error) {
	tenantID, id, revisionID, err := h.getContext(ctx, request.Msg.GetId(), request.Msg.GetRevisionId())
	if err != nil {
		return nil, err
	}
	record, err := h.repository.GetAssessmentPlan(ctx, tenantID, id, revisionID)
	if err != nil || record.TenantID != tenantID || record.Value == nil {
		return nil, getError(err)
	}
	response := connect.NewResponse(&cerebrov1.GetAssessmentPlanResponse{Plan: record.Value})
	if err := setRevisionETag(response.Header(), record.Value.GetRevision()); err != nil {
		return nil, readError(err)
	}
	return response, nil
}

func (h *Handler) ListAssessmentRuns(ctx context.Context, request *connect.Request[cerebrov1.ListAssessmentRunsRequest]) (*connect.Response[cerebrov1.ListAssessmentRunsResponse], error) {
	tenantID, page, err := h.listContext(ctx, request.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	result, err := h.repository.ListAssessmentRuns(ctx, tenantID, request.Msg, page)
	if err != nil {
		return nil, readError(err)
	}
	values := tenantValues(tenantID, result.Records, func(value *cerebrov1.AssessmentRun) bool { return value != nil })
	pageResponse, err := pageResponse(result.Next)
	if err != nil {
		return nil, readError(err)
	}
	return connect.NewResponse(&cerebrov1.ListAssessmentRunsResponse{Runs: values, Page: pageResponse}), nil
}

func (h *Handler) GetAssessmentRun(ctx context.Context, request *connect.Request[cerebrov1.GetAssessmentRunRequest]) (*connect.Response[cerebrov1.GetAssessmentRunResponse], error) {
	tenantID, id, revisionID, err := h.getContext(ctx, request.Msg.GetId(), request.Msg.GetRevisionId())
	if err != nil {
		return nil, err
	}
	record, err := h.repository.GetAssessmentRun(ctx, tenantID, id, revisionID)
	if err != nil || record.TenantID != tenantID || record.Value == nil {
		return nil, getError(err)
	}
	response := connect.NewResponse(&cerebrov1.GetAssessmentRunResponse{Run: record.Value})
	if err := setRevisionETag(response.Header(), record.Value.GetRevision()); err != nil {
		return nil, readError(err)
	}
	return response, nil
}

func (h *Handler) ListAssessmentResults(ctx context.Context, request *connect.Request[cerebrov1.ListAssessmentResultsRequest]) (*connect.Response[cerebrov1.ListAssessmentResultsResponse], error) {
	tenantID, page, err := h.listContext(ctx, request.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	result, err := h.repository.ListAssessmentResults(ctx, tenantID, request.Msg, page)
	if err != nil {
		return nil, readError(err)
	}
	values := tenantValues(tenantID, result.Records, func(value *cerebrov1.AssessmentResult) bool { return value != nil })
	pageResponse, err := pageResponse(result.Next)
	if err != nil {
		return nil, readError(err)
	}
	return connect.NewResponse(&cerebrov1.ListAssessmentResultsResponse{Results: values, Page: pageResponse}), nil
}

func (h *Handler) GetAssessmentResult(ctx context.Context, request *connect.Request[cerebrov1.GetAssessmentResultRequest]) (*connect.Response[cerebrov1.GetAssessmentResultResponse], error) {
	tenantID, id, revisionID, err := h.getContext(ctx, request.Msg.GetId(), request.Msg.GetRevisionId())
	if err != nil {
		return nil, err
	}
	record, err := h.repository.GetAssessmentResult(ctx, tenantID, id, revisionID)
	if err != nil || record.TenantID != tenantID || record.Value == nil {
		return nil, getError(err)
	}
	response := connect.NewResponse(&cerebrov1.GetAssessmentResultResponse{Result: record.Value})
	if err := setRevisionETag(response.Header(), record.Value.GetRevision()); err != nil {
		return nil, readError(err)
	}
	return response, nil
}

func (h *Handler) ListAssessmentReviews(ctx context.Context, request *connect.Request[cerebrov1.ListAssessmentReviewsRequest]) (*connect.Response[cerebrov1.ListAssessmentReviewsResponse], error) {
	tenantID, page, err := h.listContext(ctx, request.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	result, err := h.repository.ListAssessmentReviews(ctx, tenantID, request.Msg, page)
	if err != nil {
		return nil, readError(err)
	}
	values := tenantValues(tenantID, result.Records, func(value *cerebrov1.AssessmentReview) bool { return value != nil })
	pageResponse, err := pageResponse(result.Next)
	if err != nil {
		return nil, readError(err)
	}
	return connect.NewResponse(&cerebrov1.ListAssessmentReviewsResponse{Reviews: values, Page: pageResponse}), nil
}

func (h *Handler) GetAssessmentReview(ctx context.Context, request *connect.Request[cerebrov1.GetAssessmentReviewRequest]) (*connect.Response[cerebrov1.GetAssessmentReviewResponse], error) {
	tenantID, id, revisionID, err := h.getContext(ctx, request.Msg.GetId(), request.Msg.GetRevisionId())
	if err != nil {
		return nil, err
	}
	record, err := h.repository.GetAssessmentReview(ctx, tenantID, id, revisionID)
	if err != nil || record.TenantID != tenantID || record.Value == nil {
		return nil, getError(err)
	}
	response := connect.NewResponse(&cerebrov1.GetAssessmentReviewResponse{Review: record.Value})
	if err := setRevisionETag(response.Header(), record.Value.GetRevision()); err != nil {
		return nil, readError(err)
	}
	return response, nil
}

func (h *Handler) ListComplianceWorkItems(ctx context.Context, request *connect.Request[cerebrov1.ListComplianceWorkItemsRequest]) (*connect.Response[cerebrov1.ListComplianceWorkItemsResponse], error) {
	tenantID, page, err := h.listContext(ctx, request.Msg.GetPage())
	if err != nil {
		return nil, err
	}
	result, err := h.repository.ListComplianceWorkItems(ctx, tenantID, request.Msg, page)
	if err != nil {
		return nil, readError(err)
	}
	values := tenantValues(tenantID, result.Records, func(value *cerebrov1.ComplianceWorkItem) bool { return value != nil })
	pageResponse, err := pageResponse(result.Next)
	if err != nil {
		return nil, readError(err)
	}
	return connect.NewResponse(&cerebrov1.ListComplianceWorkItemsResponse{WorkItems: values, Page: pageResponse}), nil
}

func (h *Handler) GetComplianceWorkItem(ctx context.Context, request *connect.Request[cerebrov1.GetComplianceWorkItemRequest]) (*connect.Response[cerebrov1.GetComplianceWorkItemResponse], error) {
	tenantID, id, revisionID, err := h.getContext(ctx, request.Msg.GetId(), request.Msg.GetRevisionId())
	if err != nil {
		return nil, err
	}
	record, err := h.repository.GetComplianceWorkItem(ctx, tenantID, id, revisionID)
	if err != nil || record.TenantID != tenantID || record.Value == nil {
		return nil, getError(err)
	}
	response := connect.NewResponse(&cerebrov1.GetComplianceWorkItemResponse{WorkItem: record.Value})
	if err := setRevisionETag(response.Header(), record.Value.GetRevision()); err != nil {
		return nil, readError(err)
	}
	return response, nil
}

func (h *Handler) listContext(ctx context.Context, request *cerebrov1.CompliancePageRequest) (string, Page, error) {
	tenantID, err := h.resolveTenant(ctx)
	if err != nil {
		return "", Page{}, err
	}
	page, err := normalizePage(request)
	if err != nil {
		return "", Page{}, readError(err)
	}
	return tenantID, page, nil
}

func (h *Handler) getContext(ctx context.Context, id string, revisionID string) (string, string, string, error) {
	tenantID, err := h.resolveTenant(ctx)
	if err != nil {
		return "", "", "", err
	}
	id = strings.TrimSpace(id)
	revisionID = strings.TrimSpace(revisionID)
	if id == "" || revisionID == "" || len(id) > maxIdentityLen || len(revisionID) > maxIdentityLen {
		return "", "", "", readError(fmt.Errorf("%w: id and revision_id are required and bounded", ErrInvalidRequest))
	}
	return tenantID, id, revisionID, nil
}

func (h *Handler) resolveTenant(ctx context.Context) (string, error) {
	if h == nil || h.repository == nil || h.tenant == nil {
		return "", readError(errors.New("compliance read service is not configured"))
	}
	tenantID, err := h.tenant(ctx, "")
	if err != nil || strings.TrimSpace(tenantID) == "" {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("tenant-scoped authorization is required"))
	}
	return strings.TrimSpace(tenantID), nil
}

func normalizePage(request *cerebrov1.CompliancePageRequest) (Page, error) {
	page := Page{Limit: DefaultPageSize}
	if request == nil {
		return page, nil
	}
	if request.GetPageSize() > MaxPageSize {
		return Page{}, fmt.Errorf("%w: page_size exceeds %d", ErrInvalidRequest, MaxPageSize)
	}
	if request.GetPageSize() != 0 {
		page.Limit = request.GetPageSize()
	}
	cursor := strings.TrimSpace(request.GetCursor())
	if cursor == "" {
		return page, nil
	}
	if len(cursor) > maxCursorBytes {
		return Page{}, ErrInvalidCursor
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(decoded) == 0 || len(decoded) > maxCursorBytes {
		return Page{}, ErrInvalidCursor
	}
	var envelope cursorEnvelope
	decoder := json.NewDecoder(bytes.NewReader(decoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Page{}, ErrInvalidCursor
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Page{}, ErrInvalidCursor
	}
	if envelope.Version != 1 || strings.TrimSpace(envelope.ID) == "" || strings.TrimSpace(envelope.RevisionID) == "" ||
		len(envelope.ID) > maxIdentityLen || len(envelope.RevisionID) > maxIdentityLen {
		return Page{}, ErrInvalidCursor
	}
	lastModified, err := time.Parse(time.RFC3339Nano, envelope.LastModified)
	if err != nil || lastModified.IsZero() {
		return Page{}, ErrInvalidCursor
	}
	page.After = &Keyset{LastModified: lastModified.UTC(), ID: strings.TrimSpace(envelope.ID), RevisionID: strings.TrimSpace(envelope.RevisionID)}
	return page, nil
}

type cursorEnvelope struct {
	Version      int    `json:"v"`
	LastModified string `json:"last_modified"`
	ID           string `json:"id"`
	RevisionID   string `json:"revision_id"`
}

func pageResponse(next *Keyset) (*cerebrov1.CompliancePageResponse, error) {
	response := &cerebrov1.CompliancePageResponse{}
	if next == nil {
		return response, nil
	}
	if next.LastModified.IsZero() || strings.TrimSpace(next.ID) == "" || strings.TrimSpace(next.RevisionID) == "" ||
		len(next.ID) > maxIdentityLen || len(next.RevisionID) > maxIdentityLen {
		return nil, ErrInvalidCursor
	}
	content, err := json.Marshal(cursorEnvelope{
		Version: 1, LastModified: next.LastModified.UTC().Format(time.RFC3339Nano),
		ID: strings.TrimSpace(next.ID), RevisionID: strings.TrimSpace(next.RevisionID),
	})
	if err != nil {
		return nil, fmt.Errorf("encode compliance cursor: %w", err)
	}
	response.NextCursor = base64.RawURLEncoding.EncodeToString(content)
	if len(response.NextCursor) > maxCursorBytes {
		return nil, ErrInvalidCursor
	}
	return response, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidCursor
	}
	return nil
}

func tenantValues[T any](tenantID string, records []TenantRecord[T], valid func(T) bool) []T {
	values := make([]T, 0, len(records))
	for _, record := range records {
		if record.TenantID == tenantID && valid(record.Value) {
			values = append(values, record.Value)
		}
	}
	return values
}

func setRevisionETag(header interface{ Set(string, string) }, revision *cerebrov1.ComplianceRevisionMetadata) error {
	if revision == nil {
		return errors.New("compliance revision metadata is required")
	}
	etag := strings.TrimSpace(revision.GetEtag())
	if etag == "" || len(etag) > maxIdentityLen || strings.ContainsAny(etag, "\r\n") {
		return errors.New("compliance revision etag is invalid")
	}
	quoted := strings.HasPrefix(etag, `"`) && strings.HasSuffix(etag, `"`)
	weakQuoted := strings.HasPrefix(etag, `W/"`) && strings.HasSuffix(etag, `"`)
	if !quoted && !weakQuoted {
		etag = strconv.Quote(etag)
	}
	header.Set("ETag", etag)
	return nil
}

func getError(err error) error {
	if err == nil || errors.Is(err, ErrNotFound) {
		return connect.NewError(connect.CodeNotFound, errors.New("compliance revision not found"))
	}
	return readError(err)
}

func readError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInvalidCursor):
		return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid compliance read request"))
	case errors.Is(err, ErrNotFound):
		return connect.NewError(connect.CodeNotFound, errors.New("compliance revision not found"))
	default:
		return connect.NewError(connect.CodeInternal, errors.New("compliance read failed"))
	}
}
