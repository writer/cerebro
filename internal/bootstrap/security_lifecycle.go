package bootstrap

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/securitylifecyclehttp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type securityLifecycleQueryReader interface {
	ListSecurityLifecycle(context.Context, *cerebrov1.SecurityLifecycleQuery) (*cerebrov1.SecurityLifecycleQueryResult, error)
	ResolveSecurityLifecycleFinding(context.Context, string, string) (*cerebrov1.ResolveSecurityLifecycleFindingResponse, error)
}

func (a *App) handleListSecurityLifecycle(w http.ResponseWriter, r *http.Request) {
	if a.deps.SecurityLifecycleQueries == nil {
		http.Error(w, "security lifecycle reads are unavailable", http.StatusServiceUnavailable)
		return
	}
	tenantID, err := effectiveTenantFilter(r.Context(), r.URL.Query().Get("tenant_id"))
	if err != nil {
		http.Error(w, "tenant is not authorized", http.StatusForbidden)
		return
	}
	findingsOnly, err := boolQueryParam(r, "findings_only")
	if err != nil {
		http.Error(w, "findings_only must be a boolean", http.StatusBadRequest)
		return
	}
	query := &cerebrov1.SecurityLifecycleQuery{
		TenantId:     tenantID,
		FindingsOnly: findingsOnly,
		PageToken:    strings.TrimSpace(r.URL.Query().Get("page_token")),
		OwnerUrns:    trimmedQueryValues(r, "owner_urn"),
	}
	for _, value := range trimmedQueryValues(r, "subject_kind") {
		switch value {
		case "credential":
			query.SubjectKinds = append(query.SubjectKinds, cerebrov1.SecurityLifecycleSubjectKind_SECURITY_LIFECYCLE_SUBJECT_KIND_CREDENTIAL)
		case "certificate":
			query.SubjectKinds = append(query.SubjectKinds, cerebrov1.SecurityLifecycleSubjectKind_SECURITY_LIFECYCLE_SUBJECT_KIND_CERTIFICATE)
		default:
			http.Error(w, "subject_kind must be credential or certificate", http.StatusBadRequest)
			return
		}
	}
	if err := securitylifecyclehttp.SetSubjectLocator(
		query,
		strings.TrimSpace(r.URL.Query().Get("authority_id")),
		strings.TrimSpace(r.URL.Query().Get("stable_locator")),
	); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, value := range trimmedQueryValues(r, "state") {
		state, ok := securitylifecyclehttp.State(value)
		if !ok {
			http.Error(w, "state is not a recognized lifecycle state", http.StatusBadRequest)
			return
		}
		query.States = append(query.States, state)
	}
	if value := strings.TrimSpace(r.URL.Query().Get("expires_before")); value != "" {
		parsed, parseErr := time.Parse(time.RFC3339Nano, value)
		if parseErr != nil {
			http.Error(w, "expires_before must be an RFC 3339 timestamp", http.StatusBadRequest)
			return
		}
		query.ExpiresBefore = timestamppb.New(parsed)
	}
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		limit, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil || limit == 0 || limit > 500 {
			http.Error(w, "limit must be between 1 and 500", http.StatusBadRequest)
			return
		}
		query.Limit = uint32(limit)
	}
	result, err := a.deps.SecurityLifecycleQueries.ListSecurityLifecycle(r.Context(), query)
	if err != nil {
		status := http.StatusBadGateway
		switch connect.CodeOf(err) {
		case connect.CodeInvalidArgument:
			status = http.StatusBadRequest
		case connect.CodeUnavailable:
			status = http.StatusServiceUnavailable
		}
		http.Error(w, "security lifecycle read failed", status)
		return
	}
	writeProtoJSON(w, http.StatusOK, result)
}

func trimmedQueryValues(r *http.Request, name string) []string {
	values := r.URL.Query()[name]
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}
