package bootstrap

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

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
	for _, value := range trimmedQueryValues(r, "state") {
		state, ok := lifecycleState(value)
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
		if connect.CodeOf(err) == connect.CodeInvalidArgument {
			status = http.StatusBadRequest
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

func lifecycleState(value string) (cerebrov1.SecurityLifecycleState, bool) {
	switch value {
	case "active":
		return cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_ACTIVE, true
	case "expiring":
		return cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_EXPIRING, true
	case "expired":
		return cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_EXPIRED, true
	case "rotated":
		return cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_ROTATED, true
	case "revoked":
		return cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_REVOKED, true
	case "inactive":
		return cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_INACTIVE, true
	case "unknown":
		return cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_UNKNOWN, true
	default:
		return cerebrov1.SecurityLifecycleState_SECURITY_LIFECYCLE_STATE_UNSPECIFIED, false
	}
}
