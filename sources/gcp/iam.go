package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/writer/cerebro/sources/internal/gcpcloud"
)

type serviceAccountRecord = gcpcloud.ServiceAccountRecord
type serviceAccountKeyRecord = gcpcloud.ServiceAccountKeyRecord
type groupRecord = gcpcloud.GroupRecord

type lookupGroupResponse struct {
	Name     string             `json:"name"`
	GroupKey gcpcloud.EntityKey `json:"groupKey"`
}

type membershipRecord = gcpcloud.MembershipRecord

type policyResponse struct {
	Bindings []gcpcloud.IAMBinding `json:"bindings"`
}

type roleAssignmentRecord = gcpcloud.RoleAssignmentRecord

type workloadIdentityPoolsPageResponse = gcpcloud.WorkloadIdentityPoolsPageResponse
type workloadIdentityProvidersPageResponse = gcpcloud.WorkloadIdentityProvidersPageResponse

type serviceAccountImpersonationRecord = gcpcloud.ServiceAccountImpersonationRecord

func listServiceAccounts(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]serviceAccountRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, serviceBaseURL, http.MethodGet, "/v1/projects/"+url.PathEscape(settings.projectID)+"/serviceAccounts", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Accounts, "gcp service account", gcpcloud.SaveRawField[serviceAccountRecord])
	return records, response.NextPageToken, err
}

func listServiceAccountKeys(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]serviceAccountKeyRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/serviceAccounts/" + url.PathEscape(settings.serviceAccountEmail) + "/keys"
	if err := getJSON(ctx, source, settings, serviceBaseURL, http.MethodGet, path, query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Keys, "gcp service account key", gcpcloud.SaveRawField[serviceAccountKeyRecord])
	return records, response.NextPageToken, err
}

func listWorkloadIdentityPools(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.WorkloadIdentityPoolRecord, string, error) {
	location := firstNonEmpty(settings.location, "global")
	projectID := url.PathEscape(settings.projectID)
	path := "/v1/projects/" + projectID + "/locations/" + url.PathEscape(location) + "/workloadIdentityPools"
	return listPagedRecords[gcpcloud.WorkloadIdentityPoolRecord, workloadIdentityPoolsPageResponse](ctx, source, settings, pageToken, limit, serviceBaseURL, path, "pageSize", "gcp workload identity pool", func(response workloadIdentityPoolsPageResponse) []json.RawMessage {
		return response.WorkloadIdentityPools
	}, true, false, nil)
}

func listWorkloadIdentityProviders(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.WorkloadIdentityProviderRecord, string, error) {
	pools, next, err := listWorkloadIdentityPools(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectWorkloadIdentityProviders(pools, func(poolName string, providerPageToken string) ([]gcpcloud.WorkloadIdentityProviderRecord, string, error) {
		path := "/v1/" + gcpcloud.EscapePathSegments(poolName) + "/providers"
		return listPagedRecords[gcpcloud.WorkloadIdentityProviderRecord, workloadIdentityProvidersPageResponse](ctx, source, settings, providerPageToken, limit, serviceBaseURL, path, "pageSize", "gcp workload identity provider", func(response workloadIdentityProvidersPageResponse) []json.RawMessage {
			return response.WorkloadIdentityPoolProviders
		}, true, false, nil)
	})
	return records, next, err
}

func listGroups(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]groupRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}, "parent": {"customers/" + settings.customerID}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, identityBaseURL, http.MethodGet, "/v1/groups", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Groups, "gcp group", func(record *groupRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func listGroupMemberships(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]membershipRecord, string, error) {
	groupName, err := resolveGroupName(ctx, source, settings)
	if err != nil {
		return nil, "", err
	}
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	if err := getJSON(ctx, source, settings, identityBaseURL, http.MethodGet, "/v1/"+groupName+"/memberships", query, nil, &response); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Memberships, "gcp group membership", func(record *membershipRecord, raw json.RawMessage) { record.Raw = append(json.RawMessage(nil), raw...) })
	return records, response.NextPageToken, err
}

func resolveGroupName(ctx context.Context, source *Source, settings settings) (string, error) {
	if strings.HasPrefix(settings.groupKey, "groups/") {
		return settings.groupKey, nil
	}
	query := url.Values{"groupKey.id": {settings.groupKey}}
	var response lookupGroupResponse
	if err := getJSON(ctx, source, settings, identityBaseURL, http.MethodGet, "/v1/groups:lookup", query, nil, &response); err != nil {
		return "", err
	}
	if strings.TrimSpace(response.Name) == "" {
		return "", fmt.Errorf("gcp group lookup returned empty name for %q", settings.groupKey)
	}
	return response.Name, nil
}

func listRoleAssignments(ctx context.Context, source *Source, settings settings, _ string, _ int) ([]roleAssignmentRecord, string, error) {
	var response policyResponse
	if err := getJSON(ctx, source, settings, resourceManagerBaseURL, http.MethodPost, "/v1/projects/"+url.PathEscape(settings.projectID)+":getIamPolicy", nil, map[string]any{}, &response); err != nil {
		return nil, "", err
	}
	records := make([]roleAssignmentRecord, 0)
	for _, binding := range response.Bindings {
		raw, err := json.Marshal(binding)
		if err != nil {
			return nil, "", err
		}
		for _, member := range binding.Members {
			records = append(records, roleAssignmentRecord{Role: binding.Role, Member: member, Raw: raw})
		}
	}
	return records, "", nil
}

func listServiceAccountImpersonation(ctx context.Context, source *Source, settings settings, _ string, _ int) ([]serviceAccountImpersonationRecord, string, error) {
	var response policyResponse
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/serviceAccounts/" + url.PathEscape(settings.serviceAccountEmail) + ":getIamPolicy"
	if err := getJSON(ctx, source, settings, serviceBaseURL, http.MethodPost, path, nil, map[string]any{}, &response); err != nil {
		return nil, "", err
	}
	records := make([]serviceAccountImpersonationRecord, 0)
	for _, binding := range response.Bindings {
		if !impersonationRole(binding.Role) {
			continue
		}
		raw, err := json.Marshal(binding)
		if err != nil {
			return nil, "", err
		}
		for _, member := range binding.Members {
			records = append(records, serviceAccountImpersonationRecord{Role: binding.Role, Member: member, Raw: raw})
		}
	}
	return records, "", nil
}
