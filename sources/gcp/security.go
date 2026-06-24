package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/sources/internal/gcpcloud"
)

type binaryAuthorizationAttestorsPageResponse = gcpcloud.BinaryAuthorizationAttestorsPageResponse
type securityCenterFindingsPageResponse = gcpcloud.SecurityCenterFindingsPageResponse

func listBinaryAuthorizationPolicies(ctx context.Context, source *Source, settings settings, _ string, _ int) ([]gcpcloud.BinaryAuthorizationPolicyRecord, string, error) {
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/policy"
	content, _, err := getBytes(ctx, source, settings, binaryAuthorizationBaseURL, http.MethodGet, path, nil, nil, 0)
	if err := gcpcloud.OptionalServiceErr(err); err != nil {
		return nil, "", err
	}
	if len(content) == 0 {
		return nil, "", nil
	}
	var record gcpcloud.BinaryAuthorizationPolicyRecord
	if err := json.Unmarshal(content, &record); err != nil {
		return nil, "", fmt.Errorf("decode %s response: %w", path, err)
	}
	record.Raw = append(json.RawMessage(nil), content...)
	return []gcpcloud.BinaryAuthorizationPolicyRecord{record}, "", nil
}

func listBinaryAuthorizationAttestors(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.BinaryAuthorizationAttestorRecord, string, error) {
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/attestors"
	return listPagedRecords[gcpcloud.BinaryAuthorizationAttestorRecord, binaryAuthorizationAttestorsPageResponse](ctx, source, settings, pageToken, limit, binaryAuthorizationBaseURL, path, "pageSize", "gcp binary authorization attestor", func(response binaryAuthorizationAttestorsPageResponse) []json.RawMessage {
		return response.Attestors
	}, true, false, nil)
}

func listSecurityCenterFindings(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.SecurityCenterFindingRecord, string, error) {
	return listSecurityCenterFindingsWithCheckpoint(ctx, source, settings, pageToken, limit, nil)
}

func listSecurityCenterFindingsWithCheckpoint(ctx context.Context, source *Source, settings settings, pageToken string, limit int, checkpoint *cerebrov1.SourceCheckpoint) ([]gcpcloud.SecurityCenterFindingRecord, string, error) {
	path := "/v2/projects/" + url.PathEscape(settings.projectID) + "/sources/-/findings"
	readSettings := settings
	if start, ok := gcpcloud.CheckpointStart(checkpoint, gcpcloud.FindingCheckpointLookback); ok {
		readSettings.filter = gcpcloud.CombineFilters(readSettings.filter, fmt.Sprintf(`event_time >= "%s"`, start.Format(time.RFC3339Nano)))
	}
	query := url.Values{"orderBy": {"event_time desc"}}
	return listPagedRecords[gcpcloud.SecurityCenterFindingRecord, securityCenterFindingsPageResponse](ctx, source, readSettings, pageToken, limit, securityCenterBaseURL, path, "pageSize", "gcp security command center finding", func(response securityCenterFindingsPageResponse) []json.RawMessage {
		return response.ListFindingsResults
	}, true, true, query)
}
