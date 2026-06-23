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

func listBigQueryDatasets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.BigQueryDatasetRecord, string, error) {
	query := url.Values{"maxResults": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	var response pageResponse
	path := "/bigquery/v2/projects/" + url.PathEscape(settings.projectID) + "/datasets"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, bigQueryBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Datasets, "gcp bigquery dataset", gcpcloud.SaveRawField[gcpcloud.BigQueryDatasetRecord])
	if err != nil {
		return nil, "", err
	}
	for index := range records {
		datasetID := records[index].DatasetReference.DatasetID
		if strings.TrimSpace(datasetID) == "" {
			continue
		}
		detailPath := "/bigquery/v2/projects/" + url.PathEscape(settings.projectID) + "/datasets/" + url.PathEscape(datasetID)
		var raw json.RawMessage
		if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, bigQueryBaseURL, http.MethodGet, detailPath, nil, nil, &raw)); err != nil {
			return nil, "", err
		}
		if len(raw) == 0 {
			continue
		}
		var detailed gcpcloud.BigQueryDatasetRecord
		if err := json.Unmarshal(raw, &detailed); err != nil {
			return nil, "", fmt.Errorf("decode gcp bigquery dataset detail: %w", err)
		}
		detailed.Raw = append(json.RawMessage(nil), raw...)
		records[index] = detailed
	}
	return records, response.NextPageToken, nil
}

func listBigQueryTables(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.BigQueryTableRecord, string, error) {
	datasets, next, err := listBigQueryDatasets(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectBigQueryTables(settings.projectID, datasets, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, bigQueryBaseURL, http.MethodGet, path, query, nil, target))
	})
	return records, next, err
}

func listBigtableInstances(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.BigtableInstanceRecord, string, error) {
	return listPagedRecords[gcpcloud.BigtableInstanceRecord, gcpcloud.BigtablePageResponse](ctx, source, settings, pageToken, limit, bigtableAdminBaseURL, "/v2/projects/"+url.PathEscape(settings.projectID)+"/instances", "", "gcp bigtable instance", func(response gcpcloud.BigtablePageResponse) []json.RawMessage { return response.Instances }, true, false, nil)
}

func listBigtableTables(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.BigtableTableRecord, string, error) {
	instances, next, err := listBigtableInstances(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectBigtableTables(instances, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, bigtableAdminBaseURL, http.MethodGet, path, query, nil, target))
	})
	return records, next, err
}

func listAIDatasets(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.AIDatasetRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/datasets"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, aiPlatformBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Datasets, "gcp vertex ai dataset", gcpcloud.SaveRawField[gcpcloud.AIDatasetRecord])
	if err != nil {
		return nil, "", err
	}
	for index := range records {
		if strings.TrimSpace(records[index].Name) == "" {
			continue
		}
		policy, err := lookupAIResourcePolicy(ctx, source, settings, records[index].Name)
		if err != nil {
			return nil, "", err
		}
		records[index].IAMPolicy = policy
	}
	return records, response.NextPageToken, nil
}

func listAIEndpoints(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.AIEndpointRecord, string, error) {
	query := url.Values{"pageSize": {strconv.Itoa(limit)}}
	gcpcloud.AddPageToken(query, pageToken)
	if strings.TrimSpace(settings.filter) != "" {
		query.Set("filter", settings.filter)
	}
	var response pageResponse
	location := firstNonEmpty(settings.location, "-")
	path := "/v1/projects/" + url.PathEscape(settings.projectID) + "/locations/" + url.PathEscape(location) + "/endpoints"
	if err := gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, aiPlatformBaseURL, http.MethodGet, path, query, nil, &response)); err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.DecodeRecords(response.Endpoints, "gcp vertex ai endpoint", gcpcloud.SaveRawField[gcpcloud.AIEndpointRecord])
	if err != nil {
		return nil, "", err
	}
	for index := range records {
		if strings.TrimSpace(records[index].Name) == "" {
			continue
		}
		policy, err := lookupAIResourcePolicy(ctx, source, settings, records[index].Name)
		if err != nil {
			return nil, "", err
		}
		records[index].IAMPolicy = policy
	}
	return records, response.NextPageToken, nil
}

func lookupAIResourcePolicy(ctx context.Context, source *Source, settings settings, resourceName string) (gcpcloud.IAMPolicy, error) {
	var policy gcpcloud.IAMPolicy
	path := "/v1/" + gcpcloud.EscapePathSegments(resourceName) + ":getIamPolicy"
	if err := getJSON(ctx, source, settings, aiPlatformBaseURL, http.MethodPost, path, nil, map[string]any{}, &policy); err != nil {
		if gcpcloud.OptionalEnrichmentErr(err) == nil {
			return gcpcloud.IAMPolicy{}, nil
		}
		return gcpcloud.IAMPolicy{}, err
	}
	return policy, nil
}

func listSpannerInstances(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.SpannerInstanceRecord, string, error) {
	return listPagedRecords[gcpcloud.SpannerInstanceRecord, gcpcloud.SpannerPageResponse](ctx, source, settings, pageToken, limit, spannerBaseURL, "/v1/projects/"+url.PathEscape(settings.projectID)+"/instances", "pageSize", "gcp spanner instance", func(response gcpcloud.SpannerPageResponse) []json.RawMessage { return response.Instances }, true, true, nil)
}

func listSpannerDatabases(ctx context.Context, source *Source, settings settings, pageToken string, limit int) ([]gcpcloud.SpannerDatabaseRecord, string, error) {
	instances, next, err := listSpannerInstances(ctx, source, settings, pageToken, limit)
	if err != nil {
		return nil, "", err
	}
	records, err := gcpcloud.CollectSpannerDatabases(instances, limit, func(path string, query url.Values, target any) error {
		return gcpcloud.OptionalServiceErr(getJSON(ctx, source, settings, spannerBaseURL, http.MethodGet, path, query, nil, target))
	})
	return records, next, err
}
