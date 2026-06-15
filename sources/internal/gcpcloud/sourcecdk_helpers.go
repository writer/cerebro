package gcpcloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	cerebrov1 "github.com/writer/cerebro/gen/cerebro/v1"
	"github.com/writer/cerebro/internal/primitives"
	"github.com/writer/cerebro/internal/sourcecdk"
)

func ParseURNs(values ...string) ([]sourcecdk.URN, error) {
	urns := make([]sourcecdk.URN, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		urn, err := sourcecdk.ParseURN(value)
		if err != nil {
			return nil, err
		}
		urns = append(urns, urn)
	}
	return urns, nil
}

func DecodeRecords[T any](rawRecords []json.RawMessage, label string, setRaw func(*T, json.RawMessage)) ([]T, error) {
	records := make([]T, 0, len(rawRecords))
	for _, raw := range rawRecords {
		var record T
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, fmt.Errorf("decode %s: %w", label, err)
		}
		if setRaw != nil {
			setRaw(&record, raw)
		}
		records = append(records, record)
	}
	return records, nil
}

func SaveRawField[T any](record *T, raw json.RawMessage) {
	field := reflect.ValueOf(record).Elem().FieldByName("Raw")
	if field.IsValid() && field.CanSet() && field.Type() == reflect.TypeOf(json.RawMessage{}) {
		field.Set(reflect.ValueOf(append(json.RawMessage(nil), raw...)))
	}
}

func PullFromRecords[T any](records []T, next string, build func(T) (*primitives.Event, error)) (sourcecdk.Pull, error) {
	if len(records) == 0 {
		if next != "" {
			return sourcecdk.Pull{NextCursor: &cerebrov1.SourceCursor{Opaque: next}}, nil
		}
		return sourcecdk.Pull{}, nil
	}
	events := make([]*primitives.Event, 0, len(records))
	for _, record := range records {
		event, err := build(record)
		if err != nil {
			return sourcecdk.Pull{}, err
		}
		events = append(events, event)
	}
	cursor := next
	if cursor == "" {
		cursor = events[len(events)-1].GetId()
	}
	pull := sourcecdk.Pull{Events: events, Checkpoint: &cerebrov1.SourceCheckpoint{Watermark: events[len(events)-1].OccurredAt, CursorOpaque: cursor}}
	if next != "" {
		pull.NextCursor = &cerebrov1.SourceCursor{Opaque: next}
	}
	return pull, nil
}

func URNsFor[S any, T any](settings S, records []T, render func(S, T) (string, error)) ([]sourcecdk.URN, error) {
	values := make([]string, 0, len(records))
	for _, record := range records {
		rawURN, err := render(settings, record)
		if err != nil {
			return nil, err
		}
		values = append(values, rawURN)
	}
	return ParseURNs(values...)
}

func CheckList[S any, C any, T any](ctx context.Context, source S, settings C, tenant string, list func(context.Context, S, C, string, int) ([]T, string, error), label string) error {
	_, _, err := list(ctx, source, settings, "", 1)
	if err != nil {
		return fmt.Errorf("lookup %s for %s: %w", label, tenant, err)
	}
	return nil
}

func AddPageToken(values url.Values, pageToken string) {
	if strings.TrimSpace(pageToken) != "" {
		values.Set("pageToken", pageToken)
	}
}

type PagedRecordsOptions struct {
	PageToken     string
	Limit         int
	PageSizeParam string
	Label         string
	Optional      bool
	UseFilter     bool
	Filter        string
	ExtraQuery    url.Values
}

type NextPage struct {
	NextPageToken string `json:"nextPageToken"`
}

func (page NextPage) NextToken() string { return page.NextPageToken }

type BigtablePageResponse struct {
	NextPage
	Instances []json.RawMessage `json:"instances"`
	Tables    []json.RawMessage `json:"tables"`
}

type BigQueryTablesPageResponse struct {
	NextPage
	Tables []json.RawMessage `json:"tables"`
}

type CloudSQLItemsPageResponse struct {
	NextPage
	Items []json.RawMessage `json:"items"`
}

type LoggingMetricsPageResponse struct {
	NextPage
	Metrics []json.RawMessage `json:"metrics"`
}

type MonitoringPageResponse struct {
	NextPage
	AlertPolicies        []json.RawMessage `json:"alertPolicies"`
	NotificationChannels []json.RawMessage `json:"notificationChannels"`
}

type SpannerPageResponse struct {
	NextPage
	Instances []json.RawMessage `json:"instances"`
	Databases []json.RawMessage `json:"databases"`
}

type SecretManagerPageResponse struct {
	NextPage
	Versions []json.RawMessage `json:"versions"`
}

type PageTokenResponse interface {
	NextToken() string
}

func ListPagedRecords[T any, R PageTokenResponse](options PagedRecordsOptions, fetch func(url.Values, *R) error, selectRecords func(R) []json.RawMessage) ([]T, string, error) {
	query := url.Values{}
	if options.PageSizeParam != "" {
		query.Set(options.PageSizeParam, fmt.Sprint(options.Limit))
	}
	for key, values := range options.ExtraQuery {
		query[key] = append(query[key], values...)
	}
	AddPageToken(query, options.PageToken)
	if options.UseFilter && strings.TrimSpace(options.Filter) != "" {
		query.Set("filter", options.Filter)
	}
	var response R
	err := fetch(query, &response)
	if options.Optional {
		err = OptionalServiceErr(err)
	}
	if err != nil {
		return nil, "", err
	}
	records, err := DecodeRecords(selectRecords(response), options.Label, SaveRawField[T])
	return records, response.NextToken(), err
}

func CollectChildPages[P any, C any](parents []P, parentName func(P) string, list func(P, string) ([]C, string, error), attach func(*C, P)) ([]C, error) {
	records := make([]C, 0)
	for _, parent := range parents {
		if strings.TrimSpace(parentName(parent)) == "" {
			continue
		}
		children, err := CollectPages(func(pageToken string) ([]C, string, error) { return list(parent, pageToken) })
		if err != nil {
			return nil, err
		}
		for index := range children {
			attach(&children[index], parent)
		}
		records = append(records, children...)
	}
	return records, nil
}

type PathFetcher func(path string, query url.Values, target any) error

func CollectBigQueryTables(projectID string, datasets []BigQueryDatasetRecord, limit int, fetch PathFetcher) ([]BigQueryTableRecord, error) {
	return CollectChildPages(datasets, func(dataset BigQueryDatasetRecord) string { return dataset.DatasetReference.DatasetID }, func(dataset BigQueryDatasetRecord, pageToken string) ([]BigQueryTableRecord, string, error) {
		datasetID := dataset.DatasetReference.DatasetID
		query := url.Values{"maxResults": {fmt.Sprint(limit)}}
		AddPageToken(query, pageToken)
		var response BigQueryTablesPageResponse
		path := "/bigquery/v2/projects/" + url.PathEscape(projectID) + "/datasets/" + url.PathEscape(datasetID) + "/tables"
		if err := fetch(path, query, &response); err != nil {
			return nil, "", err
		}
		tables, err := DecodeRecords(response.Tables, "gcp bigquery table", SaveRawField[BigQueryTableRecord])
		if err != nil {
			return nil, "", err
		}
		for index := range tables {
			tables[index].DatasetID = datasetID
			tables[index].DatasetLocation = dataset.Location
			tableID := tables[index].TableReference.TableID
			if strings.TrimSpace(tableID) == "" {
				continue
			}
			var raw json.RawMessage
			if err := fetch(path+"/"+url.PathEscape(tableID), nil, &raw); err != nil {
				return nil, "", err
			}
			if len(raw) == 0 {
				continue
			}
			var detailed BigQueryTableRecord
			if err := json.Unmarshal(raw, &detailed); err != nil {
				return nil, "", fmt.Errorf("decode gcp bigquery table detail: %w", err)
			}
			detailed.DatasetID = datasetID
			detailed.DatasetLocation = dataset.Location
			detailed.Raw = append(json.RawMessage(nil), raw...)
			tables[index] = detailed
		}
		return tables, response.NextPageToken, nil
	}, func(record *BigQueryTableRecord, dataset BigQueryDatasetRecord) {
		record.DatasetID = dataset.DatasetReference.DatasetID
		record.DatasetLocation = dataset.Location
	})
}

func CollectBigtableTables(instances []BigtableInstanceRecord, limit int, fetch PathFetcher) ([]BigtableTableRecord, error) {
	return CollectChildPages(instances, func(instance BigtableInstanceRecord) string { return instance.Name }, func(instance BigtableInstanceRecord, pageToken string) ([]BigtableTableRecord, string, error) {
		query := url.Values{"view": {"FULL"}}
		AddPageToken(query, pageToken)
		var response BigtablePageResponse
		if err := fetch("/v2/"+EscapePathSegments(instance.Name)+"/tables", query, &response); err != nil {
			return nil, "", err
		}
		tables, err := DecodeRecords(response.Tables, "gcp bigtable table", SaveRawField[BigtableTableRecord])
		return tables, response.NextPageToken, err
	}, func(record *BigtableTableRecord, instance BigtableInstanceRecord) {
		record.InstanceName = instance.Name
	})
}

func CollectCloudSQLChildRecords[T any](projectID, collection, label string, instances []CloudSQLInstanceRecord, limit int, fetch PathFetcher, attach func(*T, CloudSQLInstanceRecord)) ([]T, error) {
	return CollectChildPages(instances, func(instance CloudSQLInstanceRecord) string { return instance.Name }, func(instance CloudSQLInstanceRecord, pageToken string) ([]T, string, error) {
		query := url.Values{"maxResults": {fmt.Sprint(limit)}}
		AddPageToken(query, pageToken)
		var response CloudSQLItemsPageResponse
		path := "/sql/v1beta4/projects/" + url.PathEscape(projectID) + "/instances/" + url.PathEscape(instance.Name) + "/" + strings.Trim(collection, "/")
		if err := fetch(path, query, &response); err != nil {
			return nil, "", err
		}
		records, err := DecodeRecords(response.Items, label, SaveRawField[T])
		return records, response.NextPageToken, err
	}, attach)
}

func CollectSpannerDatabases(instances []SpannerInstanceRecord, limit int, fetch PathFetcher) ([]SpannerDatabaseRecord, error) {
	return CollectChildPages(instances, func(instance SpannerInstanceRecord) string { return instance.Name }, func(instance SpannerInstanceRecord, pageToken string) ([]SpannerDatabaseRecord, string, error) {
		query := url.Values{"pageSize": {fmt.Sprint(limit)}}
		AddPageToken(query, pageToken)
		var response SpannerPageResponse
		if err := fetch("/v1/"+EscapePathSegments(instance.Name)+"/databases", query, &response); err != nil {
			return nil, "", err
		}
		databases, err := DecodeRecords(response.Databases, "gcp spanner database", SaveRawField[SpannerDatabaseRecord])
		return databases, response.NextPageToken, err
	}, func(record *SpannerDatabaseRecord, instance SpannerInstanceRecord) {
		record.InstanceName = instance.Name
	})
}

func CollectSecretVersions(secrets []SecretRecord, limit int, fetch PathFetcher) ([]SecretVersionRecord, error) {
	return CollectChildPages(secrets, func(secret SecretRecord) string { return secret.Name }, func(secret SecretRecord, pageToken string) ([]SecretVersionRecord, string, error) {
		query := url.Values{"pageSize": {fmt.Sprint(limit)}}
		AddPageToken(query, pageToken)
		var response SecretManagerPageResponse
		path := "/v1/" + EscapePathSegments(secret.Name) + "/versions"
		if err := fetch(path, query, &response); err != nil {
			return nil, "", err
		}
		versions, err := DecodeRecords(response.Versions, "gcp secret version", SaveRawField[SecretVersionRecord])
		return versions, response.NextPageToken, err
	}, func(record *SecretVersionRecord, secret SecretRecord) {
		record.SecretName = secret.Name
		record.SecretLocation = SecretLocation(secret)
	})
}
