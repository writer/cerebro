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
