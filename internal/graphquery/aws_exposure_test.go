package graphquery

import (
	"context"
	"errors"
	"testing"

	"github.com/writer/cerebro/internal/ports"
)

type awsExposureStubStore struct {
	requests  []ports.CypherQueryRequest
	responses [][]ports.CypherRow
	err       error
}

func (s *awsExposureStubStore) Ping(context.Context) error {
	return s.err
}

func (s *awsExposureStubStore) GetEntityNeighborhood(context.Context, string, int) (*ports.EntityNeighborhood, error) {
	return nil, nil
}

func (s *awsExposureStubStore) ExecuteReadCypher(_ context.Context, request ports.CypherQueryRequest) ([]ports.CypherRow, error) {
	s.requests = append(s.requests, request)
	if s.err != nil {
		return nil, s.err
	}
	if len(s.responses) == 0 {
		return nil, nil
	}
	rows := s.responses[0]
	s.responses = s.responses[1:]
	return rows, nil
}

func TestGetAWSPublicEndpointInsightsRequiresTenant(t *testing.T) {
	_, err := New(&awsExposureStubStore{}).GetAWSPublicEndpointInsights(context.Background(), AWSPublicEndpointInsightsRequest{})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("GetAWSPublicEndpointInsights() error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestGetAWSPublicEndpointInsightsQueriesAndParsesRows(t *testing.T) {
	store := &awsExposureStubStore{responses: [][]ports.CypherRow{
		{{Values: map[string]any{
			"aws_endpoint_count":                   int64(7),
			"internet_indicator_count":             int64(8),
			"internet_host_count":                  int64(6),
			"internet_ip_count":                    int64(2),
			"overlapping_aws_endpoint_count":       int64(3),
			"overlapping_internet_indicator_count": int64(4),
			"overlapping_vulnview_asset_count":     int64(5),
		}}},
		{{Values: map[string]any{"entity_type": "aws.application.load.balancer", "count": int64(4)}}},
		{{Values: map[string]any{
			"aws_urn":               "urn:cerebro:example:aws_application_load_balancer:alb",
			"aws_entity_type":       "aws.application.load.balancer",
			"aws_label":             "alb",
			"indicator_urn":         "urn:cerebro:example:internet_host:app.example.com",
			"indicator_entity_type": "internet.host",
			"indicator_label":       "app.example.com",
			"vulnview_urn":          "urn:cerebro:example:external_asset:app.example.com",
			"vulnview_entity_type":  "external.asset",
			"vulnview_label":        "app.example.com",
		}}},
		{{Values: map[string]any{
			"aws_urn":               "urn:cerebro:example:aws_elastic_ip:eipalloc-1",
			"aws_entity_type":       "aws.elastic.ip",
			"aws_label":             "eipalloc-1",
			"indicator_urn":         "urn:cerebro:example:internet_ip:192.0.2.10",
			"indicator_entity_type": "internet.ip",
			"indicator_label":       "192.0.2.10",
		}}},
		{{Values: map[string]any{
			"vulnview_urn":          "urn:cerebro:example:external_asset:missing.example.com",
			"vulnview_entity_type":  "external.asset",
			"vulnview_label":        "missing.example.com",
			"indicator_urn":         "urn:cerebro:example:internet_host:missing.example.com",
			"indicator_entity_type": "internet.host",
			"indicator_label":       "missing.example.com",
		}}},
		{{Values: map[string]any{
			"account_urn":         "urn:cerebro:example:cloud_account:account-a",
			"account_entity_type": "cloud.account",
			"account_label":       "account-a",
			"aws_endpoint_count":  int64(9),
			"vulnview_scan_count": int64(2),
		}}},
	}}

	result, err := New(store).GetAWSPublicEndpointInsights(context.Background(), AWSPublicEndpointInsightsRequest{
		TenantID:  "example",
		AccountID: "account-a",
		Region:    "us-east-1",
		Search:    "App",
		Limit:     250,
	})
	if err != nil {
		t.Fatalf("GetAWSPublicEndpointInsights() error = %v", err)
	}
	if len(store.requests) != 6 {
		t.Fatalf("query count = %d, want 6", len(store.requests))
	}
	if got := store.requests[0].Params["tenant_id"]; got != "example" {
		t.Fatalf("tenant_id param = %v, want example", got)
	}
	if got := store.requests[0].Params["account_id"]; got != "account-a" {
		t.Fatalf("account_id param = %v, want account-a", got)
	}
	if got := store.requests[0].Params["region"]; got != "us-east-1" {
		t.Fatalf("region param = %v, want us-east-1", got)
	}
	if got := store.requests[0].Params["search"]; got != "app" {
		t.Fatalf("search param = %v, want app", got)
	}
	if got := store.requests[2].RowLimit; got != maxAWSExposureLimit {
		t.Fatalf("sample row limit = %d, want %d", got, maxAWSExposureLimit)
	}
	if result.Counts.AWSEndpoints != 7 || result.Counts.OverlappingVulnViewAssets != 5 {
		t.Fatalf("counts = %#v", result.Counts)
	}
	if len(result.TypeCounts) != 1 || result.TypeCounts[0].EntityType != "aws.application.load.balancer" {
		t.Fatalf("type counts = %#v", result.TypeCounts)
	}
	if len(result.Overlaps) != 1 || result.Overlaps[0].InternetIndicator.Label != "app.example.com" {
		t.Fatalf("overlaps = %#v", result.Overlaps)
	}
	if len(result.AWSOnly) != 1 || result.AWSOnly[0].InternetIndicator.EntityType != "internet.ip" {
		t.Fatalf("aws_only = %#v", result.AWSOnly)
	}
	if len(result.VulnViewOnly) != 1 || result.VulnViewOnly[0].VulnViewAsset.Label != "missing.example.com" {
		t.Fatalf("vulnview_only = %#v", result.VulnViewOnly)
	}
	if len(result.CloudAccounts) != 1 || result.CloudAccounts[0].VulnViewScans != 2 {
		t.Fatalf("cloud_accounts = %#v", result.CloudAccounts)
	}
	if result.NeighborhoodURN != "urn:cerebro:example:internet_host:app.example.com" {
		t.Fatalf("neighborhood hint = %q", result.NeighborhoodURN)
	}
}
