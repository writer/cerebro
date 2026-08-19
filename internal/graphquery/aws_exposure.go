package graphquery

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultAWSExposureLimit = 25
	maxAWSExposureLimit     = 100
)

type AWSPublicEndpointInsightsRequest struct {
	TenantID  string
	AccountID string
	Region    string
	Search    string
	Limit     uint32
}

type AWSPublicEndpointInsightsResult struct {
	TenantID        string                             `json:"tenant_id"`
	GraphRevision   uint64                             `json:"graph_revision"`
	Filters         AWSPublicEndpointInsightFilters    `json:"filters"`
	Counts          AWSPublicEndpointInsightCounts     `json:"counts"`
	TypeCounts      []AWSPublicEndpointTypeCount       `json:"type_counts"`
	Overlaps        []AWSPublicEndpointOverlapSample   `json:"overlaps"`
	AWSOnly         []AWSPublicEndpointIndicatorSample `json:"aws_only"`
	VulnViewOnly    []VulnViewOnlyIndicatorSample      `json:"vulnview_only"`
	CloudAccounts   []CloudAccountCoverageSample       `json:"cloud_accounts"`
	Completeness    ExposureCoverageCompleteness       `json:"completeness"`
	NeighborhoodURN string                             `json:"neighborhood_hint,omitempty"`
}

type AWSPublicEndpointInsightFilters struct {
	AccountID string `json:"account_id,omitempty"`
	Region    string `json:"region,omitempty"`
	Search    string `json:"search,omitempty"`
	Limit     int    `json:"limit"`
}

type AWSPublicEndpointInsightCounts struct {
	AWSEndpoints                  int `json:"aws_endpoints"`
	InternetIndicators            int `json:"internet_indicators"`
	InternetHosts                 int `json:"internet_hosts"`
	InternetIPs                   int `json:"internet_ips"`
	OverlappingAWSEndpoints       int `json:"overlapping_aws_endpoints"`
	OverlappingInternetIndicators int `json:"overlapping_internet_indicators"`
	OverlappingVulnViewAssets     int `json:"overlapping_vulnview_assets"`
}

type AWSPublicEndpointTypeCount struct {
	EntityType string `json:"entity_type"`
	Count      int    `json:"count"`
}

type GraphEntityRef struct {
	URN        string `json:"urn"`
	EntityType string `json:"entity_type"`
	Label      string `json:"label"`
}

type AWSPublicEndpointOverlapSample struct {
	AWSEndpoint       GraphEntityRef `json:"aws_endpoint"`
	InternetIndicator GraphEntityRef `json:"internet_indicator"`
	VulnViewAsset     GraphEntityRef `json:"vulnview_asset"`
}

type AWSPublicEndpointIndicatorSample struct {
	AWSEndpoint       GraphEntityRef `json:"aws_endpoint"`
	InternetIndicator GraphEntityRef `json:"internet_indicator"`
}

type VulnViewOnlyIndicatorSample struct {
	VulnViewAsset     GraphEntityRef `json:"vulnview_asset"`
	InternetIndicator GraphEntityRef `json:"internet_indicator"`
}

type CloudAccountCoverageSample struct {
	Account       GraphEntityRef `json:"account"`
	AWSEndpoints  int            `json:"aws_endpoints"`
	VulnViewScans int            `json:"vulnview_scans"`
}

// ExposureCoverageCompleteness makes every bounded server collection explicit.
type ExposureCoverageCompleteness struct {
	TypeCountsTruncated    bool `json:"type_counts_truncated"`
	OverlapsTruncated      bool `json:"overlaps_truncated"`
	AWSOnlyTruncated       bool `json:"aws_only_truncated"`
	VulnViewOnlyTruncated  bool `json:"vulnview_only_truncated"`
	CloudAccountsTruncated bool `json:"cloud_accounts_truncated"`
}

func (s *Service) GetAWSPublicEndpointInsights(ctx context.Context, request AWSPublicEndpointInsightsRequest) (*AWSPublicEndpointInsightsResult, error) {
	if s == nil || s.exposure == nil {
		return nil, fmt.Errorf("%w: typed exposure coverage is unavailable", ErrRuntimeUnavailable)
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	store := s.exposure
	limit := normalizeAWSExposureLimit(request.Limit)
	typed, err := store.CompareExposureCoverage(ctx, ports.ExposureCoverageRequest{
		TenantID: tenantID,
		Profile: ports.ExposureCoverageProfile{
			PrimarySourceID:              "aws",
			PrimaryEntityKindPrefix:      "aws.",
			CorroboratingSourceID:        "vulnview",
			CorroboratingEntityKind:      "external.asset",
			IndicatorKinds:               []string{"internet.host", "internet.ip"},
			AccountKind:                  "cloud.account",
			CorroboratingObservationKind: "vulnview.scan",
		},
		AccountID: strings.TrimSpace(request.AccountID),
		Region:    strings.TrimSpace(request.Region),
		Query:     strings.TrimSpace(request.Search),
		Limit:     limit,
	})
	if err != nil {
		return nil, err
	}
	if typed == nil || typed.TenantID != tenantID {
		return nil, fmt.Errorf("%w: typed exposure coverage returned an invalid tenant", ErrRuntimeUnavailable)
	}
	result := &AWSPublicEndpointInsightsResult{
		TenantID:      tenantID,
		GraphRevision: typed.GraphRevision,
		Filters: AWSPublicEndpointInsightFilters{
			AccountID: strings.TrimSpace(request.AccountID),
			Region:    strings.TrimSpace(request.Region),
			Search:    strings.TrimSpace(request.Search),
			Limit:     limit,
		},
		Counts: AWSPublicEndpointInsightCounts{
			AWSEndpoints:                  boundedExposureInt(typed.Counts.PrimaryEntities),
			InternetIndicators:            boundedExposureInt(typed.Counts.Indicators),
			InternetHosts:                 boundedExposureInt(typed.Counts.HostIndicators),
			InternetIPs:                   boundedExposureInt(typed.Counts.IPIndicators),
			OverlappingAWSEndpoints:       boundedExposureInt(typed.Counts.OverlappingPrimaryEntities),
			OverlappingInternetIndicators: boundedExposureInt(typed.Counts.OverlappingIndicators),
			OverlappingVulnViewAssets:     boundedExposureInt(typed.Counts.OverlappingCorroboratingEntities),
		},
		Completeness: ExposureCoverageCompleteness{
			TypeCountsTruncated:    typed.Completeness.TypeCountsTruncated,
			OverlapsTruncated:      typed.Completeness.OverlapsTruncated,
			AWSOnlyTruncated:       typed.Completeness.PrimaryOnlyTruncated,
			VulnViewOnlyTruncated:  typed.Completeness.CorroboratingOnlyTruncated,
			CloudAccountsTruncated: typed.Completeness.AccountsTruncated,
		},
	}
	for _, value := range typed.TypeCounts {
		result.TypeCounts = append(result.TypeCounts, AWSPublicEndpointTypeCount{EntityType: value.EntityKind, Count: boundedExposureInt(value.Count)})
	}
	for _, value := range typed.Overlaps {
		result.Overlaps = append(result.Overlaps, AWSPublicEndpointOverlapSample{AWSEndpoint: graphEntityRef(value.Primary), InternetIndicator: graphEntityRef(value.Indicator), VulnViewAsset: graphEntityRef(value.Corroborating)})
	}
	for _, value := range typed.PrimaryOnly {
		result.AWSOnly = append(result.AWSOnly, AWSPublicEndpointIndicatorSample{AWSEndpoint: graphEntityRef(value.Primary), InternetIndicator: graphEntityRef(value.Indicator)})
	}
	for _, value := range typed.CorroboratingOnly {
		result.VulnViewOnly = append(result.VulnViewOnly, VulnViewOnlyIndicatorSample{VulnViewAsset: graphEntityRef(value.Corroborating), InternetIndicator: graphEntityRef(value.Indicator)})
	}
	for _, value := range typed.Accounts {
		result.CloudAccounts = append(result.CloudAccounts, CloudAccountCoverageSample{Account: graphEntityRef(value.Account), AWSEndpoints: boundedExposureInt(value.PrimaryEntities), VulnViewScans: boundedExposureInt(value.CorroboratingObservations)})
	}
	if len(result.Overlaps) > 0 {
		result.NeighborhoodURN = result.Overlaps[0].InternetIndicator.URN
	} else if len(result.AWSOnly) > 0 {
		result.NeighborhoodURN = result.AWSOnly[0].InternetIndicator.URN
	} else if len(result.VulnViewOnly) > 0 {
		result.NeighborhoodURN = result.VulnViewOnly[0].InternetIndicator.URN
	}
	return result, nil
}

func normalizeAWSExposureLimit(limit uint32) int {
	switch {
	case limit == 0:
		return defaultAWSExposureLimit
	case limit > maxAWSExposureLimit:
		return maxAWSExposureLimit
	default:
		return int(limit)
	}
}

func graphEntityRef(value ports.ExposureCoverageEntity) GraphEntityRef {
	return GraphEntityRef{URN: value.URN, EntityType: value.EntityType, Label: value.Label}
}

func boundedExposureInt(value uint64) int {
	if value > uint64(math.MaxInt) {
		return math.MaxInt
	}
	return int(value)
}

// cypherString remains shared by the raw-query consumers that have not moved
// behind typed graph operations yet. Exposure coverage does not call it.
func cypherString(row ports.CypherRow, key string) string {
	if row.Values == nil {
		return ""
	}
	value, ok := row.Values[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}
