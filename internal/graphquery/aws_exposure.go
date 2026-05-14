package graphquery

import (
	"context"
	"fmt"
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
	Filters         AWSPublicEndpointInsightFilters    `json:"filters"`
	Counts          AWSPublicEndpointInsightCounts     `json:"counts"`
	TypeCounts      []AWSPublicEndpointTypeCount       `json:"type_counts"`
	Overlaps        []AWSPublicEndpointOverlapSample   `json:"overlaps"`
	AWSOnly         []AWSPublicEndpointIndicatorSample `json:"aws_only"`
	VulnViewOnly    []VulnViewOnlyIndicatorSample      `json:"vulnview_only"`
	CloudAccounts   []CloudAccountCoverageSample       `json:"cloud_accounts"`
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

func (s *Service) GetAWSPublicEndpointInsights(ctx context.Context, request AWSPublicEndpointInsightsRequest) (*AWSPublicEndpointInsightsResult, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	limit := normalizeAWSExposureLimit(request.Limit)
	params := awsExposureParams(tenantID, request)
	result := &AWSPublicEndpointInsightsResult{
		TenantID: tenantID,
		Filters: AWSPublicEndpointInsightFilters{
			AccountID: strings.TrimSpace(request.AccountID),
			Region:    strings.TrimSpace(request.Region),
			Search:    strings.TrimSpace(request.Search),
			Limit:     limit,
		},
	}

	countRows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: awsExposureCountsQuery, Params: params, RowLimit: 1})
	if err != nil {
		return nil, err
	}
	if len(countRows) > 0 {
		result.Counts = awsExposureCountsFromRow(countRows[0])
	}

	typeRows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: awsExposureTypeCountsQuery, Params: params, RowLimit: 50})
	if err != nil {
		return nil, err
	}
	result.TypeCounts = awsExposureTypeCountsFromRows(typeRows)

	overlapRows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: awsExposureOverlapSamplesQuery, Params: params, RowLimit: limit})
	if err != nil {
		return nil, err
	}
	result.Overlaps = awsExposureOverlapSamplesFromRows(overlapRows)

	awsOnlyRows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: awsExposureAWSOnlySamplesQuery, Params: params, RowLimit: limit})
	if err != nil {
		return nil, err
	}
	result.AWSOnly = awsExposureAWSOnlySamplesFromRows(awsOnlyRows)

	vulnViewOnlyRows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: awsExposureVulnViewOnlySamplesQuery, Params: params, RowLimit: limit})
	if err != nil {
		return nil, err
	}
	result.VulnViewOnly = awsExposureVulnViewOnlySamplesFromRows(vulnViewOnlyRows)

	cloudAccountRows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{Query: awsExposureCloudAccountSamplesQuery, Params: params, RowLimit: limit})
	if err != nil {
		return nil, err
	}
	result.CloudAccounts = awsExposureCloudAccountsFromRows(cloudAccountRows)

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

func awsExposureParams(tenantID string, request AWSPublicEndpointInsightsRequest) map[string]any {
	limit := normalizeAWSExposureLimit(request.Limit)
	return map[string]any{
		"account_id":   strings.TrimSpace(request.AccountID),
		"region":       strings.TrimSpace(request.Region),
		"sample_limit": int64(limit),
		"search":       strings.ToLower(strings.TrimSpace(request.Search)),
		"tenant_id":    tenantID,
	}
}

const awsExposureEndpointFilter = `endpoint.entity_type STARTS WITH 'aws.'
  AND indicator.entity_type IN ['internet.host', 'internet.ip']
  AND ($account_id = '' OR coalesce(endpoint.attributes_json, '') CONTAINS ('"domain":"' + $account_id + '"'))
  AND ($region = '' OR endpoint.urn CONTAINS (':' + $region + ':') OR coalesce(endpoint.attributes_json, '') CONTAINS ('"' + $region + '"'))
  AND ($search = '' OR toLower(coalesce(endpoint.urn, '') + ' ' + coalesce(endpoint.label, '') + ' ' + coalesce(indicator.urn, '') + ' ' + coalesce(indicator.label, '')) CONTAINS $search)`

const awsExposureEndpointAccountFilter = `endpoint.entity_type STARTS WITH 'aws.'
  AND ($account_id = '' OR account.label = $account_id OR account.urn CONTAINS $account_id OR coalesce(endpoint.attributes_json, '') CONTAINS ('"domain":"' + $account_id + '"'))
  AND ($region = '' OR endpoint.urn CONTAINS (':' + $region + ':') OR coalesce(endpoint.attributes_json, '') CONTAINS ('"' + $region + '"'))
  AND ($search = '' OR toLower(coalesce(endpoint.urn, '') + ' ' + coalesce(endpoint.label, '') + ' ' + coalesce(account.urn, '') + ' ' + coalesce(account.label, '')) CONTAINS $search)`

const awsExposureCountsQuery = `MATCH (endpoint:Entity {tenant_id: $tenant_id, source_id: 'aws'})-[aws_rel:RELATION {relation: 'represents'}]->(indicator:Entity {tenant_id: $tenant_id})
WHERE ` + awsExposureEndpointFilter + `
OPTIONAL MATCH (asset:Entity {tenant_id: $tenant_id, source_id: 'vulnview', entity_type: 'external.asset'})-[:RELATION {relation: 'represents'}]->(indicator)
RETURN count(DISTINCT endpoint) AS aws_endpoint_count,
       count(DISTINCT indicator) AS internet_indicator_count,
       count(DISTINCT CASE WHEN indicator.entity_type = 'internet.host' THEN indicator END) AS internet_host_count,
       count(DISTINCT CASE WHEN indicator.entity_type = 'internet.ip' THEN indicator END) AS internet_ip_count,
       count(DISTINCT CASE WHEN asset IS NOT NULL THEN endpoint END) AS overlapping_aws_endpoint_count,
       count(DISTINCT CASE WHEN asset IS NOT NULL THEN indicator END) AS overlapping_internet_indicator_count,
       count(DISTINCT asset) AS overlapping_vulnview_asset_count`

const awsExposureTypeCountsQuery = `MATCH (endpoint:Entity {tenant_id: $tenant_id, source_id: 'aws'})-[:RELATION {relation: 'represents'}]->(indicator:Entity {tenant_id: $tenant_id})
WHERE ` + awsExposureEndpointFilter + `
RETURN endpoint.entity_type AS entity_type, count(DISTINCT endpoint) AS count
ORDER BY count DESC, entity_type`

const awsExposureOverlapSamplesQuery = `MATCH (endpoint:Entity {tenant_id: $tenant_id, source_id: 'aws'})-[:RELATION {relation: 'represents'}]->(indicator:Entity {tenant_id: $tenant_id})
WHERE ` + awsExposureEndpointFilter + `
MATCH (asset:Entity {tenant_id: $tenant_id, source_id: 'vulnview', entity_type: 'external.asset'})-[:RELATION {relation: 'represents'}]->(indicator)
RETURN endpoint.urn AS aws_urn,
       endpoint.entity_type AS aws_entity_type,
       endpoint.label AS aws_label,
       indicator.urn AS indicator_urn,
       indicator.entity_type AS indicator_entity_type,
       indicator.label AS indicator_label,
       asset.urn AS vulnview_urn,
       asset.entity_type AS vulnview_entity_type,
       asset.label AS vulnview_label
ORDER BY indicator.label, endpoint.label, asset.label
LIMIT $sample_limit`

const awsExposureAWSOnlySamplesQuery = `MATCH (endpoint:Entity {tenant_id: $tenant_id, source_id: 'aws'})-[:RELATION {relation: 'represents'}]->(indicator:Entity {tenant_id: $tenant_id})
WHERE ` + awsExposureEndpointFilter + `
  AND NOT EXISTS {
    MATCH (:Entity {tenant_id: $tenant_id, source_id: 'vulnview', entity_type: 'external.asset'})-[:RELATION {relation: 'represents'}]->(indicator)
  }
RETURN endpoint.urn AS aws_urn,
       endpoint.entity_type AS aws_entity_type,
       endpoint.label AS aws_label,
       indicator.urn AS indicator_urn,
       indicator.entity_type AS indicator_entity_type,
       indicator.label AS indicator_label
ORDER BY indicator.label, endpoint.label
LIMIT $sample_limit`

const awsExposureVulnViewOnlySamplesQuery = `MATCH (asset:Entity {tenant_id: $tenant_id, source_id: 'vulnview', entity_type: 'external.asset'})-[:RELATION {relation: 'represents'}]->(indicator:Entity {tenant_id: $tenant_id})
WHERE indicator.entity_type IN ['internet.host', 'internet.ip']
  AND $account_id = ''
  AND $region = ''
  AND ($search = '' OR toLower(coalesce(asset.urn, '') + ' ' + coalesce(asset.label, '') + ' ' + coalesce(indicator.urn, '') + ' ' + coalesce(indicator.label, '')) CONTAINS $search)
  AND NOT EXISTS {
    MATCH (endpoint:Entity {tenant_id: $tenant_id, source_id: 'aws'})-[:RELATION {relation: 'represents'}]->(indicator)
    WHERE endpoint.entity_type STARTS WITH 'aws.'
  }
RETURN asset.urn AS vulnview_urn,
       asset.entity_type AS vulnview_entity_type,
       asset.label AS vulnview_label,
       indicator.urn AS indicator_urn,
       indicator.entity_type AS indicator_entity_type,
       indicator.label AS indicator_label
ORDER BY indicator.label, asset.label
LIMIT $sample_limit`

const awsExposureCloudAccountSamplesQuery = `MATCH (endpoint:Entity {tenant_id: $tenant_id, source_id: 'aws'})-[:RELATION {relation: 'belongs_to'}]->(account:Entity {tenant_id: $tenant_id, entity_type: 'cloud.account'})
WHERE ` + awsExposureEndpointAccountFilter + `
OPTIONAL MATCH (scan:Entity {tenant_id: $tenant_id, source_id: 'vulnview', entity_type: 'vulnview.scan'})-[:RELATION {relation: 'belongs_to'}]->(account)
RETURN account.urn AS account_urn,
       account.entity_type AS account_entity_type,
       account.label AS account_label,
       count(DISTINCT endpoint) AS aws_endpoint_count,
       count(DISTINCT scan) AS vulnview_scan_count
ORDER BY aws_endpoint_count DESC, account.label
LIMIT $sample_limit`

func awsExposureCountsFromRow(row ports.CypherRow) AWSPublicEndpointInsightCounts {
	return AWSPublicEndpointInsightCounts{
		AWSEndpoints:                  cypherInt(row, "aws_endpoint_count"),
		InternetIndicators:            cypherInt(row, "internet_indicator_count"),
		InternetHosts:                 cypherInt(row, "internet_host_count"),
		InternetIPs:                   cypherInt(row, "internet_ip_count"),
		OverlappingAWSEndpoints:       cypherInt(row, "overlapping_aws_endpoint_count"),
		OverlappingInternetIndicators: cypherInt(row, "overlapping_internet_indicator_count"),
		OverlappingVulnViewAssets:     cypherInt(row, "overlapping_vulnview_asset_count"),
	}
}

func awsExposureTypeCountsFromRows(rows []ports.CypherRow) []AWSPublicEndpointTypeCount {
	result := make([]AWSPublicEndpointTypeCount, 0, len(rows))
	for _, row := range rows {
		entityType := cypherString(row, "entity_type")
		if entityType == "" {
			continue
		}
		result = append(result, AWSPublicEndpointTypeCount{EntityType: entityType, Count: cypherInt(row, "count")})
	}
	return result
}

func awsExposureOverlapSamplesFromRows(rows []ports.CypherRow) []AWSPublicEndpointOverlapSample {
	result := make([]AWSPublicEndpointOverlapSample, 0, len(rows))
	for _, row := range rows {
		sample := AWSPublicEndpointOverlapSample{
			AWSEndpoint:       awsEndpointRef(row),
			InternetIndicator: indicatorRef(row),
			VulnViewAsset:     vulnViewAssetRef(row),
		}
		if sample.AWSEndpoint.URN == "" || sample.InternetIndicator.URN == "" || sample.VulnViewAsset.URN == "" {
			continue
		}
		result = append(result, sample)
	}
	return result
}

func awsExposureAWSOnlySamplesFromRows(rows []ports.CypherRow) []AWSPublicEndpointIndicatorSample {
	result := make([]AWSPublicEndpointIndicatorSample, 0, len(rows))
	for _, row := range rows {
		sample := AWSPublicEndpointIndicatorSample{AWSEndpoint: awsEndpointRef(row), InternetIndicator: indicatorRef(row)}
		if sample.AWSEndpoint.URN == "" || sample.InternetIndicator.URN == "" {
			continue
		}
		result = append(result, sample)
	}
	return result
}

func awsExposureVulnViewOnlySamplesFromRows(rows []ports.CypherRow) []VulnViewOnlyIndicatorSample {
	result := make([]VulnViewOnlyIndicatorSample, 0, len(rows))
	for _, row := range rows {
		sample := VulnViewOnlyIndicatorSample{VulnViewAsset: vulnViewAssetRef(row), InternetIndicator: indicatorRef(row)}
		if sample.VulnViewAsset.URN == "" || sample.InternetIndicator.URN == "" {
			continue
		}
		result = append(result, sample)
	}
	return result
}

func awsExposureCloudAccountsFromRows(rows []ports.CypherRow) []CloudAccountCoverageSample {
	result := make([]CloudAccountCoverageSample, 0, len(rows))
	for _, row := range rows {
		account := GraphEntityRef{
			URN:        cypherString(row, "account_urn"),
			EntityType: cypherString(row, "account_entity_type"),
			Label:      cypherString(row, "account_label"),
		}
		if account.URN == "" {
			continue
		}
		result = append(result, CloudAccountCoverageSample{
			Account:       account,
			AWSEndpoints:  cypherInt(row, "aws_endpoint_count"),
			VulnViewScans: cypherInt(row, "vulnview_scan_count"),
		})
	}
	return result
}

func awsEndpointRef(row ports.CypherRow) GraphEntityRef {
	return GraphEntityRef{URN: cypherString(row, "aws_urn"), EntityType: cypherString(row, "aws_entity_type"), Label: cypherString(row, "aws_label")}
}

func indicatorRef(row ports.CypherRow) GraphEntityRef {
	return GraphEntityRef{URN: cypherString(row, "indicator_urn"), EntityType: cypherString(row, "indicator_entity_type"), Label: cypherString(row, "indicator_label")}
}

func vulnViewAssetRef(row ports.CypherRow) GraphEntityRef {
	return GraphEntityRef{URN: cypherString(row, "vulnview_urn"), EntityType: cypherString(row, "vulnview_entity_type"), Label: cypherString(row, "vulnview_label")}
}

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

func cypherInt(row ports.CypherRow, key string) int {
	if row.Values == nil {
		return 0
	}
	switch value := row.Values[key].(type) {
	case int:
		return value
	case int8:
		return int(value)
	case int16:
		return int(value)
	case int32:
		return int(value)
	case int64:
		return int(value)
	case uint:
		return int(value)
	case uint8:
		return int(value)
	case uint16:
		return int(value)
	case uint32:
		return int(value)
	case uint64:
		return int(value)
	case float32:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}
