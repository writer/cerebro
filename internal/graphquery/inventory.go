package graphquery

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/ports"
)

const (
	defaultInventoryLimit = 100
	maxInventoryLimit     = 500
)

type InventoryCategoryRequest struct {
	TenantID string
	SourceID string
	Limit    uint32
}

type InventoryAssetRequest struct {
	TenantID   string
	SourceID   string
	CategoryID string
	EntityType string
	Query      string
	Limit      uint32
}

type InventoryAssetDetailRequest struct {
	URN   string
	Limit uint32
}

type InventoryCategory struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	EntityTypes []string `json:"entity_types"`
	Count       int      `json:"count"`
}

type InventoryAsset struct {
	URN        string            `json:"urn"`
	EntityType string            `json:"entity_type"`
	Label      string            `json:"label"`
	SourceID   string            `json:"source_id,omitempty"`
	RuntimeID  string            `json:"runtime_id,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type InventoryAssetDetail struct {
	Asset     InventoryAsset             `json:"asset"`
	Graph     *ports.EntityNeighborhood  `json:"graph,omitempty"`
	Generated map[string]InventorySignal `json:"generated,omitempty"`
}

type InventorySignal struct {
	Count int    `json:"count"`
	State string `json:"state"`
}

func (s *Service) ListInventoryCategories(ctx context.Context, request InventoryCategoryRequest) ([]InventoryCategory, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	tenantID := strings.TrimSpace(request.TenantID)
	rows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: `MATCH (e:Entity)
WHERE ($tenant_id = '' OR e.tenant_id = $tenant_id)
  AND ($source_id = '' OR e.source_id = $source_id)
  AND NOT e.entity_type IN $excluded_entity_types
RETURN e.entity_type AS entity_type, count(e) AS count
ORDER BY count DESC, entity_type ASC
LIMIT $limit`,
		Params: map[string]any{
			"tenant_id":             tenantID,
			"source_id":             strings.TrimSpace(request.SourceID),
			"excluded_entity_types": excludedInventoryEntityTypes(),
			"limit":                 normalizeInventoryLimit(request.Limit),
		},
		RowLimit: normalizeInventoryLimit(request.Limit),
	})
	if err != nil {
		return nil, err
	}
	grouped := map[string]*InventoryCategory{}
	for _, row := range rows {
		entityType := rowString(row, "entity_type")
		if entityType == "" {
			continue
		}
		count := rowInt(row, "count")
		id, label := inventoryCategoryForEntityType(entityType)
		category := grouped[id]
		if category == nil {
			category = &InventoryCategory{ID: id, Label: label}
			grouped[id] = category
		}
		category.EntityTypes = append(category.EntityTypes, entityType)
		category.Count += count
	}
	categories := make([]InventoryCategory, 0, len(grouped))
	for _, category := range grouped {
		sort.Strings(category.EntityTypes)
		categories = append(categories, *category)
	}
	sort.Slice(categories, func(i, j int) bool {
		if categories[i].Count != categories[j].Count {
			return categories[i].Count > categories[j].Count
		}
		return categories[i].Label < categories[j].Label
	})
	return categories, nil
}

func (s *Service) ListInventoryAssets(ctx context.Context, request InventoryAssetRequest) ([]InventoryAsset, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	entityTypes := inventoryEntityTypesForFilter(request.CategoryID, request.EntityType)
	query := strings.ToLower(strings.TrimSpace(request.Query))
	rows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: `MATCH (e:Entity)
WHERE ($tenant_id = '' OR e.tenant_id = $tenant_id)
  AND ($source_id = '' OR e.source_id = $source_id)
  AND (size($entity_types) = 0 OR e.entity_type IN $entity_types)
  AND NOT e.entity_type IN $excluded_entity_types
  AND ($q = '' OR toLower(coalesce(e.label, '')) CONTAINS $q OR toLower(e.urn) CONTAINS $q OR toLower(coalesce(e.attributes_json, '')) CONTAINS $q)
RETURN e.urn AS urn, e.entity_type AS entity_type, e.label AS label, e.source_id AS source_id, e.runtime_id AS runtime_id, coalesce(e.attributes_json, '{}') AS attributes_json
ORDER BY e.entity_type ASC, e.label ASC, e.urn ASC
LIMIT $limit`,
		Params: map[string]any{
			"tenant_id":             strings.TrimSpace(request.TenantID),
			"source_id":             strings.TrimSpace(request.SourceID),
			"entity_types":          entityTypes,
			"excluded_entity_types": excludedInventoryEntityTypes(),
			"q":                     query,
			"limit":                 normalizeInventoryLimit(request.Limit),
		},
		RowLimit: normalizeInventoryLimit(request.Limit),
	})
	if err != nil {
		return nil, err
	}
	assets := make([]InventoryAsset, 0, len(rows))
	for _, row := range rows {
		asset := inventoryAssetFromRow(row)
		if strings.TrimSpace(asset.URN) != "" {
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func (s *Service) GetInventoryAsset(ctx context.Context, request InventoryAssetDetailRequest) (*InventoryAssetDetail, error) {
	if s == nil || s.store == nil {
		return nil, ErrRuntimeUnavailable
	}
	urn := strings.TrimSpace(request.URN)
	if urn == "" {
		return nil, fmt.Errorf("%w: asset urn is required", ErrInvalidRequest)
	}
	if err := validateCerebroURN(urn); err != nil {
		return nil, err
	}
	rows, err := s.store.ExecuteReadCypher(ctx, ports.CypherQueryRequest{
		Query: `MATCH (e:Entity {urn: $urn})
RETURN e.urn AS urn, e.entity_type AS entity_type, e.label AS label, e.source_id AS source_id, e.runtime_id AS runtime_id, coalesce(e.attributes_json, '{}') AS attributes_json
LIMIT 1`,
		Params:   map[string]any{"urn": urn},
		RowLimit: 1,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ports.ErrGraphEntityNotFound
	}
	limit := normalizeInventoryLimit(request.Limit)
	if limit > maxNeighborhoodLimit {
		limit = maxNeighborhoodLimit
	}
	graph, err := s.GetEntityNeighborhood(ctx, NeighborhoodRequest{RootURN: urn, Limit: uint32(limit)})
	if err != nil {
		return nil, err
	}
	return &InventoryAssetDetail{
		Asset: inventoryAssetFromRow(rows[0]),
		Graph: graph,
		Generated: map[string]InventorySignal{
			"neighborhood": {Count: len(graph.Neighbors), State: "available"},
		},
	}, nil
}

func normalizeInventoryLimit(limit uint32) int {
	switch {
	case limit == 0:
		return defaultInventoryLimit
	case limit > maxInventoryLimit:
		return maxInventoryLimit
	default:
		return int(limit)
	}
}

func inventoryAssetFromRow(row ports.CypherRow) InventoryAsset {
	return InventoryAsset{
		URN:        rowString(row, "urn"),
		EntityType: rowString(row, "entity_type"),
		Label:      firstInventoryString(rowString(row, "label"), rowString(row, "urn")),
		SourceID:   rowString(row, "source_id"),
		RuntimeID:  rowString(row, "runtime_id"),
		Attributes: parseInventoryAttributes(rowString(row, "attributes_json")),
	}
}

func parseInventoryAttributes(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		return nil
	}
	var values map[string]any
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	attrs := map[string]string{}
	for key, value := range values {
		if strings.TrimSpace(key) == "" || value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				attrs[key] = typed
			}
		case float64, bool:
			attrs[key] = fmt.Sprint(typed)
		}
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

func rowString(row ports.CypherRow, key string) string {
	value := row.Values[key]
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		if value == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

func rowInt(row ports.CypherRow, key string) int {
	value := row.Values[key]
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		var parsed int
		_, _ = fmt.Sscanf(fmt.Sprint(value), "%d", &parsed)
		return parsed
	}
}

func firstInventoryString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func excludedInventoryEntityTypes() []string {
	return []string{
		"asset_tag",
		"evidence",
		"finding",
		"grc.control",
		"grc.document",
		"grc.framework",
		"grc.policy",
		"grc.risk_scenario",
		"internet.host",
		"internet.ip",
		"package",
		"vulnerability",
	}
}

func inventoryEntityTypesForFilter(categoryID string, entityType string) []string {
	entityType = strings.TrimSpace(entityType)
	if entityType != "" {
		return []string{entityType}
	}
	categoryID = strings.TrimSpace(categoryID)
	if categoryID == "" {
		return nil
	}
	var result []string
	for candidate, category := range inventoryCategoryLookup() {
		if category.id == categoryID {
			result = append(result, candidate)
		}
	}
	sort.Strings(result)
	return result
}

type inventoryCategoryLabel struct {
	id    string
	label string
}

func inventoryCategoryForEntityType(entityType string) (string, string) {
	if label, ok := inventoryCategoryLookup()[strings.TrimSpace(entityType)]; ok {
		return label.id, label.label
	}
	normalized := strings.ReplaceAll(strings.TrimSpace(entityType), ".", "-")
	if normalized == "" {
		normalized = "other"
	}
	return normalized, titleInventoryCategory(entityType)
}

func inventoryCategoryLookup() map[string]inventoryCategoryLabel {
	return map[string]inventoryCategoryLabel{
		"aws.ec2.instance":        {"compute-instances", "Compute instances"},
		"gcp.compute.instance":    {"compute-instances", "Compute instances"},
		"kubernetes.node":         {"kubernetes-nodes", "Kubernetes nodes"},
		"kubernetes.cluster":      {"kubernetes-clusters", "Kubernetes clusters"},
		"github.code.repository":  {"git-repositories", "Git repositories"},
		"github.org":              {"github-organizations", "GitHub organizations"},
		"github.org.member":       {"github-members", "GitHub members"},
		"aws.s3.bucket":           {"block-storage", "Block storage"},
		"aws.ebs.volume":          {"block-storage", "Block storage"},
		"aws.elb.load_balancer":   {"load-balancers", "Load balancers"},
		"aws.rds.instance":        {"databases", "Databases"},
		"aws.dynamodb.table":      {"databases", "Databases"},
		"grc.integration":         {"integrations", "Integrations"},
		"grc.person":              {"people", "People"},
		"grc.target":              {"inventory-targets", "Inventory targets"},
		"grc.user":                {"people", "People"},
		"sentinelone.agent":       {"computers", "Computers"},
		"trusted_endpoint.device": {"computers", "Computers"},
		"kolide.device":           {"computers", "Computers"},
		"kandji.device":           {"computers", "Computers"},
		"cloudflare.dns.record":   {"domains", "Domains"},
		"cloudflare.zone":         {"domains", "Domains"},
		"gcp.service_account":     {"service-accounts", "Service accounts"},
		"aws.iam.role":            {"access", "Access"},
		"aws.iam.user":            {"access", "Access"},
		"okta.user":               {"people", "People"},
		"okta.group":              {"access", "Access"},
		"googleworkspace.user":    {"people", "People"},
		"googleworkspace.group":   {"access", "Access"},
	}
}

func titleInventoryCategory(entityType string) string {
	entityType = strings.TrimSpace(entityType)
	if entityType == "" {
		return "Other"
	}
	parts := strings.Fields(strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(entityType))
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}
