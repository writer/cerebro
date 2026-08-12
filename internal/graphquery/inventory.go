package graphquery

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/writer/cerebro/internal/ports"
	cerebrourn "github.com/writer/cerebro/internal/urn"
)

const (
	defaultInventoryLimit = 100
	maxInventoryLimit     = 500
)

type InventoryCategoryRequest struct {
	TenantID string
	SourceID string
	Surface  string
	Limit    uint32
}

type InventoryAssetRequest struct {
	TenantID   string
	SourceID   string
	Surface    string
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
	Surface     string   `json:"surface,omitempty"`
	EntityTypes []string `json:"entity_types"`
	Count       int      `json:"count"`
}

type InventoryAsset struct {
	URN                        string                      `json:"urn"`
	EntityType                 string                      `json:"entity_type"`
	Surface                    string                      `json:"surface,omitempty"`
	Label                      string                      `json:"label"`
	SourceID                   string                      `json:"source_id,omitempty"`
	RuntimeID                  string                      `json:"runtime_id,omitempty"`
	RiskScore                  int                         `json:"risk_score,omitempty"`
	RiskLevel                  string                      `json:"risk_level,omitempty"`
	RiskReasons                []string                    `json:"risk_reasons,omitempty"`
	ScopeState                 string                      `json:"scope_state,omitempty"`
	ScopeReason                string                      `json:"scope_reason,omitempty"`
	ScopeUpdatedAt             string                      `json:"scope_updated_at,omitempty"`
	AssetReportCount           int                         `json:"asset_report_count,omitempty"`
	LatestAssetReportStatus    string                      `json:"latest_asset_report_status,omitempty"`
	LatestAssetReportReason    string                      `json:"latest_asset_report_reason,omitempty"`
	LatestAssetReportUpdatedAt string                      `json:"latest_asset_report_updated_at,omitempty"`
	ReviewDisposition          *InventoryReviewDisposition `json:"review_disposition,omitempty"`
	Accountability             *InventoryAccountability    `json:"accountability,omitempty"`
	Attributes                 map[string]string           `json:"attributes,omitempty"`
}

type InventoryReviewDisposition struct {
	State   string                  `json:"state"`
	Label   string                  `json:"label"`
	Detail  string                  `json:"detail,omitempty"`
	Reasons []InventoryReviewReason `json:"reasons,omitempty"`
}

type InventoryReviewReason struct {
	Code  string `json:"code"`
	Label string `json:"label"`
}

type InventoryAccountability struct {
	State      string                    `json:"state"`
	Label      string                    `json:"label"`
	Principal  string                    `json:"principal,omitempty"`
	Candidates []InventoryOwnerCandidate `json:"candidates,omitempty"`
	Reasons    []InventoryReviewReason   `json:"reasons,omitempty"`
}

type InventoryOwnerCandidate struct {
	Principal  string `json:"principal"`
	Confidence string `json:"confidence,omitempty"`
	Source     string `json:"source,omitempty"`
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
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	store, ok := s.store.(ports.EntityCatalogStore)
	if !ok {
		return nil, ErrRuntimeUnavailable
	}
	filter := inventoryCatalogFilter(tenantID, request.SourceID, request.Surface)
	page, err := store.CountEntityKinds(ctx, ports.EntityKindCountRequest{Filter: filter, Limit: maxInventoryLimit})
	if err != nil {
		return nil, err
	}
	if page == nil || page.TenantID != tenantID || page.Truncated {
		return nil, fmt.Errorf("%w: inventory category catalog is incomplete", ErrRuntimeUnavailable)
	}
	counts := append([]ports.EntityKindCount(nil), page.Counts...)
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Count != counts[j].Count {
			return counts[i].Count > counts[j].Count
		}
		return counts[i].EntityKind < counts[j].EntityKind
	})
	if limit := normalizeInventoryLimit(request.Limit); len(counts) > limit {
		counts = counts[:limit]
	}
	grouped := map[string]*InventoryCategory{}
	for _, value := range counts {
		entityType := value.EntityKind
		if entityType == "" {
			continue
		}
		count := boundedInventoryCount(value.Count)
		id, label := inventoryCategoryForEntityType(entityType)
		category := grouped[id]
		if category == nil {
			category = &InventoryCategory{ID: id, Label: label, Surface: InventorySurfaceForEntityType(entityType)}
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
	tenantID := strings.TrimSpace(request.TenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: tenant_id is required", ErrInvalidRequest)
	}
	store, ok := s.store.(ports.EntityCatalogStore)
	if !ok {
		return nil, ErrRuntimeUnavailable
	}
	filter := inventoryCatalogFilter(tenantID, request.SourceID, request.Surface)
	filter.Query = strings.TrimSpace(request.Query)
	if len(entityTypes) > 0 {
		filter.IncludeKinds = entityTypes
		filter.IncludeKindPrefixes = nil
	}
	page, err := store.ListEntities(ctx, ports.EntityCatalogPageRequest{Filter: filter, Limit: normalizeInventoryLimit(request.Limit)})
	if err != nil {
		return nil, err
	}
	if page == nil || page.TenantID != tenantID {
		return nil, ErrRuntimeUnavailable
	}
	assets := make([]InventoryAsset, 0, len(page.Entities))
	for _, entity := range page.Entities {
		asset := inventoryAssetFromCatalog(entity)
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
	store, ok := s.store.(ports.EntityCatalogStore)
	if !ok {
		return nil, ErrRuntimeUnavailable
	}
	tenantID := cerebrourn.TenantID(urn)
	page, err := store.ListEntities(ctx, ports.EntityCatalogPageRequest{Filter: ports.EntityCatalogFilter{TenantID: tenantID, ExactAgentKey: urn}, Limit: 1})
	if err != nil {
		return nil, err
	}
	if page == nil || page.TenantID != tenantID {
		return nil, ErrRuntimeUnavailable
	}
	if len(page.Entities) == 0 {
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
		Asset: inventoryAssetFromCatalog(page.Entities[0]),
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

func inventoryAssetFromCatalog(entity ports.CatalogEntity) InventoryAsset {
	attrs := entity.Attributes
	score, reasons := inventoryRisk(attrs)
	return InventoryAsset{URN: entity.URN, EntityType: entity.EntityType, Surface: InventorySurfaceForEntityType(entity.EntityType), Label: firstInventoryString(entity.Label, entity.URN), SourceID: entity.SourceID, RuntimeID: entity.RuntimeID, RiskScore: score, RiskLevel: inventoryRiskLevel(score), RiskReasons: reasons, ScopeState: "in_scope", Attributes: attrs}
}

func inventoryCatalogFilter(tenantID, sourceID, surface string) ports.EntityCatalogFilter {
	filter := ports.EntityCatalogFilter{TenantID: tenantID, SourceID: strings.TrimSpace(sourceID), ExcludeKinds: excludedInventoryEntityTypes(), QueryAttributes: true}
	normalized := NormalizeInventorySurface(surface)
	if normalized == InventorySurfaceAll {
		return filter
	}
	if normalized == InventorySurfaceAsset {
		rules := inventorySurfaceNonAssetRules()
		filter.ExcludeKinds = append(filter.ExcludeKinds, rules.Exact...)
		filter.ExcludeKindPrefixes = append(filter.ExcludeKindPrefixes, rules.Prefixes...)
		return filter
	}
	rules := inventorySurfaceRules(normalized)
	filter.IncludeKinds = append(filter.IncludeKinds, rules.Exact...)
	filter.IncludeKindPrefixes = append(filter.IncludeKindPrefixes, rules.Prefixes...)
	return filter
}

func boundedInventoryCount(value uint64) int {
	if value > uint64(^uint(0)>>1) {
		return int(^uint(0) >> 1)
	}
	return int(value)
}

func inventoryRisk(attrs map[string]string) (int, []string) {
	if attrs == nil {
		return 0, nil
	}
	if score := inventoryIntAttribute(attrs, "risk_score", "risk"); score > 0 {
		return clampInventoryRisk(score), []string{"source risk score"}
	}
	score := 0
	reasons := []string{}
	if inventoryBoolAttribute(attrs, "public", "publicly_accessible", "internet_exposed", "external") {
		score += 35
		reasons = append(reasons, "public exposure")
	}
	if inventoryBoolAttribute(attrs, "privileged", "admin", "critical", "crown_jewel") {
		score += 25
		reasons = append(reasons, "privileged or critical")
	}
	if strings.EqualFold(attrs["environment"], "prod") || strings.EqualFold(attrs["environment"], "production") {
		score += 15
		reasons = append(reasons, "production")
	}
	return clampInventoryRisk(score), reasons
}

func inventoryIntAttribute(attrs map[string]string, keys ...string) int {
	for _, key := range keys {
		value := strings.TrimSpace(attrs[key])
		if value == "" {
			continue
		}
		var parsed int
		if _, err := fmt.Sscanf(value, "%d", &parsed); err == nil {
			return parsed
		}
	}
	return 0
}

func inventoryBoolAttribute(attrs map[string]string, keys ...string) bool {
	for _, key := range keys {
		switch strings.ToLower(strings.TrimSpace(attrs[key])) {
		case "1", "t", "true", "yes", "y":
			return true
		}
	}
	return false
}

func clampInventoryRisk(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func inventoryRiskLevel(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
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
	if len(result) == 0 {
		result = append(result, strings.ReplaceAll(categoryID, "-", "."))
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
