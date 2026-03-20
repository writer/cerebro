package builders

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// DataSource abstracts the data source for graph building
type DataSource interface {
	Query(ctx context.Context, query string, args ...any) (*DataQueryResult, error)
}

// QueryResult represents query results from the data source
type DataQueryResult struct {
	Columns []string
	Rows    []map[string]any
	Count   int
}

// Builder constructs the graph platform from data sources.
type Builder struct {
	source           DataSource
	logger           *slog.Logger
	stateMu          sync.RWMutex
	updateMu         sync.Mutex
	graph            *Graph
	availableTables  map[string]bool // populated tables, skips queries for missing ones
	lastBuildTime    time.Time       // event_time watermark for the last successful build (or build completion when CDC watermark is unavailable)
	lastCDCWatermark cdcWatermark
	lastMutation     GraphMutationSummary
}

// NewBuilder creates a new graph builder
func NewBuilder(source DataSource, logger *slog.Logger) *Builder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Builder{
		source: source,
		graph:  New(),
		logger: logger,
	}
}

// discoverTables queries information_schema once to learn which tables exist with data.
// If discovery fails or returns nothing, availableTables stays nil (optimistic: query everything).
func (b *Builder) discoverTables(ctx context.Context) {
	result, err := b.source.Query(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'RAW' AND row_count > 0
	`)
	if err != nil || len(result.Rows) == 0 {
		b.logger.Debug("table discovery unavailable, will query all tables")
		return
	}
	b.availableTables = make(map[string]bool, len(result.Rows))
	for _, row := range result.Rows {
		name := strings.ToUpper(queryRowString(row, "table_name"))
		b.availableTables[name] = true
	}
	b.logger.Debug("discovered populated tables", "count", len(b.availableTables))
}

func cloneAvailableTables(tables map[string]bool) map[string]bool {
	if len(tables) == 0 {
		return nil
	}
	cloned := make(map[string]bool, len(tables))
	for name, exists := range tables {
		cloned[name] = exists
	}
	return cloned
}

// hasTable returns true if the table exists and has rows (or if discovery was skipped).
func (b *Builder) hasTable(name string) bool {
	if b.availableTables == nil {
		return true // discovery failed, be optimistic
	}
	return b.availableTables[strings.ToUpper(name)]
}

// queryIfExists runs the query only if the referenced table exists.
func (b *Builder) queryIfExists(ctx context.Context, table, query string) (*DataQueryResult, error) {
	if !b.hasTable(table) {
		return &DataQueryResult{}, nil
	}
	return b.source.Query(ctx, query)
}

// BuildCandidate constructs a fresh graph instance from the data source without
// mutating the live builder graph. Callers can diff or swap the returned graph.
func (b *Builder) BuildCandidate(ctx context.Context) (*Graph, GraphMutationSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, GraphMutationSummary{}, err
	}

	validationMode := SchemaValidationWarn
	b.stateMu.RLock()
	if b.graph != nil {
		validationMode = b.graph.SchemaValidationMode()
	}
	b.stateMu.RUnlock()

	working := &Builder{
		source: b.source,
		graph:  New(),
		logger: b.logger,
	}
	working.graph.SetSchemaValidationMode(validationMode)
	start := time.Now()

	working.logger.Info("building graph platform")

	// Phase 1: discover which tables have data (1 round-trip)
	working.discoverTables(ctx)
	if err := ctx.Err(); err != nil {
		return nil, GraphMutationSummary{}, err
	}

	// Phase 2: load all nodes in parallel
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { working.buildAWSNodes(gctx); return nil })
	g.Go(func() error { working.buildGCPNodes(gctx); return nil })
	g.Go(func() error { working.buildAzureNodes(gctx); return nil })
	g.Go(func() error { working.buildOktaNodes(gctx); return nil })
	g.Go(func() error { working.buildGoogleWorkspaceNodes(gctx); return nil })
	g.Go(func() error { working.buildK8sNodes(gctx); return nil })
	_ = g.Wait()
	if err := ctx.Err(); err != nil {
		return nil, GraphMutationSummary{}, err
	}

	// Add internet entry point (needed before edge building)
	working.addInternetNode()

	// Phase 3: build indexes so edge builders get O(1) lookups
	working.graph.BuildIndex()

	working.logger.Info("graph nodes loaded",
		"nodes", working.graph.NodeCount(),
		"duration", time.Since(start))

	// Phase 4: build provider edges in parallel
	edgeStart := time.Now()
	eg, ectx := errgroup.WithContext(ctx)
	eg.Go(func() error { working.buildAWSEdges(ectx); return nil })
	eg.Go(func() error { working.buildGCPEdges(ectx); return nil })
	eg.Go(func() error { working.buildAzureEdges(ectx); return nil })
	eg.Go(func() error { working.buildKubernetesEdges(ectx); return nil })
	eg.Go(func() error { working.buildRelationshipEdges(ectx); return nil })
	_ = eg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, GraphMutationSummary{}, err
	}

	working.logger.Info("graph edges built",
		"edges", working.graph.EdgeCount(),
		"duration", time.Since(edgeStart))

	working.buildIAMPermissionUsageKnowledge(ctx)

	working.buildVendorNodes()

	// Build unified person graph overlay (person nodes + projected edges).
	if err := ctx.Err(); err != nil {
		return nil, GraphMutationSummary{}, err
	}
	working.buildUnifiedPersonGraph(ctx)
	working.buildPersonInteractionEdges(ctx)

	// Phase 5: inferred edges (these iterate nodes, run sequentially)
	inferStart := time.Now()
	if err := ctx.Err(); err != nil {
		return nil, GraphMutationSummary{}, err
	}
	working.buildAPIEndpointNodes()
	if err := ctx.Err(); err != nil {
		return nil, GraphMutationSummary{}, err
	}
	working.buildExposureEdges(ctx)
	if err := ctx.Err(); err != nil {
		return nil, GraphMutationSummary{}, err
	}
	working.buildSCMInference()
	normalization := NormalizeEntityAssetSupport(working.graph, temporalNowUTC())

	working.logger.Info("graph inferred edges built",
		"edges", working.graph.EdgeCount(),
		"duration", time.Since(inferStart))
	working.logger.Info("graph asset support normalized",
		"buckets", normalization.BucketsProcessed,
		"subresources", normalization.SubresourcesCreated,
		"observations", normalization.ObservationsCreated,
		"claims", normalization.ClaimsCreated)

	// Rebuild index with edges included
	working.graph.BuildIndex()

	// Update metadata
	finishedAt := time.Now().UTC()
	buildDuration := time.Since(start)
	working.graph.SetMetadata(Metadata{
		BuiltAt:       finishedAt,
		NodeCount:     working.graph.NodeCount(),
		EdgeCount:     working.graph.EdgeCount(),
		BuildDuration: buildDuration,
	})

	summary := GraphMutationSummary{
		Mode:      GraphMutationModeFullRebuild,
		Since:     start,
		Until:     finishedAt,
		NodeCount: working.graph.NodeCount(),
		EdgeCount: working.graph.EdgeCount(),
		Duration:  buildDuration,
	}
	working.logger.Info("graph platform built",
		"nodes", summary.NodeCount,
		"edges", summary.EdgeCount,
		"duration", summary.Duration)
	return working.graph, summary, nil
}

// Build constructs the entire graph from the data source using a fresh graph
// instance and atomically swapping it into the builder when complete.
func (b *Builder) Build(ctx context.Context) error {
	b.updateMu.Lock()
	defer b.updateMu.Unlock()

	candidate, summary, err := b.BuildCandidate(ctx)
	if err != nil {
		return err
	}

	watermark, watermarkErr := b.queryLatestCDCWatermark(ctx)
	if watermarkErr != nil || watermark.EventTime.IsZero() {
		watermark = cdcWatermark{EventTime: summary.Until}
	}

	b.stateMu.Lock()
	b.graph = candidate
	b.availableTables = nil
	b.lastBuildTime = watermark.EventTime
	b.lastCDCWatermark = watermark
	b.lastMutation = summary
	b.stateMu.Unlock()
	return nil
}

// HasChanges checks whether any asset tables have been modified since the last
// graph build by looking at the latest CDC watermark. Returns true if changes
// are detected or if the check fails (fail-open to ensure freshness).
func (b *Builder) HasChanges(ctx context.Context) bool {
	b.stateMu.RLock()
	lastBuildTime := b.lastBuildTime
	lastCDCWatermark := b.lastCDCWatermark
	b.stateMu.RUnlock()

	currentWatermark := effectiveCDCWatermark(lastBuildTime, lastCDCWatermark)
	if currentWatermark.EventTime.IsZero() {
		return true
	}
	latest, err := b.queryLatestCDCWatermark(ctx)
	if err != nil || latest.EventTime.IsZero() {
		return true // fail-open
	}
	return latest.After(currentWatermark)
}

// RebuildIfChanged rebuilds the graph only if data has changed since the last build.
// Returns true if a rebuild was performed.
func (b *Builder) RebuildIfChanged(ctx context.Context) (bool, error) {
	if !b.HasChanges(ctx) {
		b.logger.Info("graph rebuild skipped - no data changes detected")
		return false, nil
	}
	return true, b.Build(ctx)
}

// Graph returns the built graph
func (b *Builder) Graph() *Graph {
	b.stateMu.RLock()
	defer b.stateMu.RUnlock()
	return b.graph
}

// ReplaceGraph swaps the builder's live graph reference.
func (b *Builder) ReplaceGraph(g *Graph) {
	if b == nil || g == nil {
		return
	}
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	b.graph = g
}

// LastMutation returns metadata for the most recent graph update operation.
func (b *Builder) LastMutation() GraphMutationSummary {
	b.stateMu.RLock()
	defer b.stateMu.RUnlock()
	return b.lastMutation
}

func (b *Builder) buildRelationshipEdges(ctx context.Context) {
	rels, err := b.queryIfExists(ctx, "resource_relationships", `
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`)
	if err != nil {
		b.logger.Debug("relationship table not available", "error", err)
		return
	}

	for _, row := range rels.Rows {
		sourceID := normalizeRelID(queryRow(row, "source_id"))
		targetID := normalizeRelID(queryRow(row, "target_id"))
		if sourceID == "" || targetID == "" {
			continue
		}

		sourceType := strings.ToLower(queryRowString(row, "source_type"))
		targetType := strings.ToLower(queryRowString(row, "target_type"))
		relType := strings.ToUpper(queryRowString(row, "rel_type"))

		edgeSource := sourceID
		edgeTarget := targetID
		edgeSourceType := sourceType
		edgeTargetType := targetType
		kind := EdgeKindConnectsTo

		switch relType {
		case "ASSUMABLE_BY", "TRUSTED_BY":
			kind = EdgeKindCanAssume
			edgeSource = targetID
			edgeTarget = sourceID
			edgeSourceType = targetType
			edgeTargetType = sourceType
		case "HAS_ROLE":
			kind = EdgeKindCanAssume
		case "CAN_ACCESS":
			kind = EdgeKindCanRead
		case "MEMBER_OF":
			if isIdentityType(sourceType) && isIdentityType(targetType) {
				kind = EdgeKindMemberOf
			}
		case "READS_FROM":
			kind = EdgeKindCanRead
		case "WRITES_TO":
			kind = EdgeKindCanWrite
		case "HAS_PERMISSION":
			kind = EdgeKindCanAdmin
		case "EXPOSED_TO":
			kind = EdgeKindExposedTo
			if targetID == "internet" || targetType == "network:internet" {
				edgeSource = "internet"
				edgeTarget = sourceID
				edgeSourceType = "network:internet"
				edgeTargetType = sourceType
			}
		}

		b.ensureRelationshipNode(edgeSource, edgeSourceType)
		b.ensureRelationshipNode(edgeTarget, edgeTargetType)

		edge := &Edge{
			Source: edgeSource,
			Target: edgeTarget,
			Kind:   kind,
			Effect: EdgeEffectAllow,
			Properties: map[string]any{
				"relationship_type": relType,
			},
		}
		if props := queryRow(row, "properties"); props != nil {
			edge.Properties["properties"] = props
		}

		b.addEdgeIfMissing(edge)
	}

	b.logger.Debug("added relationship edges", "count", len(rels.Rows))
}

// normalizeRelID extracts a clean identifier from relationship source/target IDs.
// Some relationship rows store JSON objects (e.g. {"arn": "arn:aws:iam::..."})
// instead of plain strings; this extracts the ARN when possible.
func normalizeRelID(raw any) string {
	switch v := raw.(type) {
	case nil:
		return ""
	case []byte:
		return normalizeRelIDString(string(v))
	case map[string]any:
		if id := extractRelIDFromMap(v); id != "" {
			return id
		}
		return normalizeRelIDString(fmt.Sprintf("%v", v))
	case string:
		return normalizeRelIDString(v)
	default:
		return normalizeRelIDString(fmt.Sprintf("%v", v))
	}
}

func normalizeRelIDString(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "{") {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
			if id := extractRelIDFromMap(parsed); id != "" {
				return id
			}
		}
		if id := extractRelIDFromJSONString(raw); id != "" {
			return id
		}
	}
	if strings.HasPrefix(raw, "map[") {
		if id := extractRelIDFromMapString(raw); id != "" {
			return id
		}
	}
	return raw
}

func extractRelIDFromMap(m map[string]any) string {
	for _, key := range []string{"arn", "Arn", "ARN", "id", "Id", "ID", "resource_id", "resourceId"} {
		if val, ok := m[key]; ok {
			if id := strings.TrimSpace(toString(val)); id != "" {
				return id
			}
		}
	}
	return ""
}

func extractRelIDFromJSONString(raw string) string {
	for _, key := range []string{`"arn"`, `"Arn"`, `"ARN"`, `"id"`, `"Id"`, `"ID"`} {
		if idx := strings.Index(raw, key); idx >= 0 {
			rest := raw[idx+len(key):]
			rest = strings.TrimLeft(rest, `: "`)
			if end := strings.IndexByte(rest, '"'); end > 0 {
				return rest[:end]
			}
		}
	}
	return ""
}

func extractRelIDFromMapString(raw string) string {
	for _, key := range []string{"Arn:", "arn:", "ID:", "Id:", "id:"} {
		if idx := strings.Index(raw, key); idx >= 0 {
			rest := raw[idx+len(key):]
			if fields := strings.Fields(rest); len(fields) > 0 {
				return strings.Trim(fields[0], ",]")
			}
		}
	}
	return ""
}

func (b *Builder) ensureRelationshipNode(id, resourceType string) {
	if id == "" {
		return
	}
	if _, ok := b.graph.GetNode(id); ok {
		return
	}

	kind := nodeKindForResourceType(resourceType)
	if kind == "" {
		return
	}

	node := &Node{
		ID:       id,
		Kind:     kind,
		Name:     id,
		Provider: providerForResourceType(resourceType),
	}

	if arn, err := ParseARN(id); err == nil {
		node.Account = arn.Account
		node.Region = arn.Region
	}
	if node.Provider == "azure" {
		node.Account = azureIDSegment(id, "subscriptions")
		node.Name = azureResourceDisplayName(id)
	}

	b.graph.AddNode(node)
}

func nodeKindForResourceType(resourceType string) NodeKind {
	switch strings.ToLower(resourceType) {
	case "aws:iam:user":
		return NodeKindUser
	case "aws:iam:role":
		return NodeKindRole
	case "aws:iam:group":
		return NodeKindGroup
	case "aws:iam:instance_profile":
		return NodeKindRole
	case "okta:user":
		return NodeKindUser
	case "okta:group":
		return NodeKindGroup
	case "okta:admin_role":
		return NodeKindRole
	case "okta:application":
		return NodeKindApplication
	case "okta:scope", "google_workspace:scope":
		return NodeKindRole
	case "google_workspace:user":
		return NodeKindUser
	case "google_workspace:group":
		return NodeKindGroup
	case "google_workspace:application":
		return NodeKindApplication
	case "gcp:iam:service_account", "gcp:iam:serviceaccount":
		return NodeKindServiceAccount
	case "azure:ad:user", "entra:user":
		return NodeKindUser
	case "azure:ad:group", "entra:group":
		return NodeKindGroup
	case "azure:ad:service_principal", "entra:service_principal":
		return NodeKindServiceAccount
	case "azure:management:tenant":
		return NodeKindOrganization
	case "azure:management:management_group", "azure:management:resource_group":
		return NodeKindFolder
	case "azure:management:subscription":
		return NodeKindProject
	case "aws:s3:bucket", "gcp:storage:bucket":
		return NodeKindBucket
	case "azure:storage:account", "azure:storage:container", "azure:storage:blob":
		return NodeKindBucket
	case "aws:ec2:instance", "gcp:compute:instance":
		return NodeKindInstance
	case "azure:compute:virtual_machine":
		return NodeKindInstance
	case "aws:lambda:function", "gcp:cloudfunctions:function":
		return NodeKindFunction
	case "azure:web:function_app":
		return NodeKindFunction
	case "aws:rds:db_instance", "gcp:sql:instance":
		return NodeKindDatabase
	case "azure:sql:server", "azure:sql:database":
		return NodeKindDatabase
	case "aws:secretsmanager:secret", "gcp:secretmanager:secret":
		return NodeKindSecret
	case "azure:keyvault:vault", "azure:keyvault:key":
		return NodeKindSecret
	case "aws:ec2:security_group", "aws:ec2:vpc", "aws:ec2:subnet", "gcp:compute:network", "gcp:compute:subnetwork",
		"azure:network:interface", "azure:network:security_group", "azure:network:virtual_network", "azure:network:subnet", "azure:network:public_ip", "azure:network:load_balancer":
		return NodeKindNetwork
	case "azure:policy:assignment", "azure:compute:disk", "azure:compute:availability_set", "azure:compute:managed_cluster":
		return NodeKindService
	case "network:internet":
		return NodeKindInternet
	default:
		return ""
	}
}

func providerForResourceType(resourceType string) string {
	resourceType = strings.ToLower(resourceType)
	if strings.HasPrefix(resourceType, "aws:") {
		return "aws"
	}
	if strings.HasPrefix(resourceType, "gcp:") {
		return "gcp"
	}
	if strings.HasPrefix(resourceType, "azure:") || strings.HasPrefix(resourceType, "entra:") {
		return "azure"
	}
	if strings.HasPrefix(resourceType, "okta:") {
		return "okta"
	}
	if strings.HasPrefix(resourceType, "google_workspace:") {
		return "google_workspace"
	}
	return ""
}

func isIdentityType(resourceType string) bool {
	switch strings.ToLower(resourceType) {
	case "aws:iam:user", "aws:iam:role", "aws:iam:group", "aws:iam:instance_profile",
		"gcp:iam:service_account", "gcp:iam:serviceaccount",
		"okta:user", "okta:group", "okta:admin_role",
		"google_workspace:user", "google_workspace:group",
		"azure:ad:user", "azure:ad:group", "azure:ad:service_principal",
		"entra:user", "entra:group", "entra:service_principal":
		return true
	default:
		return false
	}
}

func (b *Builder) addEdgeIfMissing(edge *Edge) bool {
	for _, existing := range b.graph.GetOutEdges(edge.Source) {
		if existing.Target == edge.Target && existing.Kind == edge.Kind {
			return false
		}
	}
	b.graph.AddEdge(edge)
	return true
}

func (b *Builder) runNodeQueries(ctx context.Context, queries []nodeQuery) {
	type result struct {
		table string
		nodes []*Node
	}
	var mu sync.Mutex
	var results []result

	eg, ectx := errgroup.WithContext(ctx)
	for _, q := range queries {
		q := q
		eg.Go(func() error {
			rows, err := b.queryIfExists(ectx, q.table, q.query)
			if err != nil {
				b.logger.Warn("failed to query "+q.table, "error", err)
				return nil
			}
			if len(rows.Rows) == 0 {
				return nil
			}
			parsed := q.parse(rows.Rows)
			mu.Lock()
			results = append(results, result{table: q.table, nodes: parsed})
			mu.Unlock()
			return nil
		})
	}
	_ = eg.Wait()

	for _, r := range results {
		b.graph.AddNodesBatch(r.nodes)
		b.logger.Debug("added "+r.table, "count", len(r.nodes))
	}
}

type nodeQuery struct {
	table string
	query string
	parse func(rows []map[string]any) []*Node
}

func (b *Builder) addInternetNode() {
	b.graph.AddNode(&Node{
		ID:       "internet",
		Kind:     NodeKindInternet,
		Name:     "Internet",
		Provider: "external",
		Risk:     RiskCritical,
	})
}

func (b *Builder) buildExposureEdges(ctx context.Context) {
	count := 0
	networkHandled, networkCount := b.buildAWSNetworkExposureEdges(ctx)
	count += networkCount
	for _, node := range b.graph.GetAllNodes() {
		if !node.IsResource() {
			continue
		}
		if _, handled := networkHandled[node.ID]; handled {
			continue
		}
		if isNodePublic(node) {
			if b.addEdgeIfMissing(&Edge{
				ID:     "internet->" + node.ID,
				Source: "internet",
				Target: node.ID,
				Kind:   EdgeKindExposedTo,
				Effect: EdgeEffectAllow,
				Risk:   RiskHigh,
			}) {
				count++
			}
		}
	}
	b.logger.Debug("added internet exposure edges", "count", count)
}

func isNodePublic(node *Node) bool {
	if isPublic, ok := node.Properties["public"].(bool); ok && isPublic {
		return true
	}
	if pip := toString(node.Properties["public_ip"]); pip != "" {
		// Filter out placeholder / empty-like values
		if isValidPublicIP(pip) {
			return true
		}
	}
	if iamPolicy := toString(node.Properties["iam_policy"]); iamPolicy != "" {
		if strings.Contains(iamPolicy, "allUsers") || strings.Contains(iamPolicy, "allAuthenticatedUsers") {
			return true
		}
	}
	if ipAddrs := toString(node.Properties["ip_addresses"]); ipAddrs != "" {
		if strings.Contains(ipAddrs, "0.0.0.0/0") {
			return true
		}
	}
	if ingress := toString(node.Properties["ingress"]); ingress != "" {
		if strings.Contains(ingress, "INGRESS_TRAFFIC_ALL") {
			return true
		}
	}
	return false
}

// isValidPublicIP returns true if the string is a valid, non-placeholder IP address.
func isValidPublicIP(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && net.ParseIP(s) != nil
}

func toString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func extractGCPServiceAccountEmail(v any) string {
	switch sa := v.(type) {
	case []any:
		if len(sa) > 0 {
			if m, ok := sa[0].(map[string]any); ok {
				return toString(m["email"])
			}
		}
	case string:
		if strings.Contains(sa, "email") {
			return sa
		}
	}
	return ""
}

func toBool(v any) bool {
	if v == nil {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true") || b == "1"
	case float64:
		return b != 0
	case int:
		return b != 0
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func (b *Builder) buildSCMInference() {
	// Infer repository nodes from "git_repo" or "repo" tags on assets
	for _, node := range b.graph.GetAllNodes() {
		if !node.IsResource() {
			continue
		}

		var repoURL string
		if url, ok := node.Tags["git_repo"]; ok {
			repoURL = url
		} else if url, ok := node.Tags["repo"]; ok {
			repoURL = url
		} else if url, ok := node.Tags["repository"]; ok {
			repoURL = url
		} else if project, ok := node.Tags["project"]; ok {
			// heuristic: if project tag exists, assume it's a repo in default org
			// In real world, this would be configured via config
			if strings.Contains(project, "/") {
				repoURL = "https://github.com/" + project
			}
		}

		if repoURL != "" {
			b.ensureRepoNode(repoURL)

			b.graph.AddEdge(&Edge{
				ID:     node.ID + "->deployed_from->" + repoURL,
				Source: node.ID,
				Target: repoURL,
				Kind:   EdgeKindDeployedFrom,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"mechanism": "tag_inference",
				},
			})
		}
	}
}

func (b *Builder) ensureRepoNode(repoURL string) {
	if _, exists := b.graph.GetNode(repoURL); !exists {
		b.graph.AddNode(&Node{
			ID:       repoURL,
			Kind:     NodeKindRepository,
			Name:     repoURL,
			Provider: "scm",
			Properties: map[string]any{
				"url": repoURL,
			},
		})
	}
}
