package graph

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
	Query(ctx context.Context, query string, args ...any) (*QueryResult, error)
}

// QueryResult represents query results from the data source
type QueryResult struct {
	Columns []string
	Rows    []map[string]any
	Count   int
}

// Builder constructs the security graph from data sources
type Builder struct {
	source          DataSource
	graph           *Graph
	logger          *slog.Logger
	availableTables map[string]bool // populated tables, skips queries for missing ones
	lastBuildTime   time.Time       // when the last successful build finished
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

// hasTable returns true if the table exists and has rows (or if discovery was skipped).
func (b *Builder) hasTable(name string) bool {
	if b.availableTables == nil {
		return true // discovery failed, be optimistic
	}
	return b.availableTables[strings.ToUpper(name)]
}

// queryIfExists runs the query only if the referenced table exists.
func (b *Builder) queryIfExists(ctx context.Context, table, query string) (*QueryResult, error) {
	if !b.hasTable(table) {
		return &QueryResult{}, nil
	}
	return b.source.Query(ctx, query)
}

// Build constructs the entire graph from the data source.
// Phase 1: discover populated tables (1 query)
// Phase 2: load all nodes in parallel across providers
// Phase 3: build index for O(1) lookups during edge building
// Phase 4: build all edges in parallel across providers
// Phase 5: build inferred edges (exposure, SCM, relationships)
func (b *Builder) Build(ctx context.Context) error {
	start := time.Now()
	b.graph.Clear()

	b.logger.Info("building security graph")

	// Phase 1: discover which tables have data (1 round-trip)
	b.discoverTables(ctx)

	// Phase 2: load all nodes in parallel
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { b.buildAWSNodes(gctx); return nil })
	g.Go(func() error { b.buildGCPNodes(gctx); return nil })
	g.Go(func() error { b.buildAzureNodes(gctx); return nil })
	g.Go(func() error { b.buildOktaNodes(gctx); return nil })
	_ = g.Wait()

	// Add internet entry point (needed before edge building)
	b.addInternetNode()

	// Phase 3: build indexes so edge builders get O(1) lookups
	b.graph.BuildIndex()

	b.logger.Info("graph nodes loaded",
		"nodes", b.graph.NodeCount(),
		"duration", time.Since(start))

	// Phase 4: build provider edges in parallel
	edgeStart := time.Now()
	eg, ectx := errgroup.WithContext(ctx)
	eg.Go(func() error { b.buildAWSEdges(ectx); return nil })
	eg.Go(func() error { b.buildGCPEdges(ectx); return nil })
	eg.Go(func() error { b.buildAzureEdges(ectx); return nil })
	eg.Go(func() error { b.buildRelationshipEdges(ectx); return nil })
	_ = eg.Wait()

	b.logger.Info("graph edges built",
		"edges", b.graph.EdgeCount(),
		"duration", time.Since(edgeStart))

	// Phase 5: inferred edges (these iterate nodes, run sequentially)
	inferStart := time.Now()
	b.buildExposureEdges()
	b.buildSCMInference()

	b.logger.Info("graph inferred edges built",
		"edges", b.graph.EdgeCount(),
		"duration", time.Since(inferStart))

	// Rebuild index with edges included
	b.graph.BuildIndex()

	// Update metadata
	b.graph.SetMetadata(Metadata{
		BuiltAt:       time.Now(),
		NodeCount:     b.graph.NodeCount(),
		EdgeCount:     b.graph.EdgeCount(),
		BuildDuration: time.Since(start),
	})

	b.logger.Info("security graph built",
		"nodes", b.graph.NodeCount(),
		"edges", b.graph.EdgeCount(),
		"duration", time.Since(start))

	b.lastBuildTime = time.Now()
	return nil
}

// HasChanges checks whether any asset tables have been modified since the last
// graph build by looking at MAX(_cq_sync_time). Returns true if changes are
// detected or if the check fails (fail-open to ensure freshness).
func (b *Builder) HasChanges(ctx context.Context) bool {
	if b.lastBuildTime.IsZero() {
		return true
	}
	result, err := b.source.Query(ctx, `
		SELECT MAX(COALESCE(_cq_sync_time, '1970-01-01'::TIMESTAMP_TZ)) AS latest
		FROM (
			SELECT _cq_sync_time FROM RAW.AWS_IAM_ROLES
			UNION ALL SELECT _cq_sync_time FROM RAW.AWS_S3_BUCKETS
			UNION ALL SELECT _cq_sync_time FROM RAW.GCP_COMPUTE_INSTANCES
		)
	`)
	if err != nil || len(result.Rows) == 0 {
		return true // fail-open
	}
	if latest, ok := queryRow(result.Rows[0], "latest").(time.Time); ok {
		return latest.After(b.lastBuildTime)
	}
	return true
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
	return b.graph
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
	case "gcp:iam:service_account", "gcp:iam:serviceaccount":
		return NodeKindServiceAccount
	case "aws:s3:bucket", "gcp:storage:bucket":
		return NodeKindBucket
	case "aws:ec2:instance", "gcp:compute:instance":
		return NodeKindInstance
	case "aws:lambda:function", "gcp:cloudfunctions:function":
		return NodeKindFunction
	case "aws:rds:db_instance", "gcp:sql:instance":
		return NodeKindDatabase
	case "aws:secretsmanager:secret", "gcp:secretmanager:secret":
		return NodeKindSecret
	case "aws:ec2:security_group", "aws:ec2:vpc", "aws:ec2:subnet", "gcp:compute:network", "gcp:compute:subnetwork":
		return NodeKindNetwork
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
	if strings.HasPrefix(resourceType, "azure:") {
		return "azure"
	}
	if strings.HasPrefix(resourceType, "okta:") {
		return "okta"
	}
	return ""
}

func isIdentityType(resourceType string) bool {
	switch strings.ToLower(resourceType) {
	case "aws:iam:user", "aws:iam:role", "aws:iam:group", "aws:iam:instance_profile", "gcp:iam:service_account", "gcp:iam:serviceaccount", "okta:user", "okta:group", "okta:admin_role":
		return true
	default:
		return false
	}
}

func (b *Builder) addEdgeIfMissing(edge *Edge) {
	for _, existing := range b.graph.GetOutEdges(edge.Source) {
		if existing.Target == edge.Target && existing.Kind == edge.Kind {
			return
		}
	}
	b.graph.AddEdge(edge)
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

func (b *Builder) buildExposureEdges() {
	count := 0
	for _, node := range b.graph.GetAllNodes() {
		if !node.IsResource() {
			continue
		}
		if isNodePublic(node) {
			b.graph.AddEdge(&Edge{
				ID:     "internet->" + node.ID,
				Source: "internet",
				Target: node.ID,
				Kind:   EdgeKindExposedTo,
				Effect: EdgeEffectAllow,
				Risk:   RiskHigh,
			})
			count++
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
