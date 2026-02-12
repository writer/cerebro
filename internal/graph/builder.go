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
		name := strings.ToUpper(toString(row["table_name"]))
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
	if latest, ok := result.Rows[0]["latest"].(time.Time); ok {
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
		sourceID := normalizeRelID(row["source_id"])
		targetID := normalizeRelID(row["target_id"])
		if sourceID == "" || targetID == "" {
			continue
		}

		sourceType := strings.ToLower(toString(row["source_type"]))
		targetType := strings.ToLower(toString(row["target_type"]))
		relType := strings.ToUpper(toString(row["rel_type"]))

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
		if props := row["properties"]; props != nil {
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
	return ""
}

func isIdentityType(resourceType string) bool {
	switch strings.ToLower(resourceType) {
	case "aws:iam:user", "aws:iam:role", "aws:iam:group", "aws:iam:instance_profile", "gcp:iam:service_account", "gcp:iam:serviceaccount":
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

func (b *Builder) buildAWSNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "aws_iam_users",
			query: `
		SELECT arn, user_name, account_id, password_last_used, tags
		FROM aws_iam_users
	`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, u := range rows {
					nodes = append(nodes, &Node{
						ID: toString(u["arn"]), Kind: NodeKindUser, Name: toString(u["user_name"]),
						Provider: "aws", Account: toString(u["account_id"]),
						Properties: map[string]any{"last_login": u["password_last_used"]},
					})
				}
				return nodes
			},
		},
		{
			table: "aws_iam_roles",
			query: `
		SELECT arn, role_name, account_id, assume_role_policy_document, description
		FROM aws_iam_roles
	`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, r := range rows {
					nodes = append(nodes, &Node{
						ID: toString(r["arn"]), Kind: NodeKindRole, Name: toString(r["role_name"]),
						Provider: "aws", Account: toString(r["account_id"]),
						Properties: map[string]any{"trust_policy": r["assume_role_policy_document"], "description": r["description"]},
					})
				}
				return nodes
			},
		},
		{
			table: "aws_iam_groups",
			query: `
		SELECT arn, group_name, account_id
		FROM aws_iam_groups
	`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, g := range rows {
					nodes = append(nodes, &Node{
						ID: toString(g["arn"]), Kind: NodeKindGroup, Name: toString(g["group_name"]),
						Provider: "aws", Account: toString(g["account_id"]),
					})
				}
				return nodes
			},
		},
		{
			table: "aws_s3_buckets",
			query: `
		SELECT arn, name, account_id, region, block_public_acls, block_public_policy, versioning_status
		FROM aws_s3_buckets
	`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, bucket := range rows {
					isPublic := !toBool(bucket["block_public_acls"]) || !toBool(bucket["block_public_policy"])
					risk := RiskNone
					if isPublic {
						risk = RiskHigh
					}
					nodes = append(nodes, &Node{
						ID: toString(bucket["arn"]), Kind: NodeKindBucket, Name: toString(bucket["name"]),
						Provider: "aws", Account: toString(bucket["account_id"]), Region: toString(bucket["region"]),
						Risk: risk, Properties: map[string]any{"public": isPublic, "versioning": bucket["versioning_status"]},
					})
				}
				return nodes
			},
		},
		{
			table: "aws_ec2_instances",
			query: `
		SELECT arn, instance_id, account_id, region, public_ip_address, iam_instance_profile
		FROM aws_ec2_instances
	`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, inst := range rows {
					hasPublicIP := toString(inst["public_ip_address"]) != ""
					risk := RiskNone
					if hasPublicIP {
						risk = RiskMedium
					}
					nodes = append(nodes, &Node{
						ID: toString(inst["arn"]), Kind: NodeKindInstance, Name: toString(inst["instance_id"]),
						Provider: "aws", Account: toString(inst["account_id"]), Region: toString(inst["region"]),
						Risk: risk, Properties: map[string]any{"public_ip": inst["public_ip_address"], "iam_instance_profile": inst["iam_instance_profile"]},
					})
				}
				return nodes
			},
		},
		{
			table: "aws_rds_instances",
			query: `
		SELECT arn, db_instance_identifier, account_id, region, publicly_accessible, storage_encrypted
		FROM aws_rds_instances
	`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, db := range rows {
					isPublic := toBool(db["publicly_accessible"])
					risk := RiskNone
					if isPublic {
						risk = RiskCritical
					}
					nodes = append(nodes, &Node{
						ID: toString(db["arn"]), Kind: NodeKindDatabase, Name: toString(db["db_instance_identifier"]),
						Provider: "aws", Account: toString(db["account_id"]), Region: toString(db["region"]),
						Risk: risk, Properties: map[string]any{"public": isPublic, "encrypted": db["storage_encrypted"]},
					})
				}
				return nodes
			},
		},
		{
			table: "aws_lambda_functions",
			query: `
		SELECT arn, function_name, account_id, region, role
		FROM aws_lambda_functions
	`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, fn := range rows {
					nodes = append(nodes, &Node{
						ID: toString(fn["arn"]), Kind: NodeKindFunction, Name: toString(fn["function_name"]),
						Provider: "aws", Account: toString(fn["account_id"]), Region: toString(fn["region"]),
						Properties: map[string]any{"execution_role": fn["role"]},
					})
				}
				return nodes
			},
		},
		{
			table: "aws_secretsmanager_secrets",
			query: `
		SELECT arn, name, account_id, region
		FROM aws_secretsmanager_secrets
	`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, s := range rows {
					nodes = append(nodes, &Node{
						ID: toString(s["arn"]), Kind: NodeKindSecret, Name: toString(s["name"]),
						Provider: "aws", Account: toString(s["account_id"]), Region: toString(s["region"]),
						Risk: RiskHigh,
					})
				}
				return nodes
			},
		},
	}

	b.runNodeQueries(ctx, queries)
}

// runNodeQueries fires all node queries in parallel and batch-adds the results.
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

func (b *Builder) buildAWSEdges(ctx context.Context) {
	// Load IAM policy documents via policy_versions (document lives there, not in aws_iam_policies)
	policyVersions, err := b.queryIfExists(ctx, "aws_iam_policy_versions", `
		SELECT policy_arn, document FROM aws_iam_policy_versions WHERE is_default_version = true
	`)
	if err != nil {
		b.logger.Warn("failed to query IAM policy versions", "error", err)
	}
	policyDocs := make(map[string]string)
	if policyVersions != nil {
		for _, p := range policyVersions.Rows {
			policyDocs[toString(p["policy_arn"])] = toString(p["document"])
		}
	}

	// Fire all edge sub-queries in parallel
	eg, ectx := errgroup.WithContext(ctx)

	// Attached policies (user + role + group)
	eg.Go(func() error {
		userPolicies, err := b.queryIfExists(ectx, "aws_iam_user_attached_policies", `
		SELECT user_arn, policy_arn FROM aws_iam_user_attached_policies
	`)
		if err != nil {
			b.logger.Warn("failed to query user attached policies", "error", err)
			return nil
		}
		for _, up := range userPolicies.Rows {
			b.buildEdgesFromPolicy(toString(up["user_arn"]), policyDocs[toString(up["policy_arn"])], toString(up["policy_arn"]))
		}
		return nil
	})

	eg.Go(func() error {
		rolePolicies, err := b.queryIfExists(ectx, "aws_iam_role_attached_policies", `
		SELECT role_arn, policy_arn FROM aws_iam_role_attached_policies
	`)
		if err != nil {
			b.logger.Warn("failed to query role attached policies", "error", err)
			return nil
		}
		for _, rp := range rolePolicies.Rows {
			b.buildEdgesFromPolicy(toString(rp["role_arn"]), policyDocs[toString(rp["policy_arn"])], toString(rp["policy_arn"]))
		}
		return nil
	})

	eg.Go(func() error {
		groupPolicies, err := b.queryIfExists(ectx, "aws_iam_group_attached_policies", `
		SELECT group_arn, policy_arn FROM aws_iam_group_attached_policies
	`)
		if err != nil {
			b.logger.Warn("failed to query group attached policies", "error", err)
			return nil
		}
		for _, gp := range groupPolicies.Rows {
			b.buildEdgesFromPolicy(toString(gp["group_arn"]), policyDocs[toString(gp["policy_arn"])], toString(gp["policy_arn"]))
		}
		return nil
	})

	// Inline policies (user, role, group)
	eg.Go(func() error {
		rows, err := b.queryIfExists(ectx, "aws_iam_user_policies", `
		SELECT user_arn, policy_name, policy_document FROM aws_iam_user_policies
	`)
		if err != nil {
			b.logger.Warn("failed to query user inline policies", "error", err)
			return nil
		}
		for _, p := range rows.Rows {
			b.buildEdgesFromPolicy(toString(p["user_arn"]), toString(p["policy_document"]), "inline:"+toString(p["policy_name"]))
		}
		b.logger.Debug("processed user inline policies", "count", len(rows.Rows))
		return nil
	})

	eg.Go(func() error {
		rows, err := b.queryIfExists(ectx, "aws_iam_role_policies", `
		SELECT role_arn, policy_name, policy_document FROM aws_iam_role_policies
	`)
		if err != nil {
			b.logger.Warn("failed to query role inline policies", "error", err)
			return nil
		}
		for _, p := range rows.Rows {
			b.buildEdgesFromPolicy(toString(p["role_arn"]), toString(p["policy_document"]), "inline:"+toString(p["policy_name"]))
		}
		b.logger.Debug("processed role inline policies", "count", len(rows.Rows))
		return nil
	})

	eg.Go(func() error {
		rows, err := b.queryIfExists(ectx, "aws_iam_group_policies", `
		SELECT group_arn, policy_name, policy_document FROM aws_iam_group_policies
	`)
		if err != nil {
			b.logger.Warn("failed to query group inline policies", "error", err)
			return nil
		}
		for _, p := range rows.Rows {
			b.buildEdgesFromPolicy(toString(p["group_arn"]), toString(p["policy_document"]), "inline:"+toString(p["policy_name"]))
		}
		b.logger.Debug("processed group inline policies", "count", len(rows.Rows))
		return nil
	})

	// Structural edges
	eg.Go(func() error {
		if err := b.buildGroupMembershipEdges(ectx); err != nil {
			b.logger.Warn("failed to build group membership edges", "error", err)
		}
		return nil
	})
	eg.Go(func() error {
		if err := b.buildTrustEdges(ectx); err != nil {
			b.logger.Warn("failed to build trust edges", "error", err)
		}
		return nil
	})
	eg.Go(func() error {
		if err := b.buildInstanceProfileEdges(ectx); err != nil {
			b.logger.Warn("failed to build instance profile edges", "error", err)
		}
		return nil
	})
	eg.Go(func() error {
		if err := b.buildLambdaRoleEdges(ectx); err != nil {
			b.logger.Warn("failed to build lambda role edges", "error", err)
		}
		return nil
	})

	_ = eg.Wait()
}

func (b *Builder) buildEdgesFromPolicy(principalARN, policyDoc, via string) {
	if policyDoc == "" {
		return
	}

	statements, err := ParseAWSPolicy(policyDoc)
	if err != nil {
		b.logger.Debug("failed to parse policy", "via", via, "error", err)
		return
	}

	for _, stmt := range statements {
		effect := EdgeEffectAllow
		priority := 50
		if strings.EqualFold(stmt.Effect, "Deny") {
			effect = EdgeEffectDeny
			priority = 100
		}

		for _, resource := range stmt.Resources {
			matchingNodes := FindMatchingNodes(b.graph, resource)
			for _, node := range matchingNodes {
				edgeID := fmt.Sprintf("%s->%s:%s", principalARN, node.ID, stmt.Effect)
				b.graph.AddEdge(&Edge{
					ID:       edgeID,
					Source:   principalARN,
					Target:   node.ID,
					Kind:     ActionsToEdgeKind(stmt.Actions),
					Effect:   effect,
					Priority: priority,
					Properties: map[string]any{
						"actions": stmt.Actions,
						"via":     via,
					},
				})
			}
		}
	}
}

func (b *Builder) buildTrustEdges(ctx context.Context) error {
	roles, err := b.queryIfExists(ctx, "aws_iam_roles", `
		SELECT arn, account_id, assume_role_policy_document
		FROM aws_iam_roles
		WHERE assume_role_policy_document IS NOT NULL
	`)
	if err != nil {
		return err
	}

	for _, role := range roles.Rows {
		roleARN := toString(role["arn"])
		roleAccount := toString(role["account_id"])
		trustPolicy := toString(role["assume_role_policy_document"])

		principals, err := ParseTrustPolicy(trustPolicy)
		if err != nil {
			continue
		}

		for _, principal := range principals {
			principalAccount := ExtractAccountFromARN(principal.ARN)
			isCrossAccount := principalAccount != "" && principalAccount != roleAccount

			// Handle account root trust
			if strings.HasSuffix(principal.ARN, ":root") {
				// Create edge from root
				b.graph.AddEdge(&Edge{
					ID:     principal.ARN + "->assume->" + roleARN,
					Source: principal.ARN,
					Target: roleARN,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"mechanism":      "trust_policy",
						"cross_account":  isCrossAccount,
						"source_account": principalAccount,
						"target_account": roleAccount,
						"trust_type":     "account_root",
					},
				})

				// Also create edges from all principals in that account
				for _, node := range b.graph.GetNodesByAccountIndexed(principalAccount) {
					if node.Kind == NodeKindUser || node.Kind == NodeKindRole {
						b.graph.AddEdge(&Edge{
							ID:     node.ID + "->assume->" + roleARN,
							Source: node.ID,
							Target: roleARN,
							Kind:   EdgeKindCanAssume,
							Effect: EdgeEffectAllow,
							Properties: map[string]any{
								"mechanism":     "account_trust",
								"cross_account": isCrossAccount,
								"via":           principal.ARN,
							},
						})
					}
				}
			} else if principal.Type == "Service" {
				// Service principal (e.g., ec2.amazonaws.com)
				b.graph.AddEdge(&Edge{
					ID:     principal.ARN + "->assume->" + roleARN,
					Source: principal.ARN,
					Target: roleARN,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"mechanism":  "service_trust",
						"trust_type": "service",
						"is_service": true,
					},
				})
			} else if principal.IsPublic {
				// Public trust - anyone can assume
				b.graph.AddEdge(&Edge{
					ID:     "internet->assume->" + roleARN,
					Source: "internet",
					Target: roleARN,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
					Risk:   RiskCritical,
					Properties: map[string]any{
						"mechanism":  "public_trust",
						"trust_type": "public",
						"is_public":  true,
					},
				})
			} else {
				// Specific principal trust
				b.graph.AddEdge(&Edge{
					ID:     principal.ARN + "->assume->" + roleARN,
					Source: principal.ARN,
					Target: roleARN,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"mechanism":      "trust_policy",
						"cross_account":  isCrossAccount,
						"source_account": principalAccount,
						"target_account": roleAccount,
					},
				})
			}
		}
	}

	return nil
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

func (b *Builder) buildGroupMembershipEdges(ctx context.Context) error {
	memberships, err := b.queryIfExists(ctx, "aws_iam_user_groups", `
		SELECT user_arn, group_arn FROM aws_iam_user_groups
	`)
	if err != nil {
		return err
	}

	for _, m := range memberships.Rows {
		userARN := toString(m["user_arn"])
		groupARN := toString(m["group_arn"])

		b.graph.AddEdge(&Edge{
			ID:     userARN + "->member_of->" + groupARN,
			Source: userARN,
			Target: groupARN,
			Kind:   EdgeKindMemberOf,
			Effect: EdgeEffectAllow,
			Properties: map[string]any{
				"mechanism": "group_membership",
			},
		})
	}

	b.logger.Debug("added group membership edges", "count", len(memberships.Rows))
	return nil
}

func (b *Builder) buildInstanceProfileEdges(ctx context.Context) error {
	instances, err := b.queryIfExists(ctx, "aws_ec2_instances", `
		SELECT arn, iam_instance_profile
		FROM aws_ec2_instances
		WHERE iam_instance_profile IS NOT NULL AND iam_instance_profile != ''
	`)
	if err != nil {
		return err
	}

	count := 0
	for _, inst := range instances.Rows {
		instanceARN := toString(inst["arn"])
		profileInfo := inst["iam_instance_profile"]

		// Instance profile can be a string ARN or a map with 'Arn' key
		var roleARN string
		switch p := profileInfo.(type) {
		case string:
			// If it's an instance profile ARN, we need to find the role
			// For now, create edge to the profile itself
			roleARN = p
		case map[string]any:
			if arn, ok := p["Arn"].(string); ok {
				roleARN = arn
			}
		}

		if roleARN != "" {
			b.graph.AddEdge(&Edge{
				ID:     instanceARN + "->has_profile->" + roleARN,
				Source: instanceARN,
				Target: roleARN,
				Kind:   EdgeKindCanAssume,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"mechanism": "instance_profile",
				},
			})
			count++
		}
	}

	b.logger.Debug("added instance profile edges", "count", count)
	return nil
}

func (b *Builder) buildLambdaRoleEdges(ctx context.Context) error {
	lambdas, err := b.queryIfExists(ctx, "aws_lambda_functions", `
		SELECT arn, role
		FROM aws_lambda_functions
		WHERE role IS NOT NULL
	`)
	if err != nil {
		return err
	}

	count := 0
	for _, fn := range lambdas.Rows {
		functionARN := toString(fn["arn"])
		roleARN := toString(fn["role"])

		if roleARN != "" {
			b.graph.AddEdge(&Edge{
				ID:     functionARN + "->executes_as->" + roleARN,
				Source: functionARN,
				Target: roleARN,
				Kind:   EdgeKindCanAssume,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"mechanism": "execution_role",
				},
			})
			count++
		}
	}

	b.logger.Debug("added lambda execution role edges", "count", count)
	return nil
}

// GCP Builder Methods

func (b *Builder) buildGCPNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "gcp_iam_service_accounts",
			query: `SELECT unique_id, email, project_id, display_name FROM gcp_iam_service_accounts`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, sa := range rows {
					nodes = append(nodes, &Node{
						ID: toString(sa["unique_id"]), Kind: NodeKindServiceAccount, Name: toString(sa["email"]),
						Provider: "gcp", Account: toString(sa["project_id"]),
						Properties: map[string]any{"email": sa["email"], "display_name": sa["display_name"]},
					})
				}
				return nodes
			},
		},
		{
			table: "gcp_compute_instances",
			query: `SELECT id, name, project_id, zone, status, service_accounts FROM gcp_compute_instances`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, inst := range rows {
					saEmail := extractGCPServiceAccountEmail(inst["service_accounts"])
					isDefaultSA := strings.HasSuffix(saEmail, "-compute@developer.gserviceaccount.com")
					nodes = append(nodes, &Node{
						ID: toString(inst["id"]), Kind: NodeKindInstance, Name: toString(inst["name"]),
						Provider: "gcp", Account: toString(inst["project_id"]), Region: toString(inst["zone"]),
						Properties: map[string]any{
							"status":                inst["status"],
							"service_accounts":      inst["service_accounts"],
							"service_account_email": saEmail,
							"uses_default_sa":       isDefaultSA,
						},
					})
				}
				return nodes
			},
		},
		{
			table: "gcp_storage_buckets",
			query: `SELECT name, project_id, location, iam_policy, public_access_prevention, uniform_bucket_level_access FROM gcp_storage_buckets`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, bucket := range rows {
					iamStr := toString(bucket["iam_policy"])
					allUsers := strings.Contains(iamStr, "allUsers")
					allAuthUsers := strings.Contains(iamStr, "allAuthenticatedUsers")
					isPublic := allUsers || allAuthUsers
					risk := RiskNone
					if isPublic {
						risk = RiskCritical
					}
					nodes = append(nodes, &Node{
						ID: toString(bucket["name"]), Kind: NodeKindBucket, Name: toString(bucket["name"]),
						Provider: "gcp", Account: toString(bucket["project_id"]), Region: toString(bucket["location"]),
						Risk: risk, Properties: map[string]any{
							"iam_policy":                     bucket["iam_policy"],
							"public":                         isPublic,
							"public_access":                  isPublic,
							"all_users_access":               allUsers,
							"all_authenticated_users_access": allAuthUsers,
							"public_access_prevention":       bucket["public_access_prevention"],
						},
					})
				}
				return nodes
			},
		},
		{
			table: "gcp_sql_instances",
			query: `SELECT name, project_id, region, database_version, ip_addresses, settings FROM gcp_sql_instances`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, db := range rows {
					ipStr := toString(db["ip_addresses"])
					// A Cloud SQL instance is publicly accessible if it has a PRIMARY
					// IP type AND the settings authorize 0.0.0.0/0. Having both PRIMARY
					// and PRIVATE addresses doesn't negate public exposure.
					hasPublicIP := strings.Contains(ipStr, "PRIMARY")
					settingsStr := toString(db["settings"])
					hasOpenAuthNetwork := strings.Contains(settingsStr, "0.0.0.0/0")
					isPublic := hasPublicIP && hasOpenAuthNetwork
					risk := RiskNone
					if isPublic {
						risk = RiskCritical
					}
					nodes = append(nodes, &Node{
						ID: toString(db["name"]), Kind: NodeKindDatabase, Name: toString(db["name"]),
						Provider: "gcp", Account: toString(db["project_id"]), Region: toString(db["region"]),
						Risk: risk, Properties: map[string]any{
							"database_version": db["database_version"],
							"ip_addresses":     db["ip_addresses"],
							"public":           isPublic,
						},
					})
				}
				return nodes
			},
		},
		{
			table: "gcp_cloudfunctions_functions",
			query: `SELECT name, project_id, location, service_config, build_config FROM gcp_cloudfunctions_functions`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, fn := range rows {
					nodes = append(nodes, &Node{
						ID: toString(fn["name"]), Kind: NodeKindFunction, Name: toString(fn["name"]),
						Provider: "gcp", Account: toString(fn["project_id"]), Region: toString(fn["location"]),
						Properties: map[string]any{"service_config": fn["service_config"], "build_config": fn["build_config"]},
					})
				}
				return nodes
			},
		},
		{
			table: "gcp_cloudrun_services",
			query: `SELECT name, project_id, location, ingress, uri FROM gcp_cloudrun_services`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, svc := range rows {
					nodes = append(nodes, &Node{
						ID: toString(svc["name"]), Kind: NodeKindFunction, Name: toString(svc["name"]),
						Provider: "gcp", Account: toString(svc["project_id"]), Region: toString(svc["location"]),
						Properties: map[string]any{"ingress": svc["ingress"], "uri": svc["uri"]},
					})
				}
				return nodes
			},
		},
	}

	b.runNodeQueries(ctx, queries)
}

func (b *Builder) buildGCPEdges(ctx context.Context) {
	bindings, err := b.queryIfExists(ctx, "gcp_iam_policy_bindings",
		`SELECT project_id, role, members FROM gcp_iam_policy_bindings`)
	if err != nil {
		b.logger.Debug("failed to query GCP IAM bindings", "error", err)
		return
	}

	for _, binding := range bindings.Rows {
		role := toString(binding["role"])
		members := binding["members"]

		memberList, ok := members.([]any)
		if !ok {
			continue
		}

		edgeKind := gcpRoleToEdgeKind(role)
		projectID := toString(binding["project_id"])

		// Use indexed lookup (O(1)) instead of full scan
		projectNodes := b.graph.GetNodesByAccountIndexed(projectID)

		for _, m := range memberList {
			member := toString(m)
			for _, node := range projectNodes {
				if node.Provider != "gcp" || !node.IsResource() {
					continue
				}
				b.graph.AddEdge(&Edge{
					ID:     member + "->" + node.ID + ":" + role,
					Source: member,
					Target: node.ID,
					Kind:   edgeKind,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"role":    role,
						"binding": "project",
					},
				})
			}
		}
	}
	b.logger.Debug("processed GCP IAM bindings", "count", len(bindings.Rows))

	b.buildGCPServiceAccountEdges(ctx)
	b.buildGCPFirewallEdges(ctx)
}

func (b *Builder) buildGCPServiceAccountEdges(_ context.Context) {
	// Link compute instances to their service accounts
	for _, node := range b.graph.GetAllNodes() {
		if node.Provider != "gcp" || node.Kind != NodeKindInstance {
			continue
		}

		saList, ok := node.Properties["service_accounts"].([]any)
		if !ok {
			continue
		}

		for _, sa := range saList {
			saMap, ok := sa.(map[string]any)
			if !ok {
				continue
			}
			saEmail := toString(saMap["email"])
			if saEmail != "" {
				b.graph.AddEdge(&Edge{
					ID:     node.ID + "->runs_as->" + saEmail,
					Source: node.ID,
					Target: saEmail,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"mechanism": "instance_service_account",
					},
				})
			}
		}
	}
}

func gcpRoleToEdgeKind(role string) EdgeKind {
	switch {
	case contains(role, "admin"), contains(role, "owner"):
		return EdgeKindCanAdmin
	case contains(role, "editor"), contains(role, "writer"):
		return EdgeKindCanWrite
	case contains(role, "deleter"):
		return EdgeKindCanDelete
	default:
		return EdgeKindCanRead
	}
}

func (b *Builder) buildGCPFirewallEdges(ctx context.Context) {
	firewalls, err := b.queryIfExists(ctx, "gcp_compute_firewalls",
		`SELECT name, project_id, direction, source_ranges, allowed, target_tags, network FROM gcp_compute_firewalls`)
	if err != nil {
		b.logger.Debug("failed to query GCP firewalls", "error", err)
		return
	}

	count := 0
	for _, fw := range firewalls.Rows {
		direction := toString(fw["direction"])
		if direction != "INGRESS" && direction != "\"INGRESS\"" {
			continue
		}
		sourceRanges := toString(fw["source_ranges"])
		if !strings.Contains(sourceRanges, "0.0.0.0/0") {
			continue
		}

		// This firewall allows internet ingress. Find matching instances by target_tags or all instances in the project.
		projectID := toString(fw["project_id"])
		targetTags := toString(fw["target_tags"])

		for _, node := range b.graph.GetNodesByAccountIndexed(projectID) {
			if node.Provider != "gcp" || node.Kind != NodeKindInstance {
				continue
			}
			// If firewall has target_tags, only match instances with those tags
			// For now, if no target_tags, it applies to all instances in the network
			if targetTags != "" && targetTags != "[]" && targetTags != "null" {
				// Check if instance has matching tags (simplified: check name containment)
				// Full implementation would match instance tags against firewall target_tags
				continue
			}
			node.Properties["public"] = true
			b.graph.AddEdge(&Edge{
				ID:     "internet->fw:" + toString(fw["name"]) + "->" + node.ID,
				Source: "internet",
				Target: node.ID,
				Kind:   EdgeKindExposedTo,
				Effect: EdgeEffectAllow,
				Risk:   RiskHigh,
				Properties: map[string]any{
					"firewall":  fw["name"],
					"allowed":   fw["allowed"],
					"mechanism": "gcp_firewall",
				},
			})
			count++
		}
	}
	b.logger.Debug("added GCP firewall exposure edges", "count", count)
}

// Azure Builder Methods

func (b *Builder) buildAzureNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "azure_ad_service_principals",
			query: `SELECT id, display_name, app_id, service_principal_type FROM azure_ad_service_principals`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, sp := range rows {
					nodes = append(nodes, &Node{
						ID: toString(sp["id"]), Kind: NodeKindServiceAccount, Name: toString(sp["display_name"]),
						Provider: "azure", Properties: map[string]any{"app_id": sp["app_id"], "type": sp["service_principal_type"]},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_ad_users",
			query: `SELECT id, user_principal_name, display_name, mail FROM azure_ad_users`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, u := range rows {
					nodes = append(nodes, &Node{
						ID: toString(u["id"]), Kind: NodeKindUser, Name: toString(u["display_name"]),
						Provider: "azure", Properties: map[string]any{"upn": u["user_principal_name"], "mail": u["mail"]},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_compute_virtual_machines",
			query: `SELECT id, name, subscription_id, resource_group, location, identity FROM azure_compute_virtual_machines`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, vm := range rows {
					nodes = append(nodes, &Node{
						ID: toString(vm["id"]), Kind: NodeKindInstance, Name: toString(vm["name"]),
						Provider: "azure", Account: toString(vm["subscription_id"]), Region: toString(vm["location"]),
						Properties: map[string]any{"resource_group": vm["resource_group"], "identity": vm["identity"]},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_storage_accounts",
			query: `SELECT id, name, subscription_id, resource_group, location, allow_blob_public_access FROM azure_storage_accounts`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, sa := range rows {
					isPublic := toBool(sa["allow_blob_public_access"])
					risk := RiskNone
					if isPublic {
						risk = RiskHigh
					}
					nodes = append(nodes, &Node{
						ID: toString(sa["id"]), Kind: NodeKindBucket, Name: toString(sa["name"]),
						Provider: "azure", Account: toString(sa["subscription_id"]), Region: toString(sa["location"]),
						Risk: risk, Properties: map[string]any{"resource_group": sa["resource_group"], "public": isPublic},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_sql_databases",
			query: `SELECT id, name, subscription_id, resource_group, location, server_name FROM azure_sql_databases`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, db := range rows {
					nodes = append(nodes, &Node{
						ID: toString(db["id"]), Kind: NodeKindDatabase, Name: toString(db["name"]),
						Provider: "azure", Account: toString(db["subscription_id"]), Region: toString(db["location"]),
						Properties: map[string]any{"resource_group": db["resource_group"], "server": db["server_name"]},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_keyvault_vaults",
			query: `SELECT id, name, subscription_id, resource_group, location FROM azure_keyvault_vaults`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, kv := range rows {
					nodes = append(nodes, &Node{
						ID: toString(kv["id"]), Kind: NodeKindSecret, Name: toString(kv["name"]),
						Provider: "azure", Account: toString(kv["subscription_id"]), Region: toString(kv["location"]),
						Risk: RiskHigh, Properties: map[string]any{"resource_group": kv["resource_group"]},
					})
				}
				return nodes
			},
		},
		{
			table: "azure_functions_apps",
			query: `SELECT id, name, subscription_id, resource_group, location, identity FROM azure_functions_apps`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, fn := range rows {
					nodes = append(nodes, &Node{
						ID: toString(fn["id"]), Kind: NodeKindFunction, Name: toString(fn["name"]),
						Provider: "azure", Account: toString(fn["subscription_id"]), Region: toString(fn["location"]),
						Properties: map[string]any{"resource_group": fn["resource_group"], "identity": fn["identity"]},
					})
				}
				return nodes
			},
		},
	}

	b.runNodeQueries(ctx, queries)
}

func (b *Builder) buildAzureEdges(ctx context.Context) {
	roleAssignments, err := b.queryIfExists(ctx, "azure_authorization_role_assignments",
		`SELECT id, principal_id, role_definition_name, scope FROM azure_authorization_role_assignments`)
	if err != nil {
		b.logger.Debug("failed to query Azure role assignments", "error", err)
		return
	}

	// Use indexed provider lookup instead of GetAllNodes scan
	azureNodes := b.graph.GetNodesByKindIndexed(NodeKindBucket, NodeKindInstance, NodeKindDatabase, NodeKindSecret, NodeKindFunction)

	for _, ra := range roleAssignments.Rows {
		principalID := toString(ra["principal_id"])
		roleName := toString(ra["role_definition_name"])
		scope := toString(ra["scope"])
		edgeKind := azureRoleToEdgeKind(roleName)

		for _, node := range azureNodes {
			if node.Provider != "azure" {
				continue
			}
			if contains(node.ID, scope) || scope == "/" {
				b.graph.AddEdge(&Edge{
					ID:     principalID + "->" + node.ID + ":" + roleName,
					Source: principalID,
					Target: node.ID,
					Kind:   edgeKind,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"role":  roleName,
						"scope": scope,
					},
				})
			}
		}
	}
	b.logger.Debug("processed Azure role assignments", "count", len(roleAssignments.Rows))

	b.buildAzureManagedIdentityEdges(ctx)
}

func (b *Builder) buildAzureManagedIdentityEdges(_ context.Context) {
	// Link VMs and Functions to their managed identities
	for _, node := range b.graph.GetAllNodes() {
		if node.Provider != "azure" {
			continue
		}
		if node.Kind != NodeKindInstance && node.Kind != NodeKindFunction {
			continue
		}

		identity, ok := node.Properties["identity"].(map[string]any)
		if !ok {
			continue
		}

		// System-assigned managed identity
		if principalID, ok := identity["principal_id"].(string); ok && principalID != "" {
			b.graph.AddEdge(&Edge{
				ID:     node.ID + "->identity->" + principalID,
				Source: node.ID,
				Target: principalID,
				Kind:   EdgeKindCanAssume,
				Effect: EdgeEffectAllow,
				Properties: map[string]any{
					"mechanism": "system_assigned_identity",
				},
			})
		}

		// User-assigned managed identities
		if userIdentities, ok := identity["user_assigned_identities"].(map[string]any); ok {
			for identityID := range userIdentities {
				b.graph.AddEdge(&Edge{
					ID:     node.ID + "->identity->" + identityID,
					Source: node.ID,
					Target: identityID,
					Kind:   EdgeKindCanAssume,
					Effect: EdgeEffectAllow,
					Properties: map[string]any{
						"mechanism": "user_assigned_identity",
					},
				})
			}
		}
	}
}

func azureRoleToEdgeKind(role string) EdgeKind {
	switch {
	case contains(role, "Owner"), contains(role, "Contributor"):
		return EdgeKindCanAdmin
	case contains(role, "Writer"):
		return EdgeKindCanWrite
	case contains(role, "Delete"):
		return EdgeKindCanDelete
	default:
		return EdgeKindCanRead
	}
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
