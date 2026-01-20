package graph

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
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
	source DataSource
	graph  *Graph
	logger *slog.Logger
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

// Build constructs the entire graph from the data source
func (b *Builder) Build(ctx context.Context) error {
	start := time.Now()
	b.graph.Clear()

	b.logger.Info("building security graph")

	// Build AWS nodes and edges
	b.buildAWSNodes(ctx)
	b.buildAWSEdges(ctx)

	// Build GCP nodes and edges
	b.buildGCPNodes(ctx)
	b.buildGCPEdges(ctx)

	// Build Azure nodes and edges
	b.buildAzureNodes(ctx)
	b.buildAzureEdges(ctx)

	// Add internet entry point
	b.addInternetNode()

	// Build exposure edges
	b.buildExposureEdges()

	// Build Code-to-Cloud edges (inferred from tags)
	b.buildSCMInference()

	// Build edges from extracted relationships
	b.buildRelationshipEdges(ctx)

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

	return nil
}

// Graph returns the built graph
func (b *Builder) Graph() *Graph {
	return b.graph
}

func (b *Builder) buildRelationshipEdges(ctx context.Context) {
	rels, err := b.source.Query(ctx, `
		SELECT source_id, source_type, target_id, target_type, rel_type, properties
		FROM resource_relationships
	`)
	if err != nil {
		b.logger.Debug("relationship table not available", "error", err)
		return
	}

	for _, row := range rels.Rows {
		sourceID := toString(row["source_id"])
		targetID := toString(row["target_id"])
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
			} else {
				kind = EdgeKindConnectsTo
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
		default:
			kind = EdgeKindConnectsTo
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
	// IAM Users
	users, err := b.source.Query(ctx, `
		SELECT arn, user_name, account_id, password_last_used, tags
		FROM aws_iam_users
	`)
	if err != nil {
		b.logger.Warn("failed to query IAM users", "error", err)
	} else {
		for _, u := range users.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(u["arn"]),
				Kind:     NodeKindUser,
				Name:     toString(u["user_name"]),
				Provider: "aws",
				Account:  toString(u["account_id"]),
				Properties: map[string]any{
					"last_login": u["password_last_used"],
				},
			})
		}
		b.logger.Debug("added IAM users", "count", len(users.Rows))
	}

	// IAM Roles
	roles, err := b.source.Query(ctx, `
		SELECT arn, role_name, account_id, assume_role_policy_document, description
		FROM aws_iam_roles
	`)
	if err != nil {
		b.logger.Warn("failed to query IAM roles", "error", err)
	} else {
		for _, r := range roles.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(r["arn"]),
				Kind:     NodeKindRole,
				Name:     toString(r["role_name"]),
				Provider: "aws",
				Account:  toString(r["account_id"]),
				Properties: map[string]any{
					"trust_policy": r["assume_role_policy_document"],
					"description":  r["description"],
				},
			})
		}
		b.logger.Debug("added IAM roles", "count", len(roles.Rows))
	}

	// IAM Groups
	groups, err := b.source.Query(ctx, `
		SELECT arn, group_name, account_id
		FROM aws_iam_groups
	`)
	if err != nil {
		b.logger.Warn("failed to query IAM groups", "error", err)
	} else {
		for _, g := range groups.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(g["arn"]),
				Kind:     NodeKindGroup,
				Name:     toString(g["group_name"]),
				Provider: "aws",
				Account:  toString(g["account_id"]),
			})
		}
		b.logger.Debug("added IAM groups", "count", len(groups.Rows))
	}

	// S3 Buckets
	buckets, err := b.source.Query(ctx, `
		SELECT arn, name, account_id, region, block_public_acls, block_public_policy, versioning_status
		FROM aws_s3_buckets
	`)
	if err != nil {
		b.logger.Warn("failed to query S3 buckets", "error", err)
	} else {
		for _, bucket := range buckets.Rows {
			isPublic := !toBool(bucket["block_public_acls"]) || !toBool(bucket["block_public_policy"])
			risk := RiskNone
			if isPublic {
				risk = RiskHigh
			}
			b.graph.AddNode(&Node{
				ID:       toString(bucket["arn"]),
				Kind:     NodeKindBucket,
				Name:     toString(bucket["name"]),
				Provider: "aws",
				Account:  toString(bucket["account_id"]),
				Region:   toString(bucket["region"]),
				Risk:     risk,
				Properties: map[string]any{
					"public":     isPublic,
					"versioning": bucket["versioning_status"],
				},
			})
		}
		b.logger.Debug("added S3 buckets", "count", len(buckets.Rows))
	}

	// EC2 Instances
	instances, err := b.source.Query(ctx, `
		SELECT arn, instance_id, account_id, region, public_ip_address, iam_instance_profile
		FROM aws_ec2_instances
	`)
	if err != nil {
		b.logger.Warn("failed to query EC2 instances", "error", err)
	} else {
		for _, inst := range instances.Rows {
			hasPublicIP := toString(inst["public_ip_address"]) != ""
			risk := RiskNone
			if hasPublicIP {
				risk = RiskMedium
			}
			b.graph.AddNode(&Node{
				ID:       toString(inst["arn"]),
				Kind:     NodeKindInstance,
				Name:     toString(inst["instance_id"]),
				Provider: "aws",
				Account:  toString(inst["account_id"]),
				Region:   toString(inst["region"]),
				Risk:     risk,
				Properties: map[string]any{
					"public_ip":            inst["public_ip_address"],
					"iam_instance_profile": inst["iam_instance_profile"],
				},
			})
		}
		b.logger.Debug("added EC2 instances", "count", len(instances.Rows))
	}

	// RDS Instances
	rdsInstances, err := b.source.Query(ctx, `
		SELECT arn, db_instance_identifier, account_id, region, publicly_accessible, storage_encrypted
		FROM aws_rds_instances
	`)
	if err != nil {
		b.logger.Warn("failed to query RDS instances", "error", err)
	} else {
		for _, db := range rdsInstances.Rows {
			isPublic := toBool(db["publicly_accessible"])
			risk := RiskNone
			if isPublic {
				risk = RiskCritical
			}
			b.graph.AddNode(&Node{
				ID:       toString(db["arn"]),
				Kind:     NodeKindDatabase,
				Name:     toString(db["db_instance_identifier"]),
				Provider: "aws",
				Account:  toString(db["account_id"]),
				Region:   toString(db["region"]),
				Risk:     risk,
				Properties: map[string]any{
					"public":    isPublic,
					"encrypted": db["storage_encrypted"],
				},
			})
		}
		b.logger.Debug("added RDS instances", "count", len(rdsInstances.Rows))
	}

	// Lambda Functions
	lambdas, err := b.source.Query(ctx, `
		SELECT arn, function_name, account_id, region, role
		FROM aws_lambda_functions
	`)
	if err != nil {
		b.logger.Warn("failed to query Lambda functions", "error", err)
	} else {
		for _, fn := range lambdas.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(fn["arn"]),
				Kind:     NodeKindFunction,
				Name:     toString(fn["function_name"]),
				Provider: "aws",
				Account:  toString(fn["account_id"]),
				Region:   toString(fn["region"]),
				Properties: map[string]any{
					"execution_role": fn["role"],
				},
			})
		}
		b.logger.Debug("added Lambda functions", "count", len(lambdas.Rows))
	}

	// Secrets Manager Secrets
	secrets, err := b.source.Query(ctx, `
		SELECT arn, name, account_id, region
		FROM aws_secretsmanager_secrets
	`)
	if err != nil {
		b.logger.Warn("failed to query Secrets Manager secrets", "error", err)
	} else {
		for _, s := range secrets.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(s["arn"]),
				Kind:     NodeKindSecret,
				Name:     toString(s["name"]),
				Provider: "aws",
				Account:  toString(s["account_id"]),
				Region:   toString(s["region"]),
				Risk:     RiskHigh, // Secrets are inherently sensitive
			})
		}
		b.logger.Debug("added Secrets Manager secrets", "count", len(secrets.Rows))
	}

}

func (b *Builder) buildAWSEdges(ctx context.Context) {
	// Get all IAM policies for lookup
	policies, err := b.source.Query(ctx, `
		SELECT arn, name, document FROM aws_iam_policies
	`)
	if err != nil {
		b.logger.Warn("failed to query IAM policies", "error", err)
		return
	}
	policyDocs := make(map[string]string)
	for _, p := range policies.Rows {
		policyDocs[toString(p["arn"])] = toString(p["document"])
	}

	// User attached policies
	userPolicies, err := b.source.Query(ctx, `
		SELECT user_arn, policy_arn FROM aws_iam_user_attached_policies
	`)
	if err != nil {
		b.logger.Warn("failed to query user attached policies", "error", err)
	} else {
		for _, up := range userPolicies.Rows {
			userARN := toString(up["user_arn"])
			policyARN := toString(up["policy_arn"])
			doc := policyDocs[policyARN]
			b.buildEdgesFromPolicy(userARN, doc, policyARN)
		}
	}

	// Role attached policies
	rolePolicies, err := b.source.Query(ctx, `
		SELECT role_arn, policy_arn FROM aws_iam_role_attached_policies
	`)
	if err != nil {
		b.logger.Warn("failed to query role attached policies", "error", err)
	} else {
		for _, rp := range rolePolicies.Rows {
			roleARN := toString(rp["role_arn"])
			policyARN := toString(rp["policy_arn"])
			doc := policyDocs[policyARN]
			b.buildEdgesFromPolicy(roleARN, doc, policyARN)
		}
	}

	// User inline policies
	userInlinePolicies, err := b.source.Query(ctx, `
		SELECT user_arn, policy_name, policy_document FROM aws_iam_user_policies
	`)
	if err != nil {
		b.logger.Warn("failed to query user inline policies", "error", err)
	} else {
		for _, p := range userInlinePolicies.Rows {
			userARN := toString(p["user_arn"])
			policyName := toString(p["policy_name"])
			doc := toString(p["policy_document"])
			b.buildEdgesFromPolicy(userARN, doc, "inline:"+policyName)
		}
		b.logger.Debug("processed user inline policies", "count", len(userInlinePolicies.Rows))
	}

	// Role inline policies
	roleInlinePolicies, err := b.source.Query(ctx, `
		SELECT role_arn, policy_name, policy_document FROM aws_iam_role_policies
	`)
	if err != nil {
		b.logger.Warn("failed to query role inline policies", "error", err)
	} else {
		for _, p := range roleInlinePolicies.Rows {
			roleARN := toString(p["role_arn"])
			policyName := toString(p["policy_name"])
			doc := toString(p["policy_document"])
			b.buildEdgesFromPolicy(roleARN, doc, "inline:"+policyName)
		}
		b.logger.Debug("processed role inline policies", "count", len(roleInlinePolicies.Rows))
	}

	// Group inline policies
	groupInlinePolicies, err := b.source.Query(ctx, `
		SELECT group_arn, policy_name, policy_document FROM aws_iam_group_policies
	`)
	if err != nil {
		b.logger.Warn("failed to query group inline policies", "error", err)
	} else {
		for _, p := range groupInlinePolicies.Rows {
			groupARN := toString(p["group_arn"])
			policyName := toString(p["policy_name"])
			doc := toString(p["policy_document"])
			b.buildEdgesFromPolicy(groupARN, doc, "inline:"+policyName)
		}
		b.logger.Debug("processed group inline policies", "count", len(groupInlinePolicies.Rows))
	}

	// Build group membership edges
	if err := b.buildGroupMembershipEdges(ctx); err != nil {
		b.logger.Warn("failed to build group membership edges", "error", err)
	}

	// Build role assumption edges from trust policies
	if err := b.buildTrustEdges(ctx); err != nil {
		b.logger.Warn("failed to build trust edges", "error", err)
	}

	// Build EC2 instance profile -> role edges
	if err := b.buildInstanceProfileEdges(ctx); err != nil {
		b.logger.Warn("failed to build instance profile edges", "error", err)
	}

	// Build Lambda execution role edges
	if err := b.buildLambdaRoleEdges(ctx); err != nil {
		b.logger.Warn("failed to build lambda role edges", "error", err)
	}
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
	roles, err := b.source.Query(ctx, `
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
				for _, node := range b.graph.GetNodesByAccount(principalAccount) {
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
	for _, node := range b.graph.GetAllNodes() {
		if !node.IsResource() {
			continue
		}
		isPublic, ok := node.Properties["public"].(bool)
		if ok && isPublic {
			b.graph.AddEdge(&Edge{
				ID:     "internet->" + node.ID,
				Source: "internet",
				Target: node.ID,
				Kind:   EdgeKindExposedTo,
				Effect: EdgeEffectAllow,
				Risk:   RiskHigh,
			})
		}
	}
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

func toBool(v any) bool {
	if v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func (b *Builder) buildGroupMembershipEdges(ctx context.Context) error {
	// Query user-group memberships
	memberships, err := b.source.Query(ctx, `
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
	// EC2 instances with instance profiles can assume the associated role
	instances, err := b.source.Query(ctx, `
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
	// Lambda functions can assume their execution role
	lambdas, err := b.source.Query(ctx, `
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
	// GCP Service Accounts
	serviceAccounts, err := b.source.Query(ctx, `
		SELECT unique_id, email, project_id, display_name
		FROM gcp_iam_service_accounts
	`)
	if err != nil {
		b.logger.Debug("failed to query GCP service accounts", "error", err)
	} else {
		for _, sa := range serviceAccounts.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(sa["unique_id"]),
				Kind:     NodeKindServiceAccount,
				Name:     toString(sa["email"]),
				Provider: "gcp",
				Account:  toString(sa["project_id"]),
				Properties: map[string]any{
					"email":        sa["email"],
					"display_name": sa["display_name"],
				},
			})
		}
		b.logger.Debug("added GCP service accounts", "count", len(serviceAccounts.Rows))
	}

	// GCP Compute Instances
	instances, err := b.source.Query(ctx, `
		SELECT id, name, project_id, zone, status, service_accounts
		FROM gcp_compute_instances
	`)
	if err != nil {
		b.logger.Debug("failed to query GCP compute instances", "error", err)
	} else {
		for _, inst := range instances.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(inst["id"]),
				Kind:     NodeKindInstance,
				Name:     toString(inst["name"]),
				Provider: "gcp",
				Account:  toString(inst["project_id"]),
				Region:   toString(inst["zone"]),
				Properties: map[string]any{
					"status":           inst["status"],
					"service_accounts": inst["service_accounts"],
				},
			})
		}
		b.logger.Debug("added GCP compute instances", "count", len(instances.Rows))
	}

	// GCP Storage Buckets
	buckets, err := b.source.Query(ctx, `
		SELECT id, name, project_id, location, iam_policy
		FROM gcp_storage_buckets
	`)
	if err != nil {
		b.logger.Debug("failed to query GCP storage buckets", "error", err)
	} else {
		for _, bucket := range buckets.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(bucket["id"]),
				Kind:     NodeKindBucket,
				Name:     toString(bucket["name"]),
				Provider: "gcp",
				Account:  toString(bucket["project_id"]),
				Region:   toString(bucket["location"]),
				Properties: map[string]any{
					"iam_policy": bucket["iam_policy"],
				},
			})
		}
		b.logger.Debug("added GCP storage buckets", "count", len(buckets.Rows))
	}

	// GCP Cloud SQL Instances
	sqlInstances, err := b.source.Query(ctx, `
		SELECT name, project, region, database_version, ip_addresses
		FROM gcp_sql_instances
	`)
	if err != nil {
		b.logger.Debug("failed to query GCP SQL instances", "error", err)
	} else {
		for _, db := range sqlInstances.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(db["name"]),
				Kind:     NodeKindDatabase,
				Name:     toString(db["name"]),
				Provider: "gcp",
				Account:  toString(db["project"]),
				Region:   toString(db["region"]),
				Properties: map[string]any{
					"database_version": db["database_version"],
					"ip_addresses":     db["ip_addresses"],
				},
			})
		}
		b.logger.Debug("added GCP SQL instances", "count", len(sqlInstances.Rows))
	}

	// GCP Cloud Functions
	functions, err := b.source.Query(ctx, `
		SELECT name, project_id, region, service_account_email, runtime
		FROM gcp_cloudfunctions_functions
	`)
	if err != nil {
		b.logger.Debug("failed to query GCP Cloud Functions", "error", err)
	} else {
		for _, fn := range functions.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(fn["name"]),
				Kind:     NodeKindFunction,
				Name:     toString(fn["name"]),
				Provider: "gcp",
				Account:  toString(fn["project_id"]),
				Region:   toString(fn["region"]),
				Properties: map[string]any{
					"service_account": fn["service_account_email"],
					"runtime":         fn["runtime"],
				},
			})
		}
		b.logger.Debug("added GCP Cloud Functions", "count", len(functions.Rows))
	}
}

func (b *Builder) buildGCPEdges(ctx context.Context) {
	// GCP IAM Bindings (project-level)
	bindings, err := b.source.Query(ctx, `
		SELECT project_id, role, members
		FROM gcp_iam_policy_bindings
	`)
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

		for _, m := range memberList {
			member := toString(m)
			// Create edges for each resource the role grants access to
			// GCP bindings are at project level, so we create edges to project resources
			projectID := toString(binding["project_id"])

			// Find all resources in this project
			for _, node := range b.graph.GetNodesByAccount(projectID) {
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

	// Build service account edges for compute instances
	b.buildGCPServiceAccountEdges(ctx)
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

// Azure Builder Methods

func (b *Builder) buildAzureNodes(ctx context.Context) {
	// Azure Service Principals
	servicePrincipals, err := b.source.Query(ctx, `
		SELECT id, display_name, app_id, service_principal_type
		FROM azure_ad_service_principals
	`)
	if err != nil {
		b.logger.Debug("failed to query Azure service principals", "error", err)
	} else {
		for _, sp := range servicePrincipals.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(sp["id"]),
				Kind:     NodeKindServiceAccount,
				Name:     toString(sp["display_name"]),
				Provider: "azure",
				Properties: map[string]any{
					"app_id": sp["app_id"],
					"type":   sp["service_principal_type"],
				},
			})
		}
		b.logger.Debug("added Azure service principals", "count", len(servicePrincipals.Rows))
	}

	// Azure Users
	users, err := b.source.Query(ctx, `
		SELECT id, user_principal_name, display_name, mail
		FROM azure_ad_users
	`)
	if err != nil {
		b.logger.Debug("failed to query Azure AD users", "error", err)
	} else {
		for _, u := range users.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(u["id"]),
				Kind:     NodeKindUser,
				Name:     toString(u["display_name"]),
				Provider: "azure",
				Properties: map[string]any{
					"upn":  u["user_principal_name"],
					"mail": u["mail"],
				},
			})
		}
		b.logger.Debug("added Azure AD users", "count", len(users.Rows))
	}

	// Azure Virtual Machines
	vms, err := b.source.Query(ctx, `
		SELECT id, name, subscription_id, resource_group, location, identity
		FROM azure_compute_virtual_machines
	`)
	if err != nil {
		b.logger.Debug("failed to query Azure VMs", "error", err)
	} else {
		for _, vm := range vms.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(vm["id"]),
				Kind:     NodeKindInstance,
				Name:     toString(vm["name"]),
				Provider: "azure",
				Account:  toString(vm["subscription_id"]),
				Region:   toString(vm["location"]),
				Properties: map[string]any{
					"resource_group": vm["resource_group"],
					"identity":       vm["identity"],
				},
			})
		}
		b.logger.Debug("added Azure VMs", "count", len(vms.Rows))
	}

	// Azure Storage Accounts
	storageAccounts, err := b.source.Query(ctx, `
		SELECT id, name, subscription_id, resource_group, location, allow_blob_public_access
		FROM azure_storage_accounts
	`)
	if err != nil {
		b.logger.Debug("failed to query Azure storage accounts", "error", err)
	} else {
		for _, sa := range storageAccounts.Rows {
			isPublic := toBool(sa["allow_blob_public_access"])
			risk := RiskNone
			if isPublic {
				risk = RiskHigh
			}
			b.graph.AddNode(&Node{
				ID:       toString(sa["id"]),
				Kind:     NodeKindBucket,
				Name:     toString(sa["name"]),
				Provider: "azure",
				Account:  toString(sa["subscription_id"]),
				Region:   toString(sa["location"]),
				Risk:     risk,
				Properties: map[string]any{
					"resource_group": sa["resource_group"],
					"public":         isPublic,
				},
			})
		}
		b.logger.Debug("added Azure storage accounts", "count", len(storageAccounts.Rows))
	}

	// Azure SQL Databases
	sqlDatabases, err := b.source.Query(ctx, `
		SELECT id, name, subscription_id, resource_group, location, server_name
		FROM azure_sql_databases
	`)
	if err != nil {
		b.logger.Debug("failed to query Azure SQL databases", "error", err)
	} else {
		for _, db := range sqlDatabases.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(db["id"]),
				Kind:     NodeKindDatabase,
				Name:     toString(db["name"]),
				Provider: "azure",
				Account:  toString(db["subscription_id"]),
				Region:   toString(db["location"]),
				Properties: map[string]any{
					"resource_group": db["resource_group"],
					"server":         db["server_name"],
				},
			})
		}
		b.logger.Debug("added Azure SQL databases", "count", len(sqlDatabases.Rows))
	}

	// Azure Key Vaults (secrets)
	keyVaults, err := b.source.Query(ctx, `
		SELECT id, name, subscription_id, resource_group, location
		FROM azure_keyvault_vaults
	`)
	if err != nil {
		b.logger.Debug("failed to query Azure Key Vaults", "error", err)
	} else {
		for _, kv := range keyVaults.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(kv["id"]),
				Kind:     NodeKindSecret,
				Name:     toString(kv["name"]),
				Provider: "azure",
				Account:  toString(kv["subscription_id"]),
				Region:   toString(kv["location"]),
				Risk:     RiskHigh,
				Properties: map[string]any{
					"resource_group": kv["resource_group"],
				},
			})
		}
		b.logger.Debug("added Azure Key Vaults", "count", len(keyVaults.Rows))
	}

	// Azure Functions
	functions, err := b.source.Query(ctx, `
		SELECT id, name, subscription_id, resource_group, location, identity
		FROM azure_functions_apps
	`)
	if err != nil {
		b.logger.Debug("failed to query Azure Functions", "error", err)
	} else {
		for _, fn := range functions.Rows {
			b.graph.AddNode(&Node{
				ID:       toString(fn["id"]),
				Kind:     NodeKindFunction,
				Name:     toString(fn["name"]),
				Provider: "azure",
				Account:  toString(fn["subscription_id"]),
				Region:   toString(fn["location"]),
				Properties: map[string]any{
					"resource_group": fn["resource_group"],
					"identity":       fn["identity"],
				},
			})
		}
		b.logger.Debug("added Azure Functions", "count", len(functions.Rows))
	}
}

func (b *Builder) buildAzureEdges(ctx context.Context) {
	// Azure Role Assignments
	roleAssignments, err := b.source.Query(ctx, `
		SELECT id, principal_id, role_definition_name, scope
		FROM azure_authorization_role_assignments
	`)
	if err != nil {
		b.logger.Debug("failed to query Azure role assignments", "error", err)
		return
	}

	for _, ra := range roleAssignments.Rows {
		principalID := toString(ra["principal_id"])
		roleName := toString(ra["role_definition_name"])
		scope := toString(ra["scope"])

		edgeKind := azureRoleToEdgeKind(roleName)

		// Find resources that match this scope
		for _, node := range b.graph.GetAllNodes() {
			if node.Provider != "azure" || !node.IsResource() {
				continue
			}

			// Check if node ID starts with scope (Azure scopes are hierarchical)
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

	// Build managed identity edges
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
