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

	// Build nodes first
	b.buildAWSNodes(ctx)

	// Build edges
	b.buildAWSEdges(ctx)

	// Add internet entry point
	b.addInternetNode()

	// Build exposure edges
	b.buildExposureEdges()

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
