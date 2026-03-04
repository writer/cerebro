package graph

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/sync/errgroup"
)

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
