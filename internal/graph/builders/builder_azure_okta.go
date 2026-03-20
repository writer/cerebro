package builders

import (
	"context"
	"strings"
)

// Okta Builder Methods

func (b *Builder) buildOktaNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "okta_users",
			query: `SELECT id, login, email, status, last_login, mfa_enrolled, is_admin FROM okta_users`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, u := range rows {
					id := toString(u["id"])
					if id == "" {
						continue
					}
					name := toString(u["login"])
					if name == "" {
						name = toString(u["email"])
					}
					if name == "" {
						name = id
					}
					nodes = append(nodes, &Node{
						ID: id, Kind: NodeKindUser, Name: name,
						Provider: "okta",
						Properties: map[string]any{
							"email":        u["email"],
							"status":       u["status"],
							"last_login":   u["last_login"],
							"mfa_enrolled": u["mfa_enrolled"],
							"is_admin":     u["is_admin"],
						},
					})
				}
				return nodes
			},
		},
		{
			table: "okta_groups",
			query: `SELECT id, name, description, type FROM okta_groups`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, g := range rows {
					id := toString(g["id"])
					if id == "" {
						continue
					}
					name := toString(g["name"])
					if name == "" {
						name = id
					}
					nodes = append(nodes, &Node{
						ID: id, Kind: NodeKindGroup, Name: name,
						Provider: "okta",
						Properties: map[string]any{
							"description": g["description"],
							"type":        g["type"],
						},
					})
				}
				return nodes
			},
		},
		{
			table: "okta_applications",
			query: `SELECT id, label, name, status, sign_on_mode FROM okta_applications`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, app := range rows {
					id := toString(app["id"])
					if id == "" {
						continue
					}
					name := toString(app["label"])
					if name == "" {
						name = toString(app["name"])
					}
					if name == "" {
						name = id
					}
					nodes = append(nodes, &Node{
						ID: id, Kind: NodeKindApplication, Name: name,
						Provider: "okta",
						Properties: map[string]any{
							"status":       app["status"],
							"sign_on_mode": app["sign_on_mode"],
						},
					})
				}
				return nodes
			},
		},
		{
			table: "okta_admin_roles",
			query: `SELECT DISTINCT role_type, role_label FROM okta_admin_roles WHERE role_type IS NOT NULL`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, role := range rows {
					roleType := strings.TrimSpace(toString(role["role_type"]))
					if roleType == "" {
						continue
					}
					roleID := "okta_admin_role:" + strings.ToLower(roleType)
					name := toString(role["role_label"])
					if name == "" {
						name = roleType
					}
					nodes = append(nodes, &Node{
						ID: roleID, Kind: NodeKindRole, Name: name,
						Provider:   "okta",
						Properties: map[string]any{"role_type": roleType},
					})
				}
				return nodes
			},
		},
	}

	b.runNodeQueries(ctx, queries)
	b.enrichOktaApplicationGrantSignals(ctx)
}

func (b *Builder) enrichOktaApplicationGrantSignals(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "okta_app_grants", `
		SELECT app_id, source, user_id, status, created, last_updated
		FROM okta_app_grants
		WHERE app_id IS NOT NULL
	`)
	if err != nil {
		b.logger.Debug("okta app grant monitoring unavailable", "error", err)
		return
	}

	type appGrantSummary struct {
		activeGrantCount    int
		adminGrantCount     int
		principalGrantCount int
		lastGrantUpdatedAt  string
	}

	summaries := make(map[string]*appGrantSummary)
	for _, row := range rows.Rows {
		appID := toString(row["app_id"])
		if appID == "" {
			continue
		}
		status := strings.TrimSpace(toString(row["status"]))
		if status != "" && !strings.EqualFold(status, "ACTIVE") {
			continue
		}
		summary := summaries[appID]
		if summary == nil {
			summary = &appGrantSummary{}
			summaries[appID] = summary
		}
		summary.activeGrantCount++
		userID := strings.TrimSpace(toString(row["user_id"]))
		source := strings.TrimSpace(toString(row["source"]))
		if userID == "" && strings.EqualFold(source, "ADMIN") {
			summary.adminGrantCount++
		} else {
			summary.principalGrantCount++
		}
		summary.lastGrantUpdatedAt = maxRFC3339String(summary.lastGrantUpdatedAt, strings.TrimSpace(firstNonEmpty(toString(row["last_updated"]), toString(row["created"]))))
	}

	for appID, summary := range summaries {
		node, ok := b.graph.GetNode(appID)
		if !ok || node == nil || node.Provider != "okta" || node.Kind != NodeKindApplication {
			continue
		}
		if node.Properties == nil {
			node.Properties = make(map[string]any)
		}
		node.Properties["active_grant_count"] = summary.activeGrantCount
		node.Properties["admin_grant_count"] = summary.adminGrantCount
		node.Properties["principal_grant_count"] = summary.principalGrantCount
		node.Properties["last_grant_updated_at"] = summary.lastGrantUpdatedAt
	}
}
