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
}
