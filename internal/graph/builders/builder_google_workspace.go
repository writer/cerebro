package builders

import "context"

func (b *Builder) buildGoogleWorkspaceNodes(ctx context.Context) {
	queries := []nodeQuery{
		{
			table: "google_workspace_users",
			query: `SELECT id, primary_email, name, given_name, family_name, is_admin, is_delegated_admin, suspended, archived, is_enrolled_in_2sv, is_enforced_in_2sv, creation_time, last_login_time, org_unit_path FROM google_workspace_users`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, row := range rows {
					id := toString(row["id"])
					if id == "" {
						continue
					}
					name := firstNonEmpty(toString(row["primary_email"]), toString(row["name"]), id)
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindUser,
						Name:     name,
						Provider: "google_workspace",
						Properties: map[string]any{
							"email":              row["primary_email"],
							"display_name":       row["name"],
							"given_name":         row["given_name"],
							"family_name":        row["family_name"],
							"is_admin":           row["is_admin"],
							"is_delegated_admin": row["is_delegated_admin"],
							"suspended":          row["suspended"],
							"archived":           row["archived"],
							"is_enrolled_in_2sv": row["is_enrolled_in_2sv"],
							"is_enforced_in_2sv": row["is_enforced_in_2sv"],
							"creation_time":      row["creation_time"],
							"last_login_time":    row["last_login_time"],
							"org_unit_path":      row["org_unit_path"],
						},
					})
				}
				return nodes
			},
		},
		{
			table: "google_workspace_groups",
			query: `SELECT id, email, name, description, direct_members_count, admin_created FROM google_workspace_groups`,
			parse: func(rows []map[string]any) []*Node {
				nodes := make([]*Node, 0, len(rows))
				for _, row := range rows {
					id := toString(row["id"])
					if id == "" {
						continue
					}
					name := firstNonEmpty(toString(row["name"]), toString(row["email"]), id)
					nodes = append(nodes, &Node{
						ID:       id,
						Kind:     NodeKindGroup,
						Name:     name,
						Provider: "google_workspace",
						Properties: map[string]any{
							"email":                row["email"],
							"description":          row["description"],
							"direct_members_count": row["direct_members_count"],
							"admin_created":        row["admin_created"],
						},
					})
				}
				return nodes
			},
		},
		{
			table: "google_workspace_tokens",
			query: `SELECT client_id, display_text, anonymous, native_app, app_type FROM google_workspace_tokens`,
			parse: func(rows []map[string]any) []*Node {
				type appSummary struct {
					displayText string
					anonymous   bool
					nativeApp   bool
					appType     string
				}
				summaries := make(map[string]appSummary)
				for _, row := range rows {
					clientID := toString(row["client_id"])
					if clientID == "" {
						continue
					}
					summary := summaries[clientID]
					if summary.displayText == "" {
						summary.displayText = firstNonEmpty(toString(row["display_text"]), clientID)
					}
					if value, ok := row["anonymous"].(bool); ok && value {
						summary.anonymous = true
					}
					if value, ok := row["native_app"].(bool); ok && value {
						summary.nativeApp = true
					}
					if summary.appType == "" {
						summary.appType = toString(row["app_type"])
					}
					summaries[clientID] = summary
				}

				nodes := make([]*Node, 0, len(summaries))
				for clientID, summary := range summaries {
					nodes = append(nodes, &Node{
						ID:       clientID,
						Kind:     NodeKindApplication,
						Name:     firstNonEmpty(summary.displayText, clientID),
						Provider: "google_workspace",
						Properties: map[string]any{
							"client_id":    clientID,
							"display_text": summary.displayText,
							"anonymous":    summary.anonymous,
							"native_app":   summary.nativeApp,
							"app_type":     summary.appType,
						},
					})
				}
				return nodes
			},
		},
	}

	b.runNodeQueries(ctx, queries)
}
