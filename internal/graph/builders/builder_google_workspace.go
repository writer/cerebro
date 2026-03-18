package builders

import (
	"context"
	"strings"
)

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
	b.enrichGoogleWorkspaceApplicationActivity(ctx)
}

func (b *Builder) enrichGoogleWorkspaceApplicationActivity(ctx context.Context) {
	rows, err := b.queryIfExists(ctx, "google_workspace_token_activities", `
		SELECT client_id, display_text, event_name, event_time
		FROM google_workspace_token_activities
		WHERE client_id IS NOT NULL
	`)
	if err != nil {
		b.logger.Debug("google workspace token activity unavailable", "error", err)
		return
	}

	type activitySummary struct {
		recentTokenActivityCount       int
		recentTokenAuthorizeEventCount int
		recentTokenRevokeEventCount    int
		lastTokenActivityAt            string
		displayText                    string
	}

	summaries := make(map[string]*activitySummary)
	for _, row := range rows.Rows {
		clientID := strings.TrimSpace(toString(row["client_id"]))
		if clientID == "" {
			continue
		}
		summary := summaries[clientID]
		if summary == nil {
			summary = &activitySummary{}
			summaries[clientID] = summary
		}
		summary.recentTokenActivityCount++
		eventName := strings.ToLower(strings.TrimSpace(toString(row["event_name"])))
		switch {
		case strings.Contains(eventName, "authorize"), strings.Contains(eventName, "grant"):
			summary.recentTokenAuthorizeEventCount++
		case strings.Contains(eventName, "revoke"), strings.Contains(eventName, "remove"), strings.Contains(eventName, "delete"):
			summary.recentTokenRevokeEventCount++
		}
		summary.lastTokenActivityAt = maxRFC3339String(summary.lastTokenActivityAt, strings.TrimSpace(toString(row["event_time"])))
		if summary.displayText == "" {
			summary.displayText = strings.TrimSpace(toString(row["display_text"]))
		}
	}

	for clientID, summary := range summaries {
		node, ok := b.graph.GetNode(clientID)
		if !ok || node == nil {
			b.graph.AddNode(&Node{
				ID:       clientID,
				Kind:     NodeKindApplication,
				Name:     firstNonEmpty(summary.displayText, clientID),
				Provider: "google_workspace",
				Properties: map[string]any{
					"client_id":    clientID,
					"display_text": summary.displayText,
				},
			})
			node, ok = b.graph.GetNode(clientID)
			if !ok || node == nil {
				continue
			}
		}
		if node.Provider != "google_workspace" || node.Kind != NodeKindApplication {
			continue
		}
		if node.Properties == nil {
			node.Properties = make(map[string]any)
		}
		if strings.TrimSpace(node.Name) == "" {
			node.Name = firstNonEmpty(summary.displayText, clientID)
		}
		node.Properties["recent_token_activity_count"] = summary.recentTokenActivityCount
		node.Properties["recent_token_authorize_event_count"] = summary.recentTokenAuthorizeEventCount
		node.Properties["recent_token_revoke_event_count"] = summary.recentTokenRevokeEventCount
		node.Properties["last_token_activity_at"] = summary.lastTokenActivityAt
		if strings.TrimSpace(propertyString(node.Properties, "display_text")) == "" && summary.displayText != "" {
			node.Properties["display_text"] = summary.displayText
		}
	}
}
