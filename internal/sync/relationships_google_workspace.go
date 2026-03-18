package sync

import (
	"context"
	"sort"
	"strings"
)

func (r *RelationshipExtractor) extractGoogleWorkspaceRelationships(ctx context.Context) (int, error) {
	var rels []Relationship

	query := `SELECT GROUP_ID, MEMBER_ID, TYPE FROM GOOGLE_WORKSPACE_GROUP_MEMBERS WHERE GROUP_ID IS NOT NULL AND MEMBER_ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "GOOGLE_WORKSPACE_GROUP_MEMBERS", query); err != nil {
		return 0, err
	} else if ok {
		rels = appendGoogleWorkspaceGroupMembershipRelationships(rels, result.Rows)
	}

	query = `SELECT ID, USER_ID, CLIENT_ID, DISPLAY_TEXT, ANONYMOUS, NATIVE_APP, SCOPE, SCOPE_COUNT FROM GOOGLE_WORKSPACE_TOKENS WHERE USER_ID IS NOT NULL AND CLIENT_ID IS NOT NULL`
	if result, ok, err := r.queryRowsForTable(ctx, "GOOGLE_WORKSPACE_TOKENS", query); err != nil {
		return 0, err
	} else if ok {
		rels = appendGoogleWorkspaceTokenRelationships(rels, result.Rows)
	}

	return r.persistRelationships(ctx, rels)
}

func appendGoogleWorkspaceGroupMembershipRelationships(rels []Relationship, rows []map[string]interface{}) []Relationship {
	for _, row := range rows {
		groupID := toString(queryRow(row, "group_id"))
		memberID := toString(queryRow(row, "member_id"))
		memberType := strings.ToUpper(strings.TrimSpace(toString(queryRow(row, "type"))))
		if groupID == "" || memberID == "" {
			continue
		}

		sourceType := ""
		switch memberType {
		case "USER":
			sourceType = "google_workspace:user"
		case "GROUP":
			sourceType = "google_workspace:group"
		default:
			continue
		}

		rels = append(rels, Relationship{
			SourceID:   memberID,
			SourceType: sourceType,
			TargetID:   groupID,
			TargetType: "google_workspace:group",
			RelType:    RelMemberOf,
		})
	}

	return rels
}

func appendGoogleWorkspaceTokenRelationships(rels []Relationship, rows []map[string]interface{}) []Relationship {
	for _, row := range rows {
		grantID := strings.TrimSpace(toString(queryRow(row, "id")))
		userID := strings.TrimSpace(toString(queryRow(row, "user_id")))
		clientID := strings.TrimSpace(toString(queryRow(row, "client_id")))
		scopeValue := strings.TrimSpace(toString(queryRow(row, "scope")))
		if grantID == "" || userID == "" || clientID == "" {
			continue
		}

		props, err := encodeProperties(map[string]interface{}{
			"grant_id":     grantID,
			"grant_type":   "delegated_permission_consent",
			"consent_type": "Principal",
			"scope":        scopeValue,
			"display_text": toString(queryRow(row, "display_text")),
			"anonymous":    queryRow(row, "anonymous"),
			"native_app":   queryRow(row, "native_app"),
			"scope_count":  queryRow(row, "scope_count"),
		})
		if err != nil {
			props = "{}"
		}

		rels = append(rels, Relationship{
			SourceID:   userID,
			SourceType: "google_workspace:user",
			TargetID:   clientID,
			TargetType: "google_workspace:application",
			RelType:    RelCanAccess,
			Properties: props,
		})

		scopes := strings.Fields(scopeValue)
		sort.Strings(scopes)
		for _, scope := range scopes {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				continue
			}
			scopeProps, err := encodeProperties(map[string]interface{}{
				"grant_id":   grantID,
				"grant_type": "delegated_permission",
				"scope":      scope,
			})
			if err != nil {
				scopeProps = "{}"
			}
			rels = append(rels, Relationship{
				SourceID:   clientID,
				SourceType: "google_workspace:application",
				TargetID:   "google_workspace_scope:" + scope,
				TargetType: "google_workspace:scope",
				RelType:    RelCanAccess,
				Properties: scopeProps,
			})
		}
	}

	return rels
}
